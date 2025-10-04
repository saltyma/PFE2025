#include "hsm_proto.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hsm_crypto.h"
#include "hsm_keystore.h"
#include "main.h"
#include "tx_api.h"
#include "ux_device_cdc_acm.h"
#include "ux_api.h"

extern UX_SLAVE_CLASS_CDC_ACM *cdc_acm;

#define HSM_MAX_LINE_LENGTH      160U
#define HSM_LINE_SLOTS           8U
#define HSM_QUEUE_DEPTH          HSM_LINE_SLOTS
#define HSM_QUEUE_OVERFLOW       0xFFFFFFFFUL
#define HSM_SESSION_TTL_TICKS    (120U * TX_TIMER_TICKS_PER_SECOND)
#define HSM_LOCKOUT_TICKS        (30U * TX_TIMER_TICKS_PER_SECOND)
#define HSM_PBKDF_ITERATIONS     HSM_PBKDF_ITERATIONS_DEFAULT /* lowered for acceptable unlock latency on STM32U5 */

typedef struct
{
  hsm_keystore_t keystore;
  bool unlocked;
  ULONG unlock_deadline;
  ULONG lockout_deadline;
  uint8_t bad_attempts;
  bool ready_sent;
  char hsm_id[40];
} hsm_state_t;

static hsm_state_t g_state;

static TX_THREAD g_hsm_thread;
static UCHAR g_hsm_thread_stack[2048];

static TX_QUEUE g_hsm_queue;
static ULONG g_hsm_queue_buffer[HSM_QUEUE_DEPTH];

static TX_SEMAPHORE g_slot_semaphore;
static TX_MUTEX g_slot_mutex;
static TX_MUTEX g_tx_mutex;

static char g_lines[HSM_LINE_SLOTS][HSM_MAX_LINE_LENGTH];
static bool g_slot_used[HSM_LINE_SLOTS];
static uint8_t g_next_slot = 0U;

static uint8_t g_rx_buffer[HSM_MAX_LINE_LENGTH];
static uint32_t g_rx_length = 0U;
static bool g_rx_overflow = false;
static bool g_last_was_cr = false;
static bool g_cdc_ready = false;

static bool g_initialized = false;

static void hsm_command_thread(ULONG thread_input);
static void hsm_send_line(const char *line);
static void hsm_send_status(bool ok, const char *msg);
static void hsm_send_payload(const char *msg, const char *payload);
static void hsm_process_line(char *line, uint8_t slot_index);
static void hsm_handle_unlock_timeout(void);
static void hsm_reset_session(void);
static bool hsm_lockout_active(void);
static void hsm_touch_session(void);
static int32_t hsm_time_diff(ULONG future, ULONG now);
static void hsm_compute_hsmid(void);
static void hsm_process_unlock(char *pin);
static void hsm_process_factory_reset(void);

static UINT hsm_allocate_slot(uint8_t *slot_index)
{
  if (tx_semaphore_get(&g_slot_semaphore, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_NO_MEMORY;
  }

  UINT status = TX_NO_MEMORY;
  tx_mutex_get(&g_slot_mutex, TX_WAIT_FOREVER);
  for (uint32_t i = 0U; i < HSM_LINE_SLOTS; ++i)
  {
    uint8_t candidate = (uint8_t)((g_next_slot + i) % HSM_LINE_SLOTS);
    if (!g_slot_used[candidate])
    {
      g_slot_used[candidate] = true;
      g_next_slot = (uint8_t)((candidate + 1U) % HSM_LINE_SLOTS);
      *slot_index = candidate;
      status = TX_SUCCESS;
      break;
    }
  }
  tx_mutex_put(&g_slot_mutex);

  if (status != TX_SUCCESS)
  {
    tx_semaphore_put(&g_slot_semaphore);
  }
  return status;
}

static void hsm_release_slot(uint8_t slot)
{
  tx_mutex_get(&g_slot_mutex, TX_WAIT_FOREVER);
  g_slot_used[slot] = false;
  tx_mutex_put(&g_slot_mutex);
  tx_semaphore_put(&g_slot_semaphore);
}

void hsm_proto_init(void)
{
  if (g_initialized)
  {
    return;
  }

  hsm_keystore_defaults(&g_state.keystore);
  (void)hsm_keystore_load(&g_state.keystore);

  if (!hsm_crypto_init())
  {
    Error_Handler();
  }

  if (tx_mutex_create(&g_slot_mutex, "hsm_slot", TX_NO_INHERIT) != TX_SUCCESS)
  {
    Error_Handler();
  }

  if (tx_mutex_create(&g_tx_mutex, "hsm_tx", TX_NO_INHERIT) != TX_SUCCESS)
  {
    Error_Handler();
  }

  if (tx_semaphore_create(&g_slot_semaphore, "hsm_slot_sem", HSM_LINE_SLOTS) != TX_SUCCESS)
  {
    Error_Handler();
  }

  if (tx_queue_create(&g_hsm_queue,
                      "hsm_queue",
                      TX_1_ULONG,
                      g_hsm_queue_buffer,
                      sizeof(g_hsm_queue_buffer)) != TX_SUCCESS)
  {
    Error_Handler();
  }

  if (tx_thread_create(&g_hsm_thread,
                       "hsm_cmd",
                       hsm_command_thread,
                       0,
                       g_hsm_thread_stack,
                       sizeof(g_hsm_thread_stack),
                       10,
                       10,
                       TX_NO_TIME_SLICE,
                       TX_AUTO_START) != TX_SUCCESS)
  {
    Error_Handler();
  }

  g_state.unlocked = false;
  g_state.unlock_deadline = 0U;
  g_state.lockout_deadline = 0U;
  g_state.bad_attempts = 0U;
  g_state.ready_sent = false;
  memset(g_slot_used, 0, sizeof(g_slot_used));
  g_rx_length = 0U;
  g_rx_overflow = false;
  g_last_was_cr = false;
  g_cdc_ready = false;

  hsm_compute_hsmid();

  g_initialized = true;
}

static void hsm_command_thread(ULONG thread_input)
{
  (void)thread_input;

  while (1)
  {
    ULONG message = 0U;
    ULONG wait_option = TX_WAIT_FOREVER;
    if (g_state.unlocked)
    {
      ULONG now = tx_time_get();
      if (hsm_time_diff(g_state.unlock_deadline, now) <= 0)
      {
        wait_option = 0U;
      }
      else
      {
        wait_option = g_state.unlock_deadline - now;
      }
    }

    UINT status = tx_queue_receive(&g_hsm_queue, &message, wait_option);
    if (status == TX_SUCCESS)
    {
      if (message == HSM_QUEUE_OVERFLOW)
      {
        hsm_send_status(false, "ARG");
      }
      else if (message < HSM_LINE_SLOTS)
      {
        char *line = g_lines[message];
        hsm_process_line(line, (uint8_t)message);
      }
    }
    else if ((status == TX_QUEUE_EMPTY) && g_state.unlocked)
    {
      hsm_handle_unlock_timeout();
    }
  }
}

static void hsm_handle_unlock_timeout(void)
{
  ULONG now = tx_time_get();
  if (g_state.unlocked && (hsm_time_diff(g_state.unlock_deadline, now) <= 0))
  {
    g_state.unlocked = false;
    g_state.unlock_deadline = 0U;
  }
}

static int32_t hsm_time_diff(ULONG future, ULONG now)
{
  return (int32_t)(future - now);
}

static void hsm_reset_session(void)
{
  g_state.unlocked = false;
  g_state.unlock_deadline = 0U;
}

static bool hsm_lockout_active(void)
{
  if (g_state.lockout_deadline == 0U)
  {
    return false;
  }
  ULONG now = tx_time_get();
  if (hsm_time_diff(g_state.lockout_deadline, now) > 0)
  {
    return true;
  }
  g_state.lockout_deadline = 0U;
  g_state.bad_attempts = 0U;
  return false;
}

static void hsm_touch_session(void)
{
  g_state.unlocked = true;
  g_state.unlock_deadline = tx_time_get() + HSM_SESSION_TTL_TICKS;
}

static void hsm_compute_hsmid(void)
{
  uint8_t uid_bytes[12];
  uint32_t w0 = HAL_GetUIDw0();
  uint32_t w1 = HAL_GetUIDw1();
  uint32_t w2 = HAL_GetUIDw2();
  memcpy(&uid_bytes[0], &w0, sizeof(uint32_t));
  memcpy(&uid_bytes[4], &w1, sizeof(uint32_t));
  memcpy(&uid_bytes[8], &w2, sizeof(uint32_t));
  if (!hsm_crypto_base64url(uid_bytes, sizeof(uid_bytes), g_state.hsm_id, sizeof(g_state.hsm_id)))
  {
    strcpy(g_state.hsm_id, "unknown");
  }
}

static void hsm_send_buffer(const uint8_t *data, size_t length)
{
  if ((!g_cdc_ready) || (cdc_acm == UX_NULL) || (data == NULL) || (length == 0U))
  {
    return;
  }

  tx_mutex_get(&g_tx_mutex, TX_WAIT_FOREVER);

  size_t offset = 0U;
  while (offset < length)
  {
    if ((!g_cdc_ready) || (cdc_acm == UX_NULL))
    {
      break;
    }

    ULONG actual = 0U;
    UINT status = _ux_device_class_cdc_acm_write(cdc_acm,
                                                 (UCHAR *)&data[offset],
                                                 (ULONG)(length - offset),
                                                 &actual);

    if (status != UX_SUCCESS)
    {
      break;
    }

    if (actual == 0U)
    {
      tx_thread_sleep(1U);
      continue;
    }

    offset += (size_t)actual;
  }

  tx_mutex_put(&g_tx_mutex);
}

static void hsm_send_line(const char *line)
{
  if (line == NULL)
  {
    line = "";
  }
  hsm_send_buffer((const uint8_t *)line, strlen(line));
  hsm_send_buffer((const uint8_t *)"\r\n", 2U);
}

static void hsm_send_status(bool ok, const char *msg)
{
  char buffer[64];
  const char *prefix = ok ? "OK" : "ERR";
  int len = snprintf(buffer, sizeof(buffer), "%s %s", prefix, (msg != NULL) ? msg : "");
  if (len > 0)
  {
    hsm_send_line(buffer);
  }
}

static void hsm_send_payload(const char *msg, const char *payload)
{
  hsm_send_status(true, msg);
  hsm_send_line(payload);
}

static void hsm_process_info(const char *cmd)
{
  (void)cmd;
  hsm_send_status(true, "HSM-EMU v0.1");
}

static void hsm_process_hsmid(void)
{
  hsm_send_payload("HSMID", g_state.hsm_id);
}

static void hsm_process_ping(void)
{
  hsm_send_status(true, "PONG");
}

static void hsm_process_logout(const char *response)
{
  hsm_reset_session();
  hsm_send_status(true, response);
}

static bool hsm_pin_valid(const char *pin)
{
  size_t len = strlen(pin);
  return (len >= 4U) && (len <= 32U);
}

static void hsm_process_unlock(char *pin)
{
  if (pin == NULL)
  {
    hsm_send_status(false, "ARG");
    return;
  }

  if (!hsm_pin_valid(pin))
  {
    hsm_send_status(false, "ARG");
    return;
  }

  if (hsm_lockout_active())
  {
    hsm_send_status(false, "LOCKED");
    return;
  }

  bool require_new_pin = (!g_state.keystore.pin_set) || (g_state.keystore.pbkdf_iterations == 0U);

  if (require_new_pin)
  {
    uint32_t iterations = HSM_PBKDF_ITERATIONS;
    if (!hsm_crypto_random(g_state.keystore.pin_salt, sizeof(g_state.keystore.pin_salt)))
    {
      hsm_send_status(false, "FAIL");
      return;
    }
    if (!hsm_crypto_pbkdf2((const uint8_t *)pin,
                           strlen(pin),
                           g_state.keystore.pin_salt,
                           sizeof(g_state.keystore.pin_salt),
                           iterations,
                           g_state.keystore.pin_hash,
                           sizeof(g_state.keystore.pin_hash)))
    {
      hsm_send_status(false, "FAIL");
      return;
    }
    g_state.keystore.pin_set = true;
    g_state.keystore.pbkdf_iterations = iterations;
    if (!hsm_keystore_save(&g_state.keystore))
    {
      g_state.keystore.pin_set = false;
      g_state.keystore.pbkdf_iterations = 0U;
      memset(g_state.keystore.pin_salt, 0, sizeof(g_state.keystore.pin_salt));
      memset(g_state.keystore.pin_hash, 0, sizeof(g_state.keystore.pin_hash));
      hsm_send_status(false, "FAIL");
      return;
    }
    g_state.bad_attempts = 0U;
    g_state.lockout_deadline = 0U;
    hsm_touch_session();
    hsm_send_status(true, "NEWPIN");
    return;
  }

  uint8_t derived[HSM_PBKDF_HASH_SIZE];
  uint32_t iterations = g_state.keystore.pbkdf_iterations;
  if ((iterations == 0U) ||
      !hsm_crypto_pbkdf2((const uint8_t *)pin,
                         strlen(pin),
                         g_state.keystore.pin_salt,
                         sizeof(g_state.keystore.pin_salt),
                         iterations,
                         derived,
                         sizeof(derived)))
  {
    memset(derived, 0, sizeof(derived));
    hsm_send_status(false, "FAIL");
    return;
  }

  bool match = (memcmp(derived, g_state.keystore.pin_hash, sizeof(derived)) == 0);
  memset(derived, 0, sizeof(derived));

  if (match)
  {
    g_state.bad_attempts = 0U;
    g_state.lockout_deadline = 0U;
    hsm_touch_session();
    hsm_send_status(true, "UNLOCKED");
  }
  else
  {
    if (g_state.bad_attempts < 0xFFU)
    {
      g_state.bad_attempts++;
    }
    if (g_state.bad_attempts >= 5U)
    {
      g_state.lockout_deadline = tx_time_get() + HSM_LOCKOUT_TICKS;
      hsm_send_status(false, "LOCKED");
    }
    else
    {
      hsm_send_status(false, "BADPIN");
    }
  }
}

static bool hsm_require_unlocked(void)
{
  if (!g_state.unlocked)
  {
    hsm_send_status(false, "LOCKED");
    return false;
  }
  return true;
}

static void hsm_process_keygen(char **argv, int argc)
{
  if (argc != 3)
  {
    hsm_send_status(false, "ARG");
    return;
  }

  if ((strcmp(argv[1], "EC") != 0) || (strcmp(argv[2], "P256") != 0))
  {
    hsm_send_status(false, "ARG");
    return;
  }

  if (!hsm_require_unlocked())
  {
    return;
  }

  if (g_state.keystore.key_present)
  {
    hsm_touch_session();
    hsm_send_status(true, "KEYEXISTS");
    return;
  }

  uint8_t priv[HSM_PRIVKEY_SIZE];
  uint8_t pub[HSM_PUBKEY_SIZE];
  if (!hsm_crypto_keypair(priv, pub))
  {
    hsm_send_status(false, "FAIL");
    return;
  }

  memcpy(g_state.keystore.priv_key, priv, sizeof(priv));
  memcpy(g_state.keystore.pub_key, pub, sizeof(pub));
  memset(priv, 0, sizeof(priv));
  memset(pub, 0, sizeof(pub));

  g_state.keystore.key_present = true;
  if (!hsm_keystore_save(&g_state.keystore))
  {
    g_state.keystore.key_present = false;
    memset(g_state.keystore.priv_key, 0, sizeof(g_state.keystore.priv_key));
    memset(g_state.keystore.pub_key, 0, sizeof(g_state.keystore.pub_key));
    hsm_send_status(false, "FAIL");
    return;
  }

  hsm_touch_session();
  hsm_send_status(true, "KEYGEN");
}

static void hsm_process_pubkey(void)
{
  if (!hsm_require_unlocked())
  {
    return;
  }
  if (!g_state.keystore.key_present)
  {
    hsm_send_status(false, "NO_KEY");
    return;
  }

  uint8_t spki[96];
  size_t spki_len = hsm_crypto_build_spki(g_state.keystore.pub_key, spki, sizeof(spki));
  if (spki_len == 0U)
  {
    hsm_send_status(false, "FAIL");
    return;
  }

  char encoded[160];
  if (!hsm_crypto_base64(spki, spki_len, encoded, sizeof(encoded)))
  {
    hsm_send_status(false, "FAIL");
    return;
  }

  hsm_touch_session();
  hsm_send_payload("PUBKEY", encoded);
}

static bool hsm_parse_hex_digest(const char *hex, uint8_t *out)
{
  size_t len = strlen(hex);
  if (len != 64U)
  {
    return false;
  }
  for (size_t i = 0U; i < len; ++i)
  {
    if (!isxdigit((int)hex[i]))
    {
      return false;
    }
  }
  for (size_t i = 0U; i < 32U; ++i)
  {
    char buf[3];
    buf[0] = hex[i * 2U];
    buf[1] = hex[i * 2U + 1U];
    buf[2] = '\0';
    unsigned long value = strtoul(buf, NULL, 16);
    out[i] = (uint8_t)value;
  }
  return true;
}

static void hsm_process_sign(char **argv, int argc)
{
  if (argc != 3)
  {
    hsm_send_status(false, "ARG");
    return;
  }

  if (strcmp(argv[1], "SHA256") != 0)
  {
    hsm_send_status(false, "ARG");
    return;
  }

  if (!hsm_require_unlocked())
  {
    return;
  }

  if (!g_state.keystore.key_present)
  {
    hsm_send_status(false, "NO_KEY");
    return;
  }

  uint8_t digest[32];
  if (!hsm_parse_hex_digest(argv[2], digest))
  {
    hsm_send_status(false, "ARG");
    return;
  }

  uint8_t signature[80];
  size_t signature_len = sizeof(signature);
  if (!hsm_crypto_sign(g_state.keystore.priv_key, digest, signature, &signature_len))
  {
    hsm_send_status(false, "FAIL");
    return;
  }

  char encoded[160];
  if (!hsm_crypto_base64(signature, signature_len, encoded, sizeof(encoded)))
  {
    hsm_send_status(false, "FAIL");
    return;
  }

  memset(signature, 0, sizeof(signature));
  hsm_touch_session();
  hsm_send_payload("SIG", encoded);
}

static void hsm_process_factory_reset(void)
{
  /* Factory reset command: wipes stored PIN and keys. Remove if remote wipe is undesired. */
  if (!hsm_require_unlocked())
  {
    return;
  }

  if (!hsm_keystore_erase())
  {
    hsm_send_status(false, "FAIL");
    return;
  }

  hsm_keystore_defaults(&g_state.keystore);
  g_state.bad_attempts = 0U;
  g_state.lockout_deadline = 0U;
  hsm_reset_session();
  hsm_send_status(true, "FACTORY");
}

static int hsm_tokenize(char *line, char **argv, int max_args)
{
  int count = 0;
  char *p = line;
  while ((*p != '\0') && (count < max_args))
  {
    while ((*p != '\0') && isspace((int)*p))
    {
      ++p;
    }
    if (*p == '\0')
    {
      break;
    }
    argv[count++] = p;
    while ((*p != '\0') && !isspace((int)*p))
    {
      ++p;
    }
    if (*p == '\0')
    {
      break;
    }
    *p++ = '\0';
  }
  return count;
}

static void hsm_process_line(char *line, uint8_t slot_index)
{
  char *argv[4];
  int argc = hsm_tokenize(line, argv, 4);
  if (argc == 0)
  {
    hsm_send_status(false, "BAD_CMD");
    hsm_release_slot(slot_index);
    return;
  }

  if (strcmp(argv[0], "INFO") == 0)
  {
    hsm_process_info(argv[0]);
  }
  else if (strcmp(argv[0], "HSMID") == 0)
  {
    hsm_process_hsmid();
  }
  else if (strcmp(argv[0], "PING") == 0)
  {
    hsm_process_ping();
  }
  else if (strcmp(argv[0], "UNLOCK") == 0)
  {
    char *pin = (argc >= 2) ? argv[1] : NULL;
    hsm_process_unlock(pin);
  }
  else if (strcmp(argv[0], "LOGOUT") == 0)
  {
    hsm_process_logout("BYE");
  }
  else if (strcmp(argv[0], "RESET") == 0)
  {
    hsm_process_logout("RESET");
  }
  else if (strcmp(argv[0], "FACTORY") == 0)
  {
    hsm_process_factory_reset();
  }
  else if (strcmp(argv[0], "KEYGEN") == 0)
  {
    hsm_process_keygen(argv, argc);
  }
  else if (strcmp(argv[0], "PUBKEY") == 0)
  {
    hsm_process_pubkey();
  }
  else if (strcmp(argv[0], "SIGN") == 0)
  {
    hsm_process_sign(argv, argc);
  }
  else
  {
    hsm_send_status(false, "BAD_CMD");
  }

  hsm_release_slot(slot_index);
}

void hsm_proto_receive_bytes(const uint8_t *data, UINT length)
{
  if ((data == NULL) || (length == 0U))
  {
    return;
  }

  for (UINT i = 0U; i < length; ++i)
  {
    uint8_t ch = data[i];
    if (ch == '\r')
    {
      g_last_was_cr = true;
      if (g_rx_overflow)
      {
        ULONG overflow = HSM_QUEUE_OVERFLOW;
        (void)tx_queue_send(&g_hsm_queue, &overflow, TX_NO_WAIT);
      }
      else if (g_rx_length > 0U)
      {
        uint8_t slot = 0U;
        if (hsm_allocate_slot(&slot) == TX_SUCCESS)
        {
          memcpy(g_lines[slot], g_rx_buffer, g_rx_length);
          g_lines[slot][g_rx_length] = '\0';
          ULONG message = slot;
          if (tx_queue_send(&g_hsm_queue, &message, TX_NO_WAIT) != TX_SUCCESS)
          {
            hsm_release_slot(slot);
          }
        }
        else
        {
          ULONG overflow = HSM_QUEUE_OVERFLOW;
          (void)tx_queue_send(&g_hsm_queue, &overflow, TX_NO_WAIT);
        }
      }
      g_rx_length = 0U;
      g_rx_overflow = false;
    }
    else if (ch == '\n')
    {
      if (g_last_was_cr)
      {
        g_last_was_cr = false;
        continue;
      }
      g_last_was_cr = false;
      if (g_rx_overflow)
      {
        ULONG overflow = HSM_QUEUE_OVERFLOW;
        (void)tx_queue_send(&g_hsm_queue, &overflow, TX_NO_WAIT);
      }
      else if (g_rx_length > 0U)
      {
        uint8_t slot = 0U;
        if (hsm_allocate_slot(&slot) == TX_SUCCESS)
        {
          memcpy(g_lines[slot], g_rx_buffer, g_rx_length);
          g_lines[slot][g_rx_length] = '\0';
          ULONG message = slot;
          if (tx_queue_send(&g_hsm_queue, &message, TX_NO_WAIT) != TX_SUCCESS)
          {
            hsm_release_slot(slot);
          }
        }
        else
        {
          ULONG overflow = HSM_QUEUE_OVERFLOW;
          (void)tx_queue_send(&g_hsm_queue, &overflow, TX_NO_WAIT);
        }
      }
      g_rx_length = 0U;
      g_rx_overflow = false;
    }
    else
    {
      g_last_was_cr = false;
      if (g_rx_length < (HSM_MAX_LINE_LENGTH - 1U))
      {
        g_rx_buffer[g_rx_length++] = ch;
      }
      else
      {
        g_rx_overflow = true;
      }
    }
  }
}

void hsm_proto_on_cdc_ready(void)
{
  g_cdc_ready = true;
  if (!g_state.ready_sent)
  {
    hsm_send_status(true, "READY");
    g_state.ready_sent = true;
  }
}

void hsm_proto_on_cdc_disconnect(void)
{
  g_cdc_ready = false;
  g_state.ready_sent = false;
  hsm_reset_session();
  g_rx_length = 0U;
  g_rx_overflow = false;
  g_last_was_cr = false;
}
