#include "hsm_crypto.h"

#include <string.h>

#include <cmox_crypto.h>
#include <ecc/cmox_ecdsa.h>
#include <mac/cmox_hmac.h>
#include "stm32u5xx_hal.h"

#include "tx_api.h"

extern RNG_HandleTypeDef hrng;

static bool g_crypto_initialized = false;
static TX_MUTEX g_crypto_mutex;
static bool g_mutex_created = false;

static uint8_t ecc_working_buffer[2048];

static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void hsm_crypto_lock(void)
{
  if (g_mutex_created)
  {
    tx_mutex_get(&g_crypto_mutex, TX_WAIT_FOREVER);
  }
}

static void hsm_crypto_unlock(void)
{
  if (g_mutex_created)
  {
    tx_mutex_put(&g_crypto_mutex);
  }
}

bool hsm_crypto_init(void)
{
  if (!g_crypto_initialized)
  {
    cmox_init_arg_t init_arg = {CMOX_INIT_TARGET_AUTO, NULL};
    if (cmox_initialize(&init_arg) != CMOX_INIT_SUCCESS)
    {
      return false;
    }
    if (!g_mutex_created)
    {
      if (tx_mutex_create(&g_crypto_mutex, "hsm_crypto", TX_NO_INHERIT) != TX_SUCCESS)
      {
        return false;
      }
      g_mutex_created = true;
    }
    g_crypto_initialized = true;
  }
  return true;
}

bool hsm_crypto_random(uint8_t *buffer, size_t length)
{
  if ((buffer == NULL) || (length == 0U))
  {
    return false;
  }

  size_t offset = 0U;
  while (offset < length)
  {
    uint32_t random_word = 0U;
    if (HAL_RNG_GenerateRandomNumber(&hrng, &random_word) != HAL_OK)
    {
      return false;
    }
    size_t chunk = ((length - offset) >= sizeof(random_word)) ? sizeof(random_word) : (length - offset);
    memcpy(&buffer[offset], &random_word, chunk);
    offset += chunk;
  }
  return true;
}

bool hsm_crypto_pbkdf2(const uint8_t *password,
                       size_t password_len,
                       const uint8_t *salt,
                       size_t salt_len,
                       uint32_t iterations,
                       uint8_t *output,
                       size_t output_len)
{
  if ((password == NULL) || (salt == NULL) || (output == NULL))
  {
    return false;
  }
  if ((output_len == 0U) || (output_len > HSM_PBKDF_HASH_SIZE))
  {
    return false;
  }
  if (iterations == 0U)
  {
    return false;
  }

  uint8_t salt_block[HSM_PBKDF_SALT_SIZE + 4U];
  if (salt_len > HSM_PBKDF_SALT_SIZE)
  {
    return false;
  }
  memcpy(salt_block, salt, salt_len);
  salt_block[salt_len + 0U] = 0x00U;
  salt_block[salt_len + 1U] = 0x00U;
  salt_block[salt_len + 2U] = 0x00U;
  salt_block[salt_len + 3U] = 0x01U;

  uint8_t u[HSM_PBKDF_HASH_SIZE];
  size_t mac_len = sizeof(u);
  if (cmox_mac_compute(CMOX_HMAC_SHA256_ALGO,
                       salt_block,
                       salt_len + 4U,
                       password,
                       password_len,
                       NULL,
                       0U,
                       u,
                       sizeof(u),
                       &mac_len) != CMOX_MAC_SUCCESS)
  {
    return false;
  }
  if (mac_len != sizeof(u))
  {
    return false;
  }

  uint8_t t[HSM_PBKDF_HASH_SIZE];
  memcpy(t, u, sizeof(t));

  for (uint32_t i = 1U; i < iterations; ++i)
  {
    mac_len = sizeof(u);
    if (cmox_mac_compute(CMOX_HMAC_SHA256_ALGO,
                         u,
                         sizeof(u),
                         password,
                         password_len,
                         NULL,
                         0U,
                         u,
                         sizeof(u),
                         &mac_len) != CMOX_MAC_SUCCESS)
    {
      return false;
    }
    if (mac_len != sizeof(u))
    {
      return false;
    }
    for (size_t j = 0U; j < sizeof(u); ++j)
    {
      t[j] ^= u[j];
    }
  }

  memcpy(output, t, output_len);
  memset(u, 0, sizeof(u));
  memset(t, 0, sizeof(t));
  memset(salt_block, 0, sizeof(salt_block));
  return true;
}

bool hsm_crypto_keypair(uint8_t *priv_key, uint8_t *pub_key)
{
  if ((priv_key == NULL) || (pub_key == NULL))
  {
    return false;
  }

  uint8_t random_material[64];
  if (!hsm_crypto_random(random_material, sizeof(random_material)))
  {
    return false;
  }

  bool result = false;
  hsm_crypto_lock();

  cmox_ecc_handle_t ecc_ctx;
  cmox_ecc_construct(&ecc_ctx, CMOX_ECC256_MATH_FUNCS, ecc_working_buffer, sizeof(ecc_working_buffer));

  size_t priv_len = HSM_PRIVKEY_SIZE;
  size_t pub_len = HSM_PUBKEY_SIZE;
  cmox_ecc_retval_t status = cmox_ecdsa_keyGen(&ecc_ctx,
                                               CMOX_ECC_CURVE_SECP256R1,
                                               random_material,
                                               sizeof(random_material),
                                               priv_key,
                                               &priv_len,
                                               pub_key,
                                               &pub_len);
  cmox_ecc_cleanup(&ecc_ctx);
  hsm_crypto_unlock();

  if ((status == CMOX_ECC_SUCCESS) && (priv_len == HSM_PRIVKEY_SIZE) && (pub_len == HSM_PUBKEY_SIZE))
  {
    result = true;
  }

  memset(random_material, 0, sizeof(random_material));
  return result;
}

static size_t hsm_der_encode_integer(const uint8_t *input, size_t length, uint8_t *output)
{
  size_t offset = 0U;
  while ((offset < length) && (input[offset] == 0U))
  {
    offset++;
  }

  size_t used = length - offset;
  if (used == 0U)
  {
    used = 1U;
    offset = length > 0U ? (length - 1U) : 0U;
  }

  bool add_zero = (input[offset] & 0x80U) != 0U;
  size_t total_len = used + (add_zero ? 1U : 0U);

  output[0] = 0x02U;
  output[1] = (uint8_t)total_len;
  size_t idx = 2U;
  if (add_zero)
  {
    output[idx++] = 0x00U;
  }
  memcpy(&output[idx], &input[offset], used);
  idx += used;
  return idx;
}

bool hsm_crypto_sign(const uint8_t *priv_key,
                     const uint8_t *digest,
                     uint8_t *signature_der,
                     size_t *signature_len)
{
  if ((priv_key == NULL) || (digest == NULL) || (signature_der == NULL) || (signature_len == NULL))
  {
    return false;
  }

  uint8_t random_material[64];
  if (!hsm_crypto_random(random_material, sizeof(random_material)))
  {
    return false;
  }

  uint8_t raw_signature[HSM_PRIVKEY_SIZE * 2U];
  size_t raw_len = sizeof(raw_signature);

  bool result = false;

  hsm_crypto_lock();
  cmox_ecc_handle_t ecc_ctx;
  cmox_ecc_construct(&ecc_ctx, CMOX_ECC256_MATH_FUNCS, ecc_working_buffer, sizeof(ecc_working_buffer));

  cmox_ecc_retval_t status = cmox_ecdsa_sign(&ecc_ctx,
                                             CMOX_ECC_CURVE_SECP256R1,
                                             random_material,
                                             sizeof(random_material),
                                             priv_key,
                                             HSM_PRIVKEY_SIZE,
                                             digest,
                                             HSM_PBKDF_HASH_SIZE,
                                             raw_signature,
                                             &raw_len);

  cmox_ecc_cleanup(&ecc_ctx);
  hsm_crypto_unlock();

  memset(random_material, 0, sizeof(random_material));

  if ((status != CMOX_ECC_SUCCESS) || (raw_len != sizeof(raw_signature)))
  {
    memset(raw_signature, 0, sizeof(raw_signature));
    return false;
  }

  uint8_t sequence[80];
  size_t idx = 0U;
  sequence[idx++] = 0x30U;
  size_t len_pos = idx++;
  size_t r_len = hsm_der_encode_integer(raw_signature, HSM_PRIVKEY_SIZE, &sequence[idx]);
  idx += r_len;
  size_t s_len = hsm_der_encode_integer(&raw_signature[HSM_PRIVKEY_SIZE], HSM_PRIVKEY_SIZE, &sequence[idx]);
  idx += s_len;

  size_t seq_len = idx - (len_pos + 1U);
  if (seq_len > 127U)
  {
    memset(raw_signature, 0, sizeof(raw_signature));
    return false;
  }
  sequence[len_pos] = (uint8_t)seq_len;

  if (*signature_len < idx)
  {
    memset(raw_signature, 0, sizeof(raw_signature));
    return false;
  }

  memcpy(signature_der, sequence, idx);
  *signature_len = idx;
  memset(raw_signature, 0, sizeof(raw_signature));
  result = true;
  return result;
}

size_t hsm_crypto_build_spki(const uint8_t *pub_key, uint8_t *output, size_t output_size)
{
  if ((pub_key == NULL) || (output == NULL))
  {
    return 0U;
  }

  const size_t spki_len = 91U;
  if (output_size < spki_len)
  {
    return 0U;
  }

  uint8_t *p = output;
  *p++ = 0x30U;
  *p++ = 0x59U;
  *p++ = 0x30U;
  *p++ = 0x13U;
  *p++ = 0x06U;
  *p++ = 0x07U;
  *p++ = 0x2AU; *p++ = 0x86U; *p++ = 0x48U; *p++ = 0xCEU; *p++ = 0x3DU; *p++ = 0x02U; *p++ = 0x01U;
  *p++ = 0x06U;
  *p++ = 0x08U;
  *p++ = 0x2AU; *p++ = 0x86U; *p++ = 0x48U; *p++ = 0xCEU; *p++ = 0x3DU; *p++ = 0x03U; *p++ = 0x01U; *p++ = 0x07U;
  *p++ = 0x03U;
  *p++ = 0x42U;
  *p++ = 0x00U;
  *p++ = 0x04U;
  memcpy(p, pub_key, HSM_PUBKEY_SIZE);
  p += HSM_PUBKEY_SIZE;
  return spki_len;
}

static bool hsm_base64_encode_impl(const uint8_t *input,
                                   size_t input_len,
                                   char *output,
                                   size_t output_size,
                                   bool url_safe)
{
  if ((input == NULL) || (output == NULL))
  {
    return false;
  }

  const char *table = url_safe ? base64url_table : base64_table;
  size_t full_blocks = input_len / 3U;
  size_t remainder = input_len % 3U;
  size_t base_len = full_blocks * 4U + (remainder ? (url_safe ? remainder + 1U : 4U) : 0U);
  if (!url_safe && (remainder != 0U))
  {
    base_len = full_blocks * 4U + 4U;
  }

  if (output_size <= base_len)
  {
    return false;
  }

  size_t out_idx = 0U;
  size_t offset = 0U;
  for (size_t block = 0U; block < full_blocks; ++block)
  {
    uint32_t triple = ((uint32_t)input[offset] << 16)
                    | ((uint32_t)input[offset + 1U] << 8)
                    | ((uint32_t)input[offset + 2U]);
    offset += 3U;
    output[out_idx++] = table[(triple >> 18) & 0x3FU];
    output[out_idx++] = table[(triple >> 12) & 0x3FU];
    output[out_idx++] = table[(triple >> 6) & 0x3FU];
    output[out_idx++] = table[triple & 0x3FU];
  }

  if (remainder == 1U)
  {
    uint32_t triple = ((uint32_t)input[offset]) << 16;
    output[out_idx++] = table[(triple >> 18) & 0x3FU];
    output[out_idx++] = table[(triple >> 12) & 0x3FU];
    if (!url_safe)
    {
      output[out_idx++] = '=';
      output[out_idx++] = '=';
    }
  }
  else if (remainder == 2U)
  {
    uint32_t triple = (((uint32_t)input[offset]) << 16) | (((uint32_t)input[offset + 1U]) << 8);
    output[out_idx++] = table[(triple >> 18) & 0x3FU];
    output[out_idx++] = table[(triple >> 12) & 0x3FU];
    output[out_idx++] = table[(triple >> 6) & 0x3FU];
    if (!url_safe)
    {
      output[out_idx++] = '=';
    }
  }

  output[out_idx] = '\0';
  return true;
}

bool hsm_crypto_base64(const uint8_t *input,
                       size_t input_len,
                       char *output,
                       size_t output_size)
{
  return hsm_base64_encode_impl(input, input_len, output, output_size, false);
}

bool hsm_crypto_base64url(const uint8_t *input,
                          size_t input_len,
                          char *output,
                          size_t output_size)
{
  if (!hsm_base64_encode_impl(input, input_len, output, output_size, true))
  {
    return false;
  }
  size_t len = strlen(output);
  while ((len > 0U) && (output[len - 1U] == '='))
  {
    output[len - 1U] = '\0';
    --len;
  }
  return true;
}
