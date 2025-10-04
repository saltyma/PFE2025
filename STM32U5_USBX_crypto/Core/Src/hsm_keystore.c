#include "hsm_keystore.h"

#include <string.h>
#include <stdint.h>

#include "stm32u5xx_hal.h"
#include "stm32u5xx_hal_flash_ex.h"

#define HSM_KEYSTORE_MAGIC            0x324D5348u /* "HSM2" little-endian */
#define HSM_KEYSTORE_VERSION          0x00010001u
#define HSM_KEYSTORE_VERSION_LEGACY   0x00010000u

#if defined(FLASH_BASE_NS)
#define HSM_FLASH_BASE    FLASH_BASE_NS
#elif defined(FLASH_BASE)
#define HSM_FLASH_BASE    FLASH_BASE
#else
#error "Flash base address is undefined"
#endif

#define HSM_KEYSTORE_FLASH_BASE   (HSM_FLASH_BASE + FLASH_BANK_SIZE - FLASH_PAGE_SIZE)
#define HSM_KEYSTORE_FLASH_BANK   FLASH_BANK_1
#define HSM_KEYSTORE_PAGE_NUMBER  ((HSM_KEYSTORE_FLASH_BASE - HSM_FLASH_BASE) / FLASH_PAGE_SIZE)

typedef struct __attribute__((packed))
{
  uint32_t magic;
  uint32_t version;
} hsm_flash_header_t;

typedef struct __attribute__((packed))
{
  uint32_t magic;
  uint32_t version;
  uint8_t pin_set;
  uint8_t key_present;
  uint16_t reserved;
  uint8_t pin_salt[HSM_PBKDF_SALT_SIZE];
  uint8_t pin_hash[HSM_PBKDF_HASH_SIZE];
  uint8_t priv_key[HSM_PRIVKEY_SIZE];
  uint8_t pub_key[HSM_PUBKEY_SIZE];
  uint32_t crc;
} hsm_flash_record_v1_t;

typedef struct __attribute__((packed))
{
  uint32_t magic;
  uint32_t version;
  uint8_t pin_set;
  uint8_t key_present;
  uint16_t reserved;
  uint32_t pbkdf_iterations;
  uint8_t pin_salt[HSM_PBKDF_SALT_SIZE];
  uint8_t pin_hash[HSM_PBKDF_HASH_SIZE];
  uint8_t priv_key[HSM_PRIVKEY_SIZE];
  uint8_t pub_key[HSM_PUBKEY_SIZE];
  uint8_t reserved2[12];
  uint32_t crc;
} hsm_flash_record_v2_t;

_Static_assert((sizeof(hsm_flash_record_v1_t) % 16U) == 0U, "flash record must align to 128-bit");
_Static_assert((sizeof(hsm_flash_record_v2_t) % 16U) == 0U, "flash record must align to 128-bit");

static uint32_t hsm_crc32(const uint8_t *data, size_t length)
{
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < length; ++i)
  {
    crc ^= data[i];
    for (uint32_t bit = 0; bit < 8U; ++bit)
    {
      if (crc & 1U)
      {
        crc = (crc >> 1) ^ 0xEDB88320u;
      }
      else
      {
        crc >>= 1;
      }
    }
  }
  return crc ^ 0xFFFFFFFFu;
}

void hsm_keystore_defaults(hsm_keystore_t *store)
{
  if (store == NULL)
  {
    return;
  }
  memset(store, 0, sizeof(*store));
  store->pin_set = false;
  store->key_present = false;
  store->pbkdf_iterations = HSM_PBKDF_ITERATIONS_DEFAULT;
}

bool hsm_keystore_load(hsm_keystore_t *store)
{
  if (store == NULL)
  {
    return false;
  }

  const hsm_flash_header_t *header = (const hsm_flash_header_t *)HSM_KEYSTORE_FLASH_BASE;
  if (header->magic != HSM_KEYSTORE_MAGIC)
  {
    hsm_keystore_defaults(store);
    return false;
  }

  if (header->version == HSM_KEYSTORE_VERSION)
  {
    const hsm_flash_record_v2_t *flash = (const hsm_flash_record_v2_t *)header;
    uint32_t expected_crc = hsm_crc32((const uint8_t *)flash,
                                      sizeof(hsm_flash_record_v2_t) - sizeof(uint32_t));
    if (expected_crc != flash->crc)
    {
      hsm_keystore_defaults(store);
      return false;
    }

    store->pin_set = (flash->pin_set != 0U);
    store->key_present = (flash->key_present != 0U);
    store->pbkdf_iterations = flash->pbkdf_iterations;
    memcpy(store->pin_salt, flash->pin_salt, sizeof(store->pin_salt));
    memcpy(store->pin_hash, flash->pin_hash, sizeof(store->pin_hash));
    memcpy(store->priv_key, flash->priv_key, sizeof(store->priv_key));
    memcpy(store->pub_key, flash->pub_key, sizeof(store->pub_key));
    if (store->pin_set && (store->pbkdf_iterations == 0U))
    {
      store->pin_set = false;
      memset(store->pin_salt, 0, sizeof(store->pin_salt));
      memset(store->pin_hash, 0, sizeof(store->pin_hash));
    }
    return true;
  }

  if (header->version == HSM_KEYSTORE_VERSION_LEGACY)
  {
    const hsm_flash_record_v1_t *flash = (const hsm_flash_record_v1_t *)header;
    uint32_t expected_crc = hsm_crc32((const uint8_t *)flash,
                                      sizeof(hsm_flash_record_v1_t) - sizeof(uint32_t));
    if (expected_crc != flash->crc)
    {
      hsm_keystore_defaults(store);
      return false;
    }

    store->key_present = (flash->key_present != 0U);
    store->pin_set = false;
    store->pbkdf_iterations = 0U;
    memset(store->pin_salt, 0, sizeof(store->pin_salt));
    memset(store->pin_hash, 0, sizeof(store->pin_hash));
    memcpy(store->priv_key, flash->priv_key, sizeof(store->priv_key));
    memcpy(store->pub_key, flash->pub_key, sizeof(store->pub_key));
    return false;
  }

  hsm_keystore_defaults(store);
  return false;
}

bool hsm_keystore_save(const hsm_keystore_t *store)
{
  if (store == NULL)
  {
    return false;
  }

  hsm_flash_record_v2_t record;
  record.magic = HSM_KEYSTORE_MAGIC;
  record.version = HSM_KEYSTORE_VERSION;
  record.pin_set = store->pin_set ? 1U : 0U;
  record.key_present = store->key_present ? 1U : 0U;
  record.reserved = 0U;
  record.pbkdf_iterations = store->pbkdf_iterations;
  memset(record.reserved2, 0, sizeof(record.reserved2));
  memcpy(record.pin_salt, store->pin_salt, sizeof(record.pin_salt));
  memcpy(record.pin_hash, store->pin_hash, sizeof(record.pin_hash));
  memcpy(record.priv_key, store->priv_key, sizeof(record.priv_key));
  memcpy(record.pub_key, store->pub_key, sizeof(record.pub_key));
  record.crc = hsm_crc32((const uint8_t *)&record, sizeof(record) - sizeof(uint32_t));

  HAL_FLASH_Unlock();
  __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_ALL_ERRORS);

  FLASH_EraseInitTypeDef erase = {0};
  erase.TypeErase = FLASH_TYPEERASE_PAGES;
  erase.Banks = HSM_KEYSTORE_FLASH_BANK;
  erase.Page = HSM_KEYSTORE_PAGE_NUMBER;
  erase.NbPages = 1U;

  uint32_t page_error = 0U;
  if (HAL_FLASHEx_Erase(&erase, &page_error) != HAL_OK)
  {
    HAL_FLASH_Lock();
    return false;
  }

  const uint8_t *src = (const uint8_t *)&record;
  const size_t quadwords = sizeof(record) / 16U;
  uint32_t address = HSM_KEYSTORE_FLASH_BASE;

  for (size_t i = 0; i < quadwords; ++i)
  {
    const uint8_t *chunk = &src[i * 16U];
    if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, address, (uint32_t)(uintptr_t)chunk) != HAL_OK)
    {
      HAL_FLASH_Lock();
      return false;
    }
    address += 16U;
  }

  HAL_FLASH_Lock();
  return true;
}

bool hsm_keystore_erase(void)
{
  HAL_FLASH_Unlock();
  __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_ALL_ERRORS);

  FLASH_EraseInitTypeDef erase = {0};
  erase.TypeErase = FLASH_TYPEERASE_PAGES;
  erase.Banks = HSM_KEYSTORE_FLASH_BANK;
  erase.Page = HSM_KEYSTORE_PAGE_NUMBER;
  erase.NbPages = 1U;

  uint32_t page_error = 0U;
  HAL_StatusTypeDef status = HAL_FLASHEx_Erase(&erase, &page_error);
  HAL_FLASH_Lock();
  return status == HAL_OK;
}
