#ifndef HSM_KEYSTORE_H
#define HSM_KEYSTORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hsm_crypto.h"

#define HSM_PBKDF_ITERATIONS_DEFAULT   20000U

typedef struct
{
  bool pin_set;
  bool key_present;
  uint32_t pbkdf_iterations;
  uint8_t pin_salt[HSM_PBKDF_SALT_SIZE];
  uint8_t pin_hash[HSM_PBKDF_HASH_SIZE];
  uint8_t priv_key[HSM_PRIVKEY_SIZE];
  uint8_t pub_key[HSM_PUBKEY_SIZE];
} hsm_keystore_t;

void hsm_keystore_defaults(hsm_keystore_t *store);
bool hsm_keystore_load(hsm_keystore_t *store);
bool hsm_keystore_save(const hsm_keystore_t *store);
bool hsm_keystore_erase(void);

#endif /* HSM_KEYSTORE_H */
