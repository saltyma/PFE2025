#ifndef HSM_CRYPTO_H
#define HSM_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HSM_PRIVKEY_SIZE       32U
#define HSM_PUBKEY_SIZE        64U
#define HSM_PBKDF_SALT_SIZE    16U
#define HSM_PBKDF_HASH_SIZE    32U

bool hsm_crypto_init(void);
bool hsm_crypto_random(uint8_t *buffer, size_t length);
bool hsm_crypto_pbkdf2(const uint8_t *password,
                       size_t password_len,
                       const uint8_t *salt,
                       size_t salt_len,
                       uint32_t iterations,
                       uint8_t *output,
                       size_t output_len);
bool hsm_crypto_keypair(uint8_t *priv_key, uint8_t *pub_key);
bool hsm_crypto_sign(const uint8_t *priv_key,
                     const uint8_t *digest,
                     uint8_t *signature_der,
                     size_t *signature_len);
size_t hsm_crypto_build_spki(const uint8_t *pub_key,
                             uint8_t *output,
                             size_t output_size);
bool hsm_crypto_base64(const uint8_t *input,
                       size_t input_len,
                       char *output,
                       size_t output_size);
bool hsm_crypto_base64url(const uint8_t *input,
                          size_t input_len,
                          char *output,
                          size_t output_size);

#endif /* HSM_CRYPTO_H */
