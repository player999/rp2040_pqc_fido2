#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define COSE_ALG_ML_DSA_87          -50
#define COSE_ALG_ML_DSA_87_COMPAT   -20
#define COSE_ALG_ML_KEM_1024        -24
#define COSE_ALG_ES512              -36
#define COSE_ALG_ECDH_ES_HKDF256    -25
#define COSE_ALG_ECDH_ES_HKDF512    -29
#define COSE_ALG_ES256              -7

// Sizes
#define MLDSA87_PUBLIC_KEY_SIZE     2592
#define MLDSA87_SECRET_KEY_SIZE     4896
#define MLDSA87_SIGNATURE_SIZE      4627

#define MLKEM1024_PUBLIC_KEY_SIZE   1568
#define MLKEM1024_SECRET_KEY_SIZE   3168
#define MLKEM1024_CIPHERTEXT_SIZE   1568
#define MLKEM1024_SS_SIZE           32

#define P521_COORD_SIZE             66
#define P521_MAX_DER_SIG_SIZE       144

#define P256_COORD_SIZE             32
#define P256_MAX_DER_SIG_SIZE       74

void crypto_engine_init(void);
void crypto_random_bytes(uint8_t *dest, size_t len);

// SHA & HMAC
void crypto_sha256(const uint8_t *input, size_t len, uint8_t output[32]);
void crypto_sha512(const uint8_t *input, size_t len, uint8_t output[64]);
void crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t output[32]);

// AES-256-CBC
bool crypto_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                               const uint8_t *input, size_t len, uint8_t *output);
bool crypto_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                               const uint8_t *input, size_t len, uint8_t *output);

// ML-DSA-87 (PQC Signature)
bool crypto_mldsa87_keypair(uint8_t *public_key, uint8_t *secret_key);
bool crypto_mldsa87_sign(uint8_t *signature, size_t *sig_len,
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t *secret_key);
bool crypto_mldsa87_verify(const uint8_t *msg, size_t msg_len,
                           const uint8_t *signature, size_t sig_len,
                           const uint8_t *public_key);

// ML-KEM-1024 (PQC Key Exchange / KEM)
bool crypto_mlkem1024_keypair(uint8_t *public_key, uint8_t *secret_key);
bool crypto_mlkem1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                             const uint8_t *public_key);
bool crypto_mlkem1024_decaps(uint8_t *shared_secret,
                             const uint8_t *ciphertext,
                             const uint8_t *secret_key);

// ECDSA secp521r1 (ES512)
bool crypto_p521_keypair(uint8_t x[P521_COORD_SIZE], uint8_t y[P521_COORD_SIZE],
                         uint8_t priv[P521_COORD_SIZE]);
bool crypto_p521_sign(const uint8_t *hash, size_t hash_len,
                      const uint8_t priv[P521_COORD_SIZE],
                      uint8_t *sig_der, size_t *sig_der_len);
bool crypto_p521_ecdh(const uint8_t peer_x[P521_COORD_SIZE], const uint8_t peer_y[P521_COORD_SIZE],
                      const uint8_t my_priv[P521_COORD_SIZE],
                      uint8_t shared_secret[P521_COORD_SIZE]);

// ECDSA secp256r1 (ES256)
bool crypto_p256_keypair(uint8_t x[P256_COORD_SIZE], uint8_t y[P256_COORD_SIZE],
                         uint8_t priv[P256_COORD_SIZE]);
bool crypto_p256_sign(const uint8_t *hash, size_t hash_len,
                      const uint8_t priv[P256_COORD_SIZE],
                      uint8_t *sig_der, size_t *sig_der_len);
bool crypto_p256_ecdh(const uint8_t peer_x[P256_COORD_SIZE], const uint8_t peer_y[P256_COORD_SIZE],
                      const uint8_t my_priv[P256_COORD_SIZE],
                      uint8_t shared_secret[P256_COORD_SIZE]);
