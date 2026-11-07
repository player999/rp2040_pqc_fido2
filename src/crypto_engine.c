#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "crypto_engine.h"
#include <string.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "pico/rand.h"
#include <oqs/oqs.h>
#include "status_led.h"

// mbedtls headers
#include "mbedtls/platform_time.h"
#include "mbedtls/ecp.h"

mbedtls_ms_time_t mbedtls_ms_time(void) {
    return (mbedtls_ms_time_t)to_ms_since_boot(get_absolute_time());
}
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md.h"
#include "mbedtls/aes.h"

// Global OQS instances
static OQS_SIG *s_sig_mldsa87 = NULL;
static OQS_KEM *s_kem_mlkem1024 = NULL;

void crypto_random_bytes(uint8_t *dest, size_t len) {
    while (len >= 4) {
        uint32_t r = get_rand_32();
        memcpy(dest, &r, 4);
        dest += 4;
        len -= 4;
    }
    if (len > 0) {
        uint32_t r = get_rand_32();
        memcpy(dest, &r, len);
    }
}

static void oqs_randombytes_cb(uint8_t *dest, size_t len) {
    crypto_random_bytes(dest, len);
}

static int mbedtls_rng_cb(void *p_rng, unsigned char *output, size_t output_len) {
    (void)p_rng;
    crypto_random_bytes(output, output_len);
    return 0;
}

void crypto_engine_init(void) {
    OQS_randombytes_custom_algorithm(oqs_randombytes_cb);
    OQS_init();
    s_sig_mldsa87 = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    s_kem_mlkem1024 = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
}

// SHA-256
void crypto_sha256(const uint8_t *input, size_t len, uint8_t output[32]) {
    mbedtls_sha256(input, len, output, 0);
}

// SHA-512
void crypto_sha512(const uint8_t *input, size_t len, uint8_t output[64]) {
    mbedtls_sha512(input, len, output, 0);
}

// HMAC-SHA256
void crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t output[32]) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md_info, key, key_len, data, data_len, output);
}

// AES-256-CBC
bool crypto_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                               const uint8_t *input, size_t len, uint8_t *output) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    if (mbedtls_aes_setkey_enc(&aes, key, 256) != 0) {
        mbedtls_aes_free(&aes);
        return false;
    }
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv_copy, input, output);
    mbedtls_aes_free(&aes);
    return (ret == 0);
}

bool crypto_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                               const uint8_t *input, size_t len, uint8_t *output) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    if (mbedtls_aes_setkey_dec(&aes, key, 256) != 0) {
        mbedtls_aes_free(&aes);
        return false;
    }
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv_copy, input, output);
    mbedtls_aes_free(&aes);
    return (ret == 0);
}

// ML-DSA-87
extern int PQCP_MLDSA_NATIVE_MLDSA87_C_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

bool crypto_mldsa87_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t seed[32]) {
    status_led_set_mode(LED_MODE_PQC_ACTIVE);
    int rc = PQCP_MLDSA_NATIVE_MLDSA87_C_keypair_internal(public_key, secret_key, seed);
    return (rc == 0);
}

bool crypto_mldsa87_keypair(uint8_t *public_key, uint8_t *secret_key) {
    if (!s_sig_mldsa87) return false;
    status_led_set_mode(LED_MODE_PQC_ACTIVE);
    OQS_STATUS rc = OQS_SIG_keypair(s_sig_mldsa87, public_key, secret_key);
    return (rc == OQS_SUCCESS);
}

bool crypto_mldsa87_sign(uint8_t *signature, size_t *sig_len,
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t *secret_key) {
    if (!s_sig_mldsa87) return false;
    status_led_set_mode(LED_MODE_PQC_ACTIVE);
    OQS_STATUS rc = OQS_SIG_sign(s_sig_mldsa87, signature, sig_len, msg, msg_len, secret_key);
    return (rc == OQS_SUCCESS);
}

bool crypto_mldsa87_verify(const uint8_t *msg, size_t msg_len,
                           const uint8_t *signature, size_t sig_len,
                           const uint8_t *public_key) {
    if (!s_sig_mldsa87) return false;
    OQS_STATUS rc = OQS_SIG_verify(s_sig_mldsa87, msg, msg_len, signature, sig_len, public_key);
    return (rc == OQS_SUCCESS);
}

// ML-KEM-1024
bool crypto_mlkem1024_keypair(uint8_t *public_key, uint8_t *secret_key) {
    if (!s_kem_mlkem1024) return false;
    status_led_set_mode(LED_MODE_PQC_ACTIVE);
    OQS_STATUS rc = OQS_KEM_keypair(s_kem_mlkem1024, public_key, secret_key);
    return (rc == OQS_SUCCESS);
}

bool crypto_mlkem1024_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                             const uint8_t *public_key) {
    if (!s_kem_mlkem1024) return false;
    status_led_set_mode(LED_MODE_PQC_ACTIVE);
    OQS_STATUS rc = OQS_KEM_encaps(s_kem_mlkem1024, ciphertext, shared_secret, public_key);
    return (rc == OQS_SUCCESS);
}

bool crypto_mlkem1024_decaps(uint8_t *shared_secret,
                             const uint8_t *ciphertext,
                             const uint8_t *secret_key) {
    if (!s_kem_mlkem1024) return false;
    status_led_set_mode(LED_MODE_PQC_ACTIVE);
    OQS_STATUS rc = OQS_KEM_decaps(s_kem_mlkem1024, shared_secret, ciphertext, secret_key);
    return (rc == OQS_SUCCESS);
}

// ECDSA secp521r1 (ES512)
bool crypto_p521_keypair(uint8_t x[P521_COORD_SIZE], uint8_t y[P521_COORD_SIZE],
                         uint8_t priv[P521_COORD_SIZE]) {
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    if (mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP521R1, mbedtls_rng_cb, NULL) != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    // Export private key (521 bits = 66 bytes)
    mbedtls_mpi_write_binary(&ctx.d, priv, P521_COORD_SIZE);

    // Export public key coordinates (x, y)
    mbedtls_mpi_write_binary(&ctx.Q.X, x, P521_COORD_SIZE);
    mbedtls_mpi_write_binary(&ctx.Q.Y, y, P521_COORD_SIZE);

    mbedtls_ecdsa_free(&ctx);
    return true;
}

bool crypto_p521_sign(const uint8_t *hash, size_t hash_len,
                      const uint8_t priv[P521_COORD_SIZE],
                      uint8_t *sig_der, size_t *sig_der_len) {
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP521R1) != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    if (mbedtls_mpi_read_binary(&ctx.d, priv, P521_COORD_SIZE) != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    size_t slen = 0;
    // Sign using SHA-512 digest
    int ret = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA512,
                                           hash, hash_len,
                                           sig_der, P521_MAX_DER_SIG_SIZE, &slen,
                                           mbedtls_rng_cb, NULL);
    mbedtls_ecdsa_free(&ctx);
    if (ret != 0) return false;
    *sig_der_len = slen;
    return true;
}

bool crypto_p521_ecdh(const uint8_t peer_x[P521_COORD_SIZE], const uint8_t peer_y[P521_COORD_SIZE],
                      const uint8_t my_priv[P521_COORD_SIZE],
                      uint8_t shared_secret[P521_COORD_SIZE]) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point peer_Q;
    mbedtls_mpi d, z;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&peer_Q);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);

    bool ok = false;
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP521R1) != 0) goto exit;
    if (mbedtls_mpi_read_binary(&peer_Q.X, peer_x, P521_COORD_SIZE) != 0) goto exit;
    if (mbedtls_mpi_read_binary(&peer_Q.Y, peer_y, P521_COORD_SIZE) != 0) goto exit;
    if (mbedtls_mpi_lset(&peer_Q.Z, 1) != 0) goto exit;
    if (mbedtls_mpi_read_binary(&d, my_priv, P521_COORD_SIZE) != 0) goto exit;

    if (mbedtls_ecdh_compute_shared(&grp, &z, &peer_Q, &d, mbedtls_rng_cb, NULL) != 0) goto exit;
    if (mbedtls_mpi_write_binary(&z, shared_secret, P521_COORD_SIZE) != 0) goto exit;
    ok = true;

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&peer_Q);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    return ok;
}

// ECDSA secp256r1 (ES256)
bool crypto_p256_keypair(uint8_t x[P256_COORD_SIZE], uint8_t y[P256_COORD_SIZE],
                         uint8_t priv[P256_COORD_SIZE]) {
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    if (mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_rng_cb, NULL) != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    mbedtls_mpi_write_binary(&ctx.d, priv, P256_COORD_SIZE);
    mbedtls_mpi_write_binary(&ctx.Q.X, x, P256_COORD_SIZE);
    mbedtls_mpi_write_binary(&ctx.Q.Y, y, P256_COORD_SIZE);

    mbedtls_ecdsa_free(&ctx);
    return true;
}

bool crypto_p256_sign(const uint8_t *hash, size_t hash_len,
                      const uint8_t priv[P256_COORD_SIZE],
                      uint8_t *sig_der, size_t *sig_der_len) {
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    if (mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    if (mbedtls_mpi_read_binary(&ctx.d, priv, P256_COORD_SIZE) != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    size_t slen = 0;
    int ret = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256,
                                           hash, hash_len,
                                           sig_der, P256_MAX_DER_SIG_SIZE, &slen,
                                           mbedtls_rng_cb, NULL);
    mbedtls_ecdsa_free(&ctx);
    if (ret != 0) return false;
    *sig_der_len = slen;
    return true;
}

bool crypto_p256_ecdh(const uint8_t peer_x[P256_COORD_SIZE], const uint8_t peer_y[P256_COORD_SIZE],
                      const uint8_t my_priv[P256_COORD_SIZE],
                      uint8_t shared_secret[P256_COORD_SIZE]) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point peer_Q;
    mbedtls_mpi d, z;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&peer_Q);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);

    bool ok = false;
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) goto exit;
    if (mbedtls_mpi_read_binary(&peer_Q.X, peer_x, P256_COORD_SIZE) != 0) goto exit;
    if (mbedtls_mpi_read_binary(&peer_Q.Y, peer_y, P256_COORD_SIZE) != 0) goto exit;
    if (mbedtls_mpi_lset(&peer_Q.Z, 1) != 0) goto exit;
    if (mbedtls_mpi_read_binary(&d, my_priv, P256_COORD_SIZE) != 0) goto exit;

    if (mbedtls_ecdh_compute_shared(&grp, &z, &peer_Q, &d, mbedtls_rng_cb, NULL) != 0) goto exit;
    if (mbedtls_mpi_write_binary(&z, shared_secret, P256_COORD_SIZE) != 0) goto exit;
    ok = true;

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&peer_Q);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    return ok;
}
