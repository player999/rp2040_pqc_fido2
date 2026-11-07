#include "storage.h"
#include <string.h>
#include "pico/unique_id.h"
#include "pico/stdlib.h"
#include "crypto_engine.h"

// Unique AAGUID for RP2040 PQC FIDO2: f1d02040-5051-4001-8000-727032303430
static const uint8_t s_aaguid[AAGUID_SIZE] = {
    0xF1, 0xD0, 0x20, 0x40, 0x50, 0x51, 0x40, 0x01,
    0x80, 0x00, 0x72, 0x70, 0x32, 0x30, 0x34, 0x30
};

static uint8_t s_master_key[32];
static uint32_t s_counter = 1;
static ResidentCredential s_resident_creds[MAX_RESIDENT_CREDENTIALS];

// PIN state
static bool s_pin_set = false;
static uint32_t s_pin_retries = 8;
static uint8_t s_pin_hash[16] = {0};

void storage_init(void) {
    pico_unique_board_id_t id;
    pico_get_unique_board_id(&id);

    // Derive Master Key from Board Unique ID
    uint8_t salt[] = "RP2040_FIDO2_PQC_MASTER_KEY_SALT";
    uint8_t input[sizeof(id.id) + sizeof(salt)];
    memcpy(input, id.id, sizeof(id.id));
    memcpy(input + sizeof(id.id), salt, sizeof(salt));
    crypto_sha256(input, sizeof(input), s_master_key);

    memset(s_resident_creds, 0, sizeof(s_resident_creds));
    s_counter = 1;
    s_pin_set = false;
    s_pin_retries = 8;
}

uint32_t storage_get_and_increment_counter(void) {
    return s_counter++;
}

const uint8_t *storage_get_aaguid(void) {
    return s_aaguid;
}

// Format of wrapped payload:
// [2B alg] [2B key_len] [68B key_data] [32B rp_id_hash] = 104 bytes -> 112 bytes (7 blocks of 16)
#define WRAP_PAYLOAD_SIZE 112
#define WRAP_CRED_ID_SIZE (16 + WRAP_PAYLOAD_SIZE + 16) // IV (16) + cipher (112) + HMAC (16) = 144 bytes

bool storage_wrap_credential(int32_t alg, const uint8_t *seed_or_priv, size_t key_len,
                             const uint8_t rp_id_hash[32],
                             uint8_t *cred_id_out, size_t *cred_id_len) {
    if (key_len > 68) return false;

    uint8_t payload[WRAP_PAYLOAD_SIZE];
    memset(payload, 0, sizeof(payload));

    int16_t alg_s16 = (int16_t)alg;
    uint16_t klen_u16 = (uint16_t)key_len;
    memcpy(payload, &alg_s16, 2);
    memcpy(payload + 2, &klen_u16, 2);
    memcpy(payload + 4, seed_or_priv, key_len);
    memcpy(payload + 4 + 68, rp_id_hash, 32);

    uint8_t iv[16];
    crypto_random_bytes(iv, 16);

    uint8_t encrypted[WRAP_PAYLOAD_SIZE];
    if (!crypto_aes256_cbc_encrypt(s_master_key, iv, payload, sizeof(payload), encrypted)) {
        return false;
    }

    // cred_id_out = IV (16) || encrypted (112) || HMAC-SHA256(IV || encrypted)[0..16]
    memcpy(cred_id_out, iv, 16);
    memcpy(cred_id_out + 16, encrypted, sizeof(encrypted));

    uint8_t mac[32];
    crypto_hmac_sha256(s_master_key, sizeof(s_master_key), cred_id_out, 16 + sizeof(encrypted), mac);
    memcpy(cred_id_out + 16 + sizeof(encrypted), mac, 16);

    *cred_id_len = WRAP_CRED_ID_SIZE;
    return true;
}

bool storage_unwrap_credential(const uint8_t *cred_id, size_t cred_id_len,
                               const uint8_t rp_id_hash[32],
                               int32_t *alg_out, uint8_t *key_data_out, size_t *key_data_len) {
    if (cred_id_len != WRAP_CRED_ID_SIZE) return false;

    // Verify HMAC
    uint8_t mac[32];
    crypto_hmac_sha256(s_master_key, sizeof(s_master_key), cred_id, 16 + WRAP_PAYLOAD_SIZE, mac);
    if (memcmp(mac, cred_id + 16 + WRAP_PAYLOAD_SIZE, 16) != 0) {
        return false;
    }

    uint8_t iv[16];
    memcpy(iv, cred_id, 16);

    uint8_t decrypted[WRAP_PAYLOAD_SIZE];
    if (!crypto_aes256_cbc_decrypt(s_master_key, iv, cred_id + 16, WRAP_PAYLOAD_SIZE, decrypted)) {
        return false;
    }

    // Verify rp_id_hash
    if (memcmp(decrypted + 4 + 68, rp_id_hash, 32) != 0) {
        return false;
    }

    int16_t alg_s16;
    uint16_t klen_u16;
    memcpy(&alg_s16, decrypted, 2);
    memcpy(&klen_u16, decrypted + 2, 2);

    if (klen_u16 > 68) return false;

    *alg_out = (int32_t)alg_s16;
    *key_data_len = klen_u16;
    memcpy(key_data_out, decrypted + 4, klen_u16);
    return true;
}

bool storage_save_resident_credential(int32_t alg, const uint8_t *cred_id, size_t cred_id_len,
                                      const uint8_t rp_id_hash[32],
                                      const uint8_t *user_id, size_t user_id_len,
                                      const uint8_t *seed_or_priv, size_t key_len) {
    for (size_t i = 0; i < MAX_RESIDENT_CREDENTIALS; ++i) {
        if (!s_resident_creds[i].in_use) {
            s_resident_creds[i].in_use = true;
            s_resident_creds[i].alg = alg;
            memcpy(s_resident_creds[i].cred_id, cred_id, cred_id_len < CREDENTIAL_ID_SIZE ? cred_id_len : CREDENTIAL_ID_SIZE);
            memcpy(s_resident_creds[i].rp_id_hash, rp_id_hash, 32);
            s_resident_creds[i].user_id_len = user_id_len < 32 ? user_id_len : 32;
            memcpy(s_resident_creds[i].user_id, user_id, s_resident_creds[i].user_id_len);

            if (key_len <= 32) {
                memcpy(s_resident_creds[i].priv_seed, seed_or_priv, key_len);
            } else if (key_len <= P521_COORD_SIZE) {
                memcpy(s_resident_creds[i].p521_priv, seed_or_priv, key_len);
            }
            return true;
        }
    }
    return false;
}

const ResidentCredential *storage_find_resident_credential(const uint8_t rp_id_hash[32],
                                                          const uint8_t *cred_id, size_t cred_id_len) {
    for (size_t i = 0; i < MAX_RESIDENT_CREDENTIALS; ++i) {
        if (s_resident_creds[i].in_use) {
            if (memcmp(s_resident_creds[i].rp_id_hash, rp_id_hash, 32) == 0) {
                if (cred_id == NULL || memcmp(s_resident_creds[i].cred_id, cred_id, cred_id_len) == 0) {
                    return &s_resident_creds[i];
                }
            }
        }
    }
    return NULL;
}

bool storage_is_pin_set(void) {
    return s_pin_set;
}

uint32_t storage_get_pin_retries(void) {
    return s_pin_retries;
}

bool storage_set_pin(const uint8_t pin_hash[16]) {
    memcpy(s_pin_hash, pin_hash, 16);
    s_pin_set = true;
    s_pin_retries = 8;
    return true;
}

bool storage_verify_pin(const uint8_t pin_hash[16]) {
    if (!s_pin_set || s_pin_retries == 0) return false;
    if (memcmp(s_pin_hash, pin_hash, 16) == 0) {
        s_pin_retries = 8;
        return true;
    }
    s_pin_retries--;
    return false;
}

void storage_reset_pin(void) {
    s_pin_set = false;
    s_pin_retries = 8;
    memset(s_pin_hash, 0, 16);
}
