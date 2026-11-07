#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "crypto_engine.h"

#define MAX_RESIDENT_CREDENTIALS 16
#define CREDENTIAL_ID_SIZE       64
#define AAGUID_SIZE              16

typedef struct {
    bool in_use;
    int32_t alg;
    uint8_t cred_id[CREDENTIAL_ID_SIZE];
    uint8_t rp_id_hash[32];
    uint8_t user_id[32];
    size_t user_id_len;
    // For P-256/P-521/ML-DSA-87 key derivation seed (32 bytes)
    uint8_t priv_seed[32];
    // For P-521 full privkey if not seed-derived
    uint8_t p521_priv[P521_COORD_SIZE];
} ResidentCredential;

void storage_init(void);
uint32_t storage_get_and_increment_counter(void);
const uint8_t *storage_get_aaguid(void);

// Non-resident credential wrap/unwrap
bool storage_wrap_credential(int32_t alg, const uint8_t *seed_or_priv, size_t key_len,
                             const uint8_t rp_id_hash[32],
                             uint8_t *cred_id_out, size_t *cred_id_len);
bool storage_unwrap_credential(const uint8_t *cred_id, size_t cred_id_len,
                               const uint8_t rp_id_hash[32],
                               int32_t *alg_out, uint8_t *key_data_out, size_t *key_data_len);

// Resident credential management
bool storage_save_resident_credential(int32_t alg, const uint8_t *cred_id, size_t cred_id_len,
                                      const uint8_t rp_id_hash[32],
                                      const uint8_t *user_id, size_t user_id_len,
                                      const uint8_t *seed_or_priv, size_t key_len);
const ResidentCredential *storage_find_resident_credential(const uint8_t rp_id_hash[32],
                                                          const uint8_t *cred_id, size_t cred_id_len);

// Client PIN
bool storage_is_pin_set(void);
uint32_t storage_get_pin_retries(void);
bool storage_set_pin(const uint8_t pin_hash[16]);
bool storage_verify_pin(const uint8_t pin_hash[16]);
void storage_reset_pin(void);
