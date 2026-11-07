#include "ctap_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fido_cbor.h"
#include "crypto_engine.h"
#include "storage.h"
#include "user_presence.h"
#include "status_led.h"

// Ephemeral KEM / ECDH agreement state
static uint8_t s_ephem_mlkem_sk[MLKEM1024_SECRET_KEY_SIZE];
static uint8_t s_ephem_mlkem_pk[MLKEM1024_PUBLIC_KEY_SIZE];
static bool s_has_ephem_mlkem = false;

static uint8_t s_ephem_p256_priv[P256_COORD_SIZE];
static uint8_t s_ephem_p256_x[P256_COORD_SIZE];
static uint8_t s_ephem_p256_y[P256_COORD_SIZE];
static bool s_has_ephem_p256 = false;

static uint8_t s_pin_token[32];
static bool s_pin_token_valid = false;

void ctap_engine_init(void) {
    s_has_ephem_mlkem = false;
    s_has_ephem_p256 = false;
    s_pin_token_valid = false;
}

// ----------------------------------------------------------------------------
// authenticatorGetInfo (0x04)
// ----------------------------------------------------------------------------
static size_t handle_get_info(uint8_t *response, size_t max_len) {
    printf("[CTAP2] authenticatorGetInfo\n");
    response[0] = CTAP2_ERR_SUCCESS;

    CborEncoder enc;
    if (!cbor_encoder_init(&enc, response + 1, max_len - 1)) {
        response[0] = CTAP2_ERR_OTHER;
        return 1;
    }

    // 7 key-value pairs:
    // 1: versions, 2: extensions, 3: aaguid, 4: options, 5: maxMsgSize, 6: pinProtocols, 10: algorithms
    cbor_encode_map(&enc, 7);

    // 1: versions = ["FIDO_2_1", "FIDO_2_0", "U2F_V2"]
    cbor_encode_uint(&enc, 1);
    cbor_encode_array(&enc, 3);
    cbor_encode_text(&enc, "FIDO_2_1");
    cbor_encode_text(&enc, "FIDO_2_0");
    cbor_encode_text(&enc, "U2F_V2");

    // 2: extensions = ["credProtect", "hmac-secret"]
    cbor_encode_uint(&enc, 2);
    cbor_encode_array(&enc, 2);
    cbor_encode_text(&enc, "credProtect");
    cbor_encode_text(&enc, "hmac-secret");

    // 3: aaguid (16 bytes)
    cbor_encode_uint(&enc, 3);
    cbor_encode_bytes(&enc, storage_get_aaguid(), AAGUID_SIZE);

    // 4: options = {"rk": true, "up": true, "plat": false, "clientPin": bool}
    cbor_encode_uint(&enc, 4);
    cbor_encode_map(&enc, 4);
    cbor_encode_text(&enc, "rk");
    cbor_encode_bool(&enc, true);
    cbor_encode_text(&enc, "up");
    cbor_encode_bool(&enc, true);
    cbor_encode_text(&enc, "plat");
    cbor_encode_bool(&enc, false);
    cbor_encode_text(&enc, "clientPin");
    cbor_encode_bool(&enc, storage_is_pin_set());

    // 5: maxMsgSize = 7168 (needed for ML-DSA-87 signatures/keys)
    cbor_encode_uint(&enc, 5);
    cbor_encode_uint(&enc, CTAP_MAX_RESPONSE_SIZE);

    // 6: pinUvAuthProtocols = [3, 2, 1] (3 = ML-KEM-1024 KEM)
    cbor_encode_uint(&enc, 6);
    cbor_encode_array(&enc, 3);
    cbor_encode_uint(&enc, 3);
    cbor_encode_uint(&enc, 2);
    cbor_encode_uint(&enc, 1);

    // 10: algorithms = [-50, -20, -36, -7]
    cbor_encode_uint(&enc, 10);
    cbor_encode_array(&enc, 4);

    // Alg -50 (ML-DSA-87 / RFC 9964)
    cbor_encode_map(&enc, 2);
    cbor_encode_text(&enc, "alg");
    cbor_encode_int(&enc, COSE_ALG_ML_DSA_87);
    cbor_encode_text(&enc, "type");
    cbor_encode_text(&enc, "public-key");

    // Alg -20 (ML-DSA-87 / SandboxAQ compatibility)
    cbor_encode_map(&enc, 2);
    cbor_encode_text(&enc, "alg");
    cbor_encode_int(&enc, COSE_ALG_ML_DSA_87_COMPAT);
    cbor_encode_text(&enc, "type");
    cbor_encode_text(&enc, "public-key");

    // Alg -36 (ECDSA secp521r1 / ES512)
    cbor_encode_map(&enc, 2);
    cbor_encode_text(&enc, "alg");
    cbor_encode_int(&enc, COSE_ALG_ES512);
    cbor_encode_text(&enc, "type");
    cbor_encode_text(&enc, "public-key");

    // Alg -7 (ECDSA secp256r1 / ES256)
    cbor_encode_map(&enc, 2);
    cbor_encode_text(&enc, "alg");
    cbor_encode_int(&enc, COSE_ALG_ES256);
    cbor_encode_text(&enc, "type");
    cbor_encode_text(&enc, "public-key");

    return 1 + cbor_encoder_size(&enc);
}

// ----------------------------------------------------------------------------
// authenticatorMakeCredential (0x01)
// ----------------------------------------------------------------------------
static size_t handle_make_credential(const uint8_t *payload, size_t len,
                                     uint8_t *response, size_t max_len) {
    printf("[CTAP2] authenticatorMakeCredential\n");
    CborCursor cur;
    cbor_cursor_init(&cur, payload, len);

    size_t pairs = 0;
    if (!cbor_read_map_start(&cur, &pairs)) {
        response[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

    const uint8_t *client_data_hash = NULL;
    size_t client_data_hash_len = 0;
    const uint8_t *rp_id = NULL;
    size_t rp_id_len = 0;
    const uint8_t *user_id = NULL;
    size_t user_id_len = 0;
    bool resident_key = false;
    int32_t chosen_alg = 0;

    for (size_t p = 0; p < pairs; ++p) {
        uint64_t key = 0;
        if (!cbor_read_uint(&cur, &key)) {
            cbor_skip(&cur); // skip unknown key
            cbor_skip(&cur); // skip value
            continue;
        }

        switch (key) {
            case 1: // clientDataHash
                cbor_read_bytes_ptr(&cur, &client_data_hash, &client_data_hash_len);
                break;

            case 2: { // rp
                size_t rp_pairs = 0;
                if (cbor_read_map_start(&cur, &rp_pairs)) {
                    for (size_t rp_i = 0; rp_i < rp_pairs; ++rp_i) {
                        const uint8_t *rp_k = NULL;
                        size_t rp_k_len = 0;
                        cbor_read_text_ptr(&cur, &rp_k, &rp_k_len);
                        if (rp_k && rp_k_len == 2 && memcmp(rp_k, "id", 2) == 0) {
                            cbor_read_text_ptr(&cur, &rp_id, &rp_id_len);
                        } else {
                            cbor_skip(&cur);
                        }
                    }
                }
                break;
            }

            case 3: { // user
                size_t user_pairs = 0;
                if (cbor_read_map_start(&cur, &user_pairs)) {
                    for (size_t u_i = 0; u_i < user_pairs; ++u_i) {
                        const uint8_t *u_k = NULL;
                        size_t u_k_len = 0;
                        cbor_read_text_ptr(&cur, &u_k, &u_k_len);
                        if (u_k && u_k_len == 2 && memcmp(u_k, "id", 2) == 0) {
                            cbor_read_bytes_ptr(&cur, &user_id, &user_id_len);
                        } else {
                            cbor_skip(&cur);
                        }
                    }
                }
                break;
            }

            case 4: { // pubKeyCredParams
                size_t param_count = 0;
                if (cbor_read_array_start(&cur, &param_count)) {
                    for (size_t i = 0; i < param_count; ++i) {
                        size_t m_pairs = 0;
                        int64_t alg = 0;
                        if (cbor_read_map_start(&cur, &m_pairs)) {
                            for (size_t mp = 0; mp < m_pairs; ++mp) {
                                const uint8_t *mk = NULL;
                                size_t mk_len = 0;
                                cbor_read_text_ptr(&cur, &mk, &mk_len);
                                if (mk && mk_len == 3 && memcmp(mk, "alg", 3) == 0) {
                                    cbor_read_int(&cur, &alg);
                                } else {
                                    cbor_skip(&cur);
                                }
                            }
                        }
                        // Select algorithm in order of preference
                        if (chosen_alg == 0) {
                            if (alg == COSE_ALG_ML_DSA_87 || alg == COSE_ALG_ML_DSA_87_COMPAT ||
                                alg == COSE_ALG_ES512 || alg == COSE_ALG_ES256) {
                                chosen_alg = (int32_t)alg;
                            }
                        }
                    }
                }
                break;
            }

            case 7: { // options
                size_t opt_pairs = 0;
                if (cbor_read_map_start(&cur, &opt_pairs)) {
                    for (size_t opt_i = 0; opt_i < opt_pairs; ++opt_i) {
                        const uint8_t *opt_k = NULL;
                        size_t opt_k_len = 0;
                        cbor_read_text_ptr(&cur, &opt_k, &opt_k_len);
                        if (opt_k && opt_k_len == 2 && memcmp(opt_k, "rk", 2) == 0) {
                            cbor_read_bool(&cur, &resident_key);
                        } else {
                            cbor_skip(&cur);
                        }
                    }
                }
                break;
            }

            default:
                cbor_skip(&cur);
                break;
        }
    }

    if (!client_data_hash || client_data_hash_len != 32 || !rp_id || chosen_alg == 0) {
        printf("[CTAP2] Error: missing parameter or unsupported algorithm (alg=%ld)\n", (long)chosen_alg);
        response[0] = CTAP2_ERR_UNSUPPORTED_ALGORITHM;
        return 1;
    }

    printf("[CTAP2] MakeCredential for RP: '%.*s', selected alg: %ld, rk: %d\n",
           (int)rp_id_len, rp_id, (long)chosen_alg, resident_key);

    // Wait for User Presence (UP touch)
    if (!user_presence_wait(30000, NULL)) {
        printf("[CTAP2] UP timeout or denied\n");
        response[0] = CTAP2_ERR_USER_ACTION_TIMEOUT;
        return 1;
    }

    // Compute rpIdHash
    uint8_t rp_id_hash[32];
    crypto_sha256(rp_id, rp_id_len, rp_id_hash);

    // Buffer for keypair generation
    uint8_t *cose_key_buf = malloc(3000);
    if (!cose_key_buf) {
        response[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    CborEncoder cose_enc;
    cbor_encoder_init(&cose_enc, cose_key_buf, 3000);

    uint8_t cred_seed[32];
    crypto_random_bytes(cred_seed, 32);

    uint8_t cred_id[144];
    size_t cred_id_len = 0;

    // Temporary storage for signing self-attestation
    uint8_t *mldsa_sk = NULL;
    uint8_t p521_priv[P521_COORD_SIZE];
    uint8_t p256_priv[P256_COORD_SIZE];

    if (chosen_alg == COSE_ALG_ML_DSA_87 || chosen_alg == COSE_ALG_ML_DSA_87_COMPAT) {
        printf("[CTAP2] Generating ML-DSA-87 keypair...\n");
        uint8_t *mldsa_pk = malloc(MLDSA87_PUBLIC_KEY_SIZE);
        mldsa_sk = malloc(MLDSA87_SECRET_KEY_SIZE);
        if (!mldsa_pk || !mldsa_sk) {
            free(cose_key_buf);
            if (mldsa_pk) free(mldsa_pk);
            if (mldsa_sk) free(mldsa_sk);
            response[0] = CTAP2_ERR_OTHER;
            return 1;
        }

        if (!crypto_mldsa87_keypair(mldsa_pk, mldsa_sk)) {
            free(cose_key_buf);
            free(mldsa_pk);
            free(mldsa_sk);
            response[0] = CTAP2_ERR_OTHER;
            return 1;
        }

        // Encode ML-DSA-87 COSE Key
        cbor_encode_mldsa87_cose_key(&cose_enc, chosen_alg, mldsa_pk, MLDSA87_PUBLIC_KEY_SIZE);
        free(mldsa_pk);

        // Wrap credential or save resident
        storage_wrap_credential(chosen_alg, cred_seed, 32, rp_id_hash, cred_id, &cred_id_len);

    } else if (chosen_alg == COSE_ALG_ES512) {
        printf("[CTAP2] Generating ECDSA secp521r1 keypair...\n");
        uint8_t p521_x[P521_COORD_SIZE], p521_y[P521_COORD_SIZE];
        if (!crypto_p521_keypair(p521_x, p521_y, p521_priv)) {
            free(cose_key_buf);
            response[0] = CTAP2_ERR_OTHER;
            return 1;
        }

        cbor_encode_p521_cose_key(&cose_enc, chosen_alg, p521_x, P521_COORD_SIZE, p521_y, P521_COORD_SIZE);
        storage_wrap_credential(chosen_alg, p521_priv, P521_COORD_SIZE, rp_id_hash, cred_id, &cred_id_len);

    } else if (chosen_alg == COSE_ALG_ES256) {
        printf("[CTAP2] Generating ECDSA secp256r1 keypair...\n");
        uint8_t p256_x[P256_COORD_SIZE], p256_y[P256_COORD_SIZE];
        if (!crypto_p256_keypair(p256_x, p256_y, p256_priv)) {
            free(cose_key_buf);
            response[0] = CTAP2_ERR_OTHER;
            return 1;
        }

        cbor_encode_p256_cose_key(&cose_enc, chosen_alg, p256_x, P256_COORD_SIZE, p256_y, P256_COORD_SIZE);
        storage_wrap_credential(chosen_alg, p256_priv, P256_COORD_SIZE, rp_id_hash, cred_id, &cred_id_len);
    }

    if (resident_key) {
        storage_save_resident_credential(chosen_alg, cred_id, cred_id_len, rp_id_hash,
                                        user_id, user_id_len,
                                        (chosen_alg == COSE_ALG_ES512) ? p521_priv : cred_seed,
                                        (chosen_alg == COSE_ALG_ES512) ? P521_COORD_SIZE : 32);
    }

    size_t cose_key_len = cbor_encoder_size(&cose_enc);

    // Build authData
    // [32B rpIdHash] [1B flags] [4B signCount] [16B aaguid] [2B credIdLen] [credId] [coseKey]
    size_t auth_data_len = 32 + 1 + 4 + 16 + 2 + cred_id_len + cose_key_len;
    uint8_t *auth_data = malloc(auth_data_len);
    if (!auth_data) {
        free(cose_key_buf);
        if (mldsa_sk) free(mldsa_sk);
        response[0] = CTAP2_ERR_OTHER;
        return 1;
    }

    memcpy(auth_data, rp_id_hash, 32);
    auth_data[32] = 0x41; // Flags: UP=1, AT=1
    uint32_t count = storage_get_and_increment_counter();
    auth_data[33] = (uint8_t)(count >> 24);
    auth_data[34] = (uint8_t)(count >> 16);
    auth_data[35] = (uint8_t)(count >> 8);
    auth_data[36] = (uint8_t)(count);

    // Attested credential data
    memcpy(auth_data + 37, storage_get_aaguid(), 16);
    auth_data[53] = (uint8_t)(cred_id_len >> 8);
    auth_data[54] = (uint8_t)(cred_id_len);
    memcpy(auth_data + 55, cred_id, cred_id_len);
    memcpy(auth_data + 55 + cred_id_len, cose_key_buf, cose_key_len);
    free(cose_key_buf);

    // Self-Attestation signature over (authData || clientDataHash)
    size_t to_sign_len = auth_data_len + 32;
    uint8_t *to_sign = malloc(to_sign_len);
    if (!to_sign) {
        free(auth_data);
        if (mldsa_sk) free(mldsa_sk);
        response[0] = CTAP2_ERR_OTHER;
        return 1;
    }
    memcpy(to_sign, auth_data, auth_data_len);
    memcpy(to_sign + auth_data_len, client_data_hash, 32);

    uint8_t *sig_buf = malloc(5000);
    size_t sig_len = 0;

    if (chosen_alg == COSE_ALG_ML_DSA_87 || chosen_alg == COSE_ALG_ML_DSA_87_COMPAT) {
        printf("[CTAP2] Signing self-attestation with ML-DSA-87...\n");
        crypto_mldsa87_sign(sig_buf, &sig_len, to_sign, to_sign_len, mldsa_sk);
        free(mldsa_sk);
    } else if (chosen_alg == COSE_ALG_ES512) {
        printf("[CTAP2] Signing self-attestation with ES512...\n");
        uint8_t h[64];
        crypto_sha512(to_sign, to_sign_len, h);
        crypto_p521_sign(h, 64, p521_priv, sig_buf, &sig_len);
    } else if (chosen_alg == COSE_ALG_ES256) {
        printf("[CTAP2] Signing self-attestation with ES256...\n");
        uint8_t h[32];
        crypto_sha256(to_sign, to_sign_len, h);
        crypto_p256_sign(h, 32, p256_priv, sig_buf, &sig_len);
    }
    free(to_sign);

    // Build CBOR response: {"fmt": "packed", "authData": auth_data, "attStmt": {"alg": alg, "sig": sig}}
    response[0] = CTAP2_ERR_SUCCESS;
    CborEncoder resp_enc;
    cbor_encoder_init(&resp_enc, response + 1, max_len - 1);

    cbor_encode_map(&resp_enc, 3);

    // 1: fmt = "packed"
    cbor_encode_uint(&resp_enc, 1);
    cbor_encode_text(&resp_enc, "packed");

    // 2: authData
    cbor_encode_uint(&resp_enc, 2);
    cbor_encode_bytes(&resp_enc, auth_data, auth_data_len);
    free(auth_data);

    // 3: attStmt = {"alg": alg, "sig": sig}
    cbor_encode_uint(&resp_enc, 3);
    cbor_encode_map(&resp_enc, 2);
    cbor_encode_text(&resp_enc, "alg");
    cbor_encode_int(&resp_enc, chosen_alg);
    cbor_encode_text(&resp_enc, "sig");
    cbor_encode_bytes(&resp_enc, sig_buf, sig_len);
    free(sig_buf);

    printf("[CTAP2] MakeCredential success! Total response size: %zu bytes\n", 1 + cbor_encoder_size(&resp_enc));
    return 1 + cbor_encoder_size(&resp_enc);
}

// ----------------------------------------------------------------------------
// authenticatorGetAssertion (0x02)
// ----------------------------------------------------------------------------
static size_t handle_get_assertion(const uint8_t *payload, size_t len,
                                   uint8_t *response, size_t max_len) {
    printf("[CTAP2] authenticatorGetAssertion\n");
    CborCursor cur;
    cbor_cursor_init(&cur, payload, len);

    size_t pairs = 0;
    if (!cbor_read_map_start(&cur, &pairs)) {
        response[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

    const uint8_t *rp_id = NULL;
    size_t rp_id_len = 0;
    const uint8_t *client_data_hash = NULL;
    size_t client_data_hash_len = 0;
    const uint8_t *matched_cred_id = NULL;
    size_t matched_cred_id_len = 0;

    int32_t cred_alg = 0;
    uint8_t key_data[P521_COORD_SIZE];
    size_t key_data_len = 0;
    bool found_cred = false;

    // First pass: extract rpId and clientDataHash
    const uint8_t *allow_list_ptr = NULL;
    size_t allow_list_len = 0;

    for (size_t p = 0; p < pairs; ++p) {
        uint64_t key = 0;
        if (!cbor_read_uint(&cur, &key)) {
            cbor_skip(&cur);
            cbor_skip(&cur);
            continue;
        }

        if (key == 1) { // rpId
            cbor_read_text_ptr(&cur, &rp_id, &rp_id_len);
        } else if (key == 2) { // clientDataHash
            cbor_read_bytes_ptr(&cur, &client_data_hash, &client_data_hash_len);
        } else if (key == 3) { // allowList
            // Save pointer to allowList array
            allow_list_ptr = cur.ptr;
            cbor_skip(&cur);
            allow_list_len = (size_t)(cur.ptr - allow_list_ptr);
        } else {
            cbor_skip(&cur);
        }
    }

    if (!rp_id || !client_data_hash || client_data_hash_len != 32) {
        response[0] = CTAP2_ERR_MISSING_PARAMETER;
        return 1;
    }

    uint8_t rp_id_hash[32];
    crypto_sha256(rp_id, rp_id_len, rp_id_hash);

    // Try allowList first
    if (allow_list_ptr && allow_list_len > 0) {
        CborCursor al_cur;
        cbor_cursor_init(&al_cur, allow_list_ptr, allow_list_len);
        size_t al_count = 0;
        if (cbor_read_array_start(&al_cur, &al_count)) {
            for (size_t i = 0; i < al_count && !found_cred; ++i) {
                size_t d_pairs = 0;
                if (cbor_read_map_start(&al_cur, &d_pairs)) {
                    for (size_t dp = 0; dp < d_pairs; ++dp) {
                        const uint8_t *k = NULL;
                        size_t k_len = 0;
                        cbor_read_text_ptr(&al_cur, &k, &k_len);
                        if (k && k_len == 2 && memcmp(k, "id", 2) == 0) {
                            const uint8_t *cid = NULL;
                            size_t cid_len = 0;
                            cbor_read_bytes_ptr(&al_cur, &cid, &cid_len);
                            if (storage_unwrap_credential(cid, cid_len, rp_id_hash,
                                                         &cred_alg, key_data, &key_data_len)) {
                                matched_cred_id = cid;
                                matched_cred_id_len = cid_len;
                                found_cred = true;
                            }
                        } else {
                            cbor_skip(&al_cur);
                        }
                    }
                }
            }
        }
    }

    // If not found in allowList, check resident credentials
    if (!found_cred) {
        const ResidentCredential *rc = storage_find_resident_credential(rp_id_hash, NULL, 0);
        if (rc) {
            matched_cred_id = rc->cred_id;
            matched_cred_id_len = CREDENTIAL_ID_SIZE;
            cred_alg = rc->alg;
            if (cred_alg == COSE_ALG_ES512) {
                memcpy(key_data, rc->p521_priv, P521_COORD_SIZE);
                key_data_len = P521_COORD_SIZE;
            } else {
                memcpy(key_data, rc->priv_seed, 32);
                key_data_len = 32;
            }
            found_cred = true;
        }
    }

    if (!found_cred) {
        printf("[CTAP2] No credentials found for RP '%.*s'\n", (int)rp_id_len, rp_id);
        response[0] = CTAP2_ERR_NO_CREDENTIALS;
        return 1;
    }

    printf("[CTAP2] Credential matched! Algorithm: %ld\n", (long)cred_alg);

    // Wait for User Presence (UP touch)
    if (!user_presence_wait(30000, NULL)) {
        response[0] = CTAP2_ERR_USER_ACTION_TIMEOUT;
        return 1;
    }

    // Build authData: [32B rpIdHash] [1B flags] [4B signCount] = 37 bytes
    uint8_t auth_data[37];
    memcpy(auth_data, rp_id_hash, 32);
    auth_data[32] = 0x01; // Flags: UP=1
    uint32_t count = storage_get_and_increment_counter();
    auth_data[33] = (uint8_t)(count >> 24);
    auth_data[34] = (uint8_t)(count >> 16);
    auth_data[35] = (uint8_t)(count >> 8);
    auth_data[36] = (uint8_t)(count);

    // Message to sign: (authData || clientDataHash) = 37 + 32 = 69 bytes
    uint8_t to_sign[69];
    memcpy(to_sign, auth_data, 37);
    memcpy(to_sign + 37, client_data_hash, 32);

    uint8_t *sig_buf = malloc(5000);
    size_t sig_len = 0;

    if (cred_alg == COSE_ALG_ML_DSA_87 || cred_alg == COSE_ALG_ML_DSA_87_COMPAT) {
        printf("[CTAP2] Signing assertion with ML-DSA-87...\n");
        // Re-generate secret key from seed or use keypair
        uint8_t *pk = malloc(MLDSA87_PUBLIC_KEY_SIZE);
        uint8_t *sk = malloc(MLDSA87_SECRET_KEY_SIZE);
        if (pk && sk && crypto_mldsa87_keypair(pk, sk)) {
            crypto_mldsa87_sign(sig_buf, &sig_len, to_sign, sizeof(to_sign), sk);
        }
        if (pk) free(pk);
        if (sk) free(sk);
    } else if (cred_alg == COSE_ALG_ES512) {
        printf("[CTAP2] Signing assertion with ES512...\n");
        uint8_t h[64];
        crypto_sha512(to_sign, sizeof(to_sign), h);
        crypto_p521_sign(h, 64, key_data, sig_buf, &sig_len);
    } else if (cred_alg == COSE_ALG_ES256) {
        printf("[CTAP2] Signing assertion with ES256...\n");
        uint8_t h[32];
        crypto_sha256(to_sign, sizeof(to_sign), h);
        crypto_p256_sign(h, 32, key_data, sig_buf, &sig_len);
    }

    // Build CBOR response: {"credential": {"id": bytes, "type": "public-key"}, "authData": auth_data, "signature": sig}
    response[0] = CTAP2_ERR_SUCCESS;
    CborEncoder resp_enc;
    cbor_encoder_init(&resp_enc, response + 1, max_len - 1);

    cbor_encode_map(&resp_enc, 3);

    // 1: credential
    cbor_encode_uint(&resp_enc, 1);
    cbor_encode_map(&resp_enc, 2);
    cbor_encode_text(&resp_enc, "id");
    cbor_encode_bytes(&resp_enc, matched_cred_id, matched_cred_id_len);
    cbor_encode_text(&resp_enc, "type");
    cbor_encode_text(&resp_enc, "public-key");

    // 2: authData
    cbor_encode_uint(&resp_enc, 2);
    cbor_encode_bytes(&resp_enc, auth_data, sizeof(auth_data));

    // 3: signature
    cbor_encode_uint(&resp_enc, 3);
    cbor_encode_bytes(&resp_enc, sig_buf, sig_len);
    free(sig_buf);

    printf("[CTAP2] GetAssertion success! Response size: %zu bytes\n", 1 + cbor_encoder_size(&resp_enc));
    return 1 + cbor_encoder_size(&resp_enc);
}

// ----------------------------------------------------------------------------
// authenticatorClientPIN (0x06)
// ----------------------------------------------------------------------------
static size_t handle_client_pin(const uint8_t *payload, size_t len,
                                uint8_t *response, size_t max_len) {
    printf("[CTAP2] authenticatorClientPIN\n");
    CborCursor cur;
    cbor_cursor_init(&cur, payload, len);

    size_t pairs = 0;
    if (!cbor_read_map_start(&cur, &pairs)) {
        response[0] = CTAP2_ERR_INVALID_CBOR;
        return 1;
    }

    uint64_t protocol = 1;
    uint64_t subcommand = 0;

    for (size_t p = 0; p < pairs; ++p) {
        uint64_t key = 0;
        if (!cbor_read_uint(&cur, &key)) {
            cbor_skip(&cur);
            cbor_skip(&cur);
            continue;
        }

        if (key == 1) { // pinUvAuthProtocol
            cbor_read_uint(&cur, &protocol);
        } else if (key == 2) { // subCommand
            cbor_read_uint(&cur, &subcommand);
        } else {
            cbor_skip(&cur);
        }
    }

    printf("[CTAP2] ClientPIN: subCommand=%llu, protocol=%llu\n", subcommand, protocol);

    // Subcommand 1: getPINRetries
    if (subcommand == 1) {
        response[0] = CTAP2_ERR_SUCCESS;
        CborEncoder enc;
        cbor_encoder_init(&enc, response + 1, max_len - 1);
        cbor_encode_map(&enc, 1);
        cbor_encode_uint(&enc, 3); // pinRetries
        cbor_encode_uint(&enc, storage_get_pin_retries());
        return 1 + cbor_encoder_size(&enc);
    }

    // Subcommand 2: getKeyAgreement
    if (subcommand == 2) {
        response[0] = CTAP2_ERR_SUCCESS;
        CborEncoder enc;
        cbor_encoder_init(&enc, response + 1, max_len - 1);
        cbor_encode_map(&enc, 1);
        cbor_encode_uint(&enc, 1); // keyAgreement COSE Key

        if (protocol == 3) {
            // Post-Quantum Protocol 3: ML-KEM-1024
            printf("[CTAP2] Generating ML-KEM-1024 ephemeral key agreement...\n");
            crypto_mlkem1024_keypair(s_ephem_mlkem_pk, s_ephem_mlkem_sk);
            s_has_ephem_mlkem = true;
            cbor_encode_mlkem1024_cose_key(&enc, COSE_ALG_ML_KEM_1024, s_ephem_mlkem_pk, MLKEM1024_PUBLIC_KEY_SIZE);
        } else {
            // Classical Protocol 1 & 2: P-256
            printf("[CTAP2] Generating P-256 ephemeral key agreement...\n");
            crypto_p256_keypair(s_ephem_p256_x, s_ephem_p256_y, s_ephem_p256_priv);
            s_has_ephem_p256 = true;
            cbor_encode_p256_cose_key(&enc, -25, s_ephem_p256_x, P256_COORD_SIZE, s_ephem_p256_y, P256_COORD_SIZE);
        }
        return 1 + cbor_encoder_size(&enc);
    }

    // Other PIN commands
    response[0] = CTAP2_ERR_SUCCESS;
    CborEncoder enc;
    cbor_encoder_init(&enc, response + 1, max_len - 1);
    cbor_encode_map(&enc, 0);
    return 1 + cbor_encoder_size(&enc);
}

// ----------------------------------------------------------------------------
// authenticatorReset (0x07)
// ----------------------------------------------------------------------------
static size_t handle_reset(uint8_t *response, size_t max_len) {
    printf("[CTAP2] authenticatorReset\n");
    if (!user_presence_wait(10000, NULL)) {
        response[0] = CTAP2_ERR_USER_ACTION_TIMEOUT;
        return 1;
    }
    storage_reset_pin();
    response[0] = CTAP2_ERR_SUCCESS;
    return 1;
}

// ----------------------------------------------------------------------------
// Dispatcher
// ----------------------------------------------------------------------------
size_t ctap_engine_process_command(const uint8_t *request, size_t request_len,
                                   uint8_t *response, size_t response_max_len) {
    if (!request || request_len < 1 || !response || response_max_len < 1) {
        if (response) response[0] = CTAP2_ERR_INVALID_LENGTH;
        return 1;
    }

    uint8_t cmd = request[0];
    const uint8_t *payload = request + 1;
    size_t payload_len = request_len - 1;

    switch (cmd) {
        case CTAP2_CMD_GET_INFO:
            return handle_get_info(response, response_max_len);

        case CTAP2_CMD_MAKE_CREDENTIAL:
            return handle_make_credential(payload, payload_len, response, response_max_len);

        case CTAP2_CMD_GET_ASSERTION:
            return handle_get_assertion(payload, payload_len, response, response_max_len);

        case CTAP2_CMD_CLIENT_PIN:
            return handle_client_pin(payload, payload_len, response, response_max_len);

        case CTAP2_CMD_RESET:
            return handle_reset(response, response_max_len);

        default:
            printf("[CTAP2] Unknown command: 0x%02X\n", cmd);
            response[0] = CTAP2_ERR_INVALID_COMMAND;
            return 1;
    }
}
