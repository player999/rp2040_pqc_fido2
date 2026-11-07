#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *buf;
    size_t capacity;
    size_t offset;
} CborEncoder;

typedef struct {
    const uint8_t *ptr;
    const uint8_t *end;
} CborCursor;

bool cbor_encoder_init(CborEncoder *enc, uint8_t *buf, size_t capacity);
size_t cbor_encoder_size(const CborEncoder *enc);

bool cbor_encode_uint(CborEncoder *enc, uint64_t value);
bool cbor_encode_int(CborEncoder *enc, int64_t value);
bool cbor_encode_bool(CborEncoder *enc, bool value);
bool cbor_encode_bytes(CborEncoder *enc, const uint8_t *data, size_t size);
bool cbor_reserve_bytes(CborEncoder *enc, size_t size, uint8_t **out);
bool cbor_encode_text(CborEncoder *enc, const char *text);
bool cbor_encode_text_n(CborEncoder *enc, const char *text, size_t size);
bool cbor_encode_map(CborEncoder *enc, size_t pairs);
bool cbor_encode_array(CborEncoder *enc, size_t items);

// COSE Key Encoders
bool cbor_encode_p256_cose_key(CborEncoder *enc, int64_t alg, const uint8_t *x, size_t x_len,
                              const uint8_t *y, size_t y_len);
bool cbor_encode_p521_cose_key(CborEncoder *enc, int64_t alg, const uint8_t *x, size_t x_len,
                              const uint8_t *y, size_t y_len);
bool cbor_encode_mldsa87_cose_key(CborEncoder *enc, int64_t alg, const uint8_t *pubkey, size_t pubkey_len);
bool cbor_encode_mlkem1024_cose_key(CborEncoder *enc, int64_t alg, const uint8_t *pubkey, size_t pubkey_len);

// Cursor / Decoder
void cbor_cursor_init(CborCursor *cursor, const uint8_t *data, size_t size);
bool cbor_read_uint(CborCursor *cursor, uint64_t *value);
bool cbor_read_int(CborCursor *cursor, int64_t *value);
bool cbor_read_bool(CborCursor *cursor, bool *value);
bool cbor_read_bytes_ptr(CborCursor *cursor, const uint8_t **data, size_t *size);
bool cbor_read_text_ptr(CborCursor *cursor, const uint8_t **data, size_t *size);
bool cbor_read_map_start(CborCursor *cursor, size_t *pairs);
bool cbor_read_array_start(CborCursor *cursor, size_t *items);
bool cbor_skip(CborCursor *cursor);
