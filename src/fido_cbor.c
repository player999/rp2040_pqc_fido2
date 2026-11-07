#include "fido_cbor.h"
#include <string.h>

enum {
    CBOR_MAJOR_UINT = 0,
    CBOR_MAJOR_NEGINT = 1,
    CBOR_MAJOR_BYTES = 2,
    CBOR_MAJOR_TEXT = 3,
    CBOR_MAJOR_ARRAY = 4,
    CBOR_MAJOR_MAP = 5,
    CBOR_MAJOR_SIMPLE = 7,
};

#define CBOR_SKIP_DEPTH_LIMIT 16U

bool cbor_encoder_init(CborEncoder *enc, uint8_t *buf, size_t capacity) {
    if (!enc || !buf || capacity == 0) return false;
    enc->buf = buf;
    enc->capacity = capacity;
    enc->offset = 0;
    return true;
}

size_t cbor_encoder_size(const CborEncoder *enc) {
    return enc ? enc->offset : 0;
}

static bool cbor_encode_header(CborEncoder *enc, uint8_t major, uint64_t val) {
    if (!enc || enc->offset >= enc->capacity) return false;
    uint8_t m = (uint8_t)(major << 5);

    if (val < 24) {
        enc->buf[enc->offset++] = m | (uint8_t)val;
        return true;
    } else if (val <= 0xFF) {
        if (enc->offset + 2 > enc->capacity) return false;
        enc->buf[enc->offset++] = m | 24;
        enc->buf[enc->offset++] = (uint8_t)val;
        return true;
    } else if (val <= 0xFFFF) {
        if (enc->offset + 3 > enc->capacity) return false;
        enc->buf[enc->offset++] = m | 25;
        enc->buf[enc->offset++] = (uint8_t)(val >> 8);
        enc->buf[enc->offset++] = (uint8_t)(val);
        return true;
    } else if (val <= 0xFFFFFFFFULL) {
        if (enc->offset + 5 > enc->capacity) return false;
        enc->buf[enc->offset++] = m | 26;
        enc->buf[enc->offset++] = (uint8_t)(val >> 24);
        enc->buf[enc->offset++] = (uint8_t)(val >> 16);
        enc->buf[enc->offset++] = (uint8_t)(val >> 8);
        enc->buf[enc->offset++] = (uint8_t)(val);
        return true;
    } else {
        if (enc->offset + 9 > enc->capacity) return false;
        enc->buf[enc->offset++] = m | 27;
        for (int i = 7; i >= 0; --i) {
            enc->buf[enc->offset++] = (uint8_t)(val >> (i * 8));
        }
        return true;
    }
}

bool cbor_encode_uint(CborEncoder *enc, uint64_t value) {
    return cbor_encode_header(enc, CBOR_MAJOR_UINT, value);
}

bool cbor_encode_int(CborEncoder *enc, int64_t value) {
    if (value >= 0) {
        return cbor_encode_uint(enc, (uint64_t)value);
    } else {
        return cbor_encode_header(enc, CBOR_MAJOR_NEGINT, (uint64_t)(-1 - value));
    }
}

bool cbor_encode_bool(CborEncoder *enc, bool value) {
    if (!enc || enc->offset >= enc->capacity) return false;
    enc->buf[enc->offset++] = (uint8_t)((CBOR_MAJOR_SIMPLE << 5) | (value ? 21 : 20));
    return true;
}

bool cbor_encode_bytes(CborEncoder *enc, const uint8_t *data, size_t size) {
    if (!cbor_encode_header(enc, CBOR_MAJOR_BYTES, size)) return false;
    if (size == 0) return true;
    if (enc->offset + size > enc->capacity) return false;
    memcpy(enc->buf + enc->offset, data, size);
    enc->offset += size;
    return true;
}

bool cbor_reserve_bytes(CborEncoder *enc, size_t size, uint8_t **out) {
    if (!cbor_encode_header(enc, CBOR_MAJOR_BYTES, size)) return false;
    if (enc->offset + size > enc->capacity) return false;
    *out = enc->buf + enc->offset;
    enc->offset += size;
    return true;
}

bool cbor_encode_text_n(CborEncoder *enc, const char *text, size_t size) {
    if (!cbor_encode_header(enc, CBOR_MAJOR_TEXT, size)) return false;
    if (size == 0) return true;
    if (enc->offset + size > enc->capacity) return false;
    memcpy(enc->buf + enc->offset, text, size);
    enc->offset += size;
    return true;
}

bool cbor_encode_text(CborEncoder *enc, const char *text) {
    return cbor_encode_text_n(enc, text, text ? strlen(text) : 0);
}

bool cbor_encode_map(CborEncoder *enc, size_t pairs) {
    return cbor_encode_header(enc, CBOR_MAJOR_MAP, pairs);
}

bool cbor_encode_array(CborEncoder *enc, size_t items) {
    return cbor_encode_header(enc, CBOR_MAJOR_ARRAY, items);
}

// P-256 COSE Key: kty=2 (EC2), alg=-7, crv=1 (P-256), x, y
bool cbor_encode_p256_cose_key(CborEncoder *enc, int64_t alg, const uint8_t *x, size_t x_len,
                              const uint8_t *y, size_t y_len) {
    return cbor_encode_map(enc, 5) &&
           cbor_encode_int(enc, 1) && cbor_encode_int(enc, 2) &&   // 1: kty = 2 (EC2)
           cbor_encode_int(enc, 3) && cbor_encode_int(enc, alg) && // 3: alg = -7
           cbor_encode_int(enc, -1) && cbor_encode_int(enc, 1) && // -1: crv = 1 (P-256)
           cbor_encode_int(enc, -2) && cbor_encode_bytes(enc, x, x_len) && // -2: x
           cbor_encode_int(enc, -3) && cbor_encode_bytes(enc, y, y_len);   // -3: y
}

// P-521 COSE Key: kty=2 (EC2), alg=-36 (ES512), crv=3 (P-521), x (66B), y (66B)
bool cbor_encode_p521_cose_key(CborEncoder *enc, int64_t alg, const uint8_t *x, size_t x_len,
                              const uint8_t *y, size_t y_len) {
    return cbor_encode_map(enc, 5) &&
           cbor_encode_int(enc, 1) && cbor_encode_int(enc, 2) &&   // 1: kty = 2 (EC2)
           cbor_encode_int(enc, 3) && cbor_encode_int(enc, alg) && // 3: alg = -36 (ES512)
           cbor_encode_int(enc, -1) && cbor_encode_int(enc, 3) && // -1: crv = 3 (P-521)
           cbor_encode_int(enc, -2) && cbor_encode_bytes(enc, x, x_len) && // -2: x (66B)
           cbor_encode_int(enc, -3) && cbor_encode_bytes(enc, y, y_len);   // -3: y (66B)
}

// ML-DSA-87 COSE Key: kty=7 (AKP / RFC 9964), alg=-50 (or -20), -1: pubkey (2592B)
bool cbor_encode_mldsa87_cose_key(CborEncoder *enc, int64_t alg, const uint8_t *pubkey, size_t pubkey_len) {
    int64_t kty = (alg == -20) ? 5 : 7; // 7 for standard RFC 9964 (webauthn.io), 5 for legacy SandboxAQ
    return cbor_encode_map(enc, 3) &&
           cbor_encode_int(enc, 1) && cbor_encode_int(enc, kty) &&    // 1: kty = 7 (AKP) or 5
           cbor_encode_int(enc, 3) && cbor_encode_int(enc, alg) &&  // 3: alg = -50 or -20
           cbor_encode_int(enc, -1) && cbor_encode_bytes(enc, pubkey, pubkey_len); // -1: pubkey (2592 bytes)
}

// ML-KEM-1024 COSE Key: kty=6 (PQCKEM), alg=-24, -1: pubkey (1568B)
bool cbor_encode_mlkem1024_cose_key(CborEncoder *enc, int64_t alg, const uint8_t *pubkey, size_t pubkey_len) {
    return cbor_encode_map(enc, 3) &&
           cbor_encode_int(enc, 1) && cbor_encode_int(enc, 6) &&    // 1: kty = 6 (PQCKEM)
           cbor_encode_int(enc, 3) && cbor_encode_int(enc, alg) &&  // 3: alg = -24
           cbor_encode_int(enc, -1) && cbor_encode_bytes(enc, pubkey, pubkey_len); // -1: pubkey
}

// Decoder implementation
void cbor_cursor_init(CborCursor *cursor, const uint8_t *data, size_t size) {
    cursor->ptr = data;
    cursor->end = data + size;
}

static size_t cbor_remaining(const CborCursor *cursor) {
    return (cursor && cursor->end >= cursor->ptr) ? (size_t)(cursor->end - cursor->ptr) : 0;
}

static bool cbor_read_header(CborCursor *cursor, uint8_t *major, uint64_t *val) {
    if (cbor_remaining(cursor) < 1) return false;
    uint8_t byte = *cursor->ptr++;
    *major = (uint8_t)(byte >> 5);
    uint8_t add = (uint8_t)(byte & 0x1F);

    if (add < 24) {
        *val = add;
        return true;
    } else if (add == 24) {
        if (cbor_remaining(cursor) < 1) return false;
        *val = *cursor->ptr++;
        return true;
    } else if (add == 25) {
        if (cbor_remaining(cursor) < 2) return false;
        *val = ((uint64_t)cursor->ptr[0] << 8) | cursor->ptr[1];
        cursor->ptr += 2;
        return true;
    } else if (add == 26) {
        if (cbor_remaining(cursor) < 4) return false;
        *val = ((uint64_t)cursor->ptr[0] << 24) |
               ((uint64_t)cursor->ptr[1] << 16) |
               ((uint64_t)cursor->ptr[2] << 8) |
               cursor->ptr[3];
        cursor->ptr += 4;
        return true;
    } else if (add == 27) {
        if (cbor_remaining(cursor) < 8) return false;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8) | *cursor->ptr++;
        }
        *val = v;
        return true;
    }
    return false; // indefinite length or reserved not supported
}

bool cbor_read_uint(CborCursor *cursor, uint64_t *value) {
    uint8_t m;
    uint64_t v;
    const uint8_t *save = cursor->ptr;
    if (!cbor_read_header(cursor, &m, &v) || m != CBOR_MAJOR_UINT) {
        cursor->ptr = save;
        return false;
    }
    *value = v;
    return true;
}

bool cbor_read_int(CborCursor *cursor, int64_t *value) {
    uint8_t m;
    uint64_t v;
    const uint8_t *save = cursor->ptr;
    if (!cbor_read_header(cursor, &m, &v)) {
        cursor->ptr = save;
        return false;
    }
    if (m == CBOR_MAJOR_UINT) {
        *value = (int64_t)v;
        return true;
    } else if (m == CBOR_MAJOR_NEGINT) {
        *value = -1 - (int64_t)v;
        return true;
    }
    cursor->ptr = save;
    return false;
}

bool cbor_read_bool(CborCursor *cursor, bool *value) {
    uint8_t m;
    uint64_t v;
    const uint8_t *save = cursor->ptr;
    if (!cbor_read_header(cursor, &m, &v) || m != CBOR_MAJOR_SIMPLE) {
        cursor->ptr = save;
        return false;
    }
    if (v == 20) { *value = false; return true; }
    if (v == 21) { *value = true; return true; }
    cursor->ptr = save;
    return false;
}

bool cbor_read_bytes_ptr(CborCursor *cursor, const uint8_t **data, size_t *size) {
    uint8_t m;
    uint64_t len;
    const uint8_t *save = cursor->ptr;
    if (!cbor_read_header(cursor, &m, &len) || m != CBOR_MAJOR_BYTES) {
        cursor->ptr = save;
        return false;
    }
    if (cbor_remaining(cursor) < len) {
        cursor->ptr = save;
        return false;
    }
    *data = cursor->ptr;
    *size = (size_t)len;
    cursor->ptr += len;
    return true;
}

bool cbor_read_text_ptr(CborCursor *cursor, const uint8_t **data, size_t *size) {
    uint8_t m;
    uint64_t len;
    const uint8_t *save = cursor->ptr;
    if (!cbor_read_header(cursor, &m, &len) || m != CBOR_MAJOR_TEXT) {
        cursor->ptr = save;
        return false;
    }
    if (cbor_remaining(cursor) < len) {
        cursor->ptr = save;
        return false;
    }
    *data = cursor->ptr;
    *size = (size_t)len;
    cursor->ptr += len;
    return true;
}

bool cbor_read_map_start(CborCursor *cursor, size_t *pairs) {
    uint8_t m;
    uint64_t len;
    const uint8_t *save = cursor->ptr;
    if (!cbor_read_header(cursor, &m, &len) || m != CBOR_MAJOR_MAP) {
        cursor->ptr = save;
        return false;
    }
    *pairs = (size_t)len;
    return true;
}

bool cbor_read_array_start(CborCursor *cursor, size_t *items) {
    uint8_t m;
    uint64_t len;
    const uint8_t *save = cursor->ptr;
    if (!cbor_read_header(cursor, &m, &len) || m != CBOR_MAJOR_ARRAY) {
        cursor->ptr = save;
        return false;
    }
    *items = (size_t)len;
    return true;
}

static bool cbor_skip_internal(CborCursor *cursor, uint32_t depth) {
    if (depth > CBOR_SKIP_DEPTH_LIMIT) return false;
    uint8_t m;
    uint64_t val;
    if (!cbor_read_header(cursor, &m, &val)) return false;

    switch (m) {
        case CBOR_MAJOR_UINT:
        case CBOR_MAJOR_NEGINT:
        case CBOR_MAJOR_SIMPLE:
            return true;
        case CBOR_MAJOR_BYTES:
        case CBOR_MAJOR_TEXT:
            if (cbor_remaining(cursor) < val) return false;
            cursor->ptr += val;
            return true;
        case CBOR_MAJOR_ARRAY:
            for (uint64_t i = 0; i < val; ++i) {
                if (!cbor_skip_internal(cursor, depth + 1)) return false;
            }
            return true;
        case CBOR_MAJOR_MAP:
            for (uint64_t i = 0; i < val; ++i) {
                if (!cbor_skip_internal(cursor, depth + 1)) return false; // key
                if (!cbor_skip_internal(cursor, depth + 1)) return false; // value
            }
            return true;
        default:
            return false;
    }
}

bool cbor_skip(CborCursor *cursor) {
    return cbor_skip_internal(cursor, 0);
}
