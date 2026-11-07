#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CTAP_MAX_RESPONSE_SIZE 8448

enum {
    CTAP2_CMD_MAKE_CREDENTIAL = 0x01,
    CTAP2_CMD_GET_ASSERTION   = 0x02,
    CTAP2_CMD_GET_INFO        = 0x04,
    CTAP2_CMD_CLIENT_PIN      = 0x06,
    CTAP2_CMD_RESET           = 0x07,
    CTAP2_CMD_SELECTION       = 0x0B,
};

enum {
    CTAP2_ERR_SUCCESS                 = 0x00,
    CTAP2_ERR_INVALID_COMMAND         = 0x01,
    CTAP2_ERR_INVALID_PARAMETER       = 0x02,
    CTAP2_ERR_INVALID_LENGTH          = 0x03,
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE    = 0x11,
    CTAP2_ERR_INVALID_CBOR            = 0x12,
    CTAP2_ERR_MISSING_PARAMETER       = 0x14,
    CTAP2_ERR_UNSUPPORTED_ALGORITHM   = 0x26,
    CTAP2_ERR_OPERATION_DENIED        = 0x27,
    CTAP2_ERR_NO_CREDENTIALS          = 0x2E,
    CTAP2_ERR_USER_ACTION_TIMEOUT     = 0x2F,
    CTAP2_ERR_NOT_ALLOWED             = 0x30,
    CTAP2_ERR_PIN_INVALID             = 0x31,
    CTAP2_ERR_PIN_BLOCKED             = 0x32,
    CTAP2_ERR_PIN_AUTH_INVALID        = 0x33,
    CTAP2_ERR_PIN_NOT_SET             = 0x35,
    CTAP2_ERR_PIN_REQUIRED            = 0x36,
    CTAP2_ERR_OTHER                   = 0x7F,
};

void ctap_engine_init(void);

// Process a CTAP2 command payload from CTAPHID.
// Returns response length. If error, response[0] contains the error code.
size_t ctap_engine_process_command(const uint8_t *request, size_t request_len,
                                   uint8_t *response, size_t response_max_len);
