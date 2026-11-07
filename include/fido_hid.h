#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CTAPHID_PACKET_SIZE 64
#define CTAPHID_BUFFER_SIZE 8448

#define CTAPHID_CMD_PING     0x81
#define CTAPHID_CMD_MSG      0x83
#define CTAPHID_CMD_LOCK     0x84
#define CTAPHID_CMD_INIT     0x86
#define CTAPHID_CMD_WINK     0x88
#define CTAPHID_CMD_CBOR     0x90
#define CTAPHID_CMD_CANCEL   0x91
#define CTAPHID_CMD_KEEPALIVE 0xBB
#define CTAPHID_CMD_ERROR    0xBF

// Vendor Command to reboot into BOOTSEL mode
#define CTAPHID_CMD_VENDOR_REBOOT1   0xD1  // 0x80 | 0x51
#define CTAPHID_CMD_VENDOR_REBOOT2   0xF0  // 0x80 | 0x70
#define CTAPHID_CMD_VENDOR_AUTO_UP   0xD2  // Toggle User Presence auto-confirm for testing

#define CTAPHID_ERR_INVALID_CMD     0x01
#define CTAPHID_ERR_INVALID_PAR     0x02
#define CTAPHID_ERR_INVALID_LEN     0x03
#define CTAPHID_ERR_INVALID_SEQ     0x04
#define CTAPHID_ERR_MSG_TIMEOUT     0x05
#define CTAPHID_ERR_CHANNEL_BUSY    0x06
#define CTAPHID_ERR_LOCK_REQUIRED   0x0A
#define CTAPHID_ERR_INVALID_CHANNEL 0x0B
#define CTAPHID_ERR_OTHER           0x7F

void fido_hid_init(void);
void fido_hid_task(void);
void fido_hid_receive_packet(const uint8_t *packet, size_t len);
