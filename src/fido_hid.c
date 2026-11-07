#include "fido_hid.h"
#include <stdio.h>
#include <string.h>
#include "tusb.h"
#include "ctap_engine.h"
#include "user_presence.h"
#include "status_led.h"

static uint8_t s_rx_buf[CTAPHID_BUFFER_SIZE];
static size_t s_rx_total_len = 0;
static size_t s_rx_received_len = 0;
static uint32_t s_rx_cid = 0;
static uint8_t s_rx_cmd = 0;
static uint8_t s_rx_next_seq = 0;
static bool s_rx_active = false;

static uint8_t s_tx_buf[CTAPHID_BUFFER_SIZE];
static size_t s_tx_total_len = 0;
static size_t s_tx_offset = 0;
static uint32_t s_tx_cid = 0;
static uint8_t s_tx_cmd = 0;
static uint8_t s_tx_seq = 0;
static bool s_tx_active = false;

static uint32_t s_next_cid = 0x01020304;
static uint32_t s_current_cbor_cid = 0;
static volatile bool s_cancelled = false;

bool fido_hid_send_keepalive_up(void) {
    if (s_cancelled) {
        return false;
    }
    if (s_current_cbor_cid != 0 && tud_hid_ready()) {
        uint8_t packet[CTAPHID_PACKET_SIZE];
        memset(packet, 0, sizeof(packet));
        packet[0] = (uint8_t)(s_current_cbor_cid >> 24);
        packet[1] = (uint8_t)(s_current_cbor_cid >> 16);
        packet[2] = (uint8_t)(s_current_cbor_cid >> 8);
        packet[3] = (uint8_t)(s_current_cbor_cid);
        packet[4] = CTAPHID_CMD_KEEPALIVE;
        packet[5] = 0;
        packet[6] = 1; // 1 byte payload
        packet[7] = 0x02; // CTAPHID_KEEPALIVE_STATUS_UPNEEDED
        tud_hid_report(0, packet, sizeof(packet));
    }
    return true;
}

void fido_hid_init(void) {
    s_rx_active = false;
    s_tx_active = false;
    s_rx_total_len = 0;
    s_rx_received_len = 0;
    s_tx_total_len = 0;
    s_tx_offset = 0;
}

static void send_next_tx_packet(void) {
    if (!s_tx_active || !tud_hid_ready()) return;

    uint8_t packet[CTAPHID_PACKET_SIZE];
    memset(packet, 0, sizeof(packet));

    // CID (4 bytes big-endian)
    packet[0] = (uint8_t)(s_tx_cid >> 24);
    packet[1] = (uint8_t)(s_tx_cid >> 16);
    packet[2] = (uint8_t)(s_tx_cid >> 8);
    packet[3] = (uint8_t)(s_tx_cid);

    if (s_tx_offset == 0) {
        // Initialization packet: [CID 4B] [CMD 1B] [BCNTH 1B] [BCNTL 1B] [DATA up to 57B]
        packet[4] = s_tx_cmd;
        packet[5] = (uint8_t)(s_tx_total_len >> 8);
        packet[6] = (uint8_t)(s_tx_total_len);

        size_t chunk = s_tx_total_len > 57 ? 57 : s_tx_total_len;
        if (chunk > 0) {
            memcpy(packet + 7, s_tx_buf, chunk);
            s_tx_offset += chunk;
        }
        s_tx_seq = 0;
    } else {
        // Continuation packet: [CID 4B] [SEQ 1B] [DATA up to 59B]
        packet[4] = s_tx_seq;
        s_tx_seq = (s_tx_seq + 1) & 0x7F;
        size_t remaining = s_tx_total_len - s_tx_offset;
        size_t chunk = remaining > 59 ? 59 : remaining;
        if (chunk > 0) {
            memcpy(packet + 5, s_tx_buf + s_tx_offset, chunk);
            s_tx_offset += chunk;
        }
    }

    tud_hid_report(0, packet, CTAPHID_PACKET_SIZE);

    if (s_tx_offset >= s_tx_total_len) {
        s_tx_active = false;
    }
}

static void send_error(uint32_t cid, uint8_t err_code) {
    s_tx_cid = cid;
    s_tx_cmd = CTAPHID_CMD_ERROR;
    s_tx_buf[0] = err_code;
    s_tx_total_len = 1;
    s_tx_offset = 0;
    s_tx_active = true;
    send_next_tx_packet();
}

static void dispatch_ctaphid_message(uint32_t cid, uint8_t cmd, const uint8_t *payload, size_t len) {
    if (cmd == CTAPHID_CMD_INIT) {
        printf("[CTAPHID] INIT received (len=%zu)\n", len);
        if (len != 8) {
            send_error(cid, CTAPHID_ERR_INVALID_LEN);
            return;
        }

        uint32_t assigned_cid = (cid == 0xFFFFFFFF) ? s_next_cid++ : cid;

        // Response: [Nonce 8B] [CID 4B] [Proto 1B] [Maj 1B] [Min 1B] [Build 1B] [Caps 1B]
        memcpy(s_tx_buf, payload, 8);
        s_tx_buf[8]  = (uint8_t)(assigned_cid >> 24);
        s_tx_buf[9]  = (uint8_t)(assigned_cid >> 16);
        s_tx_buf[10] = (uint8_t)(assigned_cid >> 8);
        s_tx_buf[11] = (uint8_t)(assigned_cid);
        s_tx_buf[12] = 2; // Protocol version 2
        s_tx_buf[13] = 1; // Major version
        s_tx_buf[14] = 0; // Minor version
        s_tx_buf[15] = 0; // Build version
        s_tx_buf[16] = 0x05; // Capabilities: CAPABILITY_WINK | CAPABILITY_CBOR

        s_tx_cid = cid;
        s_tx_cmd = CTAPHID_CMD_INIT;
        s_tx_total_len = 17;
        s_tx_offset = 0;
        s_tx_active = true;
        send_next_tx_packet();
        return;
    }

    if (cmd == CTAPHID_CMD_VENDOR_REBOOT1 || cmd == CTAPHID_CMD_VENDOR_REBOOT2 ||
        (cmd == 0xD0 && len >= 4 && memcmp(payload, "BOOT", 4) == 0)) {
        printf("[CTAPHID] Vendor reboot command received! Rebooting to BOOTSEL...\n");
        user_presence_reboot_to_bootloader();
    }

#ifdef ENABLE_AUTO_CONFIRM
    if (cmd == CTAPHID_CMD_VENDOR_AUTO_UP) {
        bool cur = user_presence_get_auto_confirm();
        bool new_val = (len > 0) ? (payload[0] != 0) : !cur;
        user_presence_set_auto_confirm(new_val);
        printf("[CTAPHID] Vendor Auto-UP set to %d\n", new_val);
        s_tx_buf[0] = new_val ? 1 : 0;
        s_tx_cid = cid;
        s_tx_cmd = CTAPHID_CMD_VENDOR_AUTO_UP;
        s_tx_total_len = 1;
        s_tx_offset = 0;
        s_tx_active = true;
        send_next_tx_packet();
        return;
    }
#endif

    if (cmd == CTAPHID_CMD_PING) {
        printf("[CTAPHID] PING (len=%zu)\n", len);
        memcpy(s_tx_buf, payload, len);
        s_tx_cid = cid;
        s_tx_cmd = CTAPHID_CMD_PING;
        s_tx_total_len = len;
        s_tx_offset = 0;
        s_tx_active = true;
        send_next_tx_packet();
        return;
    }

    if (cmd == CTAPHID_CMD_WINK) {
        printf("[CTAPHID] WINK\n");
        status_led_set_mode(LED_MODE_SUCCESS);
        s_tx_cid = cid;
        s_tx_cmd = CTAPHID_CMD_WINK;
        s_tx_total_len = 0;
        s_tx_offset = 0;
        s_tx_active = true;
        send_next_tx_packet();
        return;
    }

    if (cmd == CTAPHID_CMD_CBOR) {
        printf("[CTAPHID] CBOR request (len=%zu)\n", len);
        s_current_cbor_cid = cid;
        s_cancelled = false;
        size_t resp_len = ctap_engine_process_command(payload, len, s_tx_buf, sizeof(s_tx_buf));
        s_current_cbor_cid = 0;
        s_tx_cid = cid;
        s_tx_cmd = CTAPHID_CMD_CBOR;
        s_tx_total_len = resp_len;
        s_tx_offset = 0;
        s_tx_active = true;
        send_next_tx_packet();
        return;
    }

    if (cmd == CTAPHID_CMD_CANCEL) {
        printf("[CTAPHID] CANCEL\n");
        s_rx_active = false;
        s_tx_active = false;
        s_cancelled = true;
        return;
    }

    printf("[CTAPHID] Unsupported cmd: 0x%02X\n", cmd);
    send_error(cid, CTAPHID_ERR_INVALID_CMD);
}

void fido_hid_receive_packet(const uint8_t *packet, size_t len) {
    if (len < CTAPHID_PACKET_SIZE) return;

    uint32_t cid = ((uint32_t)packet[0] << 24) |
                   ((uint32_t)packet[1] << 16) |
                   ((uint32_t)packet[2] << 8)  |
                   (uint32_t)packet[3];

    uint8_t cmd_or_seq = packet[4];

    if (cmd_or_seq & 0x80) {
        // Initialization packet
        s_rx_cid = cid;
        s_rx_cmd = cmd_or_seq;
        s_rx_total_len = ((size_t)packet[5] << 8) | packet[6];
        s_rx_received_len = 0;
        s_rx_next_seq = 0;
        s_rx_active = true;

        if (s_rx_total_len > CTAPHID_BUFFER_SIZE) {
            send_error(cid, CTAPHID_ERR_INVALID_LEN);
            s_rx_active = false;
            return;
        }

        size_t chunk = s_rx_total_len > 57 ? 57 : s_rx_total_len;
        if (chunk > 0) {
            memcpy(s_rx_buf, packet + 7, chunk);
            s_rx_received_len += chunk;
        }

        if (s_rx_received_len >= s_rx_total_len) {
            s_rx_active = false;
            dispatch_ctaphid_message(s_rx_cid, s_rx_cmd, s_rx_buf, s_rx_total_len);
        }
    } else {
        // Continuation packet
        if (!s_rx_active || cid != s_rx_cid) {
            send_error(cid, CTAPHID_ERR_INVALID_CHANNEL);
            return;
        }

        if (cmd_or_seq != s_rx_next_seq) {
            send_error(cid, CTAPHID_ERR_INVALID_SEQ);
            s_rx_active = false;
            return;
        }
        s_rx_next_seq = (s_rx_next_seq + 1) & 0x7F;

        size_t remaining = s_rx_total_len - s_rx_received_len;
        size_t chunk = remaining > 59 ? 59 : remaining;
        if (chunk > 0) {
            memcpy(s_rx_buf + s_rx_received_len, packet + 5, chunk);
            s_rx_received_len += chunk;
        }

        if (s_rx_received_len >= s_rx_total_len) {
            s_rx_active = false;
            dispatch_ctaphid_message(s_rx_cid, s_rx_cmd, s_rx_buf, s_rx_total_len);
        }
    }
}

void fido_hid_task(void) {
    if (s_tx_active && tud_hid_ready()) {
        send_next_tx_packet();
    }
}

// TinyUSB HID Callbacks
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type,
                           uint8_t const* buffer, uint16_t bufsize) {
    (void) itf;
    (void) report_id;
    (void) report_type;
    fido_hid_receive_packet(buffer, bufsize);
}

uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type,
                               uint8_t* buffer, uint16_t reqlen) {
    (void) itf;
    (void) report_id;
    (void) report_type;
    (void) buffer;
    (void) reqlen;
    return 0;
}

void tud_hid_report_complete_cb(uint8_t itf, uint8_t const* report, uint16_t len) {
    (void) itf;
    (void) report;
    (void) len;
    if (s_tx_active) {
        send_next_tx_packet();
    }
}
