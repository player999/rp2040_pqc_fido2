#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "bsp/board.h"
#include "tusb.h"

#include "status_led.h"
#include "user_presence.h"
#include "crypto_engine.h"
#include "storage.h"
#include "ctap_engine.h"
#include "fido_hid.h"
#include "hardware/clocks.h"
#include "pico/stdio/driver.h"

static void cdc_out_chars(const char *buf, int len) {
    if (tud_cdc_connected()) {
        tud_cdc_write(buf, len);
        tud_cdc_write_flush();
    }
}

static stdio_driver_t cdc_stdio_driver = {
    .out_chars = cdc_out_chars,
#if PICO_STDIO_ENABLE_CRLF_SUPPORT
    .crlf_enabled = true,
#endif
};

static void print_banner(void) {
    printf("\n================================================================\n");
    printf("   RP2040 Post-Quantum & Classical FIDO2 Authenticator\n");
    printf("   Target: Waveshare RP2040-One (Cortex-M0+ boosted @ 200MHz)\n");
    printf("================================================================\n");
    printf("Algorithms Supported:\n");
    printf("  [PQC] ML-DSA-87 (FIPS 204 / Dilithium-5) - COSE alg -50 & -20\n");
    printf("  [PQC] ML-KEM-1024 (FIPS 203 / Kyber-1024) - pinUvAuthProtocol 3\n");
    printf("  [ECC] ECDSA secp521r1 (P-521 / ES512)     - COSE alg -36\n");
    printf("  [ECC] ECDH secp521r1                      - COSE alg -25 / -29\n");
    printf("  [ECC] ECDSA secp256r1 (P-256 / ES256)     - COSE alg -7 (Compat)\n");
    printf("----------------------------------------------------------------\n");
    printf("Reboot to Programming Mode (BOOTSEL):\n");
    printf("  1. Press and hold BOOTSEL button for 2 seconds, OR\n");
    printf("  2. Run 'stty -F /dev/ttyACM0 1200' on the host, OR\n");
    printf("  3. Type 'b' in this serial console, OR\n");
    printf("  4. Send CTAPHID vendor reboot packet (0x51 / 0x70)\n");
    printf("================================================================\n\n");
}

static void process_cdc_commands(void) {
    if (tud_cdc_available()) {
        char ch = (char)tud_cdc_read_char();
        if (ch == 'b' || ch == 'B') {
            printf("\nConsole command 'b': Rebooting to BOOTSEL mode...\n");
            tud_cdc_write_flush();
            user_presence_reboot_to_bootloader();
#ifdef ENABLE_AUTO_CONFIRM
        } else if (ch == 't' || ch == 'T') {
            bool current = user_presence_get_auto_confirm();
            user_presence_set_auto_confirm(!current);
            printf("\n[CONFIG] User Presence Auto-Confirm: %s\n", !current ? "ENABLED" : "DISABLED");
#endif
        } else if (ch == 'i' || ch == 'I') {
            print_banner();
        } else if (ch == 'h' || ch == '?') {
            printf("\nAvailable Commands:\n");
            printf("  b - Reboot to USB BOOTSEL mode\n");
#ifdef ENABLE_AUTO_CONFIRM
            printf("  t - Toggle User Presence Auto-Confirm (current: %s)\n",
                   user_presence_get_auto_confirm() ? "ON" : "OFF");
#endif
            printf("  i - Show system info banner\n");
        }
    }
}

int main(void) {
    // Boost RP2040 system clock to 200 MHz for ~1.5x faster PQC calculations
    set_sys_clock_khz(200000, false);

    board_init();
    tusb_init();

    stdio_set_driver_enabled(&cdc_stdio_driver, true);

    status_led_init();
    user_presence_init();
    crypto_engine_init();
    storage_init();
    ctap_engine_init();
    fido_hid_init();

    status_led_set_mode(LED_MODE_IDLE);

    uint32_t last_banner_ms = 0;
    bool banner_printed = false;

    while (true) {
        tud_task();
        fido_hid_task();
        user_presence_update();
        status_led_update();
        process_cdc_commands();

        // Print banner once CDC connection is established
        if (!banner_printed && tud_cdc_connected()) {
            uint32_t now = to_ms_since_boot(get_absolute_time());
            if (last_banner_ms == 0) {
                last_banner_ms = now;
            } else if (now - last_banner_ms > 500) {
                print_banner();
                banner_printed = true;
            }
        }
    }

    return 0;
}
