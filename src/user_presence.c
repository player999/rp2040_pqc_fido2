#include "user_presence.h"
#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/bootrom.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"
#include "status_led.h"
#include "tusb.h"

static bool s_auto_confirm = false;
static uint32_t s_hold_start_ms = 0;
static bool s_was_pressed = false;

// Safe QSPI BOOTSEL button sampler while executing code from Flash (XIP)
bool __no_inline_not_in_flash_func(user_presence_is_button_pressed)(void) {
    const uint CS_PIN_INDEX = 1;
    uint32_t flags = save_and_disable_interrupts();
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
    for (volatile int i = 0; i < 1000; ++i);
    bool pressed = !(sio_hw->gpio_hi_in & (1u << 1));
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
    restore_interrupts(flags);
    return pressed;
}

void user_presence_reboot_to_bootloader(void) {
    printf("\n[REBOOT] Jumping to RP2040 USB Bootloader (BOOTSEL)...\n");
    status_led_set_mode(LED_MODE_BOOTLOADER);
    sleep_ms(100);
    reset_usb_boot(0, 0);
}

void user_presence_init(void) {
    s_hold_start_ms = 0;
    s_was_pressed = false;
}

void user_presence_set_auto_confirm(bool enable) {
    s_auto_confirm = enable;
}

bool user_presence_get_auto_confirm(void) {
    return s_auto_confirm;
}

void user_presence_update(void) {
    bool pressed = user_presence_is_button_pressed();
    uint32_t now = to_ms_since_boot(get_absolute_time());

    if (pressed) {
        if (!s_was_pressed) {
            s_was_pressed = true;
            s_hold_start_ms = now;
        } else {
            // Held continuously for > 2000 ms: emergency reboot to bootloader
            if (now - s_hold_start_ms >= 2000) {
                user_presence_reboot_to_bootloader();
            }
        }
    } else {
        s_was_pressed = false;
        s_hold_start_ms = 0;
    }
}

bool user_presence_wait(uint32_t timeout_ms, bool (*keepalive_cb)(void)) {
    if (s_auto_confirm) {
        status_led_set_mode(LED_MODE_SUCCESS);
        return true;
    }

    status_led_set_mode(LED_MODE_UP_REQUIRED);
    uint32_t start_ms = to_ms_since_boot(get_absolute_time());
    uint32_t last_keepalive_ms = start_ms;

    // Flush any existing button press before waiting
    while (user_presence_is_button_pressed()) {
        tud_task();
        sleep_ms(10);
    }

    while (to_ms_since_boot(get_absolute_time()) - start_ms < timeout_ms) {
        tud_task();
        status_led_update();
        uint32_t now = to_ms_since_boot(get_absolute_time());

        if (user_presence_is_button_pressed()) {
            uint32_t press_start = now;
            // Wait for release or debounce
            while (user_presence_is_button_pressed()) {
                tud_task();
                sleep_ms(10);
                if (to_ms_since_boot(get_absolute_time()) - press_start > 2000) {
                    user_presence_reboot_to_bootloader();
                }
            }
            status_led_set_mode(LED_MODE_SUCCESS);
            return true;
        }

        if (keepalive_cb && (now - last_keepalive_ms >= 100)) {
            last_keepalive_ms = now;
            if (!keepalive_cb()) {
                // Operation cancelled by host
                status_led_set_mode(LED_MODE_ERROR);
                return false;
            }
        }

        sleep_ms(20);
    }

    status_led_set_mode(LED_MODE_ERROR);
    return false;
}
