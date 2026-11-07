#pragma once

#include <stdint.h>
#include <stdbool.h>

#define WS2812_PIN 16

typedef enum {
    LED_MODE_OFF,
    LED_MODE_IDLE,          // Pulsing Cyan
    LED_MODE_UP_REQUIRED,   // Rapid blinking Yellow (waiting for user touch)
    LED_MODE_PQC_ACTIVE,    // Purple/Magenta during PQC processing
    LED_MODE_SUCCESS,       // Quick Green flash
    LED_MODE_ERROR,         // Red flash
    LED_MODE_BOOTLOADER,    // Solid Yellow/Orange before rebooting to BOOTSEL
} LedMode;

void status_led_init(void);
void status_led_set_mode(LedMode mode);
void status_led_update(void);
void status_led_set_color(uint8_t r, uint8_t g, uint8_t b);
