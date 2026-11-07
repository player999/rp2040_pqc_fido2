#include "status_led.h"
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "ws2812.pio.h"

static PIO pio = pio0;
static uint sm = 0;
static LedMode current_mode = LED_MODE_IDLE;
static uint32_t last_tick_ms = 0;
static uint32_t step = 0;

static inline void put_pixel(uint32_t pixel_grb) {
    pio_sm_put_blocking(pio, sm, pixel_grb << 8u);
}

static inline uint32_t urgb_u32(uint8_t r, uint8_t g, uint8_t b) {
    return ((uint32_t)(g) << 16) | ((uint32_t)(r) << 8) | (uint32_t)(b);
}

void status_led_set_color(uint8_t r, uint8_t g, uint8_t b) {
    put_pixel(urgb_u32(r, g, b));
}

void status_led_init(void) {
    uint offset = pio_add_program(pio, &ws2812_program);
    ws2812_program_init(pio, sm, offset, WS2812_PIN, 800000, false);
    status_led_set_mode(LED_MODE_IDLE);
}

void status_led_set_mode(LedMode mode) {
    current_mode = mode;
    step = 0;
    status_led_update();
}

void status_led_update(void) {
    uint32_t now = to_ms_since_boot(get_absolute_time());
    if (now - last_tick_ms < 50 && step != 0) {
        return;
    }
    last_tick_ms = now;
    step++;

    switch (current_mode) {
        case LED_MODE_OFF:
            status_led_set_color(0, 0, 0);
            break;

        case LED_MODE_IDLE: {
            // Gentle pulsing cyan / deep blue
            uint32_t phase = (step % 40);
            uint8_t intensity = (phase < 20) ? (phase * 2) : ((40 - phase) * 2);
            intensity = (intensity / 3) + 2; // subtle
            status_led_set_color(0, intensity, intensity * 2);
            break;
        }

        case LED_MODE_UP_REQUIRED: {
            // Rapid blinking bright yellow (touch user presence needed)
            if ((step % 4) < 2) {
                status_led_set_color(180, 160, 0);
            } else {
                status_led_set_color(0, 0, 0);
            }
            break;
        }

        case LED_MODE_PQC_ACTIVE:
            // Vivid purple/magenta during ML-DSA / ML-KEM calculation
            status_led_set_color(150, 0, 200);
            break;

        case LED_MODE_SUCCESS:
            // Bright green flash
            status_led_set_color(0, 200, 20);
            if (step > 10) { // ~500ms
                current_mode = LED_MODE_IDLE;
            }
            break;

        case LED_MODE_ERROR:
            // Red flash
            status_led_set_color(220, 0, 0);
            if (step > 10) {
                current_mode = LED_MODE_IDLE;
            }
            break;

        case LED_MODE_BOOTLOADER:
            // Solid amber / orange
            status_led_set_color(220, 100, 0);
            break;
    }
}
