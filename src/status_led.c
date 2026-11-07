#include "status_led.h"
#include "pico/stdlib.h"
#include "pico/time.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "ws2812.pio.h"

static PIO pio = pio0;
static uint sm = 0;
static volatile LedMode current_mode = LED_MODE_IDLE;
static volatile uint32_t step = 0;
static struct repeating_timer s_led_timer;

static inline void put_pixel(uint32_t pixel_grb) {
    pio_sm_put_blocking(pio, sm, pixel_grb << 8u);
}

static inline uint32_t urgb_u32(uint8_t r, uint8_t g, uint8_t b) {
    return ((uint32_t)(g) << 16) | ((uint32_t)(r) << 8) | (uint32_t)(b);
}

void status_led_set_color(uint8_t r, uint8_t g, uint8_t b) {
    put_pixel(urgb_u32(r, g, b));
}

static bool led_timer_callback(struct repeating_timer *t) {
    (void)t;
    status_led_update();
    return true;
}

void status_led_init(void) {
    uint offset = pio_add_program(pio, &ws2812_program);
    ws2812_program_init(pio, sm, offset, WS2812_PIN, 800000, false);
    status_led_set_mode(LED_MODE_IDLE);

    // Hardware timer interrupt every 30ms ensures smooth animations even during heavy PQC calculations
    add_repeating_timer_ms(-30, led_timer_callback, NULL, &s_led_timer);
}

void status_led_set_mode(LedMode mode) {
    current_mode = mode;
    step = 0;
    status_led_update();
}

void status_led_update(void) {
    step++;

    switch (current_mode) {
        case LED_MODE_OFF:
            status_led_set_color(0, 0, 0);
            break;

        case LED_MODE_IDLE: {
            // Calm gentle pulsing cyan/deep blue (period ~1.8s)
            uint32_t phase = (step % 60);
            uint8_t val = (phase < 30) ? (phase * 2) : ((60 - phase) * 2);
            uint8_t g = (val / 3) + 2;
            uint8_t b = val + 5;
            status_led_set_color(0, g, b);
            break;
        }

        case LED_MODE_UP_REQUIRED: {
            // Rapid blinking bright gold-yellow (touch/presence needed)
            if ((step % 6) < 3) {
                status_led_set_color(220, 180, 0);
            } else {
                status_led_set_color(0, 0, 0);
            }
            break;
        }

        case LED_MODE_PQC_ACTIVE: {
            // Distinctive breathing Neon Violet / Magenta wave:
            // Clearly signals "Post-Quantum Cryptographic computation in progress - please wait!"
            uint32_t phase = (step % 32);
            uint8_t progress = (phase < 16) ? (phase * 16) : ((32 - phase) * 16);
            // Throbs between deep violet (70, 0, 100) and brilliant neon magenta (255, 0, 255)
            uint8_t r = 70 + (progress * 185) / 240;
            uint8_t b = 100 + (progress * 155) / 240;
            status_led_set_color(r, 0, b);
            break;
        }

        case LED_MODE_SUCCESS:
            // Vivid emerald green confirmation flash
            status_led_set_color(0, 240, 25);
            if (step > 20) { // ~600ms
                current_mode = LED_MODE_IDLE;
            }
            break;

        case LED_MODE_ERROR:
            // Bright crimson red flash
            status_led_set_color(255, 0, 0);
            if (step > 20) {
                current_mode = LED_MODE_IDLE;
            }
            break;

        case LED_MODE_BOOTLOADER:
            // Solid warm amber / orange
            status_led_set_color(255, 120, 0);
            break;
    }
}
