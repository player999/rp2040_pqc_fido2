#pragma once

#include <stdbool.h>
#include <stdint.h>

void user_presence_init(void);
void user_presence_update(void);
bool user_presence_is_button_pressed(void);
bool user_presence_wait(uint32_t timeout_ms, bool (*keepalive_cb)(void));
void user_presence_reboot_to_bootloader(void) __attribute__((noreturn));
void user_presence_set_auto_confirm(bool enable);
bool user_presence_get_auto_confirm(void);
