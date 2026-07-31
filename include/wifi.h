#ifndef NETWATCH_WIFI_H
#define NETWATCH_WIFI_H

#include "config.h"
#include "platform.h"
#include <stddef.h>

int disable_wifi_if_needed_with_platform(const Config *cfg, const char *reason, int is_terminal, const NetwatchPlatform *platform, char *err, size_t err_len);
int disable_wifi_if_needed(const Config *cfg, const char *reason, int is_terminal, char *err, size_t err_len);

#endif
