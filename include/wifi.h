#ifndef NETWATCH_WIFI_H
#define NETWATCH_WIFI_H

#include "config.h"
#include <stddef.h>

int disable_wifi_if_needed(const Config *cfg, const char *reason, int is_terminal, char *err, size_t err_len);

#endif
