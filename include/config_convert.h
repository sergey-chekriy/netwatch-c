#ifndef NETWATCH_CONFIG_CONVERT_H
#define NETWATCH_CONFIG_CONVERT_H

#include "apple_trust.h"
#include "platform.h"
#include <stddef.h>

typedef AppleTrustResult (*ConfigConvertVerifier)(const char *path, char *reason, size_t reason_size);

int config_convert_in_place(const char *config_path);
int config_convert_in_place_with_platform(const char *config_path, const NetwatchPlatform *platform);
int config_convert_in_place_with_verifier(const char *config_path, ConfigConvertVerifier verifier);

#endif
