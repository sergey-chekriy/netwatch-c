#ifndef NETWATCH_CONFIG_CHECK_H
#define NETWATCH_CONFIG_CHECK_H

#include "apple_trust.h"
#include "platform.h"
#include <stddef.h>

typedef AppleTrustResult (*ConfigCheckVerifier)(const char *path, char *reason, size_t reason_size);

int config_check_file(const char *config_path);
int config_check_file_with_platform(const char *config_path, const NetwatchPlatform *platform);
int config_check_file_with_verifier(const char *config_path, ConfigCheckVerifier verifier);

#endif
