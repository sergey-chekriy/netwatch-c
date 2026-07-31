#ifndef NETWATCH_WHY_H
#define NETWATCH_WHY_H

#include "allow.h"

int why_explain_with_platform(const Config *cfg, const char *target, const NetwatchPlatform *platform);
int why_explain(const Config *cfg, const char *target, PolicyAppleVerifier verifier);
int why_command_with_platform(const char *config_path, const char *target, const NetwatchPlatform *platform);
int why_command(const char *config_path, const char *target);

#endif
