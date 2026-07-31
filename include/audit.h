#ifndef NETWATCH_AUDIT_H
#define NETWATCH_AUDIT_H

#include "platform.h"

int audit_run_with_platform(const char *cfg_path, int duration_seconds, const NetwatchPlatform *platform);
int audit_run(const char *cfg_path, int duration_seconds);

#endif
