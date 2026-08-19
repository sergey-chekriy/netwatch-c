#ifndef NETWATCH_DAEMON_H
#define NETWATCH_DAEMON_H

#include "platform.h"

char *daemon_lock_path_for_config(const char *config_path);
int daemon_run_with_status_path(const char *config_path, const char *status_path, const NetwatchPlatform *platform);
int daemon_run_with_platform(const char *config_path, const NetwatchPlatform *platform);
int daemon_run(const char *config_path);

#endif
