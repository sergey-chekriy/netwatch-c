#ifndef NETWATCH_CONFIG_BACKEND_H
#define NETWATCH_CONFIG_BACKEND_H

#include "platform.h"

int config_backend_show(const char *config_path, const NetwatchPlatform *platform);
int config_backend_set_dry_run(const char *config_path, int value, const NetwatchPlatform *platform);
int config_backend_set_poll_interval(const char *config_path, int seconds, const NetwatchPlatform *platform);
int config_backend_add_trusted_publisher(const char *config_path, const char *name, const char *path, const char *team_id, const char *signing_identifier, const NetwatchPlatform *platform);
int config_backend_remove_trusted_publisher(const char *config_path, const char *name, const NetwatchPlatform *platform);
int config_backend_add_trusted_workspace(const char *config_path, const char *name, const char *root, const char *interpreter, const NetwatchPlatform *platform);
int config_backend_remove_trusted_workspace(const char *config_path, const char *name, const NetwatchPlatform *platform);
int config_backend_reload_daemon(const NetwatchPlatform *platform);

#endif
