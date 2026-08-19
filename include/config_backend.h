#ifndef NETWATCH_CONFIG_BACKEND_H
#define NETWATCH_CONFIG_BACKEND_H

#include "platform.h"
#include <stddef.h>

int config_backend_show(const char *config_path, const NetwatchPlatform *platform);
int config_backend_set_dry_run(const char *config_path, int value, const NetwatchPlatform *platform);
int config_backend_set_apple_system_trust(const char *config_path, int value, const NetwatchPlatform *platform);
int config_backend_set_interface(const char *config_path, const char *value, const NetwatchPlatform *platform);
int config_backend_set_log_path(const char *config_path, const char *value, const NetwatchPlatform *platform);
int config_backend_set_poll_interval(const char *config_path, int seconds, const NetwatchPlatform *platform);
int config_backend_set_daemon_reload_on_sighup(const char *config_path, int value, const NetwatchPlatform *platform);
int config_backend_set_daemon_exit_on_config_error(const char *config_path, int value, const NetwatchPlatform *platform);
int config_backend_set_deny_patterns(const char *config_path, const char **values, size_t value_count, const NetwatchPlatform *platform);
int config_backend_set_allow_remote_hosts(const char *config_path, const char **values, size_t value_count, const NetwatchPlatform *platform);
int config_backend_add_allow_process(const char *config_path, const char *name, const char *path, const NetwatchPlatform *platform);
int config_backend_set_allow_process(const char *config_path, const char *old_name, const char *new_name, const char **paths, size_t path_count, const NetwatchPlatform *platform);
int config_backend_remove_allow_process(const char *config_path, const char *name, const NetwatchPlatform *platform);
int config_backend_add_trusted_publisher(const char *config_path, const char *name, const char *path, const char *team_id, const char *signing_identifier, const NetwatchPlatform *platform);
int config_backend_set_trusted_publisher(const char *config_path, const char *old_name, const char *new_name, const char **paths, size_t path_count, const char *team_id, const char *signing_identifier, const NetwatchPlatform *platform);
int config_backend_remove_trusted_publisher(const char *config_path, const char *name, const NetwatchPlatform *platform);
int config_backend_add_trusted_workspace(const char *config_path, const char *name, const char *root, const char *interpreter, const NetwatchPlatform *platform);
int config_backend_set_trusted_workspace(const char *config_path, const char *old_name, const char *new_name, const char **roots, size_t root_count, const char **interpreters, size_t interpreter_count, int allow_subdirectories, int allow_by_cwd_only, const NetwatchPlatform *platform);
int config_backend_remove_trusted_workspace(const char *config_path, const char *name, const NetwatchPlatform *platform);
int config_backend_reload_daemon(const NetwatchPlatform *platform);

#endif
