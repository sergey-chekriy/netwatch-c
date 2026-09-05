#ifndef NETWATCH_CONFIG_H
#define NETWATCH_CONFIG_H

#include "platform.h"
#include "strlist.h"
#include "trusted_app_bundle.h"
#include "trusted_workspace.h"
#include <stdbool.h>
#include <stddef.h>

#define NETWATCH_CONFIG_VERSION 2

typedef struct { char *process; StrList paths; } ProcessRule;
typedef struct { ProcessRule *items; size_t len; size_t cap; } ProcessRules;

typedef struct {
  int poll_interval_seconds;
  bool reload_on_sighup;
  bool exit_on_config_error;
} DaemonConfig;

typedef struct {
  bool dry_run;
  bool verbose_log;
  bool allow_apple_system_components;
  DaemonConfig daemon;
  char *interface;
  char *log_path;
  StrList deny_patterns;
  StrList allow_remote_hosts;
  ProcessRules allow_processes;
  TrustedPublisherRules trusted_publishers;
  TrustedAppBundleRules trusted_app_bundles;
  TrustedWorkspaceRules trusted_workspaces;
} Config;

int config_load(Config *cfg, const char *path, char *err, size_t err_len);
int config_load_with_platform(Config *cfg, const char *path, const NetwatchPlatform *platform, char *err, size_t err_len);
int config_parse_text(Config *cfg, const char *text, const char *source, char *err, size_t err_len);
void config_free(Config *cfg);

#endif
