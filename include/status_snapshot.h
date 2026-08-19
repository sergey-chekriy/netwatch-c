#ifndef NETWATCH_STATUS_SNAPSHOT_H
#define NETWATCH_STATUS_SNAPSHOT_H

#include "config.h"
#include "monitor.h"
#include "platform.h"
#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <time.h>

#define NETWATCH_STATUS_SNAPSHOT_VERSION 1

typedef struct {
  bool daemon_running;
  bool config_valid;
  bool dry_run;
  time_t last_scan_at;
  char last_scan_result[64];
  size_t unknown_count;
  bool would_disable_wifi;
  bool wifi_disabled;
  bool has_last_unknown;
  MonitorUnknownSummary last_unknown;
  char active_config_path[PATH_MAX];
  int poll_interval_seconds;
} NetwatchStatusSnapshot;

char *netwatch_status_default_path(void);
const char *netwatch_status_level(const NetwatchStatusSnapshot *snapshot);
const char *netwatch_status_level_at(const NetwatchStatusSnapshot *snapshot, time_t now);
char *netwatch_status_snapshot_json(const NetwatchStatusSnapshot *snapshot);
char *netwatch_status_snapshot_json_at(const NetwatchStatusSnapshot *snapshot, time_t now);
int netwatch_status_write(const char *path, const NetwatchStatusSnapshot *snapshot, const NetwatchPlatform *platform, char *err, size_t err_len);
int netwatch_status_print_json(const char *path, const NetwatchPlatform *platform, char *err, size_t err_len);
void netwatch_status_snapshot_from_scan(NetwatchStatusSnapshot *snapshot, const char *config_path, const Config *cfg, const MonitorScanOutcome *outcome, bool daemon_running, bool config_valid);

#endif
