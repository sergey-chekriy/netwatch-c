#ifndef NETWATCH_MONITOR_H
#define NETWATCH_MONITOR_H

#include "config.h"
#include "platform.h"
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

typedef struct {
  time_t started_at;
  time_t ended_at;
  size_t scan_cycles;
  size_t connections_scanned;
  size_t unique_processes;
  size_t unique_executable_paths;
  size_t apple_trusted_decisions;
  size_t trusted_publisher_matches;
  size_t trusted_workspace_matches;
  size_t trusted_publisher_invalid_signatures;
  size_t trusted_publisher_team_id_mismatches;
  size_t trusted_publisher_signing_identifier_mismatches;
  size_t trusted_publisher_metadata_failures;
  size_t explicit_allow_matches;
  size_t deny_matches;
  size_t unknown_decisions;
  size_t requested_enforcement_actions;
  size_t successful_wifi_disable_actions;
  size_t failed_wifi_disable_actions;
} MonitorStats;

void monitor_stats_print(const MonitorStats *stats);
int monitor_scan_config(const Config *cfg, MonitorStats *stats, const NetwatchPlatform *platform);
int monitor_run_with_stats(const char *cfg_path, bool force_dry_run, MonitorStats *stats, const NetwatchPlatform *platform);
int monitor_run_with_options(const char *cfg_path, bool force_dry_run, const NetwatchPlatform *platform);
int monitor_run_with_platform(const char *cfg_path, const NetwatchPlatform *platform);
int monitor_run(const char *cfg_path);

#endif
