#include "monitor.h"
#include "allow.h"
#include "config.h"
#include "logging.h"
#include "process.h"
#include "strlist.h"
#include "util.h"
#include "wifi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char *join_suspicious(StrList *items){
  size_t n = 1;
  for (size_t i = 0; i < items->len; i++) n += strlen(items->items[i]) + 1;
  char *out = calloc(1, n); if (!out) return NULL;
  for (size_t i = 0; i < items->len; i++){
    strcat(out, items->items[i]);
    if (i + 1 < items->len) strcat(out, "\n");
  }
  return out;
}

static void print_ok(const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  time_t now = platform->now ? platform->now(platform) : time(NULL);
  struct tm tm_utc;
#if defined(_WIN32)
  gmtime_s(&tm_utc, &now);
#else
  gmtime_r(&now, &tm_utc);
#endif
  char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
  printf("[%s] OK\n", ts);
}

static int path_known(const char *path){
  return path && path[0] && strcmp(path, "unknown");
}

static int strlist_push_unique(StrList *list, const char *value){
  for (size_t i = 0; i < list->len; i++) if (!strcmp(list->items[i], value)) return 1;
  return strlist_push(list, value);
}

static void stats_count_policy(MonitorStats *stats, ConnectionPolicy policy){
  if (!stats) return;
  if (policy.decision == CONNECTION_ALLOWED_APPLE_SYSTEM) stats->apple_trusted_decisions++;
  else if (policy.decision == CONNECTION_ALLOWED_TRUSTED_PUBLISHER) stats->trusted_publisher_matches++;
  else if (policy.decision == CONNECTION_ALLOWED_TRUSTED_APP_BUNDLE) stats->trusted_app_bundle_matches++;
  else if (policy.decision == CONNECTION_ALLOWED_TRUSTED_WORKSPACE) stats->trusted_workspace_matches++;
  else if (policy.decision == CONNECTION_ALLOWED_CONFIG) stats->explicit_allow_matches++;
  else if (policy.decision == CONNECTION_DENIED) stats->deny_matches++;
  else if (policy.decision == CONNECTION_UNKNOWN) stats->unknown_decisions++;

  if (!policy.trusted_publisher_checked || policy.trusted_publisher == TRUSTED_PUBLISHER_OK) return;
  if (policy.trusted_publisher == TRUSTED_PUBLISHER_INVALID_SIGNATURE) stats->trusted_publisher_invalid_signatures++;
  else if (policy.trusted_publisher == TRUSTED_PUBLISHER_TEAM_ID_MISMATCH) stats->trusted_publisher_team_id_mismatches++;
  else if (policy.trusted_publisher == TRUSTED_PUBLISHER_SIGNING_IDENTIFIER_MISMATCH) stats->trusted_publisher_signing_identifier_mismatches++;
  else if (policy.trusted_publisher == TRUSTED_PUBLISHER_METADATA_UNAVAILABLE || policy.trusted_publisher == TRUSTED_PUBLISHER_SECURITY_ERROR) stats->trusted_publisher_metadata_failures++;
}

static void log_trusted_publisher_success(const Config *cfg, const char *line, PathCache *cache, ConnectionPolicy policy, const NetwatchPlatform *platform){
  char *desc = describe_connection_with_platform(line, cache, policy, platform);
  char *log_path = cfg->log_path ? xstrdup(cfg->log_path) : default_log_path();
  char err[256] = {0};
  if (desc && log_path) log_message_with_platform(log_path, desc, platform, err, sizeof(err));
  free(log_path); free(desc);
}

static void set_scan_result(MonitorScanOutcome *outcome, const char *result, const NetwatchPlatform *platform){
  if (!outcome) return;
  snprintf(outcome->last_scan_result, sizeof(outcome->last_scan_result), "%s", result);
  outcome->last_scan_at = platform->now ? platform->now(platform) : time(NULL);
}

static const char *policy_reason(ConnectionPolicy policy){
  if (policy.trusted_publisher_checked && policy.decision == CONNECTION_UNKNOWN) return trusted_publisher_result_name(policy.trusted_publisher);
  if (policy.trusted_app_bundle_checked && policy.decision == CONNECTION_UNKNOWN) return trusted_app_bundle_result_name(policy.trusted_app_bundle);
  if (policy.trusted_workspace_checked && policy.decision == CONNECTION_UNKNOWN) return trusted_workspace_result_name(policy.trusted_workspace);
  return connection_decision_reason(policy.decision);
}

static void copy_or_unavailable(char *dst, size_t dst_size, const char *src){
  snprintf(dst, dst_size, "%s", src && *src ? src : "unavailable");
}

static void fill_unknown_summary(MonitorUnknownSummary *summary, const char *line, const char *proc, int pid, const char *path, ConnectionPolicy policy, const Config *cfg, const NetwatchPlatform *platform){
  *summary = (MonitorUnknownSummary){ .pid = pid, .dry_run = cfg->dry_run };
  snprintf(summary->process_name, sizeof(summary->process_name), "%s", proc);
  copy_or_unavailable(summary->executable_path, sizeof(summary->executable_path), path);
  copy_or_unavailable(summary->reason, sizeof(summary->reason), policy_reason(policy));
  char *remote = remote_of(line);
  copy_or_unavailable(summary->remote_endpoint, sizeof(summary->remote_endpoint), remote);
  free(remote);
  if (pid > 0 && platform->process_command_line){
    char *cmd = platform->process_command_line(platform, pid);
    copy_or_unavailable(summary->command_line, sizeof(summary->command_line), cmd);
    free(cmd);
  } else copy_or_unavailable(summary->command_line, sizeof(summary->command_line), NULL);
  if (pid > 0 && platform->process_cwd){
    char *cwd = platform->process_cwd(platform, pid);
    copy_or_unavailable(summary->cwd, sizeof(summary->cwd), cwd);
    free(cwd);
  } else copy_or_unavailable(summary->cwd, sizeof(summary->cwd), NULL);
}

void monitor_stats_print(const MonitorStats *stats){
  long runtime = (long)(stats->ended_at - stats->started_at);
  if (runtime < 0) runtime = 0;
  printf("Runtime statistics\n");
  printf("Runtime seconds: %ld\n", runtime);
  printf("Scan cycles: %zu\n", stats->scan_cycles);
  printf("Connections scanned: %zu\n", stats->connections_scanned);
  printf("Unique processes: %zu\n", stats->unique_processes);
  printf("Unique executable paths: %zu\n", stats->unique_executable_paths);
  printf("Apple-trusted decisions: %zu\n", stats->apple_trusted_decisions);
  printf("Trusted publisher matches: %zu\n", stats->trusted_publisher_matches);
  printf("Trusted app bundle matches: %zu\n", stats->trusted_app_bundle_matches);
  printf("Trusted workspace matches: %zu\n", stats->trusted_workspace_matches);
  printf("Trusted publisher invalid signatures: %zu\n", stats->trusted_publisher_invalid_signatures);
  printf("Trusted publisher Team ID mismatches: %zu\n", stats->trusted_publisher_team_id_mismatches);
  printf("Trusted publisher signing identifier mismatches: %zu\n", stats->trusted_publisher_signing_identifier_mismatches);
  printf("Trusted publisher metadata failures: %zu\n", stats->trusted_publisher_metadata_failures);
  printf("Explicit allow matches: %zu\n", stats->explicit_allow_matches);
  printf("Deny matches: %zu\n", stats->deny_matches);
  printf("Unknown decisions: %zu\n", stats->unknown_decisions);
  printf("Requested enforcement actions: %zu\n", stats->requested_enforcement_actions);
  printf("Successful Wi-Fi disable actions: %zu\n", stats->successful_wifi_disable_actions);
  printf("Failed Wi-Fi disable actions: %zu\n", stats->failed_wifi_disable_actions);
}

int monitor_scan_config_with_outcome(const Config *cfg, MonitorStats *stats, MonitorScanOutcome *outcome, const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  if (outcome) *outcome = (MonitorScanOutcome){0};
  char err[512] = {0};

  StrList connections = {0}, suspicious = {0};
  StrList unique_processes = {0}, unique_paths = {0};
  PathCache cache = {0};
  int rc = 0;
  if (!collect_connections_with_platform(&connections, platform, err, sizeof(err))){ fprintf(stderr, "ERROR: %s\n", err); set_scan_result(outcome, "error", platform); rc = 1; goto done; }
  if (stats) stats->scan_cycles++;

  for (size_t i = 0; i < connections.len; i++){
    char proc_copy[128] = {0};
    snprintf(proc_copy, sizeof(proc_copy), "%s", process_name_of(connections.items[i]));
    if (stats){
      if (!strlist_push_unique(&unique_processes, proc_copy)){ fprintf(stderr, "ERROR: out of memory collecting monitor statistics\n"); rc = 1; goto done; }
      stats->connections_scanned++;
    }
    int pid = 0;
    char *path_for_summary = NULL;
    if (pid_of(connections.items[i], &pid)) path_for_summary = process_path_cached_with_platform(&cache, pid, proc_copy, platform);
    ConnectionPolicy policy = connection_policy_for_pid_path_with_platform(connections.items[i], proc_copy, path_for_summary, pid, cfg, platform);
    if (stats){
      stats_count_policy(stats, policy);
      if (policy.decision != CONNECTION_ALLOWED_LOCALHOST && pid_of(connections.items[i], &pid)){
        char *path = process_path_cached_with_platform(&cache, pid, proc_copy, platform);
        if (!path){ free(path_for_summary); fprintf(stderr, "ERROR: out of memory collecting monitor statistics\n"); rc = 1; goto done; }
        int ok = !path_known(path) || strlist_push_unique(&unique_paths, path);
        free(path);
        if (!ok){ free(path_for_summary); fprintf(stderr, "ERROR: out of memory collecting monitor statistics\n"); rc = 1; goto done; }
      }
    }
    if (outcome && policy.decision == CONNECTION_UNKNOWN){
      outcome->unknown_count++;
      outcome->has_last_unknown = true;
      fill_unknown_summary(&outcome->last_unknown, connections.items[i], proc_copy, pid, path_for_summary, policy, cfg, platform);
    }
    free(path_for_summary);
    if (cfg->verbose_log && (policy.decision == CONNECTION_ALLOWED_TRUSTED_PUBLISHER
      || policy.decision == CONNECTION_ALLOWED_TRUSTED_APP_BUNDLE
      || policy.decision == CONNECTION_ALLOWED_TRUSTED_WORKSPACE)){
      log_trusted_publisher_success(cfg, connections.items[i], &cache, policy, platform);
    }
    if (connection_decision_allowed(policy.decision)) continue;
    char *desc = describe_connection_with_platform(connections.items[i], &cache, policy, platform);
    if (!desc || !strlist_push(&suspicious, desc)){ free(desc); fprintf(stderr, "ERROR: out of memory\n"); rc = 1; goto done; }
    free(desc);
  }

  if (suspicious.len){
    char *reason = join_suspicious(&suspicious);
    if (!reason){ fprintf(stderr, "ERROR: out of memory\n"); rc = 1; goto done; }
    if (stats) stats->requested_enforcement_actions++;
    if (outcome) outcome->would_disable_wifi = true;
    if (disable_wifi_if_needed_with_platform(cfg, reason, isatty(STDOUT_FILENO), platform, err, sizeof(err))){
      if (stats && !cfg->dry_run) stats->successful_wifi_disable_actions++;
      if (outcome && !cfg->dry_run) outcome->wifi_disabled = true;
    } else {
      if (stats && !cfg->dry_run) stats->failed_wifi_disable_actions++;
      fprintf(stderr, "ERROR: %s\n", err); rc = 1;
    }
    free(reason);
  } else if (isatty(STDOUT_FILENO)) print_ok(platform);

done:
  if (stats){
    stats->unique_processes = unique_processes.len;
    stats->unique_executable_paths = unique_paths.len;
    stats->ended_at = platform->now ? platform->now(platform) : time(NULL);
  }
  if (outcome && !outcome->last_scan_result[0]){
    if (rc != 0) set_scan_result(outcome, "error", platform);
    else if (outcome->unknown_count) set_scan_result(outcome, "unknown", platform);
    else if (outcome->would_disable_wifi) set_scan_result(outcome, "enforced", platform);
    else set_scan_result(outcome, "ok", platform);
    outcome->last_unknown.would_disable_wifi = outcome->would_disable_wifi;
    outcome->last_unknown.wifi_disabled = outcome->wifi_disabled;
  }
  path_cache_free(&cache);
  strlist_free(&unique_processes);
  strlist_free(&unique_paths);
  strlist_free(&connections);
  strlist_free(&suspicious);
  return rc;
}

int monitor_scan_config(const Config *cfg, MonitorStats *stats, const NetwatchPlatform *platform){
  return monitor_scan_config_with_outcome(cfg, stats, NULL, platform);
}

int monitor_run_with_stats(const char *cfg_path, bool force_dry_run, MonitorStats *stats, const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  if (stats) *stats = (MonitorStats){0};
  char err[512] = {0};
  Config cfg = {0};
  if (!config_load_with_platform(&cfg, cfg_path, platform, err, sizeof(err))){ fprintf(stderr, "ERROR: %s\n", err); return 1; }
  if (force_dry_run) cfg.dry_run = true;
  if (stats) stats->started_at = platform->now ? platform->now(platform) : time(NULL);
  int rc = monitor_scan_config(&cfg, stats, platform);
  config_free(&cfg);
  return rc;
}

int monitor_run_with_options(const char *cfg_path, bool force_dry_run, const NetwatchPlatform *platform){
  return monitor_run_with_stats(cfg_path, force_dry_run, NULL, platform);
}

int monitor_run_with_platform(const char *cfg_path, const NetwatchPlatform *platform){
  return monitor_run_with_options(cfg_path, false, platform);
}

int monitor_run(const char *cfg_path){
  return monitor_run_with_platform(cfg_path, netwatch_platform_default());
}
