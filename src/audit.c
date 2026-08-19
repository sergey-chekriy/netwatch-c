#include "audit.h"
#include "allow.h"
#include "apple_trust.h"
#include "config.h"
#include "process.h"
#include "strlist.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
  char *path;
  char *process;
  ConnectionDecision decision;
  size_t observations;
} AuditEntry;

typedef struct {
  AuditEntry *items;
  size_t len;
  size_t cap;
  size_t connections_scanned;
  time_t started_at;
  time_t ended_at;
} AuditReport;

static void audit_report_free(AuditReport *report){
  for (size_t i = 0; i < report->len; i++){
    free(report->items[i].path);
    free(report->items[i].process);
  }
  free(report->items); *report = (AuditReport){0};
}

static int path_known(const char *path){
  return path && path[0] && strcmp(path, "unknown");
}

static AuditEntry *find_entry(AuditReport *report, const char *path, ConnectionDecision decision){
  for (size_t i = 0; i < report->len; i++){
    if (report->items[i].decision == decision && !strcmp(report->items[i].path, path)) return &report->items[i];
  }
  return NULL;
}

static int add_observation(AuditReport *report, const char *process, const char *path, ConnectionDecision decision){
  AuditEntry *entry = find_entry(report, path, decision);
  if (entry){ entry->observations++; return 1; }
  if (report->len == report->cap){
    size_t cap = report->cap ? report->cap * 2 : 16;
    AuditEntry *items = realloc(report->items, cap * sizeof(*items));
    if (!items) return 0;
    report->items = items; report->cap = cap;
  }
  char *path_copy = xstrdup(path);
  char *process_copy = xstrdup(process);
  if (!path_copy || !process_copy){ free(path_copy); free(process_copy); return 0; }
  report->items[report->len] = (AuditEntry){
    .path = path_copy,
    .process = process_copy,
    .decision = decision,
    .observations = 1
  };
  report->len++; return 1;
}

static size_t unique_path_count(const AuditReport *report){
  size_t count = 0;
  for (size_t i = 0; i < report->len; i++){
    if (!path_known(report->items[i].path)) continue;
    int seen = 0;
    for (size_t j = 0; j < i; j++){
      if (path_known(report->items[j].path) && !strcmp(report->items[i].path, report->items[j].path)){ seen = 1; break; }
    }
    if (!seen) count++;
  }
  return count;
}

static int path_has_decision(const AuditReport *report, const char *path, ConnectionDecision decision){
  for (size_t i = 0; i < report->len; i++){
    if (report->items[i].decision == decision && !strcmp(report->items[i].path, path)) return 1;
  }
  return 0;
}

static int audit_scan_once(AuditReport *report, const Config *cfg, PathCache *cache, const NetwatchPlatform *platform, char *err, size_t err_len){
  StrList connections = {0};
  if (!collect_connections_with_platform(&connections, platform, err, err_len)) return 0;
  for (size_t i = 0; i < connections.len; i++){
    const char *proc = process_name_of(connections.items[i]);
    char proc_copy[128]; snprintf(proc_copy, sizeof(proc_copy), "%s", proc);
    int pid = 0;
    char *path = pid_of(connections.items[i], &pid) ? process_path_cached_with_platform(cache, pid, proc_copy, platform) : xstrdup("unknown");
    if (!path){ strlist_free(&connections); set_error(err, err_len, "out of memory resolving process path"); return 0; }
    ConnectionPolicy policy = connection_policy_for_pid_path_with_platform(connections.items[i], proc_copy, path_known(path) ? path : NULL, pid, cfg, platform);
    report->connections_scanned++;
    int ok = add_observation(report, proc_copy, path_known(path) ? path : "unknown", policy.decision);
    free(path);
    if (!ok){ strlist_free(&connections); set_error(err, err_len, "out of memory collecting audit observation"); return 0; }
  }
  strlist_free(&connections);
  return 1;
}

static void print_section(const AuditReport *report, const char *title, ConnectionDecision decision){
  int printed = 0;
  for (size_t i = 0; i < report->len; i++){
    if (report->items[i].decision != decision) continue;
    if (!printed){ printf("\n%s\n", title); printed = 1; }
    printf("  %s\n    observations: %zu\n", report->items[i].path, report->items[i].observations);
  }
}

static void print_suggestions(const AuditReport *report){
  int printed = 0;
  for (size_t i = 0; i < report->len; i++){
    const AuditEntry *entry = &report->items[i];
    if (entry->decision != CONNECTION_UNKNOWN || !path_known(entry->path) || apple_trust_is_system_path(entry->path)) continue;
    if (path_has_decision(report, entry->path, CONNECTION_DENIED)) continue;
    if (!printed){
      printf("\nSuggested allow entries (review before adding):\n\n");
      printed = 1;
    }
    printf("\"%s\":\n  \"%s\"\n", entry->process, entry->path);
  }
  if (!printed) printf("\nSuggested allow entries: none\n");
}

static void print_report(const AuditReport *report){
  long runtime = (long)(report->ended_at - report->started_at);
  if (runtime < 0) runtime = 0;
  printf("Audit report\n");
  printf("Runtime seconds: %ld\n", runtime);
  printf("Connections scanned: %zu\n", report->connections_scanned);
  printf("Unique executable paths: %zu\n", unique_path_count(report));
  print_section(report, "APPLE SYSTEM", CONNECTION_ALLOWED_APPLE_SYSTEM);
  print_section(report, "TRUSTED PUBLISHER", CONNECTION_ALLOWED_TRUSTED_PUBLISHER);
  print_section(report, "TRUSTED WORKSPACE", CONNECTION_ALLOWED_TRUSTED_WORKSPACE);
  print_section(report, "ALLOWED", CONNECTION_ALLOWED_CONFIG);
  print_section(report, "DENIED", CONNECTION_DENIED);
  print_section(report, "UNKNOWN", CONNECTION_UNKNOWN);
  print_suggestions(report);
}

int audit_run_with_platform(const char *cfg_path, int duration_seconds, const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  char err[512] = {0};
  Config cfg = {0};
  if (!config_load_with_platform(&cfg, cfg_path, platform, err, sizeof(err))){ fprintf(stderr, "ERROR: %s\n", err); return 1; }

  AuditReport report = { .started_at = platform->now ? platform->now(platform) : time(NULL) };
  PathCache cache = {0};
  int rc = 0;
  int scans = 0;
  time_t deadline = report.started_at + (duration_seconds > 0 ? duration_seconds : 0);
  for (;;){
    time_t now = platform->now ? platform->now(platform) : time(NULL);
    if (duration_seconds > 0 && scans && now >= deadline) break;
    if (!audit_scan_once(&report, &cfg, &cache, platform, err, sizeof(err))){ fprintf(stderr, "ERROR: %s\n", err); rc = 1; break; }
    scans++;
    if (duration_seconds <= 0) break;
    now = platform->now ? platform->now(platform) : time(NULL);
    if (now >= deadline) break;
    if (platform->sleep_seconds) platform->sleep_seconds(platform, 1);
    else sleep(1);
  }
  report.ended_at = platform->now ? platform->now(platform) : time(NULL);
  if (!rc) print_report(&report);
  path_cache_free(&cache);
  audit_report_free(&report);
  config_free(&cfg);
  return rc;
}

int audit_run(const char *cfg_path, int duration_seconds){
  return audit_run_with_platform(cfg_path, duration_seconds, netwatch_platform_default());
}
