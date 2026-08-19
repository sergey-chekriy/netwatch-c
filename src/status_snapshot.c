#include "status_snapshot.h"
#include "util.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
  char *data;
  size_t len;
  size_t cap;
} JsonBuf;

static int buf_reserve(JsonBuf *buf, size_t extra){
  if (buf->len + extra + 1 <= buf->cap) return 1;
  size_t cap = buf->cap ? buf->cap * 2 : 1024;
  while (cap < buf->len + extra + 1) cap *= 2;
  char *data = realloc(buf->data, cap);
  if (!data) return 0;
  buf->data = data; buf->cap = cap; return 1;
}

static int buf_add_n(JsonBuf *buf, const char *text, size_t len){
  if (!buf_reserve(buf, len)) return 0;
  memcpy(buf->data + buf->len, text, len);
  buf->len += len; buf->data[buf->len] = 0; return 1;
}

static int buf_add(JsonBuf *buf, const char *text){ return buf_add_n(buf, text, strlen(text)); }

static int buf_addf(JsonBuf *buf, const char *fmt, ...){
  va_list ap;
  va_start(ap, fmt);
  va_list copy;
  va_copy(copy, ap);
  int n = vsnprintf(NULL, 0, fmt, copy);
  va_end(copy);
  if (n < 0){ va_end(ap); return 0; }
  if (!buf_reserve(buf, (size_t)n)){ va_end(ap); return 0; }
  vsnprintf(buf->data + buf->len, buf->cap - buf->len, fmt, ap);
  va_end(ap);
  buf->len += (size_t)n; return 1;
}

static int json_string(JsonBuf *buf, const char *text){
  if (!buf_add(buf, "\"")) return 0;
  for (const unsigned char *p = (const unsigned char *)(text ? text : ""); *p; p++){
    char tmp[8];
    if (*p == '"' || *p == '\\'){
      tmp[0] = '\\'; tmp[1] = (char)*p;
      if (!buf_add_n(buf, tmp, 2)) return 0;
    } else if (*p == '\n'){
      if (!buf_add(buf, "\\n")) return 0;
    } else if (*p == '\r'){
      if (!buf_add(buf, "\\r")) return 0;
    } else if (*p == '\t'){
      if (!buf_add(buf, "\\t")) return 0;
    } else if (*p < 0x20){
      snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
      if (!buf_add(buf, tmp)) return 0;
    } else if (!buf_add_n(buf, (const char *)p, 1)) return 0;
  }
  return buf_add(buf, "\"");
}

static const char *json_bool(bool value){ return value ? "true" : "false"; }

char *netwatch_status_default_path(void){
  const char *home = home_dir();
  size_t n = strlen(home) + strlen("/.watch/netwatch.status.json") + 1;
  char *out = malloc(n);
  if (out) snprintf(out, n, "%s/.watch/netwatch.status.json", home);
  return out;
}

static int scan_is_ok(const NetwatchStatusSnapshot *snapshot){
  return snapshot && snapshot->config_valid && !strcmp(snapshot->last_scan_result, "ok")
    && snapshot->unknown_count == 0 && !snapshot->would_disable_wifi && !snapshot->wifi_disabled;
}

static int scan_is_fresh_at(const NetwatchStatusSnapshot *snapshot, time_t now){
  if (!snapshot || snapshot->last_scan_at <= 0 || snapshot->poll_interval_seconds <= 0) return 0;
  return now - snapshot->last_scan_at <= snapshot->poll_interval_seconds;
}

const char *netwatch_status_level_at(const NetwatchStatusSnapshot *snapshot, time_t now){
  if (!scan_is_ok(snapshot) || !scan_is_fresh_at(snapshot, now)) return "error";
  if (snapshot->dry_run) return "attention";
  return "ok";
}

const char *netwatch_status_level(const NetwatchStatusSnapshot *snapshot){
  return netwatch_status_level_at(snapshot, time(NULL));
}

void netwatch_status_snapshot_from_scan(NetwatchStatusSnapshot *snapshot, const char *config_path, const Config *cfg, const MonitorScanOutcome *outcome, bool daemon_running, bool config_valid){
  *snapshot = (NetwatchStatusSnapshot){
    .daemon_running = daemon_running,
    .config_valid = config_valid,
    .dry_run = cfg ? cfg->dry_run : false,
    .poll_interval_seconds = cfg ? cfg->daemon.poll_interval_seconds : 0
  };
  snprintf(snapshot->active_config_path, sizeof(snapshot->active_config_path), "%s", config_path ? config_path : "");
  snprintf(snapshot->last_scan_result, sizeof(snapshot->last_scan_result), "%s", outcome && outcome->last_scan_result[0] ? outcome->last_scan_result : "not_scanned");
  if (!outcome) return;
  snapshot->last_scan_at = outcome->last_scan_at;
  snapshot->unknown_count = outcome->unknown_count;
  snapshot->would_disable_wifi = outcome->would_disable_wifi;
  snapshot->wifi_disabled = outcome->wifi_disabled;
  snapshot->has_last_unknown = outcome->has_last_unknown;
  snapshot->last_unknown = outcome->last_unknown;
}

static int append_unknown(JsonBuf *buf, const MonitorUnknownSummary *summary){
  return buf_add(buf, "  \"lastUnknownProcessSummary\": {\n")
    && buf_addf(buf, "    \"pid\": %d,\n", summary->pid)
    && buf_add(buf, "    \"processName\": ") && json_string(buf, summary->process_name) && buf_add(buf, ",\n")
    && buf_add(buf, "    \"commandLine\": ") && json_string(buf, summary->command_line) && buf_add(buf, ",\n")
    && buf_add(buf, "    \"executablePath\": ") && json_string(buf, summary->executable_path) && buf_add(buf, ",\n")
    && buf_add(buf, "    \"cwd\": ") && json_string(buf, summary->cwd) && buf_add(buf, ",\n")
    && buf_add(buf, "    \"remoteEndpoint\": ") && json_string(buf, summary->remote_endpoint) && buf_add(buf, ",\n")
    && buf_add(buf, "    \"reason\": ") && json_string(buf, summary->reason) && buf_add(buf, ",\n")
    && buf_addf(buf, "    \"dryRun\": %s,\n", json_bool(summary->dry_run))
    && buf_addf(buf, "    \"wouldDisableWifi\": %s,\n", json_bool(summary->would_disable_wifi))
    && buf_addf(buf, "    \"wifiDisabled\": %s\n", json_bool(summary->wifi_disabled))
    && buf_add(buf, "  },\n");
}

char *netwatch_status_snapshot_json_at(const NetwatchStatusSnapshot *snapshot, time_t now){
  JsonBuf buf = {0};
  if (!snapshot) return NULL;
  if (!buf_add(&buf, "{\n")
    || !buf_addf(&buf, "  \"version\": %d,\n", NETWATCH_STATUS_SNAPSHOT_VERSION)
    || !buf_add(&buf, "  \"status\": ") || !json_string(&buf, netwatch_status_level_at(snapshot, now)) || !buf_add(&buf, ",\n")
    || !buf_addf(&buf, "  \"daemonRunning\": %s,\n", json_bool(snapshot->daemon_running))
    || !buf_addf(&buf, "  \"configValid\": %s,\n", json_bool(snapshot->config_valid))
    || !buf_addf(&buf, "  \"dryRun\": %s,\n", json_bool(snapshot->dry_run))
    || !buf_addf(&buf, "  \"lastScanAt\": %ld,\n", (long)snapshot->last_scan_at)
    || !buf_add(&buf, "  \"lastScanResult\": ") || !json_string(&buf, snapshot->last_scan_result) || !buf_add(&buf, ",\n")
    || !buf_addf(&buf, "  \"unknownCount\": %zu,\n", snapshot->unknown_count)
    || !buf_addf(&buf, "  \"wouldDisableWifi\": %s,\n", json_bool(snapshot->would_disable_wifi))
    || !buf_addf(&buf, "  \"wifiDisabled\": %s,\n", json_bool(snapshot->wifi_disabled))){
    free(buf.data); return NULL;
  }
  if (snapshot->has_last_unknown){
    if (!append_unknown(&buf, &snapshot->last_unknown)){ free(buf.data); return NULL; }
  } else if (!buf_add(&buf, "  \"lastUnknownProcessSummary\": null,\n")){
    free(buf.data); return NULL;
  }
  if (!buf_add(&buf, "  \"activeConfigPath\": ") || !json_string(&buf, snapshot->active_config_path)
    || !buf_addf(&buf, ",\n  \"pollIntervalSeconds\": %d\n", snapshot->poll_interval_seconds)
    || !buf_add(&buf, "}\n")){
    free(buf.data); return NULL;
  }
  return buf.data;
}

char *netwatch_status_snapshot_json(const NetwatchStatusSnapshot *snapshot){
  return netwatch_status_snapshot_json_at(snapshot, time(NULL));
}

int netwatch_status_write(const char *path, const NetwatchStatusSnapshot *snapshot, const NetwatchPlatform *platform, char *err, size_t err_len){
  platform = netwatch_platform_or_default(platform);
  char *json = netwatch_status_snapshot_json_at(snapshot, platform->now ? platform->now(platform) : time(NULL));
  if (!json){ set_error(err, err_len, "out of memory serializing status snapshot"); return 0; }
  char *tmp = platform->temp_path_for(platform, path);
  if (!tmp){ free(json); set_error(err, err_len, "out of memory creating status temp path"); return 0; }
  int ok = platform->write_temp_file(platform, tmp, json, 0644, err, err_len)
    && platform->rename_path(platform, tmp, path, err, err_len);
  if (ok) platform->fsync_parent_dir(platform, path);
  else platform->unlink_path(platform, tmp);
  free(tmp); free(json); return ok;
}

int netwatch_status_print_json(const char *path, const NetwatchPlatform *platform, char *err, size_t err_len){
  platform = netwatch_platform_or_default(platform);
  char *text = platform->read_file(platform, path, err, err_len);
  if (!text) return 0;
  fputs(text, stdout);
  if (text[0] && text[strlen(text) - 1] != '\n') fputc('\n', stdout);
  free(text); return 1;
}
