#include "wifi.h"
#include "logging.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int disable_wifi_if_needed_with_platform(const Config *cfg, const char *reason, int is_terminal, const NetwatchPlatform *platform, char *err, size_t err_len){
  platform = netwatch_platform_or_default(platform);
  const char *interface = cfg->interface ? cfg->interface : "Wi-Fi";
  const char *prefix = cfg->dry_run ? "DRY RUN: would disable" : "Wi-Fi disabled";
  size_t n = strlen(prefix) + strlen(interface) + strlen(reason) + 4;
  char *msg = malloc(n);
  if (!msg){ set_error(err, err_len, "out of memory building Wi-Fi message"); return 0; }
  snprintf(msg, n, "%s %s\n%s", prefix, interface, reason);

  char *log_path = cfg->log_path ? xstrdup(cfg->log_path) : default_log_path();
  int ok = log_path && log_message_with_platform(log_path, msg, platform, err, err_len);
  if (is_terminal) printf("%s\n", msg);
  if (ok && !cfg->dry_run) ok = platform->disable_wifi(platform, interface, err, err_len);
  free(log_path); free(msg); return ok;
}

int disable_wifi_if_needed(const Config *cfg, const char *reason, int is_terminal, char *err, size_t err_len){
  return disable_wifi_if_needed_with_platform(cfg, reason, is_terminal, netwatch_platform_default(), err, err_len);
}
