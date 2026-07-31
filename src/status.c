#include "status.h"
#include "config.h"
#include "cJSON.h"
#include "util.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef NETWATCH_VERSION
#define NETWATCH_VERSION "unavailable"
#endif

#define NETWATCH_LABEL "com.serg.netwatch"

static char *home_path(const char *suffix){
  const char *home = home_dir();
  size_t n = strlen(home) + strlen(suffix) + 1;
  char *out = malloc(n);
  if (out) snprintf(out, n, "%s%s", home, suffix);
  return out;
}

static const char *yes_no(int value){ return value ? "yes" : "no"; }
static const char *enabled_disabled(int value){ return value ? "enabled" : "disabled"; }

static void print_tri(const char *name, int value){
  if (value < 0) printf("%s: unavailable\n", name);
  else printf("%s: %s\n", name, yes_no(value));
}

static char *last_non_empty_line(char *text){
  char *last = NULL;
  for (char *line = text; line && *line; ){
    char *end = strchr(line, '\n');
    if (end) *end = 0;
    char *start = line;
    while (*start && isspace((unsigned char)*start)) start++;
    char *tail = start + strlen(start);
    while (tail > start && isspace((unsigned char)tail[-1])) *--tail = 0;
    if (*start) last = start;
    line = end ? end + 1 : NULL;
  }
  return last ? xstrdup(last) : NULL;
}

static void print_recent_error(const char *err_log, const NetwatchPlatform *platform){
  if (platform->access_path(platform, err_log, F_OK) != 0){
    printf("Recent startup error: unavailable (stderr log not found)\n");
    return;
  }
  char err[256] = {0};
  char *text = platform->read_file(platform, err_log, err, sizeof(err));
  if (!text){ printf("Recent startup error: unavailable (%s)\n", err); return; }
  char *line = last_non_empty_line(text);
  printf("Recent startup error: %s\n", line ? line : "none detected");
  free(line); free(text);
}

static void print_config_status(const char *cfg_path, const NetwatchPlatform *platform){
  char err[512] = {0};
  char *text = platform->read_file(platform, cfg_path, err, sizeof(err));
  if (!text){
    printf("Config valid: no\n");
    printf("Config error: %s\n", err);
    printf("Config version: unavailable\n");
    printf("Apple system trust: unavailable\n");
    printf("Trusted publisher rules: unavailable\n");
    printf("Dry run: unavailable\n");
    return;
  }

  Config cfg = {0};
  if (!config_parse_text(&cfg, text, cfg_path, err, sizeof(err))){
    printf("Config valid: no\n");
    printf("Config error: %s\n", err);
    printf("Config version: unavailable\n");
    printf("Apple system trust: unavailable\n");
    printf("Trusted publisher rules: unavailable\n");
    printf("Dry run: unavailable\n");
    free(text); return;
  }

  cJSON *root = cJSON_Parse(text);
  cJSON *version = root ? cJSON_GetObjectItemCaseSensitive(root, "version") : NULL;
  printf("Config valid: yes\n");
  printf("Config version: %s\n", version ? "2" : "2 (implicit)");
  printf("Apple system trust: %s\n", enabled_disabled(cfg.allow_apple_system_components));
  printf("Trusted publisher rules: %zu\n", cfg.trusted_publishers.len);
  printf("Dry run: %s\n", enabled_disabled(cfg.dry_run));
  cJSON_Delete(root);
  config_free(&cfg);
  free(text);
}

static void print_audit_state(int plist_installed, const char *plist_path, const NetwatchPlatform *platform){
  if (!plist_installed){
    printf("Audit mode: unavailable (LaunchAgent not installed)\n");
    return;
  }
  char err[256] = {0};
  char *text = platform->read_file(platform, plist_path, err, sizeof(err));
  if (!text){ printf("Audit mode: unavailable (%s)\n", err); return; }
  printf("Audit mode: %s\n", strstr(text, "--audit") ? "configured" : "not configured");
  free(text);
}

int status_command_with_platform(const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  char *watch_bin = home_path("/.watch/netwatch");
  char *config = home_path("/.watch/netwatch.config.json");
  char *plist = home_path("/Library/LaunchAgents/" NETWATCH_LABEL ".plist");
  char *err_log = home_path("/.watch/netwatch.launchd.err.log");
  if (!watch_bin || !config || !plist || !err_log){
    free(watch_bin); free(config); free(plist); free(err_log);
    fprintf(stderr, "ERROR: out of memory building status paths\n");
    return 1;
  }

  int plist_installed = platform->access_path(platform, plist, F_OK) == 0;
  int loaded = plist_installed && platform->launchd_service_loaded ? platform->launchd_service_loaded(platform, NETWATCH_LABEL) : 0;
  int pid = 0, running = 0;
  char running_path[4096] = {0};
  if (platform->access_path(platform, watch_bin, X_OK) == 0 && platform->find_process_by_executable){
    running = platform->find_process_by_executable(platform, watch_bin, &pid, running_path, sizeof(running_path));
  }

  printf("netwatch version: %s\n", NETWATCH_VERSION);
  printf("LaunchAgent label: %s\n", NETWATCH_LABEL);
  printf("LaunchAgent plist: %s\n", plist);
  printf("LaunchAgent installed: %s\n", yes_no(plist_installed));
  print_tri("Service loaded", loaded);
  print_tri("Running", running);
  printf("PID: %s", running == 1 ? "" : "unavailable\n");
  if (running == 1) printf("%d\n", pid);
  printf("Executable path: %s\n", watch_bin);
  printf("Running executable path: %s\n", running == 1 ? running_path : "unavailable");
  printf("Config: %s\n", config);
  print_config_status(config, platform);
  print_audit_state(plist_installed, plist, platform);
  print_recent_error(err_log, platform);

  free(watch_bin); free(config); free(plist); free(err_log);
  return 0;
}

int status_command(void){
  return status_command_with_platform(netwatch_platform_default());
}
