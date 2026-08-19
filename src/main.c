#include "app_discovery.h"
#include "audit.h"
#include "config_backend.h"
#include "config_check.h"
#include "config_convert.h"
#include "daemon.h"
#include "monitor.h"
#include "status.h"
#include "status_snapshot.h"
#include "why.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CONFIG_PATH "./netwatch.config.json"

static void print_usage(const char *argv0){
  fprintf(stderr, "Usage: %s [config.json]\n       %s --once --config <config.json>\n       %s --daemon --config <config.json>\n       %s --dry-run [config.json]\n       %s --stats [config.json]\n       %s --audit [seconds]\n       %s --status\n       %s --status-json\n       %s --convert-config <config.json>\n       %s --check-config <config.json>\n       %s --why <pid-or-executable-path>\n", argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
  fprintf(stderr, "       %s --discover-apps --json\n       %s --config-show --config <config.json>\n       %s --config-set-dry-run true|false --config <config.json>\n       %s --config-set-poll-interval <seconds> --config <config.json>\n       %s --config-add-trusted-publisher <name> --path <executable-path> --team-id <team-id> --signing-identifier <identifier> --config <config.json>\n       %s --config-remove-trusted-publisher <name> --config <config.json>\n       %s --config-add-trusted-workspace <name> --root <folder-path> --interpreter <executable-path> --config <config.json>\n       %s --config-remove-trusted-workspace <name> --config <config.json>\n       %s --reload-daemon\n", argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

static int parse_duration(const char *text, int *out){
  errno = 0;
  char *end = NULL;
  long value = strtol(text, &end, 10);
  if (errno || !end || *end || value <= 0 || value > INT_MAX) return 0;
  *out = (int)value; return 1;
}

static int parse_bool_arg(const char *text, int *out){
  if (!strcmp(text, "true")){ *out = 1; return 1; }
  if (!strcmp(text, "false")){ *out = 0; return 1; }
  return 0;
}

int main(int argc, char **argv){
  if (argc > 1 && !strcmp(argv[1], "--once")){
    if (argc != 4 || strcmp(argv[2], "--config")){ print_usage(argv[0]); return 1; }
    return monitor_run(argv[3]);
  }
  if (argc > 1 && !strcmp(argv[1], "--daemon")){
    if (argc != 4 || strcmp(argv[2], "--config")){ print_usage(argv[0]); return 1; }
    return daemon_run(argv[3]);
  }
  if (argc > 1 && !strcmp(argv[1], "--convert-config")){
    if (argc != 3){ print_usage(argv[0]); return 1; }
    return config_convert_in_place(argv[2]);
  }
  if (argc > 1 && !strcmp(argv[1], "--check-config")){
    if (argc != 3){ print_usage(argv[0]); return 1; }
    return config_check_file(argv[2]);
  }
  if (argc > 1 && !strcmp(argv[1], "--why")){
    if (argc != 3){ print_usage(argv[0]); return 1; }
    return why_command(DEFAULT_CONFIG_PATH, argv[2]);
  }
  if (argc > 1 && !strcmp(argv[1], "--discover-apps")){
    if (argc != 3 || strcmp(argv[2], "--json")){ print_usage(argv[0]); return 1; }
    return app_discovery_command_json(netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-show")){
    if (argc != 4 || strcmp(argv[2], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_show(argv[3], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-dry-run")){
    int value = 0;
    if (argc != 5 || !parse_bool_arg(argv[2], &value) || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_set_dry_run(argv[4], value, netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-poll-interval")){
    int seconds = 0;
    if (argc != 5 || !parse_duration(argv[2], &seconds) || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_set_poll_interval(argv[4], seconds, netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-add-trusted-publisher")){
    if (argc != 11 || strcmp(argv[3], "--path") || strcmp(argv[5], "--team-id") || strcmp(argv[7], "--signing-identifier") || strcmp(argv[9], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_add_trusted_publisher(argv[10], argv[2], argv[4], argv[6], argv[8], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-remove-trusted-publisher")){
    if (argc != 5 || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_remove_trusted_publisher(argv[4], argv[2], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-add-trusted-workspace")){
    if (argc != 9 || strcmp(argv[3], "--root") || strcmp(argv[5], "--interpreter") || strcmp(argv[7], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_add_trusted_workspace(argv[8], argv[2], argv[4], argv[6], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-remove-trusted-workspace")){
    if (argc != 5 || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_remove_trusted_workspace(argv[4], argv[2], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--reload-daemon")){
    if (argc != 2){ print_usage(argv[0]); return 1; }
    return config_backend_reload_daemon(netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--audit")){
    int duration_seconds = 0;
    if (argc > 3 || (argc == 3 && !parse_duration(argv[2], &duration_seconds))){ print_usage(argv[0]); return 1; }
    return audit_run(DEFAULT_CONFIG_PATH, duration_seconds);
  }
  if (argc > 1 && !strcmp(argv[1], "--status")){
    if (argc != 2){ print_usage(argv[0]); return 1; }
    return status_command();
  }
  if (argc > 1 && !strcmp(argv[1], "--status-json")){
    if (argc != 2){ print_usage(argv[0]); return 1; }
    char err[512] = {0};
    char *path = netwatch_status_default_path();
    if (!path){ fprintf(stderr, "ERROR: out of memory building status path\n"); return 1; }
    int ok = netwatch_status_print_json(path, netwatch_platform_default(), err, sizeof(err));
    if (!ok) fprintf(stderr, "ERROR: status snapshot unavailable: %s\n", err);
    free(path);
    return ok ? 0 : 1;
  }
  if (argc > 1 && !strcmp(argv[1], "--stats")){
    if (argc > 3){ print_usage(argv[0]); return 1; }
    MonitorStats stats = {0};
    int rc = monitor_run_with_stats(argc == 3 ? argv[2] : DEFAULT_CONFIG_PATH, false, &stats, netwatch_platform_default());
    if (stats.started_at) monitor_stats_print(&stats);
    return rc;
  }
  if (argc > 1 && !strcmp(argv[1], "--dry-run")){
    if (argc > 3){ print_usage(argv[0]); return 1; }
    return monitor_run_with_options(argc == 3 ? argv[2] : DEFAULT_CONFIG_PATH, true, netwatch_platform_default());
  }
  return monitor_run(argc > 1 ? argv[1] : DEFAULT_CONFIG_PATH);
}
