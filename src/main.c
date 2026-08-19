#include "audit.h"
#include "config_check.h"
#include "config_convert.h"
#include "monitor.h"
#include "status.h"
#include "why.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CONFIG_PATH "./netwatch.config.json"

static void print_usage(const char *argv0){
  fprintf(stderr, "Usage: %s [config.json]\n       %s --dry-run [config.json]\n       %s --stats [config.json]\n       %s --audit [seconds]\n       %s --status\n       %s --convert-config <config.json>\n       %s --check-config <config.json>\n       %s --why <pid-or-executable-path>\n", argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

static int parse_duration(const char *text, int *out){
  errno = 0;
  char *end = NULL;
  long value = strtol(text, &end, 10);
  if (errno || !end || *end || value <= 0 || value > INT_MAX) return 0;
  *out = (int)value; return 1;
}

int main(int argc, char **argv){
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
  if (argc > 1 && !strcmp(argv[1], "--audit")){
    int duration_seconds = 0;
    if (argc > 3 || (argc == 3 && !parse_duration(argv[2], &duration_seconds))){ print_usage(argv[0]); return 1; }
    return audit_run(DEFAULT_CONFIG_PATH, duration_seconds);
  }
  if (argc > 1 && !strcmp(argv[1], "--status")){
    if (argc != 2){ print_usage(argv[0]); return 1; }
    return status_command();
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
