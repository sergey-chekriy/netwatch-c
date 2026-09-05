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
  fprintf(stderr, "       %s --discover-apps --json\n       %s --config-show --config <config.json>\n       %s --config-set-dry-run true|false --config <config.json>\n       %s --config-set-poll-interval <seconds> --config <config.json>\n       %s --config-add-trusted-publisher <name> --path <executable-path> --team-id <team-id> --signing-identifier <identifier> --config <config.json>\n       %s --config-set-trusted-publisher <old-name> --name <new-name> --path <path> [--path <path> ...] --team-id <team-id> --signing-identifier <identifier> --config <config.json>\n       %s --config-remove-trusted-publisher <name> --config <config.json>\n       %s --config-add-trusted-workspace <name> --root <folder-path> --interpreter <executable-path> --config <config.json>\n       %s --config-set-trusted-workspace <old-name> --name <new-name> --root <path> [--root <path> ...] --interpreter <path> [--interpreter <path> ...] --allow-subdirectories true|false --allow-by-cwd-only true|false --config <config.json>\n       %s --config-remove-trusted-workspace <name> --config <config.json>\n       %s --reload-daemon\n", argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
  fprintf(stderr, "       %s --config-add-trusted-app-bundle <name> --bundle-root <app-path> --team-id <team-id> --signing-identifier <identifier> [--signing-identifier-prefix <prefix> ...] --allow-subdirectories true|false --config <config.json>\n       %s --config-remove-trusted-app-bundle <name> --config <config.json>\n", argv0, argv0);
  fprintf(stderr, "       %s --config-set-apple-system-trust true|false --config <config.json>\n       %s --config-set-interface <name-or-empty> --config <config.json>\n       %s --config-set-log-path <path-or-empty> --config <config.json>\n       %s --config-set-verbose-log true|false --config <config.json>\n", argv0, argv0, argv0, argv0);
  fprintf(stderr, "       %s --config-set-daemon-reload-on-sighup true|false --config <config.json>\n       %s --config-set-daemon-exit-on-config-error true|false --config <config.json>\n       %s --config-set-deny-patterns [--value <pattern> ...] --config <config.json>\n       %s --config-set-allow-remote-hosts [--value <prefix> ...] --config <config.json>\n", argv0, argv0, argv0, argv0);
  fprintf(stderr, "       %s --config-add-allow-process <name> --path <path-or-prefix*> --config <config.json>\n       %s --config-set-allow-process <old-name> --name <new-name> --path <path-or-prefix*> [--path <path-or-prefix*> ...] --config <config.json>\n       %s --config-remove-allow-process <name> --config <config.json>\n", argv0, argv0, argv0);
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

static int set_allow_process_command(int argc, char **argv){
  if (argc < 9 || strcmp(argv[3], "--name")) return 2;
  const char **paths = calloc((size_t)argc, sizeof(*paths));
  if (!paths){ fprintf(stderr, "ERROR: out of memory\n"); return 1; }
  const char *config_path = NULL;
  size_t path_count = 0;
  int rc = 2;
  for (int i = 5; i < argc;){
    if (!strcmp(argv[i], "--path") && i + 1 < argc){
      paths[path_count++] = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--config") && i + 2 == argc){
      config_path = argv[i + 1];
      i += 2;
    } else {
      goto done;
    }
  }
  if (config_path && path_count > 0){
    rc = config_backend_set_allow_process(config_path, argv[2], argv[4], paths, path_count, netwatch_platform_default());
  }
done:
  free(paths);
  return rc;
}

static int set_string_array_command(int argc, char **argv, int remote_hosts){
  if (argc < 4) return 2;
  const char **values = calloc((size_t)argc, sizeof(*values));
  if (!values){ fprintf(stderr, "ERROR: out of memory\n"); return 1; }
  const char *config_path = NULL;
  size_t value_count = 0;
  int rc = 2;
  for (int i = 2; i < argc;){
    if (!strcmp(argv[i], "--value") && i + 1 < argc){
      values[value_count++] = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--config") && i + 2 == argc){
      config_path = argv[i + 1];
      i += 2;
    } else {
      goto done;
    }
  }
  if (config_path){
    rc = remote_hosts
      ? config_backend_set_allow_remote_hosts(config_path, values, value_count, netwatch_platform_default())
      : config_backend_set_deny_patterns(config_path, values, value_count, netwatch_platform_default());
  }
done:
  free(values);
  return rc;
}

static int set_trusted_publisher_command(int argc, char **argv){
  if (argc < 13 || strcmp(argv[3], "--name")) return 2;
  const char **paths = calloc((size_t)argc, sizeof(*paths));
  if (!paths){ fprintf(stderr, "ERROR: out of memory\n"); return 1; }
  const char *team_id = NULL, *signing_identifier = NULL, *config_path = NULL;
  size_t path_count = 0;
  int rc = 2;
  for (int i = 5; i < argc;){
    if (!strcmp(argv[i], "--path") && i + 1 < argc){ paths[path_count++] = argv[i + 1]; i += 2; }
    else if (!strcmp(argv[i], "--team-id") && i + 1 < argc){ team_id = argv[i + 1]; i += 2; }
    else if (!strcmp(argv[i], "--signing-identifier") && i + 1 < argc){ signing_identifier = argv[i + 1]; i += 2; }
    else if (!strcmp(argv[i], "--config") && i + 2 == argc){ config_path = argv[i + 1]; i += 2; }
    else goto done;
  }
  if (config_path && team_id && signing_identifier && path_count > 0){
    rc = config_backend_set_trusted_publisher(config_path, argv[2], argv[4], paths, path_count, team_id, signing_identifier, netwatch_platform_default());
  }
done:
  free(paths);
  return rc;
}

static int set_trusted_workspace_command(int argc, char **argv){
  if (argc < 15 || strcmp(argv[3], "--name")) return 2;
  const char **roots = calloc((size_t)argc, sizeof(*roots));
  const char **interpreters = calloc((size_t)argc, sizeof(*interpreters));
  if (!roots || !interpreters){ free(roots); free(interpreters); fprintf(stderr, "ERROR: out of memory\n"); return 1; }
  const char *config_path = NULL;
  size_t root_count = 0, interpreter_count = 0;
  int allow_subdirectories = -1, allow_by_cwd_only = -1, rc = 2;
  for (int i = 5; i < argc;){
    if (!strcmp(argv[i], "--root") && i + 1 < argc){ roots[root_count++] = argv[i + 1]; i += 2; }
    else if (!strcmp(argv[i], "--interpreter") && i + 1 < argc){ interpreters[interpreter_count++] = argv[i + 1]; i += 2; }
    else if (!strcmp(argv[i], "--allow-subdirectories") && i + 1 < argc && parse_bool_arg(argv[i + 1], &allow_subdirectories)){ i += 2; }
    else if (!strcmp(argv[i], "--allow-by-cwd-only") && i + 1 < argc && parse_bool_arg(argv[i + 1], &allow_by_cwd_only)){ i += 2; }
    else if (!strcmp(argv[i], "--config") && i + 2 == argc){ config_path = argv[i + 1]; i += 2; }
    else goto done;
  }
  if (config_path && root_count > 0 && interpreter_count > 0 && allow_subdirectories >= 0 && allow_by_cwd_only >= 0){
    rc = config_backend_set_trusted_workspace(config_path, argv[2], argv[4], roots, root_count, interpreters, interpreter_count, allow_subdirectories, allow_by_cwd_only, netwatch_platform_default());
  }
done:
  free(roots); free(interpreters);
  return rc;
}

static int add_trusted_app_bundle_command(int argc, char **argv){
  if (argc < 13) return 2;
  const char **identifiers = calloc((size_t)argc, sizeof(*identifiers));
  const char **prefixes = calloc((size_t)argc, sizeof(*prefixes));
  if (!identifiers || !prefixes){
    free(identifiers); free(prefixes); fprintf(stderr, "ERROR: out of memory\n"); return 1;
  }
  const char *bundle_root = NULL, *team_id = NULL, *config_path = NULL;
  size_t identifier_count = 0, prefix_count = 0;
  int allow_subdirectories = -1, rc = 2;
  for (int i = 3; i < argc;){
    if (!strcmp(argv[i], "--bundle-root") && i + 1 < argc){ bundle_root = argv[i + 1]; i += 2; }
    else if (!strcmp(argv[i], "--team-id") && i + 1 < argc){ team_id = argv[i + 1]; i += 2; }
    else if (!strcmp(argv[i], "--signing-identifier") && i + 1 < argc){ identifiers[identifier_count++] = argv[i + 1]; i += 2; }
    else if (!strcmp(argv[i], "--signing-identifier-prefix") && i + 1 < argc){ prefixes[prefix_count++] = argv[i + 1]; i += 2; }
    else if (!strcmp(argv[i], "--allow-subdirectories") && i + 1 < argc
      && parse_bool_arg(argv[i + 1], &allow_subdirectories)){ i += 2; }
    else if (!strcmp(argv[i], "--config") && i + 2 == argc){ config_path = argv[i + 1]; i += 2; }
    else goto done;
  }
  if (bundle_root && team_id && config_path && (identifier_count || prefix_count)
    && allow_subdirectories >= 0){
    rc = config_backend_add_trusted_app_bundle(config_path, argv[2], bundle_root, team_id,
      identifiers, identifier_count, prefixes, prefix_count, allow_subdirectories,
      netwatch_platform_default());
  }
done:
  free(identifiers); free(prefixes);
  return rc;
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
  if (argc > 1 && !strcmp(argv[1], "--config-set-apple-system-trust")){
    int value = 0;
    if (argc != 5 || !parse_bool_arg(argv[2], &value) || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_set_apple_system_trust(argv[4], value, netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-interface")){
    if (argc != 5 || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_set_interface(argv[4], argv[2], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-log-path")){
    if (argc != 5 || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_set_log_path(argv[4], argv[2], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-verbose-log")){
    int value = 0;
    if (argc != 5 || !parse_bool_arg(argv[2], &value) || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_set_verbose_log(argv[4], value, netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-poll-interval")){
    int seconds = 0;
    if (argc != 5 || !parse_duration(argv[2], &seconds) || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_set_poll_interval(argv[4], seconds, netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-daemon-reload-on-sighup")){
    int value = 0;
    if (argc != 5 || !parse_bool_arg(argv[2], &value) || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_set_daemon_reload_on_sighup(argv[4], value, netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-daemon-exit-on-config-error")){
    int value = 0;
    if (argc != 5 || !parse_bool_arg(argv[2], &value) || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_set_daemon_exit_on_config_error(argv[4], value, netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-deny-patterns")){
    int rc = set_string_array_command(argc, argv, 0);
    if (rc == 2){ print_usage(argv[0]); return 1; }
    return rc;
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-allow-remote-hosts")){
    int rc = set_string_array_command(argc, argv, 1);
    if (rc == 2){ print_usage(argv[0]); return 1; }
    return rc;
  }
  if (argc > 1 && !strcmp(argv[1], "--config-add-trusted-publisher")){
    if (argc != 11 || strcmp(argv[3], "--path") || strcmp(argv[5], "--team-id") || strcmp(argv[7], "--signing-identifier") || strcmp(argv[9], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_add_trusted_publisher(argv[10], argv[2], argv[4], argv[6], argv[8], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-trusted-publisher")){
    int rc = set_trusted_publisher_command(argc, argv);
    if (rc == 2){ print_usage(argv[0]); return 1; }
    return rc;
  }
  if (argc > 1 && !strcmp(argv[1], "--config-remove-trusted-publisher")){
    if (argc != 5 || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_remove_trusted_publisher(argv[4], argv[2], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-add-trusted-app-bundle")){
    int rc = add_trusted_app_bundle_command(argc, argv);
    if (rc == 2){ print_usage(argv[0]); return 1; }
    return rc;
  }
  if (argc > 1 && !strcmp(argv[1], "--config-remove-trusted-app-bundle")){
    if (argc != 5 || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_remove_trusted_app_bundle(argv[4], argv[2], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-add-trusted-workspace")){
    if (argc != 9 || strcmp(argv[3], "--root") || strcmp(argv[5], "--interpreter") || strcmp(argv[7], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_add_trusted_workspace(argv[8], argv[2], argv[4], argv[6], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-trusted-workspace")){
    int rc = set_trusted_workspace_command(argc, argv);
    if (rc == 2){ print_usage(argv[0]); return 1; }
    return rc;
  }
  if (argc > 1 && !strcmp(argv[1], "--config-remove-trusted-workspace")){
    if (argc != 5 || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_remove_trusted_workspace(argv[4], argv[2], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-add-allow-process")){
    if (argc != 7 || strcmp(argv[3], "--path") || strcmp(argv[5], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_add_allow_process(argv[6], argv[2], argv[4], netwatch_platform_default());
  }
  if (argc > 1 && !strcmp(argv[1], "--config-set-allow-process")){
    int rc = set_allow_process_command(argc, argv);
    if (rc == 2){ print_usage(argv[0]); return 1; }
    return rc;
  }
  if (argc > 1 && !strcmp(argv[1], "--config-remove-allow-process")){
    if (argc != 5 || strcmp(argv[3], "--config")){ print_usage(argv[0]); return 1; }
    return config_backend_remove_allow_process(argv[4], argv[2], netwatch_platform_default());
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
