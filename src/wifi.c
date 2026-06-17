#include "wifi.h"
#include "logging.h"
#include "util.h"
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
extern char **environ;

static int run_networksetup_off(const char *interface, char *err, size_t err_len){
  pid_t pid = 0;
  char *argv[] = { "networksetup", "-setairportpower", (char *)interface, "off", NULL };
  int rc = posix_spawnp(&pid, "networksetup", NULL, NULL, argv, environ);
  if (rc != 0){ set_error(err, err_len, "failed to spawn networksetup: %d", rc); return 0; }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0){ set_error(err, err_len, "failed to wait for networksetup"); return 0; }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0){
    set_error(err, err_len, "networksetup failed with status %d", status); return 0;
  }
  return 1;
}

int disable_wifi_if_needed(const Config *cfg, const char *reason, int is_terminal, char *err, size_t err_len){
  const char *interface = cfg->interface ? cfg->interface : "Wi-Fi";
  const char *prefix = cfg->dry_run ? "DRY RUN: would disable" : "Wi-Fi disabled";
  size_t n = strlen(prefix) + strlen(interface) + strlen(reason) + 4;
  char *msg = malloc(n);
  if (!msg){ set_error(err, err_len, "out of memory building Wi-Fi message"); return 0; }
  snprintf(msg, n, "%s %s\n%s", prefix, interface, reason);

  char *log_path = cfg->log_path ? xstrdup(cfg->log_path) : default_log_path();
  int ok = log_path && log_message(log_path, msg, err, err_len);
  if (is_terminal) printf("%s\n", msg);
  if (ok && !cfg->dry_run) ok = run_networksetup_off(interface, err, err_len);
  free(log_path); free(msg); return ok;
}
