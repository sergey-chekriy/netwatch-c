#include "daemon.h"
#include "config.h"
#include "logging.h"
#include "monitor.h"
#include "util.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t reload_requested = 0;

static void daemon_signal_handler(int signo){
  if (signo == SIGTERM || signo == SIGINT) stop_requested = 1;
  else if (signo == SIGHUP) reload_requested = 1;
}

static int install_signal_handlers(void){
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = daemon_signal_handler;
  sigemptyset(&sa.sa_mask);
  return sigaction(SIGTERM, &sa, NULL) == 0
    && sigaction(SIGINT, &sa, NULL) == 0
    && sigaction(SIGHUP, &sa, NULL) == 0;
}

char *daemon_lock_path_for_config(const char *config_path){
  char resolved[PATH_MAX];
  const char *lock_key = config_path ? config_path : "default";
  if (config_path && realpath(config_path, resolved)) lock_key = resolved;
  unsigned long hash = 5381;
  for (const unsigned char *p = (const unsigned char *)lock_key; *p; p++){
    hash = ((hash << 5) + hash) + *p;
  }
  char buf[128];
  snprintf(buf, sizeof(buf), "/tmp/netwatch-%lu.lock", hash);
  return xstrdup(buf);
}

static int acquire_lock(const char *config_path, char *err, size_t err_len){
  char *path = daemon_lock_path_for_config(config_path);
  if (!path){ set_error(err, err_len, "out of memory creating daemon lock path"); return -1; }
  int fd = open(path, O_RDWR | O_CREAT, 0600);
  if (fd < 0){ set_error(err, err_len, "failed to open daemon lock %s: %s", path, strerror(errno)); free(path); return -1; }
  if (flock(fd, LOCK_EX | LOCK_NB) != 0){
    set_error(err, err_len, "another netwatch daemon instance is already running for this config");
    close(fd); free(path); return -1;
  }
  if (ftruncate(fd, 0) != 0){
    set_error(err, err_len, "failed to update daemon lock %s: %s", path, strerror(errno));
    close(fd); free(path); return -1;
  }
  char pid_text[32]; snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)getpid());
  size_t pid_len = strlen(pid_text);
  if (write(fd, pid_text, pid_len) != (ssize_t)pid_len){
    set_error(err, err_len, "failed to write daemon lock %s: %s", path, strerror(errno));
    close(fd); free(path); return -1;
  }
  free(path);
  return fd;
}

static int should_stop(const NetwatchPlatform *platform){
  return stop_requested || (platform->daemon_should_stop && platform->daemon_should_stop(platform));
}

static int should_reload(const NetwatchPlatform *platform){
  if (reload_requested){ reload_requested = 0; return 1; }
  return platform->daemon_should_reload && platform->daemon_should_reload(platform);
}

static void log_reload_error(const Config *cfg, const NetwatchPlatform *platform, const char *message){
  char *log_path = cfg->log_path ? xstrdup(cfg->log_path) : default_log_path();
  char err[256] = {0};
  char text[768];
  snprintf(text, sizeof(text), "Config reload failed: %s", message);
  if (log_path) log_message_with_platform(log_path, text, platform, err, sizeof(err));
  free(log_path);
}

static int reload_config(const char *config_path, Config *cfg, const NetwatchPlatform *platform){
  char err[512] = {0};
  Config next = {0};
  if (!config_load_with_platform(&next, config_path, platform, err, sizeof(err))){
    fprintf(stderr, "ERROR: %s\n", err);
    if (cfg->daemon.exit_on_config_error) return 0;
    log_reload_error(cfg, platform, err);
    return 1;
  }
  config_free(cfg);
  *cfg = next;
  return 1;
}

int daemon_run_with_platform(const char *config_path, const NetwatchPlatform *platform){
  if (!config_path || !*config_path){ fprintf(stderr, "ERROR: config path is required\n"); return 1; }
  platform = netwatch_platform_or_default(platform);
  stop_requested = 0; reload_requested = 0;
  if (!install_signal_handlers()){ fprintf(stderr, "ERROR: failed to install signal handlers\n"); return 1; }

  char err[512] = {0};
  Config cfg = {0};
  if (!config_load_with_platform(&cfg, config_path, platform, err, sizeof(err))){ fprintf(stderr, "ERROR: %s\n", err); return 1; }
  int lock_fd = acquire_lock(config_path, err, sizeof(err));
  if (lock_fd < 0){ fprintf(stderr, "ERROR: %s\n", err); config_free(&cfg); return 1; }

  int rc = 0;
  while (!should_stop(platform)){
    if (should_reload(platform) && cfg.daemon.reload_on_sighup && !reload_config(config_path, &cfg, platform)){ rc = 1; break; }
    rc = monitor_scan_config(&cfg, NULL, platform);
    if (rc != 0) break;
    if (should_stop(platform)) break;
    if (should_reload(platform)){
      if (cfg.daemon.reload_on_sighup && !reload_config(config_path, &cfg, platform)){ rc = 1; break; }
      if (should_stop(platform)) break;
    }
    if (platform->sleep_seconds) platform->sleep_seconds(platform, (unsigned int)cfg.daemon.poll_interval_seconds);
    else sleep((unsigned int)cfg.daemon.poll_interval_seconds);
  }

  close(lock_fd);
  config_free(&cfg);
  return rc;
}

int daemon_run(const char *config_path){
  return daemon_run_with_platform(config_path, netwatch_platform_default());
}
