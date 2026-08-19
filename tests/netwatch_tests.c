#include "allow.h"
#include "apple_trust.h"
#include "audit.h"
#include "config.h"
#include "config_check.h"
#include "config_convert.h"
#include "daemon.h"
#include "monitor.h"
#include "status.h"
#include "status_snapshot.h"
#include "strlist.h"
#include "util.h"
#include "why.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct { int rc; char *out; char *err; } Capture;

static void add_rule(Config *cfg, const char *proc, const char *path){
  cfg->allow_processes.items = calloc(1, sizeof(*cfg->allow_processes.items));
  assert(cfg->allow_processes.items);
  cfg->allow_processes.len = cfg->allow_processes.cap = 1;
  cfg->allow_processes.items[0].process = xstrdup(proc);
  assert(cfg->allow_processes.items[0].process);
  assert(strlist_push(&cfg->allow_processes.items[0].paths, path));
}

static void assert_contains(const char *text, const char *needle){
  if (!strstr(text, needle)){
    fprintf(stderr, "missing expected text: %s\n--- text ---\n%s\n", needle, text ? text : "(null)");
    assert(0);
  }
}
static void assert_not_contains(const char *text, const char *needle){ assert(!strstr(text, needle)); }
static void assert_before(const char *text, const char *left, const char *right){
  char *l = strstr(text, left), *r = strstr(text, right);
  assert(l && r && l < r);
}

static char *must_read(const char *path){
  char err[256] = {0};
  char *text = read_file(path, err, sizeof(err));
  assert(text);
  return text;
}

static void write_text_mode(const char *path, const char *text, mode_t mode){
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
  assert(fd >= 0);
  assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
  assert(close(fd) == 0);
  assert(chmod(path, mode) == 0);
}

static char *temp_dir(void){
  char path[] = "/tmp/netwatch_tests_XXXXXX";
  assert(mkdtemp(path));
  return xstrdup(path);
}

static char *join_path_dup(const char *dir, const char *name){
  size_t n = strlen(dir) + strlen(name) + 2;
  char *out = malloc(n);
  assert(out);
  snprintf(out, n, "%s/%s", dir, name);
  return out;
}

static void mkdir_ok(const char *path){ assert(mkdir(path, 0755) == 0 || errno == EEXIST); }

static void make_status_dirs(const char *home){
  char *watch = join_path_dup(home, ".watch");
  char *library = join_path_dup(home, "Library");
  char *agents = join_path_dup(library, "LaunchAgents");
  mkdir_ok(watch); mkdir_ok(library); mkdir_ok(agents);
  free(watch); free(library); free(agents);
}

static char *save_home_set(const char *home){
  const char *old = getenv("HOME");
  char *saved = old ? xstrdup(old) : NULL;
  assert(setenv("HOME", home, 1) == 0);
  return saved;
}

static void restore_home(char *saved){
  if (saved) assert(setenv("HOME", saved, 1) == 0);
  else assert(unsetenv("HOME") == 0);
  free(saved);
}

static char *write_config(const char *text){
  char path[] = "/tmp/netwatch_config_XXXXXX";
  int fd = mkstemp(path);
  assert(fd >= 0);
  assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
  assert(close(fd) == 0);
  return xstrdup(path);
}

static Config parse_config_ok(const char *text){
  Config cfg = {0};
  char err[512] = {0};
  assert(config_parse_text(&cfg, text, "test config", err, sizeof(err)));
  return cfg;
}

static void assert_config_error(const char *text, const char *needle){
  Config cfg = {0};
  char err[512] = {0};
  assert(!config_parse_text(&cfg, text, "test config", err, sizeof(err)));
  assert(strstr(err, needle));
}

static AppleTrustResult fake_verifier(const char *path, char *reason, size_t reason_size){
  if (strstr(path, "trusted")){
    if (reason && reason_size) snprintf(reason, reason_size, "trusted by test verifier");
    return APPLE_TRUST_OK;
  }
  if (reason && reason_size) snprintf(reason, reason_size, "rejected by test verifier");
  return APPLE_TRUST_INVALID_SIGNATURE;
}

typedef struct {
  int apple_calls;
  int identity_calls;
  int collect_calls;
  int process_path_calls;
  int process_cwd_calls;
  int process_argv_calls;
  int process_parent_pid_calls;
  int process_command_line_calls;
  int wifi_calls;
  int copy_calls;
  int fail_copy;
  int fail_wifi;
  int fail_collect;
  const char *process_path;
  const char *process_cwd;
  const char **process_argv;
  size_t process_argv_count;
  int parent_pid;
  const char *command_line;
  const char *parent_command_line;
  const char **connections;
  size_t connection_count;
  const char **process_paths;
  size_t process_path_count;
  time_t now_value;
  int sleep_calls;
  unsigned int slept_seconds;
  int launchd_calls;
  int launchd_loaded_result;
  int find_process_calls;
  int write_temp_file_calls;
  int not_scanned_status_after_scan;
  int read_file_calls;
  int daemon_stop_calls;
  int daemon_reload_calls;
  int daemon_reload_used;
  int find_process_result;
  int daemon_stop_after_collects;
  int daemon_reload_after_collects;
  int running_pid;
  const char *running_path;
  const char **read_files;
  size_t read_file_count;
  CodeSignatureIdentityResult identity_result;
  const char *team_id;
  const char *signing_identifier;
  char wifi_interface[64];
} FakePlatformState;

static char *fake_platform_read_file(const NetwatchPlatform *platform, const char *path, char *err, size_t err_len){
  FakePlatformState *state = platform->ctx;
  size_t call = (size_t)state->read_file_calls++;
  if (state->read_files && call < state->read_file_count) return xstrdup(state->read_files[call]);
  return netwatch_platform_default()->read_file(netwatch_platform_default(), path, err, err_len);
}

static AppleTrustResult fake_platform_apple(const NetwatchPlatform *platform, const char *path, char *reason, size_t reason_size){
  FakePlatformState *state = platform->ctx;
  state->apple_calls++;
  return fake_verifier(path, reason, reason_size);
}

static CodeSignatureIdentityResult fake_platform_identity(const NetwatchPlatform *platform, const char *path, CodeSignatureIdentity *identity, char *err, size_t err_len){
  (void)path; (void)err; (void)err_len;
  FakePlatformState *state = platform->ctx;
  state->identity_calls++;
  if (identity){
    snprintf(identity->team_id, sizeof(identity->team_id), "%s", state->team_id ? state->team_id : "TEAMID1234");
    snprintf(identity->signing_identifier, sizeof(identity->signing_identifier), "%s", state->signing_identifier ? state->signing_identifier : "com.example.App");
  }
  return state->identity_result;
}

static int fake_platform_collect(const NetwatchPlatform *platform, StrList *connections, char *err, size_t err_len){
  FakePlatformState *state = platform->ctx;
  state->collect_calls++;
  if (state->fail_collect){ set_error(err, err_len, "fake collect failure"); return 0; }
  if (state->connections){
    for (size_t i = 0; i < state->connection_count; i++) if (!strlist_push(connections, state->connections[i])) return 0;
    return 1;
  }
  return strlist_push(connections, "FakeProc 42 user 10u IPv4 TCP 10.0.0.1:123->203.0.113.10:443 (ESTABLISHED)");
}

static char *fake_platform_process_path(const NetwatchPlatform *platform, int pid, const char *proc_name){
  (void)pid; (void)proc_name;
  FakePlatformState *state = platform->ctx;
  size_t call = (size_t)state->process_path_calls++;
  if (state->process_paths && call < state->process_path_count) return xstrdup(state->process_paths[call]);
  return xstrdup(state->process_path ? state->process_path : "unknown");
}

static char *fake_platform_process_cwd(const NetwatchPlatform *platform, int pid){
  (void)pid;
  FakePlatformState *state = platform->ctx;
  state->process_cwd_calls++;
  return state->process_cwd ? xstrdup(state->process_cwd) : NULL;
}

static int fake_platform_process_argv(const NetwatchPlatform *platform, int pid, StrList *argv, char *err, size_t err_len){
  (void)pid; (void)err; (void)err_len;
  FakePlatformState *state = platform->ctx;
  state->process_argv_calls++;
  if (!state->process_argv) return 0;
  for (size_t i = 0; i < state->process_argv_count; i++) if (!strlist_push(argv, state->process_argv[i])) return 0;
  return 1;
}

static int fake_platform_process_parent_pid(const NetwatchPlatform *platform, int pid, int *ppid){
  (void)pid;
  FakePlatformState *state = platform->ctx;
  state->process_parent_pid_calls++;
  if (!state->parent_pid) return 0;
  if (ppid) *ppid = state->parent_pid;
  return 1;
}

static char *fake_platform_process_command_line(const NetwatchPlatform *platform, int pid){
  FakePlatformState *state = platform->ctx;
  state->process_command_line_calls++;
  if (pid == state->parent_pid && state->parent_command_line) return xstrdup(state->parent_command_line);
  return state->command_line ? xstrdup(state->command_line) : NULL;
}

static int fake_platform_disable_wifi(const NetwatchPlatform *platform, const char *interface, char *err, size_t err_len){
  FakePlatformState *state = platform->ctx;
  state->wifi_calls++;
  snprintf(state->wifi_interface, sizeof(state->wifi_interface), "%s", interface);
  if (state->fail_wifi){ set_error(err, err_len, "fake Wi-Fi failure"); return 0; }
  return 1;
}

static int fake_platform_copy_file(const NetwatchPlatform *platform, const char *src, const char *dst, mode_t mode, char *err, size_t err_len){
  FakePlatformState *state = platform->ctx;
  state->copy_calls++;
  if (state->fail_copy){ set_error(err, err_len, "fake backup failure"); return 0; }
  return netwatch_platform_default()->copy_file(netwatch_platform_default(), src, dst, mode, err, err_len);
}

static int fake_platform_write_temp_file(const NetwatchPlatform *platform, const char *path, const char *text, mode_t mode, char *err, size_t err_len){
  FakePlatformState *state = platform->ctx;
  state->write_temp_file_calls++;
  if (state->collect_calls > 0 && strstr(text, "\"lastScanResult\": \"not_scanned\"")) state->not_scanned_status_after_scan++;
  return netwatch_platform_default()->write_temp_file(netwatch_platform_default(), path, text, mode, err, err_len);
}

static time_t fake_platform_now(const NetwatchPlatform *platform){
  FakePlatformState *state = platform->ctx;
  return state->now_value ? state->now_value : 1700000000;
}

static void fake_platform_sleep(const NetwatchPlatform *platform, unsigned int seconds){
  FakePlatformState *state = platform->ctx;
  state->sleep_calls++;
  state->slept_seconds += seconds;
  if (state->now_value) state->now_value += seconds;
}

static int fake_platform_launchd_loaded(const NetwatchPlatform *platform, const char *label){
  (void)label;
  FakePlatformState *state = platform->ctx;
  state->launchd_calls++;
  return state->launchd_loaded_result;
}

static int fake_platform_find_process(const NetwatchPlatform *platform, const char *expected_path, int *pid, char *path, size_t path_size){
  (void)expected_path;
  FakePlatformState *state = platform->ctx;
  state->find_process_calls++;
  if (state->find_process_result == 1){
    if (pid) *pid = state->running_pid;
    if (path && path_size) snprintf(path, path_size, "%s", state->running_path ? state->running_path : expected_path);
  }
  return state->find_process_result;
}

static int fake_platform_daemon_should_stop(const NetwatchPlatform *platform){
  FakePlatformState *state = platform->ctx;
  state->daemon_stop_calls++;
  return state->daemon_stop_after_collects && state->collect_calls >= state->daemon_stop_after_collects;
}

static int fake_platform_daemon_should_reload(const NetwatchPlatform *platform){
  FakePlatformState *state = platform->ctx;
  state->daemon_reload_calls++;
  if (state->daemon_reload_used) return 0;
  if (state->daemon_reload_after_collects && state->collect_calls >= state->daemon_reload_after_collects){
    state->daemon_reload_used = 1;
    return 1;
  }
  return 0;
}

static NetwatchPlatform fake_platform(FakePlatformState *state){
  NetwatchPlatform platform = *netwatch_platform_default();
  platform.ctx = state;
  platform.read_file = fake_platform_read_file;
  platform.write_temp_file = fake_platform_write_temp_file;
  platform.apple_trust_check = fake_platform_apple;
  platform.collect_connections = fake_platform_collect;
  platform.process_path = fake_platform_process_path;
  platform.process_cwd = fake_platform_process_cwd;
  platform.process_argv = fake_platform_process_argv;
  platform.process_parent_pid = fake_platform_process_parent_pid;
  platform.process_command_line = fake_platform_process_command_line;
  platform.disable_wifi = fake_platform_disable_wifi;
  platform.code_signature_identity = fake_platform_identity;
  platform.copy_file = fake_platform_copy_file;
  platform.now = fake_platform_now;
  platform.sleep_seconds = fake_platform_sleep;
  platform.daemon_should_stop = fake_platform_daemon_should_stop;
  platform.daemon_should_reload = fake_platform_daemon_should_reload;
  platform.launchd_service_loaded = fake_platform_launchd_loaded;
  platform.find_process_by_executable = fake_platform_find_process;
  return platform;
}

static Capture capture_convert(const char *path){
  char out_path[] = "/tmp/netwatch_convert_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_convert_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = config_convert_in_place_with_verifier(path, fake_verifier);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static Capture capture_convert_platform(const char *path, const NetwatchPlatform *platform){
  char out_path[] = "/tmp/netwatch_convert_platform_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_convert_platform_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = config_convert_in_place_with_platform(path, platform);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static Capture capture_check(const char *path){
  char out_path[] = "/tmp/netwatch_check_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_check_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = config_check_file_with_verifier(path, fake_verifier);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static Capture capture_check_platform(const char *path, const NetwatchPlatform *platform){
  char out_path[] = "/tmp/netwatch_check_platform_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_check_platform_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = config_check_file_with_platform(path, platform);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static Capture capture_why(const Config *cfg, const char *target){
  char out_path[] = "/tmp/netwatch_why_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_why_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = why_explain(cfg, target, fake_verifier);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static Capture capture_why_platform(const Config *cfg, const char *target, const NetwatchPlatform *platform){
  char out_path[] = "/tmp/netwatch_why_platform_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_why_platform_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = why_explain_with_platform(cfg, target, platform);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static Capture capture_audit(const char *path, int duration_seconds, const NetwatchPlatform *platform){
  char out_path[] = "/tmp/netwatch_audit_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_audit_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = audit_run_with_platform(path, duration_seconds, platform);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static Capture capture_monitor_stats(const char *path, MonitorStats *stats, const NetwatchPlatform *platform){
  char out_path[] = "/tmp/netwatch_stats_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_stats_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = monitor_run_with_stats(path, false, stats, platform);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static Capture capture_daemon_status(const char *path, const char *status_path, const NetwatchPlatform *platform){
  char out_path[] = "/tmp/netwatch_daemon_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_daemon_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = daemon_run_with_status_path(path, status_path, platform);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static Capture capture_daemon(const char *path, const NetwatchPlatform *platform){
  char status_path[] = "/tmp/netwatch_status_json_XXXXXX";
  int fd = mkstemp(status_path);
  assert(fd >= 0);
  close(fd); unlink(status_path);
  Capture cap = capture_daemon_status(path, status_path, platform);
  unlink(status_path);
  return cap;
}

static Capture capture_status(const NetwatchPlatform *platform){
  char out_path[] = "/tmp/netwatch_status_out_XXXXXX";
  char err_path[] = "/tmp/netwatch_status_err_XXXXXX";
  int out_fd = mkstemp(out_path), err_fd = mkstemp(err_path);
  assert(out_fd >= 0 && err_fd >= 0);

  fflush(NULL);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  assert(saved_out >= 0 && saved_err >= 0);
  assert(dup2(out_fd, STDOUT_FILENO) >= 0);
  assert(dup2(err_fd, STDERR_FILENO) >= 0);
  int rc = status_command_with_platform(platform);
  fflush(NULL);
  assert(dup2(saved_out, STDOUT_FILENO) >= 0);
  assert(dup2(saved_err, STDERR_FILENO) >= 0);
  close(saved_out); close(saved_err); close(out_fd); close(err_fd);

  Capture cap = { .rc = rc, .out = must_read(out_path), .err = must_read(err_path) };
  unlink(out_path); unlink(err_path);
  return cap;
}

static void capture_free(Capture *cap){
  free(cap->out); free(cap->err); *cap = (Capture){0};
}

static int run_netwatch_mode_cwd(const char *mode, const char *config_path, const char *extra_arg, const char *path_env, const char *out_path, const char *cwd){
  const char *bin = getenv("NETWATCH_BIN");
  if (!bin) bin = "./netwatch";
  char resolved_bin[PATH_MAX];
  const char *exec_bin = realpath(bin, resolved_bin) ? resolved_bin : bin;
  pid_t pid = fork();
  assert(pid >= 0);
  if (pid == 0){
    if (cwd && chdir(cwd) != 0) _exit(126);
    if (path_env) setenv("PATH", path_env, 1);
    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0){ dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd); }
    if (extra_arg) execl(exec_bin, exec_bin, mode, config_path, extra_arg, NULL);
    else if (config_path) execl(exec_bin, exec_bin, mode, config_path, NULL);
    else execl(exec_bin, exec_bin, mode, NULL);
    _exit(127);
  }
  int status = 0;
  assert(waitpid(pid, &status, 0) == pid);
  return WIFEXITED(status) ? WEXITSTATUS(status) : 255;
}

static int run_netwatch_mode(const char *mode, const char *config_path, const char *extra_arg, const char *path_env, const char *out_path){
  return run_netwatch_mode_cwd(mode, config_path, extra_arg, path_env, out_path, NULL);
}

static int run_netwatch(const char *config_path, const char *extra_arg, const char *path_env, const char *out_path){
  return run_netwatch_mode("--convert-config", config_path, extra_arg, path_env, out_path);
}

static void test_system_paths(void){
  assert(apple_trust_is_system_path("/System/Library/foo"));
  assert(apple_trust_is_system_path("/usr/libexec/ciphermld"));
  assert(apple_trust_is_system_path("/usr/lib/libSomething.dylib"));
  assert(!apple_trust_is_system_path("/SystemMalware/foo"));
  assert(!apple_trust_is_system_path("/usr/libexec-malicious/foo"));
  assert(!apple_trust_is_system_path("/usr/local/bin/foo"));
  assert(!apple_trust_is_system_path("/Applications/Foo.app/Contents/MacOS/Foo"));
  assert(!apple_trust_is_system_path("/Library/AppleLike/foo"));
  assert(!apple_trust_is_system_path("relative/path"));
  assert(!apple_trust_is_system_path(""));
  assert(!apple_trust_is_system_path(NULL));
}

static void test_policy_priority(void){
  const char *line = "proc 123 user 10u IPv4 TCP 10.0.0.1:1->8.8.8.8:443 (ESTABLISHED)";
  Config cfg = { .allow_apple_system_components = true };
  assert(strlist_push(&cfg.deny_patterns, "proc"));
  add_rule(&cfg, "proc", "/System/Library/foo");
  assert(connection_policy_for_path(line, "proc", "/System/Library/foo", &cfg).decision == CONNECTION_DENIED);
  config_free(&cfg);

  cfg = (Config){ .allow_apple_system_components = true };
  add_rule(&cfg, "proc", "/System/Library/foo");
  assert(connection_policy_for_path(line, "proc", "/System/Library/foo", &cfg).decision == CONNECTION_ALLOWED_CONFIG);
  config_free(&cfg);

  cfg = (Config){ .allow_apple_system_components = false };
  assert(connection_policy_for_path(line, "proc", "/System/Library/foo", &cfg).decision == CONNECTION_UNKNOWN);
  config_free(&cfg);

  cfg = (Config){0};
  assert(connection_policy_for_path(
    "local 1 user TCP 127.0.0.1:123 (LISTEN)",
    "local",
    "/tmp/local",
    &cfg).decision == CONNECTION_ALLOWED_LOCALHOST);
  config_free(&cfg);
}

static void test_trusted_publisher_policy(void){
  const char *app_path = "/Applications/Publisher.app/Contents/MacOS/Publisher";
  const char *line = "Publisher 123 user 10u IPv4 TCP 10.0.0.1:1->8.8.8.8:443 (ESTABLISHED)";
  Config cfg = parse_config_ok(
    "{\n"
    "  \"version\": 2,\n"
    "  \"trustedPublishers\": {\n"
    "    \"Publisher App\": {\n"
    "      \"paths\": [\"/Applications/Publisher.app/Contents/MacOS/Publisher\"],\n"
    "      \"teamId\": \"TEAMID1234\",\n"
    "      \"signingIdentifier\": \"com.example.App\"\n"
    "    }\n"
    "  },\n"
    "  \"allowProcesses\": {\n"
    "    \"Publisher\": \"/Applications/Publisher.app/Contents/MacOS/Publisher\",\n"
    "    \"Other\": \"/Applications/Other.app/Contents/MacOS/Other\"\n"
    "  },\n"
    "  \"allowRemoteHosts\": [\"8.8.8.\"]\n"
    "}\n");

  FakePlatformState state = { .team_id = "TEAMID1234", .signing_identifier = "com.example.App" };
  NetwatchPlatform platform = fake_platform(&state);
  ConnectionPolicy policy = connection_policy_for_path_with_platform(line, "Publisher", app_path, &cfg, &platform);
  assert(policy.decision == CONNECTION_ALLOWED_TRUSTED_PUBLISHER);
  assert(policy.trusted_publisher_checked);
  assert(policy.trusted_publisher == TRUSTED_PUBLISHER_OK);
  assert(!strcmp(policy.matched_publisher, "Publisher App"));
  assert(state.identity_calls == 1);

  state = (FakePlatformState){ .team_id = "TEAMID1234", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(
    "Publisher 127 user TCP 1->9.9.9.9:443 (ESTABLISHED)",
    "Publisher",
    "/Applications/OtherPublisher.app/Contents/MacOS/Publisher",
    &cfg,
    &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(!policy.trusted_publisher_checked);
  assert(state.identity_calls == 0);

  policy = connection_policy_for_path_with_platform(
    "Other 124 user TCP 1->8.8.8.8:443 (ESTABLISHED)",
    "Other",
    "/Applications/Other.app/Contents/MacOS/Other",
    &cfg,
    &platform);
  assert(policy.decision == CONNECTION_ALLOWED_CONFIG);

  state = (FakePlatformState){ .team_id = "WRONGTEAM", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(line, "Publisher", app_path, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_publisher == TRUSTED_PUBLISHER_TEAM_ID_MISMATCH);
  assert(state.identity_calls == 1);
  assert(state.apple_calls == 0);

  state = (FakePlatformState){ .team_id = "TEAMID1234", .signing_identifier = "com.example.Other" };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(line, "Publisher", app_path, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_publisher == TRUSTED_PUBLISHER_SIGNING_IDENTIFIER_MISMATCH);

  state = (FakePlatformState){ .identity_result = CODE_SIGNATURE_IDENTITY_INVALID_SIGNATURE };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(line, "Publisher", app_path, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_publisher == TRUSTED_PUBLISHER_INVALID_SIGNATURE);

  state = (FakePlatformState){ .identity_result = CODE_SIGNATURE_IDENTITY_METADATA_UNAVAILABLE };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(line, "Publisher", app_path, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_publisher == TRUSTED_PUBLISHER_METADATA_UNAVAILABLE);

  state = (FakePlatformState){ .identity_result = CODE_SIGNATURE_IDENTITY_SECURITY_ERROR };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(line, "Publisher", app_path, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_publisher == TRUSTED_PUBLISHER_SECURITY_ERROR);

  state = (FakePlatformState){ .team_id = "BADTEAM", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(
    "Publisher 123 user TCP 127.0.0.1:123 (LISTEN)",
    "Publisher",
    app_path,
    &cfg,
    &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_publisher == TRUSTED_PUBLISHER_TEAM_ID_MISMATCH);

  Config multi_cfg = parse_config_ok(
    "{\n"
    "  \"version\": 2,\n"
    "  \"trustedPublishers\": {\n"
    "    \"Bad Rule\": {\n"
    "      \"paths\": [\"/Applications/Publisher.app/Contents/MacOS/Publisher\"],\n"
    "      \"teamId\": \"BADTEAM\",\n"
    "      \"signingIdentifier\": \"com.example.App\"\n"
    "    },\n"
    "    \"Good Rule\": {\n"
    "      \"paths\": [\"/Applications/Publisher.app/Contents/MacOS/Publisher\"],\n"
    "      \"teamId\": \"TEAMID1234\",\n"
    "      \"signingIdentifier\": \"com.example.App\"\n"
    "    }\n"
    "  },\n"
    "  \"allowProcesses\": {\n"
    "    \"Publisher\": \"/Applications/Publisher.app/Contents/MacOS/Publisher\"\n"
    "  }\n"
    "}\n");
  state = (FakePlatformState){ .team_id = "TEAMID1234", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(line, "Publisher", app_path, &multi_cfg, &platform);
  assert(policy.decision == CONNECTION_ALLOWED_TRUSTED_PUBLISHER);
  assert(!strcmp(policy.matched_publisher, "Good Rule"));
  assert(state.identity_calls == 2);
  config_free(&multi_cfg);

  multi_cfg = parse_config_ok(
    "{\n"
    "  \"version\": 2,\n"
    "  \"trustedPublishers\": {\n"
    "    \"Alpha Bad\": {\n"
    "      \"paths\": [\"/Applications/Publisher.app/Contents/MacOS/Publisher\"],\n"
    "      \"teamId\": \"BADTEAM\",\n"
    "      \"signingIdentifier\": \"com.example.App\"\n"
    "    },\n"
    "    \"Zed Bad\": {\n"
    "      \"paths\": [\"/Applications/Publisher.app/Contents/MacOS/Publisher\"],\n"
    "      \"teamId\": \"TEAMID1234\",\n"
    "      \"signingIdentifier\": \"com.example.Other\"\n"
    "    }\n"
    "  },\n"
    "  \"allowProcesses\": {\n"
    "    \"Publisher\": \"/Applications/Publisher.app/Contents/MacOS/Publisher\"\n"
    "  }\n"
    "}\n");
  state = (FakePlatformState){ .team_id = "TEAMID1234", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(line, "Publisher", app_path, &multi_cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_publisher == TRUSTED_PUBLISHER_TEAM_ID_MISMATCH);
  assert(!strcmp(policy.matched_publisher, "Alpha Bad"));
  assert(state.identity_calls == 2);
  config_free(&multi_cfg);

  cfg.allow_apple_system_components = true;
  free(cfg.trusted_publishers.items[0].paths.items[0]);
  cfg.trusted_publishers.items[0].paths.items[0] = xstrdup("/usr/libexec/trusted_publisher_fixture");
  assert(cfg.trusted_publishers.items[0].paths.items[0]);
  free(cfg.allow_processes.items[0].paths.items[0]);
  cfg.allow_processes.items[0].paths.items[0] = xstrdup("/usr/libexec/trusted_publisher_fixture");
  assert(cfg.allow_processes.items[0].paths.items[0]);
  state = (FakePlatformState){ .team_id = "WRONGTEAM", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(
    "Publisher 125 user TCP 1->8.8.8.8:443 (ESTABLISHED)",
    "Publisher",
    "/usr/libexec/trusted_publisher_fixture",
    &cfg,
    &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_publisher == TRUSTED_PUBLISHER_TEAM_ID_MISMATCH);
  assert(state.apple_calls == 0);

  assert(strlist_push(&cfg.deny_patterns, "Publisher"));
  state = (FakePlatformState){ .team_id = "TEAMID1234", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  policy = connection_policy_for_path_with_platform(
    "Publisher 126 user TCP 1->2 (ESTABLISHED)",
    "Publisher",
    "/usr/libexec/trusted_publisher_fixture",
    &cfg,
    &platform);
  assert(policy.decision == CONNECTION_DENIED);
  assert(state.identity_calls == 0);

  config_free(&cfg);
}

static const char *available_apple_binary(void){
  static const char *paths[] = {
    "/usr/libexec/ciphermld",
    "/usr/libexec/remindd",
    "/usr/libexec/trustd",
    "/usr/libexec/cfprefsd",
    "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"
  };
  for (size_t i = 0; i < sizeof(paths) / sizeof(*paths); i++){
    if (access(paths[i], F_OK) == 0 && apple_trust_check(paths[i], NULL, 0) == APPLE_TRUST_OK) return paths[i];
  }
  return NULL;
}

static void test_apple_signature_policy(void){
  const char *path = available_apple_binary();
  if (!path){
    puts("SKIP: no optional Apple system binary found");
    return;
  }

  Config cfg = { .allow_apple_system_components = true };
  ConnectionPolicy policy = connection_policy_for_path("appleproc 1 user TCP 1->2 (ESTABLISHED)", "appleproc", path, &cfg);
  assert(policy.decision == CONNECTION_ALLOWED_APPLE_SYSTEM);
  assert(policy.apple_trust_checked);
  assert(policy.apple_trust == APPLE_TRUST_OK);

  assert(strlist_push(&cfg.deny_patterns, "appleproc"));
  assert(connection_policy_for_path("appleproc 1 user TCP 1->2 (ESTABLISHED)", "appleproc", path, &cfg).decision == CONNECTION_DENIED);
  config_free(&cfg);
}

static void test_temp_executable_rejected(void){
  char path[] = "/tmp/netwatch_unsigned_XXXXXX";
  int fd = mkstemp(path);
  assert(fd >= 0);
  FILE *f = fdopen(fd, "w");
  assert(f);
  assert(fputs("#!/bin/sh\nexit 0\n", f) >= 0);
  assert(fclose(f) == 0);
  assert(chmod(path, 0700) == 0);
  assert(apple_trust_check(path, NULL, 0) != APPLE_TRUST_OK);
  assert(unlink(path) == 0);
}

static void test_config_bool(void){
  char err[256] = {0};
  Config cfg = {0};
  char *path = write_config("{\"dryRun\":true}");
  assert(config_load(&cfg, path, err, sizeof(err)));
  assert(!cfg.allow_apple_system_components);
  config_free(&cfg);
  assert(unlink(path) == 0);
  free(path);

  path = write_config("{\"version\":2,\"dryRun\":true}");
  assert(config_load(&cfg, path, err, sizeof(err)));
  config_free(&cfg);
  assert(unlink(path) == 0);
  free(path);

  path = write_config("{\"version\":3,\"dryRun\":true}");
  assert(!config_load(&cfg, path, err, sizeof(err)));
  assert(strstr(err, "Unsupported config version: 3"));
  assert(strstr(err, "Supported version: 2"));
  assert(unlink(path) == 0);
  free(path);

  path = write_config("{\"version\":1,\"dryRun\":true}");
  assert(!config_load(&cfg, path, err, sizeof(err)));
  assert(strstr(err, "Unsupported config version: 1"));
  assert(strstr(err, "Supported version: 2"));
  assert(unlink(path) == 0);
  free(path);

  path = write_config("{\"version\":\"2\",\"dryRun\":true}");
  assert(!config_load(&cfg, path, err, sizeof(err)));
  assert(strstr(err, "version must be the number 2"));
  assert(unlink(path) == 0);
  free(path);

  path = write_config("{\"allowAppleSystemComponents\":true}");
  assert(config_load(&cfg, path, err, sizeof(err)));
  assert(cfg.allow_apple_system_components);
  config_free(&cfg);
  assert(unlink(path) == 0);
  free(path);

  path = write_config("{\"allowAppleSystemComponents\":\"yes\"}");
  assert(!config_load(&cfg, path, err, sizeof(err)));
  assert(strstr(err, "allowAppleSystemComponents must be boolean"));
  assert(unlink(path) == 0);
  free(path);
}

static void test_config_trusted_publishers(void){
  Config cfg = parse_config_ok("{\"version\":2,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n");
  assert(cfg.trusted_publishers.len == 0);
  config_free(&cfg);

  cfg = parse_config_ok(
    "{\n"
    "  \"version\": 2,\n"
    "  \"trustedPublishers\": {\n"
    "    \"Google Chrome\": {\n"
    "      \"paths\": [\"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\"],\n"
    "      \"teamId\": \"EQHXZ8M8AV\",\n"
    "      \"signingIdentifier\": \"com.google.Chrome\"\n"
    "    },\n"
    "    \"Docker Desktop\": {\n"
    "      \"paths\": [\"/Applications/Docker.app/Contents/MacOS/Docker Desktop\"],\n"
    "      \"teamId\": \"9BNSXJN65R\",\n"
    "      \"signingIdentifier\": \"com.docker.docker\",\n"
    "      \"requireValidSignature\": true\n"
    "    }\n"
    "  }\n"
    "}\n");
  assert(cfg.trusted_publishers.len == 2);
  assert(!strcmp(cfg.trusted_publishers.items[0].name, "Google Chrome"));
  assert(!strcmp(cfg.trusted_publishers.items[0].paths.items[0], "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"));
  assert(!strcmp(cfg.trusted_publishers.items[0].team_id, "EQHXZ8M8AV"));
  assert(!strcmp(cfg.trusted_publishers.items[0].signing_identifier, "com.google.Chrome"));
  assert(cfg.trusted_publishers.items[0].require_valid_signature);
  assert(!strcmp(cfg.trusted_publishers.items[1].name, "Docker Desktop"));
  config_free(&cfg);

  assert_config_error("{\"trustedPublishers\":{\"App\":{\"teamId\":\"T\",\"signingIdentifier\":\"id\"}}}\n", "trustedPublishers.App.paths expected non-empty array");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[],\"teamId\":\"T\",\"signingIdentifier\":\"id\"}}}\n", "trustedPublishers.App.paths expected non-empty array");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"\"],\"teamId\":\"T\",\"signingIdentifier\":\"id\"}}}\n", "trustedPublishers.App.paths[0] expected non-empty string");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"relative\"],\"teamId\":\"T\",\"signingIdentifier\":\"id\"}}}\n", "trustedPublishers.App.paths[0] expected absolute executable path");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"/Applications/App.app/*\"],\"teamId\":\"T\",\"signingIdentifier\":\"id\"}}}\n", "wildcard paths are not supported");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[123],\"teamId\":\"T\",\"signingIdentifier\":\"id\"}}}\n", "trustedPublishers.App.paths[0] expected non-empty string");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"/A\"],\"signingIdentifier\":\"id\"}}}\n", "trustedPublishers.App.teamId expected non-empty string");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"/A\"],\"teamId\":\"\",\"signingIdentifier\":\"id\"}}}\n", "trustedPublishers.App.teamId expected non-empty string");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"/A\"],\"teamId\":\"T\"}}}\n", "trustedPublishers.App.signingIdentifier expected non-empty string");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"/A\"],\"teamId\":\"T\",\"signingIdentifier\":\"\"}}}\n", "trustedPublishers.App.signingIdentifier expected non-empty string");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"/A\"],\"teamId\":\"T\",\"signingIdentifier\":\"id\",\"requireValidSignature\":\"yes\"}}}\n", "trustedPublishers.App.requireValidSignature must be boolean");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"/A\"],\"teamId\":\"T\",\"signingIdentifier\":\"id\",\"requireValidSignature\":false}}}\n", "false is not supported for trusted publisher rules");
  assert_config_error("{\"trustedPublishers\":{\"App\":{\"paths\":[\"/A\"],\"teamId\":\"T\",\"signingIdentifier\":\"id\",\"hash\":\"no\"}}}\n", "trustedPublishers.App.hash unsupported field");
  assert_config_error("{\"trustedPublishers\":[]}\n", "trustedPublishers must be an object");
}

static void test_config_trusted_workspaces(void){
  Config cfg = parse_config_ok("{\"version\":2,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n");
  assert(cfg.trusted_workspaces.len == 0);
  config_free(&cfg);

  cfg = parse_config_ok(
    "{\n"
    "  \"version\": 2,\n"
    "  \"trustedWorkspaces\": {\n"
    "    \"scripts\": {\n"
    "      \"roots\": [\"/Users/serg/project\"],\n"
    "      \"allowSubdirectories\": true,\n"
    "      \"interpreters\": [\"/usr/local/bin/node\"]\n"
    "    },\n"
    "    \"cwd-only\": {\n"
    "      \"roots\": [\"/Users/serg/one\"],\n"
    "      \"allowSubdirectories\": false,\n"
    "      \"interpreters\": [\"/bin/bash\"],\n"
    "      \"allowByCwdOnly\": true\n"
    "    }\n"
    "  }\n"
    "}\n");
  assert(cfg.trusted_workspaces.len == 2);
  assert(!strcmp(cfg.trusted_workspaces.items[0].name, "scripts"));
  assert(!strcmp(cfg.trusted_workspaces.items[0].roots.items[0], "/Users/serg/project"));
  assert(cfg.trusted_workspaces.items[0].allow_subdirectories);
  assert(!cfg.trusted_workspaces.items[0].allow_by_cwd_only);
  assert(!strcmp(cfg.trusted_workspaces.items[0].interpreters.items[0], "/usr/local/bin/node"));
  assert(cfg.trusted_workspaces.items[1].allow_by_cwd_only);
  config_free(&cfg);

  assert_config_error("{\"trustedWorkspaces\":[]}\n", "trustedWorkspaces must be an object");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"allowSubdirectories\":true,\"interpreters\":[\"/bin/node\"]}}}\n", "trustedWorkspaces.w.roots expected non-empty array");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[],\"allowSubdirectories\":true,\"interpreters\":[\"/bin/node\"]}}}\n", "trustedWorkspaces.w.roots expected non-empty array");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"\"],\"allowSubdirectories\":true,\"interpreters\":[\"/bin/node\"]}}}\n", "trustedWorkspaces.w.roots[0] expected non-empty string");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"relative\"],\"allowSubdirectories\":true,\"interpreters\":[\"/bin/node\"]}}}\n", "trustedWorkspaces.w.roots[0] expected absolute path");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"/tmp/*\"],\"allowSubdirectories\":true,\"interpreters\":[\"/bin/node\"]}}}\n", "wildcard paths are not supported");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"/tmp\"],\"allowSubdirectories\":true}}}\n", "trustedWorkspaces.w.interpreters expected non-empty array");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"/tmp\"],\"allowSubdirectories\":true,\"interpreters\":[]}}}\n", "trustedWorkspaces.w.interpreters expected non-empty array");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"/tmp\"],\"interpreters\":[\"/bin/node\"]}}}\n", "trustedWorkspaces.w.allowSubdirectories must be boolean");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"/tmp\"],\"allowSubdirectories\":\"yes\",\"interpreters\":[\"/bin/node\"]}}}\n", "trustedWorkspaces.w.allowSubdirectories must be boolean");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"/tmp\"],\"allowSubdirectories\":true,\"interpreters\":[\"node\"]}}}\n", "trustedWorkspaces.w.interpreters[0] expected absolute path");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"/tmp\"],\"allowSubdirectories\":true,\"interpreters\":[\"/bin/node\"],\"allowByCwdOnly\":\"yes\"}}}\n", "trustedWorkspaces.w.allowByCwdOnly must be boolean");
  assert_config_error("{\"trustedWorkspaces\":{\"w\":{\"roots\":[\"/tmp\"],\"allowSubdirectories\":true,\"interpreters\":[\"/bin/node\"],\"hash\":\"no\"}}}\n", "trustedWorkspaces.w.hash unsupported field");
}

static void test_config_daemon(void){
  Config cfg = parse_config_ok("{\"version\":2,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n");
  assert(cfg.daemon.poll_interval_seconds == 300);
  assert(cfg.daemon.reload_on_sighup);
  assert(!cfg.daemon.exit_on_config_error);
  config_free(&cfg);

  cfg = parse_config_ok(
    "{\n"
    "  \"version\": 2,\n"
    "  \"daemon\": {\n"
    "    \"pollIntervalSeconds\": 5,\n"
    "    \"reloadOnSighup\": false,\n"
    "    \"exitOnConfigError\": true\n"
    "  },\n"
    "  \"allowProcesses\": {},\n"
    "  \"allowRemoteHosts\": []\n"
    "}\n");
  assert(cfg.daemon.poll_interval_seconds == 5);
  assert(!cfg.daemon.reload_on_sighup);
  assert(cfg.daemon.exit_on_config_error);
  config_free(&cfg);

  assert_config_error("{\"daemon\":[]}\n", "daemon must be an object");
  assert_config_error("{\"daemon\":{\"pollIntervalSeconds\":0}}\n", "daemon.pollIntervalSeconds must be a positive integer");
  assert_config_error("{\"daemon\":{\"pollIntervalSeconds\":-1}}\n", "daemon.pollIntervalSeconds must be a positive integer");
  assert_config_error("{\"daemon\":{\"pollIntervalSeconds\":1.5}}\n", "daemon.pollIntervalSeconds must be a positive integer");
  assert_config_error("{\"daemon\":{\"pollIntervalSeconds\":\"30\"}}\n", "daemon.pollIntervalSeconds must be a positive integer");
  assert_config_error("{\"daemon\":{\"reloadOnSighup\":\"yes\"}}\n", "daemon.reloadOnSighup must be boolean");
  assert_config_error("{\"daemon\":{\"exitOnConfigError\":\"no\"}}\n", "daemon.exitOnConfigError must be boolean");
  assert_config_error("{\"daemon\":{\"lockPath\":\"/tmp/x\"}}\n", "daemon.lockPath unsupported field");
}

static Config parse_workspace_config(const char *root, const char *interpreter, int allow_subdirs, int allow_by_cwd_only, int add_path_allow, int add_apple){
  char text[8192];
  snprintf(text, sizeof(text),
    "{\n"
    "  \"version\": 2,\n"
    "  \"allowAppleSystemComponents\": %s,\n"
    "  \"trustedWorkspaces\": {\n"
    "    \"scripts\": {\n"
    "      \"roots\": [\"%s\"],\n"
    "      \"allowSubdirectories\": %s,\n"
    "      \"interpreters\": [\"%s\"]%s%s\n"
    "    }\n"
    "  },\n"
    "  \"allowProcesses\": %s,\n"
    "  \"allowRemoteHosts\": []\n"
    "}\n",
    add_apple ? "true" : "false",
    root,
    allow_subdirs ? "true" : "false",
    interpreter,
    allow_by_cwd_only ? ",\n      \"allowByCwdOnly\": " : "",
    allow_by_cwd_only ? "true" : "",
    add_path_allow ? "{\"node\":\"/tmp/netwatch_placeholder\"}" : "{}");
  Config cfg = parse_config_ok(text);
  if (add_path_allow){
    free(cfg.allow_processes.items[0].paths.items[0]);
    cfg.allow_processes.items[0].paths.items[0] = xstrdup(interpreter);
    assert(cfg.allow_processes.items[0].paths.items[0]);
  }
  return cfg;
}

static void test_trusted_workspace_policy(void){
  char *dir = temp_dir();
  char *root = join_path_dup(dir, "root");
  char *sub = join_path_dup(root, "sub");
  char *outside_dir = join_path_dup(dir, "outside");
  mkdir_ok(root); mkdir_ok(sub); mkdir_ok(outside_dir);
  char *interpreter = join_path_dup(dir, "node");
  char *other_interpreter = join_path_dup(dir, "python");
  char *script = join_path_dup(root, "job.js");
  char *sub_script = join_path_dup(sub, "subjob.js");
  char *outside_script = join_path_dup(outside_dir, "evil.js");
  char *escape = join_path_dup(root, "escape.js");
  write_text_mode(interpreter, "#!/bin/sh\n", 0700);
  write_text_mode(other_interpreter, "#!/bin/sh\n", 0700);
  write_text_mode(script, "x", 0600);
  write_text_mode(sub_script, "x", 0600);
  write_text_mode(outside_script, "x", 0600);
  assert(symlink(outside_script, escape) == 0);

  Config cfg = parse_workspace_config(root, interpreter, 1, 0, 1, 1);
  const char *argv_ok[] = { interpreter, script };
  FakePlatformState state = { .process_cwd = root, .process_argv = argv_ok, .process_argv_count = 2 };
  NetwatchPlatform platform = fake_platform(&state);
  ConnectionPolicy policy = connection_policy_for_pid_path_with_platform(
    "node 42 user TCP 1->2 (ESTABLISHED)", "node", interpreter, 42, &cfg, &platform);
  assert(policy.decision == CONNECTION_ALLOWED_TRUSTED_WORKSPACE);
  assert(policy.trusted_workspace == TRUSTED_WORKSPACE_OK);
  assert(!strcmp(policy.matched_workspace, "scripts"));

  const char *argv_sub[] = { interpreter, "subjob.js" };
  state = (FakePlatformState){ .process_cwd = sub, .process_argv = argv_sub, .process_argv_count = 2 };
  platform = fake_platform(&state);
  policy = connection_policy_for_pid_path_with_platform("node 43 user TCP 1->2 (ESTABLISHED)", "node", interpreter, 43, &cfg, &platform);
  assert(policy.decision == CONNECTION_ALLOWED_TRUSTED_WORKSPACE);

  const char *argv_outside[] = { interpreter, outside_script };
  state = (FakePlatformState){ .process_cwd = root, .process_argv = argv_outside, .process_argv_count = 2 };
  platform = fake_platform(&state);
  policy = connection_policy_for_pid_path_with_platform("node 44 user TCP 1->2 (ESTABLISHED)", "node", interpreter, 44, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_workspace == TRUSTED_WORKSPACE_SCRIPT_OUTSIDE_ROOT);
  assert(!policy.matched_process);
  assert(state.apple_calls == 0);

  const char *argv_escape[] = { interpreter, escape };
  state = (FakePlatformState){ .process_cwd = root, .process_argv = argv_escape, .process_argv_count = 2 };
  platform = fake_platform(&state);
  policy = connection_policy_for_pid_path_with_platform("node 45 user TCP 1->2 (ESTABLISHED)", "node", interpreter, 45, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_workspace == TRUSTED_WORKSPACE_SCRIPT_OUTSIDE_ROOT);

  state = (FakePlatformState){ .process_path = interpreter, .process_cwd = root, .process_argv = argv_ok, .process_argv_count = 2 };
  platform = fake_platform(&state);
  policy = connection_policy_for_pid_path_with_platform("python 46 user TCP 1->2 (ESTABLISHED)", "python", other_interpreter, 46, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(!policy.trusted_workspace_checked);
  config_free(&cfg);

  cfg = parse_workspace_config(root, interpreter, 0, 0, 0, 0);
  state = (FakePlatformState){ .process_path = interpreter, .process_cwd = root, .process_argv = argv_ok, .process_argv_count = 2 };
  platform = fake_platform(&state);
  policy = connection_policy_for_pid_path_with_platform("node 47 user TCP 1->2 (ESTABLISHED)", "node", interpreter, 47, &cfg, &platform);
  assert(policy.decision == CONNECTION_ALLOWED_TRUSTED_WORKSPACE);
  state = (FakePlatformState){ .process_cwd = sub, .process_argv = argv_sub, .process_argv_count = 2 };
  platform = fake_platform(&state);
  policy = connection_policy_for_pid_path_with_platform("node 48 user TCP 1->2 (ESTABLISHED)", "node", interpreter, 48, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_workspace == TRUSTED_WORKSPACE_CWD_OUTSIDE_ROOT);
  config_free(&cfg);

  cfg = parse_workspace_config(root, interpreter, 1, 0, 0, 0);
  const char *argv_no_script[] = { interpreter };
  state = (FakePlatformState){ .process_cwd = root, .process_argv = argv_no_script, .process_argv_count = 1 };
  platform = fake_platform(&state);
  policy = connection_policy_for_pid_path_with_platform("node 49 user TCP 1->2 (ESTABLISHED)", "node", interpreter, 49, &cfg, &platform);
  assert(policy.decision == CONNECTION_UNKNOWN);
  assert(policy.trusted_workspace == TRUSTED_WORKSPACE_SCRIPT_UNAVAILABLE);
  config_free(&cfg);

  cfg = parse_workspace_config(root, interpreter, 1, 1, 0, 0);
  state = (FakePlatformState){ .process_cwd = root, .process_argv = argv_no_script, .process_argv_count = 1 };
  platform = fake_platform(&state);
  policy = connection_policy_for_pid_path_with_platform("node 50 user TCP 1->2 (ESTABLISHED)", "node", interpreter, 50, &cfg, &platform);
  assert(policy.decision == CONNECTION_ALLOWED_TRUSTED_WORKSPACE);
  config_free(&cfg);

  cfg = parse_workspace_config(root, interpreter, 1, 0, 0, 0);
  assert(strlist_push(&cfg.deny_patterns, "node"));
  state = (FakePlatformState){ .process_path = interpreter, .process_cwd = root, .process_argv = argv_ok, .process_argv_count = 2 };
  platform = fake_platform(&state);
  policy = connection_policy_for_pid_path_with_platform("node 51 user TCP 1->2 (ESTABLISHED)", "node", interpreter, 51, &cfg, &platform);
  assert(policy.decision == CONNECTION_DENIED);
  assert(state.process_cwd_calls == 0);

  Capture cap = capture_why_platform(&cfg, "51", &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: DENIED");
  capture_free(&cap);
  config_free(&cfg);

  cfg = parse_workspace_config(root, interpreter, 1, 0, 0, 0);
  state = (FakePlatformState){ .process_path = interpreter, .process_cwd = root, .process_argv = argv_ok, .process_argv_count = 2 };
  platform = fake_platform(&state);
  cap = capture_why_platform(&cfg, "52", &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: ALLOWED");
  assert_contains(cap.out, "Trust source: TRUSTED_WORKSPACE");
  assert_contains(cap.out, "interpreter matched trustedWorkspaces.scripts");
  assert_contains(cap.out, "cwd is inside trusted workspace root");
  assert_contains(cap.out, "script path is inside trusted workspace root");
  capture_free(&cap);

  state = (FakePlatformState){ .process_path = interpreter, .process_cwd = root, .process_argv = argv_outside, .process_argv_count = 2 };
  platform = fake_platform(&state);
  cap = capture_why_platform(&cfg, "53", &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: UNKNOWN");
  assert_contains(cap.out, "script path is outside trusted workspace root");
  capture_free(&cap);
  config_free(&cfg);

  unlink(escape); unlink(interpreter); unlink(other_interpreter); unlink(script); unlink(sub_script); unlink(outside_script);
  rmdir(sub); rmdir(root); rmdir(outside_dir); rmdir(dir);
  free(root); free(sub); free(outside_dir); free(interpreter); free(other_interpreter);
  free(script); free(sub_script); free(outside_script); free(escape); free(dir);
}

static void test_config_conversion(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "config.json");
  char *trusted_string = join_path_dup(dir, "trusted_string");
  char *trusted_array = join_path_dup(dir, "trusted_array");
  char *trusted_all = join_path_dup(dir, "trusted_all");
  char *third = join_path_dup(dir, "third_party");
  char *rejected = join_path_dup(dir, "rejected_path");
  write_text_mode(trusted_string, "x", 0700);
  write_text_mode(trusted_array, "x", 0700);
  write_text_mode(trusted_all, "x", 0700);
  write_text_mode(third, "x", 0700);
  write_text_mode(rejected, "x", 0700);

  char original[4096];
  snprintf(original, sizeof(original),
    "{\n"
    "  \"dryRun\": true,\n"
    "  \"daemon\": {\n"
    "    \"pollIntervalSeconds\": 10,\n"
    "    \"reloadOnSighup\": true,\n"
    "    \"exitOnConfigError\": false\n"
    "  },\n"
    "  \"futureFlag\": true,\n"
    "  \"trustedPublishers\": {\n"
    "    \"Manual Trusted\": {\n"
    "      \"paths\": [\"/Applications/Manual Trusted.app/Contents/MacOS/Manual Trusted\"],\n"
    "      \"teamId\": \"TEAMID1234\",\n"
    "      \"signingIdentifier\": \"com.example.ManualTrusted\"\n"
    "    }\n"
    "  },\n"
    "  \"trustedWorkspaces\": {\n"
    "    \"Manual Workspace\": {\n"
    "      \"roots\": [\"%s\"],\n"
    "      \"allowSubdirectories\": true,\n"
    "      \"interpreters\": [\"%s\"],\n"
    "      \"allowByCwdOnly\": false\n"
    "    }\n"
    "  },\n"
    "  \"denyPatterns\": [\"deny-me\"],\n"
    "  \"allowProcesses\": {\n"
    "    \"trustedString\": \"%s\",\n"
    "    \"third\": \"%s\",\n"
    "    \"wildApple\": \"/usr/libexec/*\",\n"
    "    \"missingApple\": \"/usr/libexec/netwatch_missing_test_binary\",\n"
    "    \"rejected\": \"%s\",\n"
    "    \"mixed\": [\n"
    "      \"%s\",\n"
    "      \"%s\",\n"
    "      \"/System/Library/*\"\n"
    "    ],\n"
    "    \"allApple\": [\"%s\"]\n"
    "  },\n"
    "  \"allowRemoteHosts\": []\n"
    "}\n",
    dir, third, trusted_string, third, rejected, trusted_array, third, trusted_all);
  write_text_mode(config, original, 0640);

  Capture cap = capture_convert(config);
  assert(cap.rc == 0);
  char *converted = must_read(config);
  char *backup = join_path_dup(dir, "config.json.bak");
  char *backup_text = must_read(backup);
  struct stat st;
  assert(stat(config, &st) == 0);
  assert((st.st_mode & 0777) == 0640);
  assert(!strcmp(backup_text, original));

  assert_contains(converted, "\"allowAppleSystemComponents\": true");
  assert_contains(converted, "\"version\": 2");
  assert_contains(converted, "\"daemon\"");
  assert_contains(converted, "\"pollIntervalSeconds\": 10");
  assert_contains(converted, "\"futureFlag\": true");
  assert_contains(converted, "\"trustedPublishers\"");
  assert_contains(converted, "\"Manual Trusted\"");
  assert_contains(converted, "\"TEAMID1234\"");
  assert_contains(converted, "\"com.example.ManualTrusted\"");
  assert_contains(converted, "\"trustedWorkspaces\"");
  assert_contains(converted, "\"Manual Workspace\"");
  assert_contains(converted, "\"allowByCwdOnly\": false");
  assert_contains(converted, third);
  assert_contains(converted, "/usr/libexec/*");
  assert_contains(converted, "/usr/libexec/netwatch_missing_test_binary");
  assert_contains(converted, rejected);
  assert_not_contains(converted, trusted_string);
  assert_not_contains(converted, trusted_array);
  assert_not_contains(converted, trusted_all);
  assert_not_contains(converted, "\"trustedString\"");
  assert_not_contains(converted, "\"allApple\"");

  assert_contains(cap.out, "--- ");
  assert_contains(cap.out, "+++ ");
  assert_contains(cap.out, "+  \"version\": 2");
  assert_contains(cap.out, "+  \"allowAppleSystemComponents\": true");
  assert_contains(cap.out, "-    \"trustedString\":");
  assert_contains(cap.out, "Config converted successfully.");
  assert_contains(cap.out, "Removed trusted Apple entries: 3");

  capture_free(&cap);
  free(converted); free(backup_text);

  cap = capture_convert(config);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Config is already up to date.");
  char *backup2 = join_path_dup(dir, "config.json.bak.1");
  assert(access(backup2, F_OK) != 0);
  capture_free(&cap);

  unlink(config); unlink(backup); unlink(trusted_string); unlink(trusted_array);
  unlink(trusted_all); unlink(third); unlink(rejected); rmdir(dir);
  free(config); free(backup); free(backup2); free(trusted_string); free(trusted_array);
  free(trusted_all); free(third); free(rejected); free(dir);
}

static void test_backup_suffix(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "config.json");
  char *backup = join_path_dup(dir, "config.json.bak");
  char *backup1 = join_path_dup(dir, "config.json.bak.1");
  const char *original = "{\"dryRun\":true,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n";
  write_text_mode(config, original, 0600);
  write_text_mode(backup, "existing backup\n", 0600);

  Capture cap = capture_convert(config);
  assert(cap.rc == 0);
  char *backup_text = must_read(backup);
  char *backup1_text = must_read(backup1);
  assert(!strcmp(backup_text, "existing backup\n"));
  assert(!strcmp(backup1_text, original));
  capture_free(&cap);

  unlink(config); unlink(backup); unlink(backup1); rmdir(dir);
  free(config); free(backup); free(backup1); free(backup_text); free(backup1_text); free(dir);
}

static void test_deterministic_json_formatting(void){
  char *dir = temp_dir();
  char *config_a = join_path_dup(dir, "a.json");
  char *config_b = join_path_dup(dir, "b.json");
  const char *a =
    "{\n"
    "  \"zUnknown\": {\"beta\": false, \"alpha\": true},\n"
    "  \"dryRun\": true,\n"
    "  \"daemon\": {\"reloadOnSighup\": true, \"pollIntervalSeconds\": 11, \"exitOnConfigError\": false},\n"
    "  \"trustedPublishers\": {\n"
    "    \"BetaPub\": {\"teamId\": \"BTEAM\", \"signingIdentifier\": \"com.beta\", \"paths\": [\"/Applications/Beta.app/Contents/MacOS/Beta\"]},\n"
    "    \"AlphaPub\": {\"signingIdentifier\": \"com.alpha\", \"paths\": [\"/Applications/Alpha.app/Contents/MacOS/Alpha\"], \"teamId\": \"ATEAM\"}\n"
    "  },\n"
    "  \"trustedWorkspaces\": {\n"
    "    \"BetaWs\": {\"interpreters\": [\"/usr/local/bin/node\"], \"roots\": [\"/Users/serg/beta\"], \"allowSubdirectories\": true},\n"
    "    \"AlphaWs\": {\"allowSubdirectories\": false, \"roots\": [\"/Users/serg/alpha\"], \"interpreters\": [\"/usr/bin/python3\"]}\n"
    "  },\n"
    "  \"allowProcesses\": {\n"
    "    \"Beta\": \"/Applications/Beta.app/Contents/*\",\n"
    "    \"Alpha\": [\"array-second\", \"array-first\"]\n"
    "  },\n"
    "  \"allowRemoteHosts\": [\"2\", \"1\"],\n"
    "  \"denyPatterns\": [\"deny-b\", \"deny-a\"]\n"
    "}\n";
  const char *b =
    "{\n"
    "  \"allowRemoteHosts\": [\"2\", \"1\"],\n"
    "  \"allowProcesses\": {\n"
    "    \"Alpha\": [\"array-second\", \"array-first\"],\n"
    "    \"Beta\": \"/Applications/Beta.app/Contents/*\"\n"
    "  },\n"
    "  \"denyPatterns\": [\"deny-b\", \"deny-a\"],\n"
    "  \"daemon\": {\"exitOnConfigError\": false, \"pollIntervalSeconds\": 11, \"reloadOnSighup\": true},\n"
    "  \"dryRun\": true,\n"
    "  \"trustedPublishers\": {\n"
    "    \"AlphaPub\": {\"teamId\": \"ATEAM\", \"paths\": [\"/Applications/Alpha.app/Contents/MacOS/Alpha\"], \"signingIdentifier\": \"com.alpha\"},\n"
    "    \"BetaPub\": {\"paths\": [\"/Applications/Beta.app/Contents/MacOS/Beta\"], \"signingIdentifier\": \"com.beta\", \"teamId\": \"BTEAM\"}\n"
    "  },\n"
    "  \"trustedWorkspaces\": {\n"
    "    \"AlphaWs\": {\"interpreters\": [\"/usr/bin/python3\"], \"allowSubdirectories\": false, \"roots\": [\"/Users/serg/alpha\"]},\n"
    "    \"BetaWs\": {\"allowSubdirectories\": true, \"roots\": [\"/Users/serg/beta\"], \"interpreters\": [\"/usr/local/bin/node\"]}\n"
    "  },\n"
    "  \"zUnknown\": {\"alpha\": true, \"beta\": false}\n"
    "}\n";
  write_text_mode(config_a, a, 0600);
  write_text_mode(config_b, b, 0600);

  Capture cap = capture_convert(config_a);
  assert(cap.rc == 0);
  capture_free(&cap);
  cap = capture_convert(config_b);
  assert(cap.rc == 0);
  capture_free(&cap);

  char *out_a = must_read(config_a);
  char *out_b = must_read(config_b);
  assert(!strcmp(out_a, out_b));
  assert(out_a[strlen(out_a) - 1] == '\n');
  assert_contains(out_a, "\"zUnknown\"");
  assert_before(out_a, "\"version\"", "\"dryRun\"");
  assert_before(out_a, "\"dryRun\"", "\"daemon\"");
  assert_before(out_a, "\"daemon\"", "\"allowAppleSystemComponents\"");
  assert_before(out_a, "\"allowAppleSystemComponents\"", "\"trustedPublishers\"");
  assert_before(out_a, "\"trustedPublishers\"", "\"trustedWorkspaces\"");
  assert_before(out_a, "\"trustedWorkspaces\"", "\"denyPatterns\"");
  assert_before(out_a, "\"Alpha\"", "\"Beta\"");
  assert_before(out_a, "\"AlphaPub\"", "\"BetaPub\"");
  assert_before(out_a, "\"AlphaWs\"", "\"BetaWs\"");
  assert_before(out_a, "\"alpha\"", "\"beta\"");
  assert_before(out_a, "\"array-second\"", "\"array-first\"");
  assert_before(out_a, "\"2\"", "\"1\"");

  char err[256] = {0};
  Config cfg = {0};
  assert(config_load(&cfg, config_a, err, sizeof(err)));
  config_free(&cfg);

  cap = capture_convert(config_a);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Config is already up to date.");
  char *backup2 = join_path_dup(dir, "a.json.bak.1");
  assert(access(backup2, F_OK) != 0);
  capture_free(&cap);

  char *backup_a = join_path_dup(dir, "a.json.bak");
  char *backup_b = join_path_dup(dir, "b.json.bak");
  unlink(config_a); unlink(config_b); unlink(backup_a); unlink(backup_b);
  free(out_a); free(out_b); free(backup2); free(backup_a); free(backup_b);
  rmdir(dir); free(config_a); free(config_b); free(dir);
}

static void test_invalid_and_failed_backup(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "config.json");
  write_text_mode(config, "{", 0600);
  Capture cap = capture_convert(config);
  assert(cap.rc != 0);
  char *text = must_read(config);
  assert(!strcmp(text, "{"));
  free(text); capture_free(&cap);

  const char *original = "{\"dryRun\":true,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n";
  write_text_mode(config, original, 0600);
  char *bak[4] = {
    join_path_dup(dir, "config.json.bak"),
    join_path_dup(dir, "config.json.bak.1"),
    join_path_dup(dir, "config.json.bak.2"),
    join_path_dup(dir, "config.json.bak.3")
  };
  for (size_t i = 0; i < 4; i++) write_text_mode(bak[i], "blocked\n", 0600);
  cap = capture_convert(config);
  assert(cap.rc != 0);
  text = must_read(config);
  assert(!strcmp(text, original));
  assert_not_contains(text, "allowAppleSystemComponents");
  free(text); capture_free(&cap);

  unlink(config);
  for (size_t i = 0; i < 4; i++){ unlink(bak[i]); free(bak[i]); }
  rmdir(dir); free(config); free(dir);
}

static void test_cli_convert_mode(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "config.json");
  char *out = join_path_dup(dir, "out.txt");
  char *marker = join_path_dup(dir, "lsof-marker");
  char *lsof = join_path_dup(dir, "lsof");
  char script[1024];
  snprintf(script, sizeof(script), "#!/bin/sh\necho called > %s\nexit 0\n", marker);
  write_text_mode(lsof, script, 0755);
  write_text_mode(config, "{\"dryRun\":true,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n", 0600);

  const char *old_path = getenv("PATH");
  char path_env[4096];
  snprintf(path_env, sizeof(path_env), "%s:%s", dir, old_path ? old_path : "");
  assert(run_netwatch(config, NULL, path_env, out) == 0);
  assert(access(marker, F_OK) != 0);
  char *converted = must_read(config);
  assert_contains(converted, "\"allowAppleSystemComponents\": true");
  assert_contains(converted, "\"version\": 2");
  free(converted);

  assert(run_netwatch(NULL, NULL, path_env, out) != 0);
  assert(run_netwatch(config, "extra.json", path_env, out) != 0);

  unlink(config); unlink(out); unlink(lsof); unlink(marker);
  char *backup = join_path_dup(dir, "config.json.bak");
  unlink(backup); free(backup);
  rmdir(dir);
  free(config); free(out); free(marker); free(lsof); free(dir);
}

static void test_check_config(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "config.json");
  char *out = join_path_dup(dir, "out.txt");
  char *marker = join_path_dup(dir, "lsof-marker");
  char *lsof = join_path_dup(dir, "lsof");
  char script[1024];
  snprintf(script, sizeof(script), "#!/bin/sh\necho called > %s\nexit 0\n", marker);
  write_text_mode(lsof, script, 0755);

  write_text_mode(config, "{\"version\":2,\"dryRun\":true,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n", 0600);
  Capture cap = capture_check(config);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Config OK.");
  capture_free(&cap);

  const char *warning_config =
    "{\n"
    "  \"version\": 2,\n"
    "  \"allowAppleSystemComponents\": true,\n"
    "  \"denyPatterns\": [\"deny\", \"deny\", \"shadow\"],\n"
    "  \"allowProcesses\": {\n"
    "    \"shadowProc\": \"/tmp/netwatch_missing_exact\",\n"
    "    \"shadowProc\": \"/tmp/netwatch_missing_exact\",\n"
    "    \"BadWildcard\": \"/Applications/Foo*bad\",\n"
    "    \"Relative\": [\"relative/path\", \"relative/path\"],\n"
    "    \"AppleMissing\": \"/usr/libexec/netwatch_rejected_check_binary\"\n"
    "  },\n"
    "  \"allowRemoteHosts\": []\n"
    "}\n";
  write_text_mode(config, warning_config, 0600);
  cap = capture_check(config);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Config valid with warnings:");
  assert_contains(cap.out, "duplicate deny pattern: deny");
  assert_contains(cap.out, "duplicate process entry: shadowProc");
  assert_contains(cap.out, "invalid wildcard usage");
  assert_contains(cap.out, "expected absolute executable path: relative/path");
  assert_contains(cap.out, "executable does not currently exist");
  assert_contains(cap.out, "Apple trust verification did not pass");
  assert_contains(cap.out, "shadowed by deny pattern: shadow");
  capture_free(&cap);

  write_text_mode(config,
    "{\"version\":2,\"trustedWorkspaces\":{\"Missing Workspace\":{\"roots\":[\"/tmp/netwatch_missing_workspace_root\"],\"allowSubdirectories\":true,\"interpreters\":[\"/tmp/netwatch_missing_workspace_node\"]}},\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    0600);
  cap = capture_check(config);
  assert(cap.rc == 0);
  assert_contains(cap.out, "workspace root does not currently exist");
  assert_contains(cap.out, "interpreter does not currently exist");
  capture_free(&cap);

  char *publisher_exe = join_path_dup(dir, "publisher");
  write_text_mode(publisher_exe, "x", 0700);
  char publisher_config[2048];
  snprintf(publisher_config, sizeof(publisher_config),
    "{\"version\":2,\"trustedPublishers\":{\"Publisher App\":{\"paths\":[\"%s\"],\"teamId\":\"TEAMID1234\",\"signingIdentifier\":\"com.example.App\"}},\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    publisher_exe);
  write_text_mode(config, publisher_config, 0600);
  FakePlatformState state = { .team_id = "TEAMID1234", .signing_identifier = "com.example.App" };
  NetwatchPlatform platform = fake_platform(&state);
  cap = capture_check_platform(config, &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Config OK.");
  capture_free(&cap);

  state = (FakePlatformState){ .team_id = "BADTEAM", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  cap = capture_check_platform(config, &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "current executable Team ID does not match configured Team ID");
  capture_free(&cap);

  state = (FakePlatformState){ .team_id = "TEAMID1234", .signing_identifier = "com.example.Other" };
  platform = fake_platform(&state);
  cap = capture_check_platform(config, &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "current executable signing identifier does not match configured signing identifier");
  capture_free(&cap);

  state = (FakePlatformState){ .identity_result = CODE_SIGNATURE_IDENTITY_INVALID_SIGNATURE };
  platform = fake_platform(&state);
  cap = capture_check_platform(config, &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "current executable signature is invalid");
  capture_free(&cap);

  snprintf(publisher_config, sizeof(publisher_config),
    "{\"version\":2,\"trustedPublishers\":{\"Publisher A\":{\"paths\":[\"%s\"],\"teamId\":\"TEAMID1234\",\"signingIdentifier\":\"com.example.App\"},\"Publisher B\":{\"paths\":[\"%s\"],\"teamId\":\"TEAMID1234\",\"signingIdentifier\":\"com.example.App\"}},\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    publisher_exe, publisher_exe);
  write_text_mode(config, publisher_config, 0600);
  state = (FakePlatformState){ .team_id = "TEAMID1234", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  cap = capture_check_platform(config, &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "duplicate trusted publisher path");
  assert_contains(cap.out, "trustedPublishers.Publisher A.paths[0]");
  capture_free(&cap);

  write_text_mode(config,
    "{\"version\":2,\"trustedPublishers\":{\"Missing App\":{\"paths\":[\"/tmp/netwatch_missing_publisher_binary\"],\"teamId\":\"TEAMID1234\",\"signingIdentifier\":\"com.example.App\"}},\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    0600);
  cap = capture_check(config);
  assert(cap.rc == 0);
  assert_contains(cap.out, "trustedPublishers.Missing App.paths[0]");
  assert_contains(cap.out, "executable does not currently exist");
  capture_free(&cap);

  write_text_mode(config, "{\"version\":2,\"allowProcesses\":{\"Bad\":123}}\n", 0600);
  cap = capture_check(config);
  assert(cap.rc != 0);
  assert_contains(cap.out, "Config invalid:");
  assert_contains(cap.out, "allowProcesses.Bad must be string or array of strings");
  capture_free(&cap);

  write_text_mode(config, "{\"version\":2,\"trustedPublishers\":{\"App\":{\"paths\":[\"/A\"],\"teamId\":\"T\",\"signingIdentifier\":\"id\",\"requireValidSignature\":false}}}\n", 0600);
  cap = capture_check(config);
  assert(cap.rc != 0);
  assert_contains(cap.out, "false is not supported for trusted publisher rules");
  capture_free(&cap);

  write_text_mode(config, "{\"version\":3,\"dryRun\":true}\n", 0600);
  cap = capture_check(config);
  assert(cap.rc != 0);
  assert_contains(cap.out, "Unsupported config version: 3");
  assert_contains(cap.out, "Supported version: 2");
  capture_free(&cap);

  write_text_mode(config, "{\"version\":2,\"dryRun\":true,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n", 0600);
  const char *old_path = getenv("PATH");
  char path_env[4096];
  snprintf(path_env, sizeof(path_env), "%s:%s", dir, old_path ? old_path : "");
  assert(run_netwatch_mode("--check-config", config, NULL, path_env, out) == 0);
  assert(access(marker, F_OK) != 0);
  char *cli_out = must_read(out);
  assert_contains(cli_out, "Config OK.");
  free(cli_out);

  assert(run_netwatch_mode("--check-config", NULL, NULL, path_env, out) != 0);
  assert(run_netwatch_mode("--check-config", config, "extra.json", path_env, out) != 0);

  unlink(config); unlink(out); unlink(lsof); unlink(marker); unlink(publisher_exe);
  rmdir(dir);
  free(config); free(out); free(marker); free(lsof); free(publisher_exe); free(dir);
}

static void test_why_command(void){
  Config cfg = {0};
  assert(strlist_push(&cfg.deny_patterns, "blocked"));
  Capture cap = capture_why(&cfg, "/tmp/blocked");
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: DENIED");
  assert_contains(cap.out, "matched deny rule: blocked");
  capture_free(&cap);
  config_free(&cfg);

  add_rule(&cfg, "AllowedProc", "/Applications/Allowed.app/Contents/*");
  cap = capture_why(&cfg, "/Applications/Allowed.app/Contents/MacOS/Allowed");
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: ALLOWED");
  assert_contains(cap.out, "matched allowProcesses.AllowedProc");
  assert_contains(cap.out, "matched path: /Applications/Allowed.app/Contents/*");
  capture_free(&cap);
  config_free(&cfg);

  cfg = (Config){ .allow_apple_system_components = true };
  cap = capture_why(&cfg, "/usr/libexec/trusted_why_fixture");
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: APPLE_SYSTEM");
  assert_contains(cap.out, "approved Apple system root");
  assert_contains(cap.out, "Apple signature valid");
  capture_free(&cap);
  config_free(&cfg);

  cfg = (Config){0};
  cap = capture_why(&cfg, "/tmp/unknown");
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: UNKNOWN");
  assert_contains(cap.out, "no deny rule matched");
  assert_contains(cap.out, "no allow rule matched");
  assert_contains(cap.out, "not an automatically trusted Apple system component");
  capture_free(&cap);
  config_free(&cfg);

  cfg = (Config){ .allow_apple_system_components = true };
  assert(strlist_push(&cfg.deny_patterns, "AllowedProc"));
  add_rule(&cfg, "AllowedProc", "/usr/libexec/trusted_why_fixture");
  cap = capture_why(&cfg, "/usr/libexec/trusted_why_fixture");
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: DENIED");
  assert_contains(cap.out, "matched deny rule: AllowedProc");
  capture_free(&cap);
  config_free(&cfg);

  cfg = (Config){ .allow_apple_system_components = true };
  add_rule(&cfg, "AppleAllowed", "/usr/libexec/trusted_why_fixture");
  cap = capture_why(&cfg, "/usr/libexec/trusted_why_fixture");
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: ALLOWED");
  assert_contains(cap.out, "matched allowProcesses.AppleAllowed");
  capture_free(&cap);
  config_free(&cfg);

  cfg = parse_config_ok(
    "{\"version\":2,\"trustedPublishers\":{\"Publisher App\":{\"paths\":[\"/Applications/Publisher.app/Contents/MacOS/Publisher\"],\"teamId\":\"TEAMID1234\",\"signingIdentifier\":\"com.example.App\"}},\"allowProcesses\":{\"Publisher\":\"/Applications/Publisher.app/Contents/MacOS/Publisher\"}}\n");
  FakePlatformState state = { .team_id = "TEAMID1234", .signing_identifier = "com.example.App" };
  NetwatchPlatform platform = fake_platform(&state);
  cap = capture_why_platform(&cfg, "/Applications/Publisher.app/Contents/MacOS/Publisher", &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: ALLOWED");
  assert_contains(cap.out, "Trust source: TRUSTED_PUBLISHER");
  assert_contains(cap.out, "executable path matched trustedPublishers.Publisher App");
  assert_contains(cap.out, "code signature valid");
  assert_contains(cap.out, "Team ID matched");
  assert_contains(cap.out, "signing identifier matched");
  capture_free(&cap);

  state = (FakePlatformState){ .team_id = "BADTEAM", .signing_identifier = "com.example.App" };
  platform = fake_platform(&state);
  cap = capture_why_platform(&cfg, "/Applications/Publisher.app/Contents/MacOS/Publisher", &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: UNKNOWN");
  assert_contains(cap.out, "Trust source: NONE");
  assert_contains(cap.out, "Team ID mismatch");
  assert_contains(cap.out, "Expected Team ID:");
  assert_contains(cap.out, "TEAMID1234");
  assert_contains(cap.out, "Actual Team ID:");
  assert_contains(cap.out, "BADTEAM");
  assert_not_contains(cap.out, "matched allowProcesses.Publisher");
  capture_free(&cap);

  state = (FakePlatformState){ .team_id = "TEAMID1234", .signing_identifier = "com.example.Other" };
  platform = fake_platform(&state);
  cap = capture_why_platform(&cfg, "/Applications/Publisher.app/Contents/MacOS/Publisher", &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: UNKNOWN");
  assert_contains(cap.out, "signing identifier mismatch");
  assert_contains(cap.out, "Expected signing identifier:");
  assert_contains(cap.out, "com.example.App");
  assert_contains(cap.out, "Actual signing identifier:");
  assert_contains(cap.out, "com.example.Other");
  capture_free(&cap);

  state = (FakePlatformState){ .identity_result = CODE_SIGNATURE_IDENTITY_INVALID_SIGNATURE };
  platform = fake_platform(&state);
  cap = capture_why_platform(&cfg, "/Applications/Publisher.app/Contents/MacOS/Publisher", &platform);
  assert(cap.rc == 0);
  assert_contains(cap.out, "Decision: UNKNOWN");
  assert_contains(cap.out, "code signature invalid");
  capture_free(&cap);
  config_free(&cfg);

  cfg = (Config){0};
  cap = capture_why(&cfg, "ProcessName");
  assert(cap.rc != 0);
  assert_contains(cap.err, "unresolved process name: ProcessName");
  capture_free(&cap);

  char *dir = temp_dir();
  char *config = join_path_dup(dir, "netwatch.config.json");
  char *out = join_path_dup(dir, "out.txt");
  char *marker = join_path_dup(dir, "lsof-marker");
  char *lsof = join_path_dup(dir, "lsof");
  char script[1024];
  snprintf(script, sizeof(script), "#!/bin/sh\necho called > %s\nexit 0\n", marker);
  write_text_mode(lsof, script, 0755);
  write_text_mode(config, "{\"version\":2,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n", 0600);
  const char *old_path = getenv("PATH");
  char path_env[4096];
  snprintf(path_env, sizeof(path_env), "%s:%s", dir, old_path ? old_path : "");
  assert(run_netwatch_mode_cwd("--why", "/tmp/why_cli_unknown", NULL, path_env, out, dir) == 0);
  assert(access(marker, F_OK) != 0);
  char *cli_out = must_read(out);
  assert_contains(cli_out, "Decision: UNKNOWN");
  free(cli_out);
  assert(run_netwatch_mode_cwd("--why", NULL, NULL, path_env, out, dir) != 0);
  assert(run_netwatch_mode_cwd("--why", "/tmp/a", "/tmp/b", path_env, out, dir) != 0);

  unlink(config); unlink(out); unlink(lsof); unlink(marker);
  rmdir(dir);
  free(config); free(out); free(marker); free(lsof); free(dir);
}

static void test_platform_injection(void){
  FakePlatformState state = {0};
  NetwatchPlatform platform = fake_platform(&state);
  Config cfg = { .allow_apple_system_components = true };
  ConnectionPolicy policy = connection_policy_for_path_with_platform(
    "TrustedProc 1 user TCP 1->2 (ESTABLISHED)",
    "TrustedProc",
    "/usr/libexec/trusted_platform_fixture",
    &cfg,
    &platform);
  assert(policy.decision == CONNECTION_ALLOWED_APPLE_SYSTEM);
  assert(state.apple_calls == 1);
  config_free(&cfg);

  char *dir = temp_dir();
  char *config = join_path_dup(dir, "config.json");
  char *log = join_path_dup(dir, "netwatch.log");
  char config_text[1024];
  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":false,\"logPath\":\"%s\",\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);

  state = (FakePlatformState){ .process_path = "/tmp/platform_unknown" };
  platform = fake_platform(&state);
  assert(monitor_run_with_platform(config, &platform) == 0);
  assert(state.collect_calls == 1);
  assert(state.process_path_calls == 1);
  assert(state.wifi_calls == 1);
  assert(!strcmp(state.wifi_interface, "Wi-Fi"));
  char *log_text = must_read(log);
  assert_contains(log_text, "Wi-Fi disabled Wi-Fi");
  assert_contains(log_text, "/tmp/platform_unknown");
  free(log_text);

  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":false,\"logPath\":\"%s\",\"denyPatterns\":[\"FakeProc\"],\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);
  state = (FakePlatformState){ .process_path = "/tmp/platform_denied" };
  platform = fake_platform(&state);
  assert(monitor_run_with_platform(config, &platform) == 0);
  assert(state.collect_calls == 1);
  assert(state.process_path_calls == 1);
  assert(state.wifi_calls == 1);
  log_text = must_read(log);
  assert_contains(log_text, "[DENIED]");
  assert_contains(log_text, "explicit deny rule");
  free(log_text);

  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":false,\"logPath\":\"%s\",\"allowProcesses\":{\"FakeProc\":\"/tmp/platform_allowed\"},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);
  state = (FakePlatformState){ .process_path = "/tmp/platform_allowed" };
  platform = fake_platform(&state);
  assert(monitor_run_with_platform(config, &platform) == 0);
  assert(state.collect_calls == 1);
  assert(state.process_path_calls == 1);
  assert(state.wifi_calls == 0);

  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":false,\"logPath\":\"%s\",\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);
  state = (FakePlatformState){ .process_path = "/tmp/platform_dry_unknown" };
  platform = fake_platform(&state);
  assert(monitor_run_with_options(config, true, &platform) == 0);
  assert(state.collect_calls == 1);
  assert(state.process_path_calls == 1);
  assert(state.wifi_calls == 0);
  log_text = must_read(log);
  assert_contains(log_text, "DRY RUN: would disable Wi-Fi");
  assert_contains(log_text, "/tmp/platform_dry_unknown");
  free(log_text);

  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":true,\"logPath\":\"%s\",\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);
  state = (FakePlatformState){ .process_path = "/tmp/platform_config_dry_unknown" };
  platform = fake_platform(&state);
  assert(monitor_run_with_platform(config, &platform) == 0);
  assert(state.wifi_calls == 0);

  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":false,\"allowAppleSystemComponents\":true,\"logPath\":\"%s\",\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);
  state = (FakePlatformState){ .process_path = "/usr/libexec/trusted_platform_monitor" };
  platform = fake_platform(&state);
  assert(monitor_run_with_platform(config, &platform) == 0);
  assert(state.apple_calls == 1);
  assert(state.wifi_calls == 0);

  unlink(config); unlink(log); rmdir(dir);
  free(config); free(log); free(dir);
}

static void test_cli_dry_run_mode(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "netwatch.config.json");
  char *out = join_path_dup(dir, "out.txt");
  char *log = join_path_dup(dir, "netwatch.log");
  char *wifi_marker = join_path_dup(dir, "networksetup-marker");
  char *lsof = join_path_dup(dir, "lsof");
  char *networksetup = join_path_dup(dir, "networksetup");

  char lsof_script[2048];
  snprintf(lsof_script, sizeof(lsof_script),
    "#!/bin/sh\n"
    "if [ \"$1\" = \"-i\" ]; then\n"
    "  echo 'FakeProc 42 user 10u IPv4 TCP 10.0.0.1:123->203.0.113.10:443 (ESTABLISHED)'\n"
    "elif [ \"$1\" = \"-a\" ]; then\n"
    "  echo 'n/Applications/Fake.app/Contents/MacOS/Fake'\n"
    "fi\n"
    "exit 0\n");
  write_text_mode(lsof, lsof_script, 0755);

  char networksetup_script[1024];
  snprintf(networksetup_script, sizeof(networksetup_script), "#!/bin/sh\necho called > %s\nexit 0\n", wifi_marker);
  write_text_mode(networksetup, networksetup_script, 0755);

  char config_text[1024];
  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":false,\"logPath\":\"%s\",\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);

  const char *old_path = getenv("PATH");
  char path_env[4096];
  snprintf(path_env, sizeof(path_env), "%s:%s", dir, old_path ? old_path : "");
  assert(run_netwatch_mode_cwd("--dry-run", NULL, NULL, path_env, out, dir) == 0);
  assert(access(wifi_marker, F_OK) != 0);
  char *log_text = must_read(log);
  assert_contains(log_text, "DRY RUN: would disable Wi-Fi");
  assert_contains(log_text, "/Applications/Fake.app/Contents/MacOS/Fake");
  free(log_text);

  assert(run_netwatch_mode_cwd("--dry-run", config, "extra.json", path_env, out, dir) != 0);

  unlink(config); unlink(out); unlink(log); unlink(wifi_marker); unlink(lsof); unlink(networksetup);
  rmdir(dir);
  free(config); free(out); free(log); free(wifi_marker); free(lsof); free(networksetup); free(dir);
}

static void test_cli_once_mode(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "netwatch.config.json");
  char *out = join_path_dup(dir, "out.txt");
  char *log = join_path_dup(dir, "netwatch.log");
  char *wifi_marker = join_path_dup(dir, "networksetup-marker");
  char *lsof = join_path_dup(dir, "lsof");
  char *networksetup = join_path_dup(dir, "networksetup");

  write_text_mode(lsof,
    "#!/bin/sh\n"
    "if [ \"$1\" = \"-i\" ]; then\n"
    "  echo 'OnceProc 42 user 10u IPv4 TCP 10.0.0.1:123->203.0.113.10:443 (ESTABLISHED)'\n"
    "elif [ \"$1\" = \"-a\" ]; then\n"
    "  echo 'n/Applications/Once.app/Contents/MacOS/Once'\n"
    "fi\n"
    "exit 0\n",
    0755);
  char script[1024];
  snprintf(script, sizeof(script), "#!/bin/sh\necho called > %s\nexit 0\n", wifi_marker);
  write_text_mode(networksetup, script, 0755);
  snprintf(script, sizeof(script),
    "{\"version\":2,\"dryRun\":true,\"logPath\":\"%s\",\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, script, 0600);

  const char *old_path = getenv("PATH");
  char path_env[4096];
  snprintf(path_env, sizeof(path_env), "%s:%s", dir, old_path ? old_path : "");
  assert(run_netwatch_mode_cwd("--once", "--config", config, path_env, out, dir) == 0);
  assert(access(wifi_marker, F_OK) != 0);
  char *log_text = must_read(log);
  assert_contains(log_text, "DRY RUN: would disable Wi-Fi");
  free(log_text);
  assert(run_netwatch_mode_cwd("--once", config, NULL, path_env, out, dir) != 0);

  unlink(config); unlink(out); unlink(log); unlink(wifi_marker); unlink(lsof); unlink(networksetup);
  rmdir(dir);
  free(config); free(out); free(log); free(wifi_marker); free(lsof); free(networksetup); free(dir);
}

static void test_audit_mode(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "config.json");
  char *workspace_root = join_path_dup(dir, "workspace");
  mkdir_ok(workspace_root);
  char *workspace_interpreter = join_path_dup(dir, "node");
  char *workspace_script = join_path_dup(workspace_root, "job.js");
  write_text_mode(workspace_interpreter, "#!/bin/sh\n", 0700);
  write_text_mode(workspace_script, "x", 0600);
  char audit_config[4096];
  snprintf(audit_config, sizeof(audit_config),
    "{\"version\":2,\"dryRun\":false,\"allowAppleSystemComponents\":true,\"denyPatterns\":[\"BlockedProc\"],\"trustedPublishers\":{\"PublisherProc\":{\"paths\":[\"/Applications/Publisher.app/Contents/MacOS/Publisher\"],\"teamId\":\"TEAMID1234\",\"signingIdentifier\":\"com.example.App\"}},\"trustedWorkspaces\":{\"WorkspaceProc\":{\"roots\":[\"%s\"],\"allowSubdirectories\":true,\"interpreters\":[\"%s\"]}},\"allowProcesses\":{\"AllowedProc\":\"/Applications/Allowed.app/Contents/MacOS/Allowed\"},\"allowRemoteHosts\":[]}\n",
    workspace_root, workspace_interpreter);
  write_text_mode(config, audit_config,
    0600);

  const char *connections[] = {
    "TrustedProc 11 user 10u IPv4 TCP 10.0.0.1:1->203.0.113.1:443 (ESTABLISHED)",
    "PublisherProc 17 user 10u IPv4 TCP 10.0.0.1:7->203.0.113.7:443 (ESTABLISHED)",
    "WorkspaceProc 18 user 10u IPv4 TCP 10.0.0.1:8->203.0.113.8:443 (ESTABLISHED)",
    "AllowedProc 12 user 10u IPv4 TCP 10.0.0.1:2->203.0.113.2:443 (ESTABLISHED)",
    "BlockedProc 13 user 10u IPv4 TCP 10.0.0.1:3->203.0.113.3:443 (ESTABLISHED)",
    "UnknownProc 14 user 10u IPv4 TCP 10.0.0.1:4->203.0.113.4:443 (ESTABLISHED)",
    "UnknownProc 14 user 10u IPv4 TCP 10.0.0.1:4->203.0.113.4:443 (ESTABLISHED)",
    "MaybeProc 15 user 10u IPv4 TCP 10.0.0.1:5->203.0.113.5:443 (ESTABLISHED)",
    "BlockedProc 16 user 10u IPv4 TCP 10.0.0.1:6->203.0.113.6:443 (ESTABLISHED)"
  };
  const char *paths[] = {
    "/usr/libexec/trusted_audit_fixture",
    "/Applications/Publisher.app/Contents/MacOS/Publisher",
    workspace_interpreter,
    "/Applications/Allowed.app/Contents/MacOS/Allowed",
    "/opt/blocked",
    "/opt/netwatch_unknown",
    "/opt/deny_seen_unknown",
    "/opt/deny_seen_unknown"
  };
  FakePlatformState state = {
    .connections = connections,
    .connection_count = sizeof(connections) / sizeof(*connections),
    .process_paths = paths,
    .process_path_count = sizeof(paths) / sizeof(*paths),
    .process_cwd = workspace_root,
    .process_argv = (const char *[]){ workspace_interpreter, workspace_script },
    .process_argv_count = 2,
    .now_value = 1700000000
  };
  NetwatchPlatform platform = fake_platform(&state);
  Capture cap = capture_audit(config, 0, &platform);
  assert(cap.rc == 0);
  assert(state.collect_calls == 1);
  assert(state.process_path_calls == 8);
  assert(state.wifi_calls == 0);
  assert_contains(cap.out, "Audit report");
  assert_contains(cap.out, "Runtime seconds: 0");
  assert_contains(cap.out, "Connections scanned: 9");
  assert_contains(cap.out, "Unique executable paths: 7");
  assert_contains(cap.out, "APPLE SYSTEM");
  assert_contains(cap.out, "/usr/libexec/trusted_audit_fixture");
  assert_contains(cap.out, "TRUSTED PUBLISHER");
  assert_contains(cap.out, "/Applications/Publisher.app/Contents/MacOS/Publisher");
  assert_contains(cap.out, "TRUSTED WORKSPACE");
  assert_contains(cap.out, workspace_interpreter);
  assert_contains(cap.out, "ALLOWED");
  assert_contains(cap.out, "/Applications/Allowed.app/Contents/MacOS/Allowed");
  assert_contains(cap.out, "DENIED");
  assert_contains(cap.out, "/opt/blocked");
  assert_contains(cap.out, "UNKNOWN");
  assert_contains(cap.out, "/opt/netwatch_unknown");
  assert_contains(cap.out, "observations: 2");
  assert_contains(cap.out, "Suggested allow entries (review before adding):");
  assert_contains(cap.out, "\"UnknownProc\":");
  assert_contains(cap.out, "\"/opt/netwatch_unknown\"");
  assert_not_contains(cap.out, "\"TrustedProc\":");
  assert_not_contains(cap.out, "\"PublisherProc\":");
  assert_not_contains(cap.out, "\"WorkspaceProc\":");
  assert_not_contains(cap.out, "\"BlockedProc\":");
  assert_not_contains(cap.out, "\"MaybeProc\":");
  capture_free(&cap);

  unlink(config); unlink(workspace_interpreter); unlink(workspace_script);
  rmdir(workspace_root); rmdir(dir);
  free(config); free(workspace_root); free(workspace_interpreter); free(workspace_script); free(dir);
}

static void test_audit_duration(void){
  char *config = write_config("{\"version\":2,\"dryRun\":false,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n");
  FakePlatformState state = { .process_path = "/opt/audit_duration_unknown", .now_value = 1700000000 };
  NetwatchPlatform platform = fake_platform(&state);
  Capture cap = capture_audit(config, 2, &platform);
  assert(cap.rc == 0);
  assert(state.collect_calls == 2);
  assert(state.wifi_calls == 0);
  assert(state.sleep_calls == 2);
  assert(state.slept_seconds == 2);
  assert_contains(cap.out, "Runtime seconds: 2");
  assert_contains(cap.out, "Connections scanned: 2");
  assert_contains(cap.out, "observations: 2");
  capture_free(&cap);
  unlink(config); free(config);
}

static void test_cli_audit_mode(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "netwatch.config.json");
  char *out = join_path_dup(dir, "out.txt");
  char *wifi_marker = join_path_dup(dir, "networksetup-marker");
  char *lsof = join_path_dup(dir, "lsof");
  char *networksetup = join_path_dup(dir, "networksetup");

  write_text_mode(lsof,
    "#!/bin/sh\n"
    "if [ \"$1\" = \"-i\" ]; then\n"
    "  echo 'AuditProc 42 user 10u IPv4 TCP 10.0.0.1:123->203.0.113.10:443 (ESTABLISHED)'\n"
    "elif [ \"$1\" = \"-a\" ]; then\n"
    "  echo 'n/Applications/Audit.app/Contents/MacOS/Audit'\n"
    "fi\n"
    "exit 0\n",
    0755);
  char networksetup_script[1024];
  snprintf(networksetup_script, sizeof(networksetup_script), "#!/bin/sh\necho called > %s\nexit 0\n", wifi_marker);
  write_text_mode(networksetup, networksetup_script, 0755);
  write_text_mode(config, "{\"version\":2,\"dryRun\":false,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n", 0600);

  const char *old_path = getenv("PATH");
  char path_env[4096];
  snprintf(path_env, sizeof(path_env), "%s:%s", dir, old_path ? old_path : "");
  assert(run_netwatch_mode_cwd("--audit", NULL, NULL, path_env, out, dir) == 0);
  assert(access(wifi_marker, F_OK) != 0);
  char *cli_out = must_read(out);
  assert_contains(cli_out, "Audit report");
  assert_contains(cli_out, "Connections scanned: 1");
  assert_contains(cli_out, "UNKNOWN");
  assert_contains(cli_out, "\"AuditProc\":");
  assert_contains(cli_out, "\"/Applications/Audit.app/Contents/MacOS/Audit\"");
  free(cli_out);
  assert(run_netwatch_mode_cwd("--audit", "0", NULL, path_env, out, dir) != 0);
  assert(run_netwatch_mode_cwd("--audit", "1", "extra", path_env, out, dir) != 0);

  unlink(config); unlink(out); unlink(wifi_marker); unlink(lsof); unlink(networksetup);
  rmdir(dir);
  free(config); free(out); free(wifi_marker); free(lsof); free(networksetup); free(dir);
}

static void test_monitor_stats(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "config.json");
  char *log = join_path_dup(dir, "netwatch.log");
  char *workspace_root = join_path_dup(dir, "workspace");
  mkdir_ok(workspace_root);
  char *workspace_interpreter = join_path_dup(dir, "node");
  char *workspace_script = join_path_dup(workspace_root, "job.js");
  write_text_mode(workspace_interpreter, "#!/bin/sh\n", 0700);
  write_text_mode(workspace_script, "x", 0600);
  char config_text[4096];
  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":false,\"allowAppleSystemComponents\":true,\"logPath\":\"%s\",\"denyPatterns\":[\"BlockedProc\"],\"trustedPublishers\":{\"PublisherProc\":{\"paths\":[\"/Applications/Publisher.app/Contents/MacOS/Publisher\"],\"teamId\":\"TEAMID1234\",\"signingIdentifier\":\"com.example.App\"}},\"trustedWorkspaces\":{\"WorkspaceProc\":{\"roots\":[\"%s\"],\"allowSubdirectories\":true,\"interpreters\":[\"%s\"]}},\"allowProcesses\":{\"AllowedProc\":\"/Applications/Allowed.app/Contents/MacOS/Allowed\"},\"allowRemoteHosts\":[]}\n",
    log, workspace_root, workspace_interpreter);
  write_text_mode(config, config_text, 0600);

  const char *connections[] = {
    "TrustedProc 11 user 10u IPv4 TCP 10.0.0.1:1->203.0.113.1:443 (ESTABLISHED)",
    "PublisherProc 15 user 10u IPv4 TCP 10.0.0.1:5->203.0.113.5:443 (ESTABLISHED)",
    "WorkspaceProc 16 user 10u IPv4 TCP 10.0.0.1:6->203.0.113.6:443 (ESTABLISHED)",
    "AllowedProc 12 user 10u IPv4 TCP 10.0.0.1:2->203.0.113.2:443 (ESTABLISHED)",
    "BlockedProc 13 user 10u IPv4 TCP 10.0.0.1:3->203.0.113.3:443 (ESTABLISHED)",
    "UnknownProc 14 user 10u IPv4 TCP 10.0.0.1:4->203.0.113.4:443 (ESTABLISHED)",
    "UnknownProc 14 user 10u IPv4 TCP 10.0.0.1:4->203.0.113.4:443 (ESTABLISHED)"
  };
  const char *paths[] = {
    "/usr/libexec/trusted_stats_fixture",
    "/Applications/Publisher.app/Contents/MacOS/Publisher",
    workspace_interpreter,
    "/Applications/Allowed.app/Contents/MacOS/Allowed",
    "/opt/stats_blocked",
    "/opt/stats_unknown"
  };
  FakePlatformState state = {
    .connections = connections,
    .connection_count = sizeof(connections) / sizeof(*connections),
    .process_paths = paths,
    .process_path_count = sizeof(paths) / sizeof(*paths),
    .process_cwd = workspace_root,
    .process_argv = (const char *[]){ workspace_interpreter, workspace_script },
    .process_argv_count = 2,
    .now_value = 1700000000
  };
  NetwatchPlatform platform = fake_platform(&state);
  MonitorStats stats = { .connections_scanned = 999 };
  assert(monitor_run_with_stats(config, false, &stats, &platform) == 0);
  assert(state.collect_calls == 1);
  assert(state.process_path_calls == 6);
  assert(state.wifi_calls == 1);
  assert(stats.scan_cycles == 1);
  assert(stats.connections_scanned == 7);
  assert(stats.unique_processes == 6);
  assert(stats.unique_executable_paths == 6);
  assert(stats.apple_trusted_decisions == 1);
  assert(stats.trusted_publisher_matches == 1);
  assert(stats.trusted_workspace_matches == 1);
  assert(stats.explicit_allow_matches == 1);
  assert(stats.deny_matches == 1);
  assert(stats.unknown_decisions == 2);
  assert(stats.requested_enforcement_actions == 1);
  assert(stats.successful_wifi_disable_actions == 1);
  assert(stats.failed_wifi_disable_actions == 0);
  char *log_text = must_read(log);
  assert_contains(log_text, "[TRUSTED_PUBLISHER]");
  assert_contains(log_text, "PUBLISHER RULE: PublisherProc");
  assert_contains(log_text, "[TRUSTED_WORKSPACE]");
  assert_contains(log_text, "WORKSPACE RULE: WorkspaceProc");
  free(log_text);

  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":true,\"logPath\":\"%s\",\"trustedPublishers\":{\"PublisherProc\":{\"paths\":[\"/Applications/Publisher.app/Contents/MacOS/Publisher\"],\"teamId\":\"TEAMID1234\",\"signingIdentifier\":\"com.example.App\"}},\"allowProcesses\":{\"PublisherProc\":\"/Applications/Publisher.app/Contents/MacOS/Publisher\"},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);
  state = (FakePlatformState){ .process_path = "/Applications/Publisher.app/Contents/MacOS/Publisher", .team_id = "BADTEAM", .signing_identifier = "com.example.App", .now_value = 1700000000 };
  platform = fake_platform(&state);
  assert(monitor_run_with_stats(config, false, &stats, &platform) == 0);
  assert(stats.connections_scanned == 1);
  assert(stats.trusted_publisher_matches == 0);
  assert(stats.trusted_publisher_team_id_mismatches == 1);
  assert(stats.explicit_allow_matches == 0);
  assert(stats.unknown_decisions == 1);
  assert(stats.requested_enforcement_actions == 1);
  assert(state.wifi_calls == 0);

  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":true,\"logPath\":\"%s\",\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);
  state = (FakePlatformState){ .process_path = "/opt/stats_dry_unknown", .now_value = 1700000000 };
  platform = fake_platform(&state);
  assert(monitor_run_with_stats(config, false, &stats, &platform) == 0);
  assert(state.wifi_calls == 0);
  assert(stats.connections_scanned == 1);
  assert(stats.unknown_decisions == 1);
  assert(stats.requested_enforcement_actions == 1);
  assert(stats.successful_wifi_disable_actions == 0);
  assert(stats.failed_wifi_disable_actions == 0);

  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":false,\"logPath\":\"%s\",\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);
  state = (FakePlatformState){ .process_path = "/opt/stats_failed_unknown", .fail_wifi = 1, .now_value = 1700000000 };
  platform = fake_platform(&state);
  Capture cap = capture_monitor_stats(config, &stats, &platform);
  assert(cap.rc != 0);
  assert_contains(cap.err, "fake Wi-Fi failure");
  assert(state.wifi_calls == 1);
  assert(stats.connections_scanned == 1);
  assert(stats.requested_enforcement_actions == 1);
  assert(stats.successful_wifi_disable_actions == 0);
  assert(stats.failed_wifi_disable_actions == 1);
  capture_free(&cap);

  unlink(config); unlink(log); unlink(workspace_interpreter); unlink(workspace_script);
  rmdir(workspace_root); rmdir(dir);
  free(config); free(log); free(workspace_root); free(workspace_interpreter); free(workspace_script); free(dir);
}

static char *daemon_config_text(const char *log_path, int dry_run, int interval, int reload, int exit_on_error){
  char text[1024];
  snprintf(text, sizeof(text),
    "{\"version\":2,\"dryRun\":%s,\"logPath\":\"%s\",\"daemon\":{\"pollIntervalSeconds\":%d,\"reloadOnSighup\":%s,\"exitOnConfigError\":%s},\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    dry_run ? "true" : "false",
    log_path,
    interval,
    reload ? "true" : "false",
    exit_on_error ? "true" : "false");
  return xstrdup(text);
}

static void test_daemon_mode(void){
  char *dir = temp_dir();
  char *log = join_path_dup(dir, "daemon.log");
  char *base_text = daemon_config_text(log, 1, 1, 1, 0);
  assert(base_text);
  char *config = write_config(base_text);
  free(base_text);
  FakePlatformState state = { .daemon_stop_after_collects = 3 };
  NetwatchPlatform platform = fake_platform(&state);
  Capture cap = capture_daemon(config, &platform);
  assert(cap.rc == 0);
  assert(state.collect_calls == 3);
  assert(state.sleep_calls == 2);
  assert(state.slept_seconds == 2);
  assert(state.wifi_calls == 0);
  capture_free(&cap);

  char *reload_a = daemon_config_text(log, 1, 1, 1, 0);
  char *reload_b = daemon_config_text(log, 1, 7, 1, 0);
  assert(reload_a && reload_b);
  const char *reload_texts[] = {
    reload_a,
    reload_b
  };
  state = (FakePlatformState){
    .read_files = reload_texts,
    .read_file_count = 2,
    .daemon_reload_after_collects = 1,
    .daemon_stop_after_collects = 2
  };
  platform = fake_platform(&state);
  cap = capture_daemon(config, &platform);
  assert(cap.rc == 0);
  assert(state.read_file_calls == 2);
  assert(state.collect_calls == 2);
  assert(state.sleep_calls == 1);
  assert(state.slept_seconds == 7);
  assert(state.not_scanned_status_after_scan == 0);
  capture_free(&cap);
  free(reload_a); free(reload_b);

  char *invalid_a = daemon_config_text(log, 1, 5, 1, 0);
  assert(invalid_a);
  const char *invalid_reload_texts[] = {
    invalid_a,
    "{\"version\":2,\"daemon\":{\"pollIntervalSeconds\":0}}\n"
  };
  state = (FakePlatformState){
    .read_files = invalid_reload_texts,
    .read_file_count = 2,
    .daemon_reload_after_collects = 1,
    .daemon_stop_after_collects = 2
  };
  platform = fake_platform(&state);
  cap = capture_daemon(config, &platform);
  assert(cap.rc == 0);
  assert(state.read_file_calls == 2);
  assert(state.collect_calls == 2);
  assert(state.sleep_calls == 1);
  assert(state.slept_seconds == 5);
  assert_contains(cap.err, "daemon.pollIntervalSeconds must be a positive integer");
  capture_free(&cap);
  free(invalid_a);

  char *exit_a = daemon_config_text(log, 1, 5, 1, 1);
  assert(exit_a);
  const char *exit_reload_texts[] = {
    exit_a,
    "{\"version\":2,\"daemon\":{\"pollIntervalSeconds\":0}}\n"
  };
  state = (FakePlatformState){
    .read_files = exit_reload_texts,
    .read_file_count = 2,
    .daemon_reload_after_collects = 1,
    .daemon_stop_after_collects = 3
  };
  platform = fake_platform(&state);
  cap = capture_daemon(config, &platform);
  assert(cap.rc != 0);
  assert(state.collect_calls == 1);
  assert(state.sleep_calls == 0);
  capture_free(&cap);
  free(exit_a);

  state = (FakePlatformState){ .daemon_stop_after_collects = 1, .process_path = "/opt/daemon_unknown" };
  platform = fake_platform(&state);
  cap = capture_daemon(config, &platform);
  assert(cap.rc == 0);
  assert(state.collect_calls == 1);
  assert(state.wifi_calls == 0);
  capture_free(&cap);

  char *lock_path = daemon_lock_path_for_config(config);
  assert(lock_path);
  int lock_fd = open(lock_path, O_RDWR | O_CREAT, 0600);
  assert(lock_fd >= 0);
  assert(flock(lock_fd, LOCK_EX | LOCK_NB) == 0);
  state = (FakePlatformState){ .daemon_stop_after_collects = 1 };
  platform = fake_platform(&state);
  cap = capture_daemon(config, &platform);
  assert(cap.rc != 0);
  assert_contains(cap.err, "another netwatch daemon instance is already running");
  capture_free(&cap);
  close(lock_fd);

  state = (FakePlatformState){ .daemon_stop_after_collects = 1 };
  platform = fake_platform(&state);
  cap = capture_daemon(config, &platform);
  assert(cap.rc == 0);
  capture_free(&cap);
  lock_fd = open(lock_path, O_RDWR | O_CREAT, 0600);
  assert(lock_fd >= 0);
  assert(flock(lock_fd, LOCK_EX | LOCK_NB) == 0);
  close(lock_fd);
  unlink(lock_path);
  free(lock_path);
  unlink(config); unlink(log); rmdir(dir);
  free(config); free(log); free(dir);
}

static void test_daemon_lock_path_canonicalizes_config(void){
  char cwd[PATH_MAX];
  assert(getcwd(cwd, sizeof(cwd)));
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "netwatch.config.json");
  write_text_mode(config, "{\"version\":2,\"dryRun\":true}\n", 0600);
  char *absolute_lock = daemon_lock_path_for_config(config);
  assert(absolute_lock);
  assert(chdir(dir) == 0);
  char *relative_lock = daemon_lock_path_for_config("netwatch.config.json");
  assert(relative_lock);
  assert(chdir(cwd) == 0);
  assert(strcmp(absolute_lock, relative_lock) == 0);
  free(absolute_lock); free(relative_lock);
  unlink(config); rmdir(dir);
  free(config); free(dir);
}

static void test_status_snapshot_json(void){
  const time_t now = 1700000100;
  Config cfg = { .dry_run = false, .daemon = { .poll_interval_seconds = 300 } };
  MonitorScanOutcome outcome = { .last_scan_at = 1700000000 };
  snprintf(outcome.last_scan_result, sizeof(outcome.last_scan_result), "ok");
  NetwatchStatusSnapshot snapshot;
  netwatch_status_snapshot_from_scan(&snapshot, "/tmp/netwatch.config.json", &cfg, &outcome, true, true);
  assert(!strcmp(netwatch_status_level_at(&snapshot, now), "ok"));
  assert(!strcmp(netwatch_status_level_at(&snapshot, 1700000401), "error"));
  snapshot.daemon_running = false;
  assert(!strcmp(netwatch_status_level_at(&snapshot, now), "ok"));
  char *json = netwatch_status_snapshot_json_at(&snapshot, now);
  assert(json);
  assert_contains(json, "\"status\": \"ok\"");
  assert_contains(json, "\"daemonRunning\": false");
  assert_contains(json, "\"lastUnknownProcessSummary\": null");
  assert_not_contains(json, "history");
  free(json);

  cfg.dry_run = true;
  netwatch_status_snapshot_from_scan(&snapshot, "/tmp/netwatch.config.json", &cfg, &outcome, true, true);
  assert(!strcmp(netwatch_status_level_at(&snapshot, now), "attention"));
  json = netwatch_status_snapshot_json_at(&snapshot, now);
  assert_contains(json, "\"status\": \"attention\"");
  assert_contains(json, "\"dryRun\": true");
  free(json);

  outcome = (MonitorScanOutcome){ .last_scan_at = 1700000001, .unknown_count = 1, .would_disable_wifi = true, .has_last_unknown = true };
  snprintf(outcome.last_scan_result, sizeof(outcome.last_scan_result), "unknown");
  outcome.last_unknown = (MonitorUnknownSummary){ .pid = 42, .dry_run = true, .would_disable_wifi = true, .wifi_disabled = false };
  snprintf(outcome.last_unknown.process_name, sizeof(outcome.last_unknown.process_name), "node");
  snprintf(outcome.last_unknown.command_line, sizeof(outcome.last_unknown.command_line), "node script.js");
  snprintf(outcome.last_unknown.executable_path, sizeof(outcome.last_unknown.executable_path), "/opt/node");
  snprintf(outcome.last_unknown.cwd, sizeof(outcome.last_unknown.cwd), "/tmp/project");
  snprintf(outcome.last_unknown.remote_endpoint, sizeof(outcome.last_unknown.remote_endpoint), "203.0.113.10:443");
  snprintf(outcome.last_unknown.reason, sizeof(outcome.last_unknown.reason), "not present in allowlist");
  cfg.dry_run = true;
  netwatch_status_snapshot_from_scan(&snapshot, "/tmp/netwatch.config.json", &cfg, &outcome, true, true);
  json = netwatch_status_snapshot_json_at(&snapshot, now);
  assert_contains(json, "\"status\": \"error\"");
  assert_contains(json, "\"unknownCount\": 1");
  assert_contains(json, "\"wouldDisableWifi\": true");
  assert_contains(json, "\"wifiDisabled\": false");
  assert_contains(json, "\"processName\": \"node\"");
  assert_not_contains(json, "environment");
  free(json);

  cfg.dry_run = false;
  outcome.wifi_disabled = true;
  outcome.last_unknown.dry_run = false;
  outcome.last_unknown.wifi_disabled = true;
  netwatch_status_snapshot_from_scan(&snapshot, "/tmp/netwatch.config.json", &cfg, &outcome, true, true);
  json = netwatch_status_snapshot_json_at(&snapshot, now);
  assert_contains(json, "\"status\": \"error\"");
  assert_contains(json, "\"wifiDisabled\": true");
  free(json);

  outcome = (MonitorScanOutcome){ .last_scan_at = 1700000002 };
  snprintf(outcome.last_scan_result, sizeof(outcome.last_scan_result), "error");
  netwatch_status_snapshot_from_scan(&snapshot, "/tmp/netwatch.config.json", &cfg, &outcome, true, true);
  json = netwatch_status_snapshot_json_at(&snapshot, now);
  assert_contains(json, "\"status\": \"error\"");
  free(json);

  char *dir = temp_dir();
  char *path = join_path_dup(dir, "status.json");
  char err[256] = {0};
  assert(netwatch_status_write(path, &snapshot, netwatch_platform_default(), err, sizeof(err)));
  char *text = must_read(path);
  assert_contains(text, "\"status\": \"error\"");
  free(text);
  char tmp[PATH_MAX];
  snprintf(tmp, sizeof(tmp), "%s/.status.json.tmp.%ld.0", dir, (long)getpid());
  assert(access(tmp, F_OK) != 0);
  unlink(path); rmdir(dir);
  free(path); free(dir);
}

static void test_daemon_status_snapshot(void){
  char *dir = temp_dir();
  char *log = join_path_dup(dir, "daemon.log");
  char *status_path = join_path_dup(dir, "status.json");
  char *config_text = daemon_config_text(log, 1, 1, 1, 0);
  char *config = write_config(config_text);
  free(config_text);
  FakePlatformState state = {
    .daemon_stop_after_collects = 1,
    .process_path = "/opt/unknown",
    .process_cwd = "/tmp/project",
    .command_line = "UnknownProc --connect",
    .fail_collect = 0,
    .now_value = 1700000100
  };
  NetwatchPlatform platform = fake_platform(&state);
  Capture cap = capture_daemon_status(config, status_path, &platform);
  assert(cap.rc == 0);
  char *status = must_read(status_path);
  assert_contains(status, "\"status\": \"error\"");
  assert_contains(status, "\"daemonRunning\": false");
  assert_contains(status, "\"unknownCount\": 1");
  assert_contains(status, "\"wouldDisableWifi\": true");
  assert_contains(status, "\"wifiDisabled\": false");
  assert_contains(status, "\"processName\": \"FakeProc\"");
  free(status); capture_free(&cap);

  state = (FakePlatformState){ .daemon_stop_after_collects = 2, .fail_collect = 1, .now_value = 1700000200 };
  platform = fake_platform(&state);
  cap = capture_daemon_status(config, status_path, &platform);
  assert(cap.rc != 0);
  status = must_read(status_path);
  assert_contains(status, "\"status\": \"error\"");
  assert_contains(status, "\"lastScanResult\": \"error\"");
  free(status); capture_free(&cap);

  unlink(config); unlink(log); unlink(status_path); rmdir(dir);
  free(config); free(log); free(status_path); free(dir);
}

static void test_cli_status_json_mode(void){
  char *home = temp_dir();
  make_status_dirs(home);
  char *saved_home = save_home_set(home);
  char *watch = join_path_dup(home, ".watch");
  char *status_path = join_path_dup(watch, "netwatch.status.json");
  write_text_mode(status_path, "{\"version\":1,\"status\":\"ok\"}\n", 0644);

  char *out = join_path_dup(home, "out.txt");
  const char *old_path = getenv("PATH");
  char path_env[4096];
  snprintf(path_env, sizeof(path_env), "%s", old_path ? old_path : "");
  assert(run_netwatch_mode_cwd("--status-json", NULL, NULL, path_env, out, home) == 0);
  char *text = must_read(out);
  assert_contains(text, "\"status\":\"ok\"");
  free(text);
  unlink(status_path);
  assert(run_netwatch_mode_cwd("--status-json", NULL, NULL, path_env, out, home) != 0);
  text = must_read(out);
  assert_contains(text, "status snapshot unavailable");
  free(text);

  unlink(out); rmdir(watch); rmdir(home);
  restore_home(saved_home);
  free(home); free(watch); free(status_path); free(out);
}

static void test_launchd_daemon_plist(void){
  char *text = must_read("packaging/launchd/com.sergey.netwatch.plist");
  assert_contains(text, "<string>/usr/local/bin/netwatch</string>");
  assert_contains(text, "<string>--daemon</string>");
  assert_contains(text, "<string>--config</string>");
  assert_contains(text, "<string>/etc/netwatch/config.json</string>");
  assert_contains(text, "<key>RunAtLoad</key>");
  assert_contains(text, "<key>KeepAlive</key>");
  assert_contains(text, "<key>ThrottleInterval</key>");
  free(text);
}

static void test_cli_stats_mode(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "netwatch.config.json");
  char *out = join_path_dup(dir, "out.txt");
  char *log = join_path_dup(dir, "netwatch.log");
  char *wifi_marker = join_path_dup(dir, "networksetup-marker");
  char *lsof = join_path_dup(dir, "lsof");
  char *networksetup = join_path_dup(dir, "networksetup");

  write_text_mode(lsof,
    "#!/bin/sh\n"
    "if [ \"$1\" = \"-i\" ]; then\n"
    "  echo 'StatsProc 42 user 10u IPv4 TCP 10.0.0.1:123->203.0.113.10:443 (ESTABLISHED)'\n"
    "elif [ \"$1\" = \"-a\" ]; then\n"
    "  echo 'n/Applications/Stats.app/Contents/MacOS/Stats'\n"
    "fi\n"
    "exit 0\n",
    0755);
  char networksetup_script[1024];
  snprintf(networksetup_script, sizeof(networksetup_script), "#!/bin/sh\necho called > %s\nexit 0\n", wifi_marker);
  write_text_mode(networksetup, networksetup_script, 0755);
  char config_text[1024];
  snprintf(config_text, sizeof(config_text),
    "{\"version\":2,\"dryRun\":true,\"logPath\":\"%s\",\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    log);
  write_text_mode(config, config_text, 0600);

  const char *old_path = getenv("PATH");
  char path_env[4096];
  snprintf(path_env, sizeof(path_env), "%s:%s", dir, old_path ? old_path : "");
  assert(run_netwatch_mode_cwd("--stats", NULL, NULL, path_env, out, dir) == 0);
  assert(access(wifi_marker, F_OK) != 0);
  char *cli_out = must_read(out);
  assert_contains(cli_out, "Runtime statistics");
  assert_contains(cli_out, "Scan cycles: 1");
  assert_contains(cli_out, "Connections scanned: 1");
  assert_contains(cli_out, "Unique processes: 1");
  assert_contains(cli_out, "Unique executable paths: 1");
  assert_contains(cli_out, "Unknown decisions: 1");
  assert_contains(cli_out, "Requested enforcement actions: 1");
  assert_contains(cli_out, "Successful Wi-Fi disable actions: 0");
  free(cli_out);
  assert(run_netwatch_mode_cwd("--stats", config, "extra.json", path_env, out, dir) != 0);

  unlink(config); unlink(out); unlink(log); unlink(wifi_marker); unlink(lsof); unlink(networksetup);
  rmdir(dir);
  free(config); free(out); free(log); free(wifi_marker); free(lsof); free(networksetup); free(dir);
}

static void test_status_command(void){
  char *home = temp_dir();
  make_status_dirs(home);
  char *saved_home = save_home_set(home);
  char *watch = join_path_dup(home, ".watch");
  char *library = join_path_dup(home, "Library");
  char *agents = join_path_dup(library, "LaunchAgents");
  char *bin = join_path_dup(watch, "netwatch");
  char *config = join_path_dup(watch, "netwatch.config.json");
  char *err_log = join_path_dup(watch, "netwatch.launchd.err.log");
  char *plist = join_path_dup(agents, "com.serg.netwatch.plist");

  write_text_mode(bin, "#!/bin/sh\n", 0755);
  write_text_mode(config,
    "{\"version\":2,\"dryRun\":true,\"allowAppleSystemComponents\":true,\"trustedPublishers\":{\"Status Publisher\":{\"paths\":[\"/Applications/Status.app/Contents/MacOS/Status\"],\"teamId\":\"TEAMID1234\",\"signingIdentifier\":\"com.example.Status\"}},\"trustedWorkspaces\":{\"Status Workspace\":{\"roots\":[\"/tmp\"],\"allowSubdirectories\":true,\"interpreters\":[\"/bin/sh\"]}},\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n",
    0600);
  write_text_mode(plist, "<plist><string>/tmp/netwatch</string></plist>\n", 0600);
  write_text_mode(err_log, "old startup line\nlatest startup line\n", 0600);

  FakePlatformState state = {
    .launchd_loaded_result = 1,
    .find_process_result = 1,
    .running_pid = 4321,
    .running_path = bin
  };
  NetwatchPlatform platform = fake_platform(&state);
  Capture cap = capture_status(&platform);
  assert(cap.rc == 0);
  assert(state.launchd_calls == 1);
  assert(state.find_process_calls == 1);
  assert(state.collect_calls == 0);
  assert(state.wifi_calls == 0);
  assert_contains(cap.out, "netwatch version: unavailable");
  assert_contains(cap.out, "LaunchAgent label: com.serg.netwatch");
  assert_contains(cap.out, "LaunchAgent installed: yes");
  assert_contains(cap.out, "Service loaded: yes");
  assert_contains(cap.out, "Running: yes");
  assert_contains(cap.out, "PID: 4321");
  assert_contains(cap.out, bin);
  assert_contains(cap.out, "Config valid: yes");
  assert_contains(cap.out, "Config version: 2");
  assert_contains(cap.out, "Apple system trust: enabled");
  assert_contains(cap.out, "Trusted publisher rules: 1");
  assert_contains(cap.out, "Trusted workspace rules: 1");
  assert_contains(cap.out, "Dry run: enabled");
  assert_contains(cap.out, "Audit mode: not configured");
  assert_contains(cap.out, "Recent startup error: latest startup line");
  capture_free(&cap);

  restore_home(saved_home);
  unlink(bin); unlink(config); unlink(err_log); unlink(plist);
  rmdir(agents); rmdir(library); rmdir(watch); rmdir(home);
  free(watch); free(library); free(agents); free(bin); free(config); free(err_log); free(plist); free(home);
}

static void test_status_missing_and_partial(void){
  char *home = temp_dir();
  char *saved_home = save_home_set(home);
  FakePlatformState state = { .launchd_loaded_result = 1, .find_process_result = 1, .running_pid = 99 };
  NetwatchPlatform platform = fake_platform(&state);
  Capture cap = capture_status(&platform);
  assert(cap.rc == 0);
  assert(state.launchd_calls == 0);
  assert(state.find_process_calls == 0);
  assert_contains(cap.out, "LaunchAgent installed: no");
  assert_contains(cap.out, "Service loaded: no");
  assert_contains(cap.out, "Running: no");
  assert_contains(cap.out, "PID: unavailable");
  assert_contains(cap.out, "Config valid: no");
  assert_contains(cap.out, "Config version: unavailable");
  assert_contains(cap.out, "Apple system trust: unavailable");
  assert_contains(cap.out, "Trusted publisher rules: unavailable");
  assert_contains(cap.out, "Trusted workspace rules: unavailable");
  assert_contains(cap.out, "Dry run: unavailable");
  assert_contains(cap.out, "Audit mode: unavailable (LaunchAgent not installed)");
  assert_contains(cap.out, "Recent startup error: unavailable (stderr log not found)");
  capture_free(&cap);
  restore_home(saved_home);
  rmdir(home); free(home);

  home = temp_dir();
  make_status_dirs(home);
  saved_home = save_home_set(home);
  char *watch = join_path_dup(home, ".watch");
  char *library = join_path_dup(home, "Library");
  char *agents = join_path_dup(library, "LaunchAgents");
  char *bin = join_path_dup(watch, "netwatch");
  char *config = join_path_dup(watch, "netwatch.config.json");
  char *err_log = join_path_dup(watch, "netwatch.launchd.err.log");
  char *plist = join_path_dup(agents, "com.serg.netwatch.plist");
  write_text_mode(bin, "#!/bin/sh\n", 0755);
  write_text_mode(config, "{\"version\":3,\"dryRun\":true}\n", 0600);
  write_text_mode(plist, "<plist><string>--audit</string></plist>\n", 0600);
  write_text_mode(err_log, "\n", 0600);

  state = (FakePlatformState){ .launchd_loaded_result = -1, .find_process_result = -1 };
  platform = fake_platform(&state);
  cap = capture_status(&platform);
  assert(cap.rc == 0);
  assert(state.launchd_calls == 1);
  assert(state.find_process_calls == 1);
  assert_contains(cap.out, "LaunchAgent installed: yes");
  assert_contains(cap.out, "Service loaded: unavailable");
  assert_contains(cap.out, "Running: unavailable");
  assert_contains(cap.out, "Config valid: no");
  assert_contains(cap.out, "Unsupported config version: 3");
  assert_contains(cap.out, "Trusted publisher rules: unavailable");
  assert_contains(cap.out, "Trusted workspace rules: unavailable");
  assert_contains(cap.out, "Audit mode: configured");
  assert_contains(cap.out, "Recent startup error: none detected");
  capture_free(&cap);

  restore_home(saved_home);
  unlink(bin); unlink(config); unlink(err_log); unlink(plist);
  rmdir(agents); rmdir(library); rmdir(watch); rmdir(home);
  free(watch); free(library); free(agents); free(bin); free(config); free(err_log); free(plist); free(home);
}

static void test_cli_status_mode(void){
  char *dir = temp_dir();
  make_status_dirs(dir);
  char *saved_home = save_home_set(dir);
  char *watch = join_path_dup(dir, ".watch");
  char *library = join_path_dup(dir, "Library");
  char *agents = join_path_dup(library, "LaunchAgents");
  char *config = join_path_dup(watch, "netwatch.config.json");
  char *out = join_path_dup(dir, "out.txt");
  char *lsof_marker = join_path_dup(dir, "lsof-marker");
  char *wifi_marker = join_path_dup(dir, "networksetup-marker");
  char *lsof = join_path_dup(dir, "lsof");
  char *networksetup = join_path_dup(dir, "networksetup");
  char *launchctl = join_path_dup(dir, "launchctl");
  char *plist = join_path_dup(agents, "com.serg.netwatch.plist");

  write_text_mode(config, "{\"version\":2,\"dryRun\":true,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n", 0600);
  write_text_mode(plist, "<plist></plist>\n", 0600);
  char script[1024];
  snprintf(script, sizeof(script), "#!/bin/sh\necho called > %s\nexit 0\n", lsof_marker);
  write_text_mode(lsof, script, 0755);
  snprintf(script, sizeof(script), "#!/bin/sh\necho called > %s\nexit 0\n", wifi_marker);
  write_text_mode(networksetup, script, 0755);
  write_text_mode(launchctl, "#!/bin/sh\nexit 1\n", 0755);

  const char *old_path = getenv("PATH");
  char path_env[4096];
  snprintf(path_env, sizeof(path_env), "%s:%s", dir, old_path ? old_path : "");
  assert(run_netwatch_mode_cwd("--status", NULL, NULL, path_env, out, dir) == 0);
  assert(access(lsof_marker, F_OK) != 0);
  assert(access(wifi_marker, F_OK) != 0);
  char *cli_out = must_read(out);
  assert_contains(cli_out, "LaunchAgent installed: yes");
  assert_contains(cli_out, "Service loaded: no");
  assert_contains(cli_out, "Config valid: yes");
  assert_contains(cli_out, "Trusted publisher rules: 0");
  assert_contains(cli_out, "Trusted workspace rules: 0");
  free(cli_out);
  assert(run_netwatch_mode_cwd("--status", "extra", NULL, path_env, out, dir) != 0);

  restore_home(saved_home);
  unlink(config); unlink(out); unlink(lsof_marker); unlink(wifi_marker); unlink(lsof); unlink(networksetup); unlink(launchctl); unlink(plist);
  rmdir(agents); rmdir(library); rmdir(watch); rmdir(dir);
  free(watch); free(library); free(agents); free(config); free(out); free(lsof_marker); free(wifi_marker); free(lsof); free(networksetup); free(launchctl); free(plist); free(dir);
}

static void test_platform_converter_failure(void){
  char *dir = temp_dir();
  char *config = join_path_dup(dir, "config.json");
  const char *original = "{\"version\":2,\"dryRun\":true,\"allowProcesses\":{},\"allowRemoteHosts\":[]}\n";
  write_text_mode(config, original, 0600);

  FakePlatformState state = { .fail_copy = 1 };
  NetwatchPlatform platform = fake_platform(&state);
  Capture cap = capture_convert_platform(config, &platform);
  assert(cap.rc != 0);
  assert_contains(cap.err, "fake backup failure");
  assert(state.copy_calls == 1);
  char *text = must_read(config);
  assert(!strcmp(text, original));
  assert_not_contains(text, "allowAppleSystemComponents");
  char *backup = join_path_dup(dir, "config.json.bak");
  assert(access(backup, F_OK) != 0);
  free(text); capture_free(&cap);

  unlink(config); unlink(backup); rmdir(dir);
  free(config); free(backup); free(dir);
}

int main(void){
  test_system_paths();
  test_policy_priority();
  test_trusted_publisher_policy();
  test_apple_signature_policy();
  test_temp_executable_rejected();
  test_config_bool();
  test_config_trusted_publishers();
  test_config_trusted_workspaces();
  test_config_daemon();
  test_trusted_workspace_policy();
  test_config_conversion();
  test_backup_suffix();
  test_deterministic_json_formatting();
  test_invalid_and_failed_backup();
  test_cli_convert_mode();
  test_check_config();
  test_why_command();
  test_platform_injection();
  test_cli_dry_run_mode();
  test_cli_once_mode();
  test_audit_mode();
  test_audit_duration();
  test_cli_audit_mode();
  test_monitor_stats();
  test_daemon_mode();
  test_daemon_lock_path_canonicalizes_config();
  test_status_snapshot_json();
  test_daemon_status_snapshot();
  test_launchd_daemon_plist();
  test_cli_stats_mode();
  test_cli_status_json_mode();
  test_status_command();
  test_status_missing_and_partial();
  test_cli_status_mode();
  test_platform_converter_failure();
  puts("OK");
  return 0;
}
