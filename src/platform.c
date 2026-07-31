#include "platform.h"
#include "util.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CSCommon.h>
#include <Security/SecBase.h>
#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libproc.h>
#endif

extern char **environ;

typedef int (*LineHandler)(const char *line, void *ctx);

static char *platform_read_file_default(const NetwatchPlatform *platform, const char *path, char *err, size_t err_len){
  (void)platform;
  return read_file(path, err, err_len);
}

static int platform_access_path_default(const NetwatchPlatform *platform, const char *path, int mode){
  (void)platform;
  return access(path, mode);
}

static int platform_stat_path_default(const NetwatchPlatform *platform, const char *path, struct stat *st){
  (void)platform;
  return stat(path, st);
}

static char *path_dirname(const char *path){
  const char *slash = strrchr(path, '/');
  if (!slash) return xstrdup(".");
  if (slash == path) return xstrdup("/");
  size_t n = (size_t)(slash - path);
  char *out = malloc(n + 1); if (!out) return NULL;
  memcpy(out, path, n); out[n] = 0; return out;
}

static const char *path_basename_const(const char *path){
  const char *slash = strrchr(path, '/');
  return slash ? slash + 1 : path;
}

static char *join_path(const char *dir, const char *name){
  size_t slash = strcmp(dir, "/") ? 1 : 0;
  size_t n = strlen(dir) + slash + strlen(name) + 1;
  char *out = malloc(n);
  if (out) snprintf(out, n, "%s%s%s", dir, slash ? "/" : "", name);
  return out;
}

static char *platform_temp_path_for_default(const NetwatchPlatform *platform, const char *path){
  char *dir = path_dirname(path); if (!dir) return NULL;
  const char *base = path_basename_const(path);
  char name[512];
  for (int i = 0; i < 100; i++){
    snprintf(name, sizeof(name), ".%s.tmp.%ld.%d", base, (long)getpid(), i);
    char *candidate = join_path(dir, name);
    if (!candidate){ free(dir); return NULL; }
    if (platform_access_path_default(platform, candidate, F_OK) != 0){ free(dir); return candidate; }
    free(candidate);
  }
  free(dir); return NULL;
}

static char *platform_backup_path_for_default(const NetwatchPlatform *platform, const char *path){
  (void)platform;
  struct stat st;
  for (int i = 0; i <= 3; i++){
    size_t n = strlen(path) + 16;
    char *candidate = malloc(n); if (!candidate) return NULL;
    if (i == 0) snprintf(candidate, n, "%s.bak", path);
    else snprintf(candidate, n, "%s.bak.%d", path, i);
    if (lstat(candidate, &st) != 0){
      if (errno == ENOENT) return candidate;
      free(candidate); return NULL;
    }
    free(candidate);
  }
  errno = EEXIST;
  return NULL;
}

static int write_all_fd(int fd, const char *data, size_t len){
  while (len){
    ssize_t n = write(fd, data, len);
    if (n < 0){ if (errno == EINTR) continue; return 0; }
    data += n; len -= (size_t)n;
  }
  return 1;
}

static int platform_write_temp_file_default(const NetwatchPlatform *platform, const char *path, const char *text, mode_t mode, char *err, size_t err_len){
  (void)platform;
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode & 07777);
  if (fd < 0){ set_error(err, err_len, "failed to open temporary config: %s", strerror(errno)); return 0; }
  int ok = fchmod(fd, mode & 07777) == 0
    && write_all_fd(fd, text, strlen(text))
    && fsync(fd) == 0;
  if (close(fd) != 0) ok = 0;
  if (!ok){
    set_error(err, err_len, "failed to write temporary config: %s", strerror(errno));
    unlink(path);
  }
  return ok;
}

static int platform_copy_file_default(const NetwatchPlatform *platform, const char *src, const char *dst, mode_t mode, char *err, size_t err_len){
  (void)platform;
  int in = open(src, O_RDONLY);
  if (in < 0){ set_error(err, err_len, "failed to open backup source: %s", strerror(errno)); return 0; }
  int out = open(dst, O_WRONLY | O_CREAT | O_EXCL, mode & 07777);
  if (out < 0){ close(in); set_error(err, err_len, "failed to create backup: %s", strerror(errno)); return 0; }
  char buf[8192];
  int ok = 1;
  for (;;){
    ssize_t n = read(in, buf, sizeof(buf));
    if (n < 0){ if (errno == EINTR) continue; ok = 0; break; }
    if (!n) break;
    if (!write_all_fd(out, buf, (size_t)n)){ ok = 0; break; }
  }
  if (ok && fsync(out) != 0) ok = 0;
  if (close(out) != 0) ok = 0;
  close(in);
  if (!ok){
    set_error(err, err_len, "failed to copy backup: %s", strerror(errno));
    unlink(dst);
  }
  return ok;
}

static int platform_rename_path_default(const NetwatchPlatform *platform, const char *src, const char *dst, char *err, size_t err_len){
  (void)platform;
  if (rename(src, dst) == 0) return 1;
  set_error(err, err_len, "failed to replace config: %s", strerror(errno));
  return 0;
}

static int platform_unlink_path_default(const NetwatchPlatform *platform, const char *path){
  (void)platform;
  return unlink(path);
}

static void platform_fsync_parent_dir_default(const NetwatchPlatform *platform, const char *path){
  (void)platform;
  char *dir = path_dirname(path); if (!dir) return;
  int fd = open(dir, O_RDONLY);
  if (fd >= 0){ fsync(fd); close(fd); }
  free(dir);
}

static int bad_path_candidate(const char *p){
  static const char *bad[] = { ".strings", ".stringsdict", ".loctable", ".car", ".dat", ".db", ".sqlite", ".sqlite-shm", ".plist", ".png", ".jpg", ".jpeg", ".icns", ".nib", ".ttf", ".otf", ".dylib" };
  size_t len = strlen(p);
  for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++){
    size_t n = strlen(bad[i]);
    if (len >= n && !strcasecmp(p + len - n, bad[i])) return 1;
  }
  return 0;
}

static int good_path_candidate(const char *p){
  if (!p || bad_path_candidate(p)) return 0;
  static const char *prefixes[] = { "/Applications/", "/System/Applications/", "/System/Library/", "/System/Volumes/Preboot/Cryptexes/App/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/", "/opt/homebrew/" };
  for (size_t i = 0; i < sizeof(prefixes) / sizeof(*prefixes); i++) if (!strncmp(p, prefixes[i], strlen(prefixes[i]))) return 1;
  return 0;
}

static char *proc_pid_path(int pid){
#ifdef __APPLE__
  char buf[PROC_PIDPATHINFO_MAXSIZE];
  int len = proc_pidpath(pid, buf, sizeof(buf));
  return len > 0 ? xstrdup(buf) : NULL;
#else
  (void)pid; return NULL;
#endif
}

static int spawn_lines(char *const argv[], LineHandler handler, void *ctx, char *err, size_t err_len){
  int fds[2];
  if (pipe(fds) != 0){ set_error(err, err_len, "failed to create pipe for %s", argv[0]); return 0; }

  posix_spawn_file_actions_t actions;
  int rc = posix_spawn_file_actions_init(&actions);
  if (rc != 0){
    close(fds[0]); close(fds[1]);
    set_error(err, err_len, "failed to initialize spawn actions for %s: %d", argv[0], rc);
    return 0;
  }

  int devnull = open("/dev/null", O_RDWR);
  int actions_ok = posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO) == 0
    && posix_spawn_file_actions_addclose(&actions, fds[0]) == 0
    && posix_spawn_file_actions_addclose(&actions, fds[1]) == 0;
  if (devnull >= 0){
    actions_ok = actions_ok
      && posix_spawn_file_actions_adddup2(&actions, devnull, STDERR_FILENO) == 0
      && posix_spawn_file_actions_addclose(&actions, devnull) == 0;
  }
  if (!actions_ok){
    posix_spawn_file_actions_destroy(&actions);
    close(fds[0]); close(fds[1]);
    if (devnull >= 0) close(devnull);
    set_error(err, err_len, "failed to prepare spawn actions for %s", argv[0]);
    return 0;
  }

  pid_t pid = 0;
  rc = posix_spawnp(&pid, argv[0], &actions, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&actions);
  close(fds[1]);
  if (devnull >= 0) close(devnull);
  if (rc != 0){
    close(fds[0]);
    set_error(err, err_len, "failed to spawn %s: %d", argv[0], rc);
    return 0;
  }

  FILE *stream = fdopen(fds[0], "r");
  if (!stream){
    close(fds[0]);
    int ignored = 0; while (waitpid(pid, &ignored, 0) < 0 && errno == EINTR){}
    set_error(err, err_len, "failed to read output from %s", argv[0]);
    return 0;
  }

  int ok = 1;
  char *line = NULL; size_t cap = 0;
  while (getline(&line, &cap, stream) != -1){
    size_t n = strlen(line); if (n && line[n - 1] == '\n') line[n - 1] = 0;
    if (ok && !handler(line, ctx)){
      ok = 0;
      set_error(err, err_len, "failed to process output from %s", argv[0]);
    }
  }
  free(line);
  if (ferror(stream) && ok){ ok = 0; set_error(err, err_len, "failed to read output from %s", argv[0]); }
  fclose(stream);

  int status = 0;
  while (waitpid(pid, &status, 0) < 0){
    if (errno == EINTR) continue;
    set_error(err, err_len, "failed to wait for %s", argv[0]);
    return 0;
  }
  if (!WIFEXITED(status)){ set_error(err, err_len, "%s exited abnormally", argv[0]); return 0; }
  if (WEXITSTATUS(status) != 0){ set_error(err, err_len, "%s exited with status %d", argv[0], WEXITSTATUS(status)); return 0; }
  return ok;
}

static int add_lsof_candidate(StrList *paths, const char *line){
  if (line && line[0] == 'n' && good_path_candidate(line + 1)) return strlist_push(paths, line + 1);
  return 1;
}

static int add_lsof_candidate_line(const char *line, void *ctx){
  return add_lsof_candidate((StrList *)ctx, line);
}

static char *lsof_executable_path(int pid, const char *proc_name){
  StrList paths = {0};
  char pid_arg[32]; snprintf(pid_arg, sizeof(pid_arg), "%d", pid);
  char *argv[] = { "lsof", "-a", "-p", pid_arg, "-d", "txt", "-Fn", NULL };
  if (!spawn_lines(argv, add_lsof_candidate_line, &paths, NULL, 0)){ strlist_free(&paths); return NULL; }

  char *app = NULL, *system = NULL, *first = NULL;
  for (size_t i = 0; i < paths.len; i++){
    const char *base = strrchr(paths.items[i], '/'); base = base ? base + 1 : paths.items[i];
    if (!strncmp(base, proc_name, strlen(proc_name))){ char *out = xstrdup(paths.items[i]); strlist_free(&paths); return out; }
    if (!app && strstr(paths.items[i], ".app/Contents/")) app = paths.items[i];
    if (!system && (!strncmp(paths.items[i], "/System/", 8) || !strncmp(paths.items[i], "/usr/", 5) || !strncmp(paths.items[i], "/bin/", 5) || !strncmp(paths.items[i], "/sbin/", 6))) system = paths.items[i];
    if (!first) first = paths.items[i];
  }
  char *out = xstrdup(app ? app : system ? system : first ? first : "unknown");
  strlist_free(&paths); return out;
}

static char *platform_process_path_default(const NetwatchPlatform *platform, int pid, const char *proc_name){
  (void)platform;
  char *path = proc_pid_path(pid);
  if (!path) path = lsof_executable_path(pid, proc_name);
  return path ? path : xstrdup("unknown");
}

static int collect_connection_line(const char *line, void *ctx){
  if (!strstr(line, "ESTABLISHED") && !strstr(line, "LISTEN")) return 1;
  return strlist_push((StrList *)ctx, line);
}

static int platform_collect_connections_default(const NetwatchPlatform *platform, StrList *connections, char *err, size_t err_len){
  (void)platform;
  char *argv[] = { "lsof", "-i", "-n", "-P", NULL };
  return spawn_lines(argv, collect_connection_line, connections, err, err_len);
}

static AppleTrustResult platform_apple_trust_check_default(const NetwatchPlatform *platform, const char *path, char *reason, size_t reason_size){
  (void)platform;
  return apple_trust_check(path, reason, reason_size);
}

static int cfstring_to_buf(CFTypeRef value, char *out, size_t out_len){
  if (!value || CFGetTypeID(value) != CFStringGetTypeID() || !out || !out_len) return 0;
  return CFStringGetCString((CFStringRef)value, out, out_len, kCFStringEncodingUTF8);
}

static CodeSignatureIdentityResult platform_code_signature_identity_default(const NetwatchPlatform *platform, const char *path, CodeSignatureIdentity *identity, char *err, size_t err_len){
  (void)platform;
  if (identity) *identity = (CodeSignatureIdentity){0};
  if (!path || !*path || !identity){
    set_error(err, err_len, "missing executable path for code signature identity");
    return CODE_SIGNATURE_IDENTITY_SECURITY_ERROR;
  }

  CFStringRef path_string = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
  if (!path_string){
    set_error(err, err_len, "failed to create Security.framework path string");
    return CODE_SIGNATURE_IDENTITY_SECURITY_ERROR;
  }
  CFURLRef url = CFURLCreateWithFileSystemPath(NULL, path_string, kCFURLPOSIXPathStyle, false);
  CFRelease(path_string);
  if (!url){
    set_error(err, err_len, "failed to create Security.framework path URL");
    return CODE_SIGNATURE_IDENTITY_SECURITY_ERROR;
  }

  SecStaticCodeRef code = NULL;
  OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
  CFRelease(url);
  if (status != errSecSuccess){
    set_error(err, err_len, "failed to create static code object: %d", (int)status);
    return CODE_SIGNATURE_IDENTITY_SECURITY_ERROR;
  }

  CodeSignatureIdentityResult result = CODE_SIGNATURE_IDENTITY_SECURITY_ERROR;
  status = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
  if (status != errSecSuccess){
    set_error(err, err_len, "code signature invalid: %d", (int)status);
    result = CODE_SIGNATURE_IDENTITY_INVALID_SIGNATURE;
    goto done;
  }

  CFDictionaryRef info = NULL;
  status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
  if (status != errSecSuccess || !info){
    set_error(err, err_len, "failed to copy code signing information: %d", (int)status);
    result = CODE_SIGNATURE_IDENTITY_SECURITY_ERROR;
    goto done;
  }
  int has_team = cfstring_to_buf(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), identity->team_id, sizeof(identity->team_id));
  int has_identifier = cfstring_to_buf(CFDictionaryGetValue(info, kSecCodeInfoIdentifier), identity->signing_identifier, sizeof(identity->signing_identifier));
  CFRelease(info);
  if (!has_team || !has_identifier){
    set_error(err, err_len, "code signature identity metadata unavailable");
    result = CODE_SIGNATURE_IDENTITY_METADATA_UNAVAILABLE;
    goto done;
  }
  result = CODE_SIGNATURE_IDENTITY_OK;

done:
  CFRelease(code);
  return result;
}

static int platform_disable_wifi_default(const NetwatchPlatform *platform, const char *interface, char *err, size_t err_len){
  (void)platform;
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

static time_t platform_now_default(const NetwatchPlatform *platform){
  (void)platform;
  return time(NULL);
}

static void platform_sleep_seconds_default(const NetwatchPlatform *platform, unsigned int seconds){
  (void)platform;
  sleep(seconds);
}

static int spawn_quiet(char *const argv[]){
  posix_spawn_file_actions_t actions;
  if (posix_spawn_file_actions_init(&actions) != 0) return -1;
  int devnull = open("/dev/null", O_RDWR);
  if (devnull >= 0){
    posix_spawn_file_actions_adddup2(&actions, devnull, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, devnull, STDERR_FILENO);
  }
  pid_t pid = 0;
  int rc = posix_spawnp(&pid, argv[0], &actions, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&actions);
  if (devnull >= 0) close(devnull);
  if (rc != 0) return -1;
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return -1;
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int platform_launchd_service_loaded_default(const NetwatchPlatform *platform, const char *label){
  (void)platform;
  char target[256];
  snprintf(target, sizeof(target), "gui/%d/%s", (int)getuid(), label);
  char *argv[] = { "launchctl", "print", target, NULL };
  int rc = spawn_quiet(argv);
  return rc < 0 ? -1 : rc == 0;
}

static int same_path(const char *left, const char *right){
  char left_real[PATH_MAX], right_real[PATH_MAX];
  const char *l = realpath(left, left_real) ? left_real : left;
  const char *r = realpath(right, right_real) ? right_real : right;
  return l && r && !strcmp(l, r);
}

static int platform_find_process_by_executable_default(const NetwatchPlatform *platform, const char *expected_path, int *pid_out, char *path, size_t path_size){
  (void)platform;
#ifdef __APPLE__
  int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
  if (bytes <= 0) return -1;
  pid_t *pids = calloc(1, (size_t)bytes);
  if (!pids) return -1;
  bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes);
  if (bytes <= 0){ free(pids); return -1; }
  int count = bytes / (int)sizeof(pid_t);
  for (int i = 0; i < count; i++){
    if (!pids[i] || pids[i] == getpid()) continue;
    char proc_path[PROC_PIDPATHINFO_MAXSIZE];
    int len = proc_pidpath(pids[i], proc_path, sizeof(proc_path));
    if (len <= 0) continue;
    proc_path[len < (int)sizeof(proc_path) ? len : (int)sizeof(proc_path) - 1] = 0;
    if (!same_path(proc_path, expected_path)) continue;
    if (pid_out) *pid_out = pids[i];
    if (path && path_size) snprintf(path, path_size, "%s", proc_path);
    free(pids); return 1;
  }
  free(pids); return 0;
#else
  (void)expected_path; (void)pid_out; (void)path; (void)path_size;
  return -1;
#endif
}

static const NetwatchPlatform default_platform = {
  .read_file = platform_read_file_default,
  .access_path = platform_access_path_default,
  .stat_path = platform_stat_path_default,
  .temp_path_for = platform_temp_path_for_default,
  .backup_path_for = platform_backup_path_for_default,
  .write_temp_file = platform_write_temp_file_default,
  .copy_file = platform_copy_file_default,
  .rename_path = platform_rename_path_default,
  .unlink_path = platform_unlink_path_default,
  .fsync_parent_dir = platform_fsync_parent_dir_default,
  .collect_connections = platform_collect_connections_default,
  .process_path = platform_process_path_default,
  .apple_trust_check = platform_apple_trust_check_default,
  .code_signature_identity = platform_code_signature_identity_default,
  .disable_wifi = platform_disable_wifi_default,
  .now = platform_now_default,
  .sleep_seconds = platform_sleep_seconds_default,
  .launchd_service_loaded = platform_launchd_service_loaded_default,
  .find_process_by_executable = platform_find_process_by_executable_default
};

const NetwatchPlatform *netwatch_platform_default(void){ return &default_platform; }

const NetwatchPlatform *netwatch_platform_or_default(const NetwatchPlatform *platform){
  return platform ? platform : &default_platform;
}
