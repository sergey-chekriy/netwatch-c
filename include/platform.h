#ifndef NETWATCH_PLATFORM_H
#define NETWATCH_PLATFORM_H

#include "apple_trust.h"
#include "strlist.h"
#include "trusted_publisher.h"
#include <stddef.h>
#include <sys/stat.h>
#include <time.h>

typedef struct NetwatchPlatform NetwatchPlatform;

struct NetwatchPlatform {
  void *ctx;
  char *(*read_file)(const NetwatchPlatform *platform, const char *path, char *err, size_t err_len);
  int (*access_path)(const NetwatchPlatform *platform, const char *path, int mode);
  int (*stat_path)(const NetwatchPlatform *platform, const char *path, struct stat *st);
  char *(*temp_path_for)(const NetwatchPlatform *platform, const char *path);
  char *(*backup_path_for)(const NetwatchPlatform *platform, const char *path);
  int (*write_temp_file)(const NetwatchPlatform *platform, const char *path, const char *text, mode_t mode, char *err, size_t err_len);
  int (*copy_file)(const NetwatchPlatform *platform, const char *src, const char *dst, mode_t mode, char *err, size_t err_len);
  int (*rename_path)(const NetwatchPlatform *platform, const char *src, const char *dst, char *err, size_t err_len);
  int (*unlink_path)(const NetwatchPlatform *platform, const char *path);
  void (*fsync_parent_dir)(const NetwatchPlatform *platform, const char *path);
  int (*collect_connections)(const NetwatchPlatform *platform, StrList *connections, char *err, size_t err_len);
  char *(*process_path)(const NetwatchPlatform *platform, int pid, const char *proc_name);
  AppleTrustResult (*apple_trust_check)(const NetwatchPlatform *platform, const char *path, char *reason, size_t reason_size);
  CodeSignatureIdentityResult (*code_signature_identity)(const NetwatchPlatform *platform, const char *path, CodeSignatureIdentity *identity, char *err, size_t err_len);
  int (*disable_wifi)(const NetwatchPlatform *platform, const char *interface, char *err, size_t err_len);
  time_t (*now)(const NetwatchPlatform *platform);
  void (*sleep_seconds)(const NetwatchPlatform *platform, unsigned int seconds);
  int (*launchd_service_loaded)(const NetwatchPlatform *platform, const char *label);
  int (*find_process_by_executable)(const NetwatchPlatform *platform, const char *expected_path, int *pid, char *path, size_t path_size);
};

const NetwatchPlatform *netwatch_platform_default(void);
const NetwatchPlatform *netwatch_platform_or_default(const NetwatchPlatform *platform);

#endif
