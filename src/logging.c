#include "logging.h"
#include "util.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static int mkdir_p_for_file(const char *path){
  char *copy = xstrdup(path); if (!copy) return 0;
  char *slash = strrchr(copy, '/');
  if (!slash){ free(copy); return 1; }
  *slash = 0;
  for (char *p = copy + 1; *p; p++){
    if (*p == '/'){
      *p = 0;
      if (mkdir(copy, 0755) && errno != EEXIST){ free(copy); return 0; }
      *p = '/';
    }
  }
  int ok = !mkdir(copy, 0755) || errno == EEXIST;
  free(copy); return ok;
}

char *default_log_path(void){
  const char *home = home_dir();
  size_t n = strlen(home) + strlen("/.watch/netwatch.log") + 1;
  char *out = malloc(n); if (out) snprintf(out, n, "%s/.watch/netwatch.log", home);
  return out;
}

int log_message_with_platform(const char *log_path, const char *msg, const NetwatchPlatform *platform, char *err, size_t err_len){
  if (!mkdir_p_for_file(log_path)){ set_error(err, err_len, "failed to create log directory"); return 0; }
  FILE *f = fopen(log_path, "a");
  if (!f){ set_error(err, err_len, "failed to open log %s", log_path); return 0; }
  platform = netwatch_platform_or_default(platform);
  time_t now = platform->now ? platform->now(platform) : time(NULL);
  struct tm tm_utc;
#if defined(_WIN32)
  gmtime_s(&tm_utc, &now);
#else
  gmtime_r(&now, &tm_utc);
#endif
  char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
  fprintf(f, "[%s] %s\n", ts, msg);
  fclose(f); return 1;
}

int log_message(const char *log_path, const char *msg, char *err, size_t err_len){
  return log_message_with_platform(log_path, msg, netwatch_platform_default(), err, err_len);
}
