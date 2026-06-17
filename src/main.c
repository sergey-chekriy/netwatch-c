#include "allow.h"
#include "config.h"
#include "logging.h"
#include "process.h"
#include "strlist.h"
#include "util.h"
#include "wifi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char *join_suspicious(StrList *items){
  size_t n = 1;
  for (size_t i = 0; i < items->len; i++) n += strlen(items->items[i]) + 1;
  char *out = calloc(1, n); if (!out) return NULL;
  for (size_t i = 0; i < items->len; i++){
    strcat(out, items->items[i]);
    if (i + 1 < items->len) strcat(out, "\n");
  }
  return out;
}

static void print_ok(void){
  time_t now = time(NULL);
  struct tm tm_utc;
#if defined(_WIN32)
  gmtime_s(&tm_utc, &now);
#else
  gmtime_r(&now, &tm_utc);
#endif
  char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
  printf("[%s] OK\n", ts);
}

static int run(const char *cfg_path){
  char err[512] = {0};
  Config cfg = {0};
  if (!config_load(&cfg, cfg_path, err, sizeof(err))){ fprintf(stderr, "ERROR: %s\n", err); return 1; }

  StrList connections = {0}, suspicious = {0};
  PathCache cache = {0};
  int rc = 0;
  if (!collect_connections(&connections, err, sizeof(err))){ fprintf(stderr, "ERROR: %s\n", err); rc = 1; goto done; }

  for (size_t i = 0; i < connections.len; i++){
    if (connection_allowed(connections.items[i], &cfg, &cache)) continue;
    char *desc = describe_connection(connections.items[i], &cache);
    if (!desc || !strlist_push(&suspicious, desc)){ free(desc); fprintf(stderr, "ERROR: out of memory\n"); rc = 1; goto done; }
    free(desc);
  }

  if (suspicious.len){
    char *reason = join_suspicious(&suspicious);
    if (!reason){ fprintf(stderr, "ERROR: out of memory\n"); rc = 1; goto done; }
    if (!disable_wifi_if_needed(&cfg, reason, isatty(STDOUT_FILENO), err, sizeof(err))){
      fprintf(stderr, "ERROR: %s\n", err); rc = 1;
    }
    free(reason);
  } else if (isatty(STDOUT_FILENO)) print_ok();

done:
  path_cache_free(&cache);
  strlist_free(&connections);
  strlist_free(&suspicious);
  config_free(&cfg);
  return rc;
}

int main(int argc, char **argv){
  return run(argc > 1 ? argv[1] : "./netwatch.config.json");
}
