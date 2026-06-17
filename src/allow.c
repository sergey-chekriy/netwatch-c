#include "allow.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const ProcessRule *find_rule(const Config *cfg, const char *proc){
  for (size_t i = 0; i < cfg->allow_processes.len; i++){
    if (!strcmp(cfg->allow_processes.items[i].process, proc)) return &cfg->allow_processes.items[i];
  }
  return NULL;
}

static int localhost_listen(const char *line){
  return strstr(line, "LISTEN") && (strstr(line, "127.0.0.1") || strstr(line, "localhost"));
}

static int process_allowed(const char *line, const Config *cfg, PathCache *cache){
  const char *proc = process_name_of(line);
  const ProcessRule *rule = find_rule(cfg, proc);
  if (!rule) return 0;
  int pid = 0;
  if (!pid_of(line, &pid)) return 0;
  char *actual = process_path_cached(cache, pid, proc);
  int ok = 0;
  for (size_t i = 0; actual && i < rule->paths.len; i++){
    if (path_has_prefix_rule(actual, rule->paths.items[i])){ ok = 1; break; }
  }
  free(actual); return ok;
}

static int remote_allowed(const char *line, const Config *cfg){
  char *remote = remote_of(line); if (!remote) return 0;
  int ok = 0;
  for (size_t i = 0; i < cfg->allow_remote_hosts.len; i++){
    if (!strncmp(remote, cfg->allow_remote_hosts.items[i], strlen(cfg->allow_remote_hosts.items[i]))){ ok = 1; break; }
  }
  free(remote); return ok;
}

bool connection_allowed(const char *line, const Config *cfg, PathCache *cache){
  if (strlist_has_contains_ci(&cfg->deny_patterns, line)) return false;
  if (localhost_listen(line)) return true;
  if (process_allowed(line, cfg, cache)) return true;
  return remote_allowed(line, cfg);
}

char *describe_connection(const char *line, PathCache *cache){
  const char *proc = process_name_of(line);
  int pid = 0;
  char *path = pid_of(line, &pid) ? process_path_cached(cache, pid, proc) : xstrdup("unknown");
  if (!path) return NULL;
  size_t n = strlen(line) + strlen(path) + 10;
  char *out = malloc(n);
  if (out) snprintf(out, n, "%s\n  PATH: %s", line, path);
  free(path); return out;
}
