#include "process.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void path_cache_free(PathCache *cache){
  if (!cache) return;
  for (size_t i = 0; i < cache->len; i++) free(cache->items[i].path);
  free(cache->items); *cache = (PathCache){0};
}

static char *path_cache_get(PathCache *cache, int pid){
  for (size_t i = 0; cache && i < cache->len; i++) if (cache->items[i].pid == pid) return xstrdup(cache->items[i].path);
  return NULL;
}

static int path_cache_put(PathCache *cache, int pid, const char *path){
  if (cache->len == cache->cap){
    size_t cap = cache->cap ? cache->cap * 2 : 32;
    PathCacheEntry *items = realloc(cache->items, cap * sizeof(*items));
    if (!items) return 0;
    cache->items = items; cache->cap = cap;
  }
  cache->items[cache->len].pid = pid;
  cache->items[cache->len].path = xstrdup(path ? path : "unknown");
  return cache->items[cache->len].path ? (++cache->len, 1) : 0;
}

const char *process_name_of(const char *line){
  static char proc[128];
  size_t i = 0;
  while (line && line[i] && line[i] != ' ' && line[i] != '\t' && i + 1 < sizeof(proc)){
    proc[i] = line[i]; i++;
  }
  proc[i] = 0; return proc;
}

int pid_of(const char *line, int *pid){
  char proc[128];
  return line && sscanf(line, "%127s %d", proc, pid) == 2;
}

char *remote_of(const char *line){
  const char *arrow = strstr(line ? line : "", "->");
  if (!arrow) return xstrdup("");
  arrow += 2;
  while (*arrow == ' ' || *arrow == '\t') arrow++;
  const char *end = arrow;
  while (*end && *end != ' ' && *end != '\t' && *end != '(') end++;
  char *out = malloc((size_t)(end - arrow) + 1);
  if (!out) return NULL;
  memcpy(out, arrow, (size_t)(end - arrow)); out[end - arrow] = 0; return out;
}

char *process_path_cached_with_platform(PathCache *cache, int pid, const char *proc_name, const NetwatchPlatform *platform){
  char *cached = path_cache_get(cache, pid); if (cached) return cached;
  platform = netwatch_platform_or_default(platform);
  char *path = platform->process_path(platform, pid, proc_name);
  if (!path) path = xstrdup("unknown");
  path_cache_put(cache, pid, path);
  return path;
}

char *process_path_cached(PathCache *cache, int pid, const char *proc_name){
  return process_path_cached_with_platform(cache, pid, proc_name, netwatch_platform_default());
}

int collect_connections_with_platform(StrList *connections, const NetwatchPlatform *platform, char *err, size_t err_len){
  platform = netwatch_platform_or_default(platform);
  return platform->collect_connections(platform, connections, err, err_len);
}

int collect_connections(StrList *connections, char *err, size_t err_len){
  return collect_connections_with_platform(connections, netwatch_platform_default(), err, err_len);
}
