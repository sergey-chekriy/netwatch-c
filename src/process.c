#include "process.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#ifdef __APPLE__
#include <libproc.h>
#endif

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

static char *proc_pid_path(int pid){
#ifdef __APPLE__
  char buf[PROC_PIDPATHINFO_MAXSIZE];
  int len = proc_pidpath(pid, buf, sizeof(buf));
  return len > 0 ? xstrdup(buf) : NULL;
#else
  (void)pid; return NULL;
#endif
}

static void add_lsof_candidate(StrList *paths, const char *line){
  if (line && line[0] == 'n' && good_path_candidate(line + 1)) strlist_push(paths, line + 1);
}

static char *lsof_executable_path(int pid, const char *proc_name){
  char cmd[128]; snprintf(cmd, sizeof(cmd), "lsof -a -p %d -d txt -Fn 2>/dev/null", pid);
  FILE *pipe = popen(cmd, "r"); if (!pipe) return NULL;
  StrList paths = {0};
  char *line = NULL; size_t cap = 0;
  while (getline(&line, &cap, pipe) != -1){
    size_t n = strlen(line); if (n && line[n - 1] == '\n') line[n - 1] = 0;
    add_lsof_candidate(&paths, line);
  }
  free(line); pclose(pipe);

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

char *process_path_cached(PathCache *cache, int pid, const char *proc_name){
  char *cached = path_cache_get(cache, pid); if (cached) return cached;
  char *path = proc_pid_path(pid);
  if (!path) path = lsof_executable_path(pid, proc_name);
  if (!path) path = xstrdup("unknown");
  path_cache_put(cache, pid, path);
  return path;
}

int collect_connections(StrList *connections, char *err, size_t err_len){
  FILE *pipe = popen("lsof -i -n -P", "r");
  if (!pipe){ set_error(err, err_len, "failed to run lsof"); return 0; }
  char *line = NULL; size_t cap = 0;
  while (getline(&line, &cap, pipe) != -1){
    if (!strstr(line, "ESTABLISHED") && !strstr(line, "LISTEN")) continue;
    size_t n = strlen(line); if (n && line[n - 1] == '\n') line[n - 1] = 0;
    if (!strlist_push(connections, line)){ free(line); pclose(pipe); set_error(err, err_len, "out of memory collecting connections"); return 0; }
  }
  free(line);
  int rc = pclose(pipe);
  if (rc != 0){ set_error(err, err_len, "lsof exited with status %d", rc); return 0; }
  return 1;
}
