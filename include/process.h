#ifndef NETWATCH_PROCESS_H
#define NETWATCH_PROCESS_H

#include "platform.h"
#include "strlist.h"
#include <stddef.h>

typedef struct { int pid; char *path; } PathCacheEntry;
typedef struct { PathCacheEntry *items; size_t len; size_t cap; } PathCache;

void path_cache_free(PathCache *cache);
char *process_path_cached_with_platform(PathCache *cache, int pid, const char *proc_name, const NetwatchPlatform *platform);
char *process_path_cached(PathCache *cache, int pid, const char *proc_name);
int collect_connections_with_platform(StrList *connections, const NetwatchPlatform *platform, char *err, size_t err_len);
int collect_connections(StrList *connections, char *err, size_t err_len);
const char *process_name_of(const char *line);
int pid_of(const char *line, int *pid);
char *remote_of(const char *line);

#endif
