#ifndef NETWATCH_CONFIG_H
#define NETWATCH_CONFIG_H

#include "strlist.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct { char *process; StrList paths; } ProcessRule;
typedef struct { ProcessRule *items; size_t len; size_t cap; } ProcessRules;

typedef struct {
  bool dry_run;
  char *interface;
  char *log_path;
  StrList deny_patterns;
  StrList allow_remote_hosts;
  ProcessRules allow_processes;
} Config;

int config_load(Config *cfg, const char *path, char *err, size_t err_len);
void config_free(Config *cfg);

#endif
