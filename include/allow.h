#ifndef NETWATCH_ALLOW_H
#define NETWATCH_ALLOW_H

#include "config.h"
#include "process.h"
#include <stdbool.h>

bool connection_allowed(const char *line, const Config *cfg, PathCache *cache);
char *describe_connection(const char *line, PathCache *cache);

#endif
