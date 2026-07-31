#ifndef NETWATCH_STRLIST_H
#define NETWATCH_STRLIST_H

#include <stddef.h>

typedef struct { char **items; size_t len; size_t cap; } StrList;

void strlist_free(StrList *list);
int strlist_push(StrList *list, const char *value);
const char *strlist_find_contains_ci(const StrList *list, const char *text);
int strlist_has_contains_ci(const StrList *list, const char *text);

#endif
