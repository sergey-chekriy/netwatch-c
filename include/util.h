#ifndef NETWATCH_UTIL_H
#define NETWATCH_UTIL_H

#include <stddef.h>

char *xstrdup(const char *s);
char *read_file(const char *path, char *err, size_t err_len);
const char *home_dir(void);
void set_error(char *err, size_t err_len, const char *fmt, ...);
int path_has_prefix_rule(const char *actual, const char *rule);

#endif
