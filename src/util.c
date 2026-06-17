#include "util.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void set_error(char *err, size_t err_len, const char *fmt, ...){
  if (!err || !err_len) return;
  va_list ap; va_start(ap, fmt); vsnprintf(err, err_len, fmt, ap); va_end(ap);
}

char *xstrdup(const char *s){
  if (!s) return NULL;
  size_t n = strlen(s) + 1;
  char *out = malloc(n); if (out) memcpy(out, s, n);
  return out;
}

char *read_file(const char *path, char *err, size_t err_len){
  FILE *f = fopen(path, "rb");
  if (!f){ set_error(err, err_len, "failed to open %s", path); return NULL; }
  if (fseek(f, 0, SEEK_END) != 0){ fclose(f); set_error(err, err_len, "failed to seek %s", path); return NULL; }
  long size = ftell(f);
  if (size < 0){ fclose(f); set_error(err, err_len, "failed to read size of %s", path); return NULL; }
  rewind(f);
  char *buf = malloc((size_t)size + 1);
  if (!buf){ fclose(f); set_error(err, err_len, "out of memory reading %s", path); return NULL; }
  size_t got = fread(buf, 1, (size_t)size, f);
  fclose(f);
  if (got != (size_t)size){ free(buf); set_error(err, err_len, "short read of %s", path); return NULL; }
  buf[got] = 0; return buf;
}

const char *home_dir(void){
  const char *home = getenv("HOME"); return home && *home ? home : ".";
}

int path_has_prefix_rule(const char *actual, const char *rule){
  if (!actual || !rule) return 0;
  size_t n = strlen(rule);
  return n && rule[n - 1] == '*' ? !strncmp(actual, rule, n - 1) : !strcmp(actual, rule);
}
