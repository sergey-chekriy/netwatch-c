#include "strlist.h"
#include "util.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void strlist_free(StrList *list){
  if (!list) return;
  for (size_t i = 0; i < list->len; i++) free(list->items[i]);
  free(list->items); *list = (StrList){0};
}

int strlist_push(StrList *list, const char *value){
  if (list->len == list->cap){
    size_t cap = list->cap ? list->cap * 2 : 8;
    char **items = realloc(list->items, cap * sizeof(*items));
    if (!items) return 0;
    list->items = items; list->cap = cap;
  }
  return (list->items[list->len] = xstrdup(value)) ? (++list->len, 1) : 0;
}

static int contains_ci(const char *s, const char *needle){
  if (!s || !needle) return 0;
  size_t n = strlen(needle); if (!n) return 1;
  for (; *s; s++){
    size_t i = 0;
    for (; i < n && s[i]; i++){
      if (tolower((unsigned char)s[i]) != tolower((unsigned char)needle[i])) break;
    }
    if (i == n) return 1;
  }
  return 0;
}

const char *strlist_find_contains_ci(const StrList *list, const char *text){
  for (size_t i = 0; list && i < list->len; i++) if (contains_ci(text, list->items[i])) return list->items[i];
  return NULL;
}

int strlist_has_contains_ci(const StrList *list, const char *text){
  return strlist_find_contains_ci(list, text) != NULL;
}
