#include "cJSON.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const char *p; } Parser;

static void skip_ws(Parser *ps){ while (*ps->p && isspace((unsigned char)*ps->p)) ps->p++; }
static cJSON *parse_value(Parser *ps);

static cJSON *new_item(int type){
  cJSON *item = calloc(1, sizeof(*item)); if (item) item->type = type; return item;
}

static void append_child(cJSON *parent, cJSON *child){
  if (!parent->child){ parent->child = child; return; }
  cJSON *it = parent->child; while (it->next) it = it->next; it->next = child;
}

static char hex_val(char c){
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int append_char(char **buf, size_t *len, size_t *cap, char c){
  if (*len + 1 >= *cap){
    size_t next = *cap ? *cap * 2 : 32;
    char *tmp = realloc(*buf, next); if (!tmp) return 0;
    *buf = tmp; *cap = next;
  }
  (*buf)[(*len)++] = c; return 1;
}

static char *parse_string_raw(Parser *ps){
  if (*ps->p != '"') return NULL;
  ps->p++;
  char *buf = NULL; size_t len = 0, cap = 0;
  while (*ps->p && *ps->p != '"'){
    unsigned char c = (unsigned char)*ps->p++;
    if (c == '\\'){
      c = (unsigned char)*ps->p++;
      if (c == '"' || c == '\\' || c == '/'){}
      else if (c == 'b') c = '\b';
      else if (c == 'f') c = '\f';
      else if (c == 'n') c = '\n';
      else if (c == 'r') c = '\r';
      else if (c == 't') c = '\t';
      else if (c == 'u'){
        char h1 = hex_val(ps->p[0]), h2 = hex_val(ps->p[1]);
        char h3 = hex_val(ps->p[2]), h4 = hex_val(ps->p[3]);
        if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0){ free(buf); return NULL; }
        unsigned code = ((unsigned)h1 << 12) | ((unsigned)h2 << 8) | ((unsigned)h3 << 4) | (unsigned)h4;
        ps->p += 4;
        c = code < 0x80 ? (unsigned char)code : '?';
      } else { free(buf); return NULL; }
    }
    if (!append_char(&buf, &len, &cap, (char)c)){ free(buf); return NULL; }
  }
  if (*ps->p != '"'){ free(buf); return NULL; }
  ps->p++;
  if (!append_char(&buf, &len, &cap, 0)){ free(buf); return NULL; }
  return buf;
}

static cJSON *parse_string(Parser *ps){
  cJSON *item = new_item(cJSON_String); if (!item) return NULL;
  item->valuestring = parse_string_raw(ps);
  if (!item->valuestring){ cJSON_Delete(item); return NULL; }
  return item;
}

static cJSON *parse_literal(Parser *ps, const char *lit, int type){
  size_t n = strlen(lit); if (strncmp(ps->p, lit, n)) return NULL;
  ps->p += n; return new_item(type);
}

static cJSON *parse_array(Parser *ps){
  if (*ps->p != '[') return NULL;
  ps->p++; skip_ws(ps);
  cJSON *array = new_item(cJSON_Array); if (!array) return NULL;
  if (*ps->p == ']'){ ps->p++; return array; }
  for (;;){
    cJSON *child = parse_value(ps); if (!child){ cJSON_Delete(array); return NULL; }
    append_child(array, child); skip_ws(ps);
    if (*ps->p == ']'){ ps->p++; return array; }
    if (*ps->p != ','){ cJSON_Delete(array); return NULL; }
    ps->p++; skip_ws(ps);
  }
}

static cJSON *parse_object(Parser *ps){
  if (*ps->p != '{') return NULL;
  ps->p++; skip_ws(ps);
  cJSON *object = new_item(cJSON_Object); if (!object) return NULL;
  if (*ps->p == '}'){ ps->p++; return object; }
  for (;;){
    char *key = parse_string_raw(ps); if (!key){ cJSON_Delete(object); return NULL; }
    skip_ws(ps);
    if (*ps->p != ':'){ free(key); cJSON_Delete(object); return NULL; }
    ps->p++; skip_ws(ps);
    cJSON *child = parse_value(ps); if (!child){ free(key); cJSON_Delete(object); return NULL; }
    child->string = key; append_child(object, child); skip_ws(ps);
    if (*ps->p == '}'){ ps->p++; return object; }
    if (*ps->p != ','){ cJSON_Delete(object); return NULL; }
    ps->p++; skip_ws(ps);
  }
}

static cJSON *parse_value(Parser *ps){
  skip_ws(ps);
  if (*ps->p == '{') return parse_object(ps);
  if (*ps->p == '[') return parse_array(ps);
  if (*ps->p == '"') return parse_string(ps);
  if (!strncmp(ps->p, "true", 4)) return parse_literal(ps, "true", cJSON_True);
  if (!strncmp(ps->p, "false", 5)) return parse_literal(ps, "false", cJSON_False);
  if (!strncmp(ps->p, "null", 4)) return parse_literal(ps, "null", cJSON_NULL);
  return NULL;
}

cJSON *cJSON_Parse(const char *text){
  if (!text) return NULL;
  Parser ps = { text };
  cJSON *root = parse_value(&ps); if (!root) return NULL;
  skip_ws(&ps);
  if (*ps.p){ cJSON_Delete(root); return NULL; }
  return root;
}

void cJSON_Delete(cJSON *item){
  while (item){
    cJSON *next = item->next;
    cJSON_Delete(item->child);
    free(item->valuestring);
    free(item->string);
    free(item);
    item = next;
  }
}

cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *object, const char *string){
  if (!cJSON_IsObject(object) || !string) return NULL;
  for (cJSON *it = object->child; it; it = it->next){
    if (it->string && !strcmp(it->string, string)) return it;
  }
  return NULL;
}

int cJSON_GetArraySize(const cJSON *array){
  if (!cJSON_IsArray(array)) return 0;
  int n = 0; for (cJSON *it = array->child; it; it = it->next) n++; return n;
}

cJSON *cJSON_GetArrayItem(const cJSON *array, int index){
  if (!cJSON_IsArray(array) || index < 0) return NULL;
  int i = 0; for (cJSON *it = array->child; it; it = it->next, i++) if (i == index) return it;
  return NULL;
}
