#include "config_convert.h"
#include "config.h"
#include "config_json.h"
#include "cJSON.h"
#include "util.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct { char *data; size_t len; size_t cap; } Buffer;
typedef struct { char *process; char *path; char *reason; } ConvertNote;
typedef struct { ConvertNote *items; size_t len; size_t cap; } ConvertNotes;

typedef struct {
  size_t removed;
  size_t preserved;
  size_t ambiguous;
  ConvertNotes removed_notes;
  ConvertNotes preserved_notes;
} ConvertSummary;

typedef struct { char **items; size_t len; size_t cap; } Lines;
typedef struct { char type; const char *line; } DiffOp;
typedef struct { DiffOp *items; size_t len; size_t cap; } DiffOps;
typedef struct { const cJSON *item; int rank; size_t index; } JsonObjectItem;

static int fail_msg(const char *fmt, ...){
  va_list ap;
  fprintf(stderr, "ERROR: ");
  va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
  fputc('\n', stderr);
  return 1;
}

static int buf_reserve(Buffer *buf, size_t add){
  if (buf->len + add + 1 <= buf->cap) return 1;
  size_t cap = buf->cap ? buf->cap * 2 : 256;
  while (cap < buf->len + add + 1) cap *= 2;
  char *data = realloc(buf->data, cap); if (!data) return 0;
  buf->data = data; buf->cap = cap; return 1;
}

static int buf_append_n(Buffer *buf, const char *s, size_t n){
  if (!buf_reserve(buf, n)) return 0;
  memcpy(buf->data + buf->len, s, n);
  buf->len += n; buf->data[buf->len] = 0; return 1;
}

static int buf_append(Buffer *buf, const char *s){ return buf_append_n(buf, s, strlen(s)); }
static int buf_append_char(Buffer *buf, char c){ return buf_append_n(buf, &c, 1); }

static int buf_indent(Buffer *buf, int indent){
  for (int i = 0; i < indent; i++) if (!buf_append_char(buf, ' ')) return 0;
  return 1;
}

static int json_print_value(Buffer *buf, const cJSON *item, int indent, int depth);

static int json_print_string(Buffer *buf, const char *s){
  static const char hex[] = "0123456789abcdef";
  if (!buf_append_char(buf, '"')) return 0;
  for (; s && *s; s++){
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\'){
      if (!buf_append_char(buf, '\\') || !buf_append_char(buf, (char)c)) return 0;
    } else if (c == '\n'){
      if (!buf_append(buf, "\\n")) return 0;
    } else if (c == '\r'){
      if (!buf_append(buf, "\\r")) return 0;
    } else if (c == '\t'){
      if (!buf_append(buf, "\\t")) return 0;
    } else if (c < 32){
      char esc[] = "\\u00xx";
      esc[4] = hex[c >> 4]; esc[5] = hex[c & 15];
      if (!buf_append(buf, esc)) return 0;
    } else if (!buf_append_char(buf, (char)c)) return 0;
  }
  return buf_append_char(buf, '"');
}

static int json_print_array(Buffer *buf, const cJSON *item, int indent, int depth){
  if (!item->child) return buf_append(buf, "[]");
  if (!buf_append(buf, "[\n")) return 0;
  for (const cJSON *it = item->child; it; it = it->next){
    if (!buf_indent(buf, indent + 2) || !json_print_value(buf, it, indent + 2, depth + 1)) return 0;
    if (it->next && !buf_append_char(buf, ',')) return 0;
    if (!buf_append_char(buf, '\n')) return 0;
  }
  return buf_indent(buf, indent) && buf_append_char(buf, ']');
}

static int top_level_key_rank(const char *key){
  static const char *keys[] = {
    "version",
    "dryRun",
    "daemon",
    "allowAppleSystemComponents",
    "trustedPublishers",
    "trustedAppBundles",
    "trustedWorkspaces",
    "interface",
    "logPath",
    "verboseLog",
    "denyPatterns",
    "allowProcesses",
    "allowRemoteHosts"
  };
  for (size_t i = 0; i < sizeof(keys) / sizeof(*keys); i++) if (key && !strcmp(key, keys[i])) return (int)i;
  return 1000;
}

static int json_object_item_cmp(const void *a, const void *b){
  const JsonObjectItem *left = a, *right = b;
  if (left->rank != right->rank) return left->rank < right->rank ? -1 : 1;
  const char *lk = left->item->string ? left->item->string : "";
  const char *rk = right->item->string ? right->item->string : "";
  int key_cmp = strcmp(lk, rk);
  if (key_cmp) return key_cmp;
  if (left->index == right->index) return 0;
  return left->index < right->index ? -1 : 1;
}

static JsonObjectItem *json_object_items(const cJSON *object, int depth, size_t *count){
  *count = 0;
  for (const cJSON *it = object->child; it; it = it->next) (*count)++;
  if (!*count) return NULL;
  JsonObjectItem *items = malloc(*count * sizeof(*items)); if (!items) return NULL;
  size_t i = 0;
  for (const cJSON *it = object->child; it; it = it->next, i++){
    items[i] = (JsonObjectItem){
      .item = it,
      .rank = depth == 0 ? top_level_key_rank(it->string) : 1000,
      .index = i
    };
  }
  qsort(items, *count, sizeof(*items), json_object_item_cmp);
  return items;
}

static int json_print_object(Buffer *buf, const cJSON *item, int indent, int depth){
  if (!item->child) return buf_append(buf, "{}");
  if (!buf_append(buf, "{\n")) return 0;
  int ok = 0;
  size_t count = 0;
  JsonObjectItem *items = json_object_items(item, depth, &count);
  if (!items) return 0;
  for (size_t i = 0; i < count; i++){
    const cJSON *it = items[i].item;
    if (!buf_indent(buf, indent + 2) || !json_print_string(buf, it->string) || !buf_append(buf, ": ")) goto done;
    if (!json_print_value(buf, it, indent + 2, depth + 1)) goto done;
    if (i + 1 < count && !buf_append_char(buf, ',')) goto done;
    if (!buf_append_char(buf, '\n')) goto done;
  }
  ok = buf_indent(buf, indent) && buf_append_char(buf, '}');
done:
  free(items);
  return ok;
}

static int json_print_value(Buffer *buf, const cJSON *item, int indent, int depth){
  if (cJSON_IsObject(item)) return json_print_object(buf, item, indent, depth);
  if (cJSON_IsArray(item)) return json_print_array(buf, item, indent, depth);
  if (cJSON_IsString(item)) return json_print_string(buf, item->valuestring);
  if (cJSON_IsNumber(item)) return buf_append(buf, item->valuestring);
  if (cJSON_IsTrue(item)) return buf_append(buf, "true");
  if (cJSON_IsFalse(item)) return buf_append(buf, "false");
  if (cJSON_IsNull(item)) return buf_append(buf, "null");
  return 0;
}

char *config_json_print(cJSON *root){
  Buffer buf = {0};
  if (!json_print_value(&buf, root, 0, 0) || !buf_append_char(&buf, '\n')){ free(buf.data); return NULL; }
  return buf.data;
}

static cJSON *json_new_bool(const char *key){
  cJSON *item = calloc(1, sizeof(*item)); if (!item) return NULL;
  item->type = cJSON_True;
  item->string = xstrdup(key);
  if (!item->string){ cJSON_Delete(item); return NULL; }
  return item;
}

static cJSON *json_new_number(const char *key, int value){
  cJSON *item = calloc(1, sizeof(*item)); if (!item) return NULL;
  item->type = cJSON_Number;
  item->string = xstrdup(key);
  char value_text[32]; snprintf(value_text, sizeof(value_text), "%d", value);
  item->valuestring = xstrdup(value_text);
  if (!item->string || !item->valuestring){ cJSON_Delete(item); return NULL; }
  return item;
}

static void json_insert_after(cJSON *object, cJSON *after, cJSON *item){
  if (!after){
    item->next = object->child;
    object->child = item;
    return;
  }
  item->next = after->next;
  after->next = item;
}

static void json_delete_child(cJSON *parent, cJSON *child){
  cJSON **it = &parent->child;
  while (*it && *it != child) it = &(*it)->next;
  if (*it){
    *it = child->next;
    child->next = NULL;
    cJSON_Delete(child);
  }
}

static int notes_push(ConvertNotes *notes, const char *process, const char *path, const char *reason){
  if (notes->len == notes->cap){
    size_t cap = notes->cap ? notes->cap * 2 : 8;
    ConvertNote *items = realloc(notes->items, cap * sizeof(*items));
    if (!items) return 0;
    notes->items = items; notes->cap = cap;
  }
  char *process_copy = xstrdup(process);
  char *path_copy = xstrdup(path);
  char *reason_copy = reason ? xstrdup(reason) : NULL;
  if (!process_copy || !path_copy || (reason && !reason_copy)){
    free(process_copy); free(path_copy); free(reason_copy);
    return 0;
  }
  notes->items[notes->len] = (ConvertNote){ process_copy, path_copy, reason_copy };
  notes->len++; return 1;
}

static void notes_free(ConvertNotes *notes){
  for (size_t i = 0; i < notes->len; i++){
    free(notes->items[i].process);
    free(notes->items[i].path);
    free(notes->items[i].reason);
  }
  free(notes->items); *notes = (ConvertNotes){0};
}

static int path_has_wildcard(const char *path){ return path && strchr(path, '*'); }

static int note_preserved_path(ConvertSummary *summary, const char *process, const char *path, const char *reason){
  summary->preserved++;
  if (!reason) return 1;
  summary->ambiguous++;
  return notes_push(&summary->preserved_notes, process, path, reason);
}

static AppleTrustResult convert_apple_trust_check(const NetwatchPlatform *platform, ConfigConvertVerifier verifier, const char *path, char *reason, size_t reason_size){
  if (verifier) return verifier(path, reason, reason_size);
  return platform->apple_trust_check(platform, path, reason, reason_size);
}

static int path_removable(const char *process, const char *path, const NetwatchPlatform *platform, ConfigConvertVerifier verifier, ConvertSummary *summary){
  if (!path || path_has_wildcard(path)){
    return note_preserved_path(summary, process, path ? path : "", path && apple_trust_is_system_path(path) ? "wildcard path" : NULL), 0;
  }
  if (platform->access_path(platform, path, F_OK) != 0){
    return note_preserved_path(summary, process, path, apple_trust_is_system_path(path) ? "path does not exist" : NULL), 0;
  }
  char reason[128] = {0};
  AppleTrustResult result = convert_apple_trust_check(platform, verifier, path, reason, sizeof(reason));
  if (result == APPLE_TRUST_OK) return 1;
  return note_preserved_path(summary, process, path, apple_trust_is_system_path(path) ? apple_trust_result_name(result) : NULL), 0;
}

static int remove_path_note(ConvertSummary *summary, const char *process, const char *path){
  summary->removed++;
  return notes_push(&summary->removed_notes, process, path, NULL);
}

static int convert_allow_string(cJSON *allow_processes, cJSON *item, const NetwatchPlatform *platform, ConfigConvertVerifier verifier, ConvertSummary *summary){
  if (!path_removable(item->string, item->valuestring, platform, verifier, summary)) return 1;
  if (!remove_path_note(summary, item->string, item->valuestring)) return 0;
  json_delete_child(allow_processes, item);
  return 1;
}

static int convert_allow_array(cJSON *allow_processes, cJSON *item, const NetwatchPlatform *platform, ConfigConvertVerifier verifier, ConvertSummary *summary){
  for (cJSON *path = item->child, *next = NULL; path; path = next){
    next = path->next;
    if (!cJSON_IsString(path)){
      summary->preserved++; summary->ambiguous++;
      if (!notes_push(&summary->preserved_notes, item->string, "(non-string array value)", "unsupported allowProcesses array value")) return 0;
      continue;
    }
    if (!path_removable(item->string, path->valuestring, platform, verifier, summary)) continue;
    if (!remove_path_note(summary, item->string, path->valuestring)) return 0;
    json_delete_child(item, path);
  }
  if (!item->child) json_delete_child(allow_processes, item);
  return 1;
}

static int convert_allow_processes(cJSON *root, const NetwatchPlatform *platform, ConfigConvertVerifier verifier, ConvertSummary *summary){
  cJSON *allow_processes = cJSON_GetObjectItemCaseSensitive(root, "allowProcesses");
  if (!allow_processes || !cJSON_IsObject(allow_processes)) return 1;
  for (cJSON *item = allow_processes->child, *next = NULL; item; item = next){
    next = item->next;
    if (cJSON_IsString(item)){
      if (!convert_allow_string(allow_processes, item, platform, verifier, summary)) return 0;
    } else if (cJSON_IsArray(item)){
      if (!convert_allow_array(allow_processes, item, platform, verifier, summary)) return 0;
    } else {
      summary->preserved++; summary->ambiguous++;
      if (!notes_push(&summary->preserved_notes, item->string ? item->string : "(unknown)", "(unsupported value)", "unsupported allowProcesses value type")) return 0;
    }
  }
  return 1;
}

static int convert_tree(cJSON *root, const NetwatchPlatform *platform, ConfigConvertVerifier verifier, ConvertSummary *summary, int *changed){
  cJSON *version = cJSON_GetObjectItemCaseSensitive(root, "version");
  if (!version){
    version = json_new_number("version", NETWATCH_CONFIG_VERSION);
    if (!version) return 0;
    json_insert_after(root, NULL, version);
    *changed = 1;
  }

  cJSON *flag = cJSON_GetObjectItemCaseSensitive(root, "allowAppleSystemComponents");
  if (!flag){
    cJSON *dry_run = cJSON_GetObjectItemCaseSensitive(root, "dryRun");
    flag = json_new_bool("allowAppleSystemComponents");
    if (!flag) return 0;
    json_insert_after(root, dry_run ? dry_run : version, flag);
    *changed = 1;
  } else if (!cJSON_IsTrue(flag)){
    flag->type = cJSON_True;
    *changed = 1;
  }

  size_t before = summary->removed;
  if (!convert_allow_processes(root, platform, verifier, summary)) return 0;
  if (summary->removed != before) *changed = 1;
  return 1;
}

static int same_original_file(const char *path, const NetwatchPlatform *platform, const struct stat *original){
  struct stat st;
  return platform->stat_path(platform, path, &st) == 0
    && st.st_dev == original->st_dev
    && st.st_ino == original->st_ino
    && st.st_size == original->st_size
    && st.st_mtimespec.tv_sec == original->st_mtimespec.tv_sec
    && st.st_mtimespec.tv_nsec == original->st_mtimespec.tv_nsec;
}

static int lines_push(Lines *lines, const char *start, size_t len){
  if (lines->len == lines->cap){
    size_t cap = lines->cap ? lines->cap * 2 : 32;
    char **items = realloc(lines->items, cap * sizeof(*items));
    if (!items) return 0;
    lines->items = items; lines->cap = cap;
  }
  char *line = malloc(len + 1); if (!line) return 0;
  memcpy(line, start, len); line[len] = 0;
  lines->items[lines->len++] = line; return 1;
}

static int split_lines(const char *text, Lines *lines){
  const char *start = text;
  for (const char *p = text; ; p++){
    if (*p == '\n'){
      if (!lines_push(lines, start, (size_t)(p - start))) return 0;
      start = p + 1;
    } else if (*p == 0){
      return p == start || lines_push(lines, start, (size_t)(p - start));
    }
  }
}

static void lines_free(Lines *lines){
  for (size_t i = 0; i < lines->len; i++) free(lines->items[i]);
  free(lines->items); *lines = (Lines){0};
}

static int ops_push(DiffOps *ops, char type, const char *line){
  if (ops->len == ops->cap){
    size_t cap = ops->cap ? ops->cap * 2 : 64;
    DiffOp *items = realloc(ops->items, cap * sizeof(*items));
    if (!items) return 0;
    ops->items = items; ops->cap = cap;
  }
  ops->items[ops->len++] = (DiffOp){ type, line };
  return 1;
}

static int print_unified_diff(const char *old_name, const char *old_text, const char *new_name, const char *new_text){
  Lines old_lines = {0}, new_lines = {0};
  DiffOps ops = {0};
  size_t *lcs = NULL;
  int ok = split_lines(old_text, &old_lines) && split_lines(new_text, &new_lines);
  if (!ok) goto done;

  size_t rows = old_lines.len + 1, cols = new_lines.len + 1;
  if (cols && rows > ((size_t)-1) / cols) goto done;
  lcs = calloc(rows * cols, sizeof(*lcs)); if (!lcs) goto done;
  for (size_t i = old_lines.len; i > 0; i--){
    for (size_t j = new_lines.len; j > 0; j--){
      size_t at = (i - 1) * cols + (j - 1);
      if (!strcmp(old_lines.items[i - 1], new_lines.items[j - 1])) lcs[at] = lcs[i * cols + j] + 1;
      else lcs[at] = lcs[i * cols + (j - 1)] > lcs[(i - 1) * cols + j] ? lcs[i * cols + (j - 1)] : lcs[(i - 1) * cols + j];
    }
  }

  size_t i = 0, j = 0;
  while (i < old_lines.len || j < new_lines.len){
    if (i < old_lines.len && j < new_lines.len && !strcmp(old_lines.items[i], new_lines.items[j])){
      if (!ops_push(&ops, ' ', old_lines.items[i])) goto done;
      i++; j++;
    } else if (j < new_lines.len && (i == old_lines.len || lcs[i * cols + (j + 1)] >= lcs[(i + 1) * cols + j])){
      if (!ops_push(&ops, '+', new_lines.items[j++])) goto done;
    } else if (i < old_lines.len){
      if (!ops_push(&ops, '-', old_lines.items[i++])) goto done;
    }
  }

  printf("--- %s\n+++ %s\n@@\n", old_name, new_name);
  for (size_t k = 0; k < ops.len; k++) printf("%c%s\n", ops.items[k].type, ops.items[k].line);
  ok = 1;

done:
  free(lcs);
  free(ops.items);
  lines_free(&old_lines);
  lines_free(&new_lines);
  return ok;
}

static void print_summary(const char *backup_path, const ConvertSummary *summary){
  printf("Config converted successfully.\n");
  printf("Backup: %s\n", backup_path);
  printf("Removed trusted Apple entries: %zu\n", summary->removed);
  printf("Preserved allow entries: %zu\n", summary->preserved);
  printf("Preserved unverified or ambiguous entries: %zu\n", summary->ambiguous);
  for (size_t i = 0; i < summary->removed_notes.len; i++){
    printf("Removed Apple system entry:\n  %s -> %s\n", summary->removed_notes.items[i].process, summary->removed_notes.items[i].path);
  }
  for (size_t i = 0; i < summary->preserved_notes.len && i < 8; i++){
    printf("Preserved allow entry:\n  %s -> %s (%s)\n",
      summary->preserved_notes.items[i].process,
      summary->preserved_notes.items[i].path,
      summary->preserved_notes.items[i].reason);
  }
}

static int config_convert_in_place_base(const char *config_path, const NetwatchPlatform *platform, ConfigConvertVerifier verifier){
  if (!config_path || !*config_path) return fail_msg("config path is required");
  platform = netwatch_platform_or_default(platform);
  char err[512] = {0};
  char *original = platform->read_file(platform, config_path, err, sizeof(err));
  if (!original) return fail_msg("%s", err);

  Config cfg = {0};
  if (!config_parse_text(&cfg, original, config_path, err, sizeof(err))){
    free(original); return fail_msg("%s", err);
  }
  config_free(&cfg);

  cJSON *root = cJSON_Parse(original);
  if (!cJSON_IsObject(root)){
    cJSON_Delete(root); free(original); return fail_msg("config root must be object");
  }

  int rc = 1, changed = 0;
  char *converted = NULL, *tmp_path = NULL, *backup_path = NULL;
  ConvertSummary summary = {0};
  struct stat st;

  if (!convert_tree(root, platform, verifier, &summary, &changed)){
    fail_msg("out of memory converting config"); goto done;
  }
  if (!changed){
    printf("Config is already up to date.\n");
    rc = 0; goto done;
  }

  converted = config_json_print(root);
  if (!converted){ fail_msg("out of memory serializing converted config"); goto done; }
  if (!config_parse_text(&cfg, converted, "converted config", err, sizeof(err))){
    fail_msg("converted config did not validate: %s", err); goto done;
  }
  config_free(&cfg);

  if (platform->stat_path(platform, config_path, &st) != 0){ fail_msg("failed to stat %s", config_path); goto done; }
  tmp_path = platform->temp_path_for(platform, config_path);
  if (!tmp_path){ fail_msg("failed to create temporary path"); goto done; }
  if (!platform->write_temp_file(platform, tmp_path, converted, st.st_mode, err, sizeof(err))){ fail_msg("%s", err); goto done; }
  if (!same_original_file(config_path, platform, &st)){ fail_msg("config changed while converting"); goto done; }

  backup_path = platform->backup_path_for(platform, config_path);
  if (!backup_path){ fail_msg("failed to choose backup path: %s", strerror(errno)); goto done; }
  if (!platform->copy_file(platform, config_path, backup_path, st.st_mode, err, sizeof(err))){ fail_msg("%s", err); goto done; }

  if (!platform->rename_path(platform, tmp_path, config_path, err, sizeof(err))){
    fail_msg("%s", err);
    platform->unlink_path(platform, backup_path);
    goto done;
  }
  free(tmp_path); tmp_path = NULL;
  platform->fsync_parent_dir(platform, config_path);

  char *backup_text = platform->read_file(platform, backup_path, err, sizeof(err));
  char *final_text = platform->read_file(platform, config_path, err, sizeof(err));
  if (!backup_text || !final_text || !print_unified_diff(backup_path, backup_text ? backup_text : "", config_path, final_text ? final_text : "")){
    free(backup_text); free(final_text); fail_msg("failed to print conversion diff"); goto done;
  }
  free(backup_text); free(final_text);
  print_summary(backup_path, &summary);
  rc = 0;

done:
  if (tmp_path){ platform->unlink_path(platform, tmp_path); free(tmp_path); }
  free(backup_path);
  free(converted);
  notes_free(&summary.removed_notes);
  notes_free(&summary.preserved_notes);
  cJSON_Delete(root);
  free(original);
  return rc;
}

int config_convert_in_place_with_platform(const char *config_path, const NetwatchPlatform *platform){
  return config_convert_in_place_base(config_path, platform, NULL);
}

int config_convert_in_place_with_verifier(const char *config_path, ConfigConvertVerifier verifier){
  return config_convert_in_place_base(config_path, netwatch_platform_default(), verifier);
}

int config_convert_in_place(const char *config_path){
  return config_convert_in_place_with_platform(config_path, netwatch_platform_default());
}
