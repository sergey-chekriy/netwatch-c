#include "config_backend.h"
#include "config.h"
#include "config_json.h"
#include "cJSON.h"
#include "util.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NETWATCH_DAEMON_LABEL "com.serg.netwatch"

typedef int (*ConfigEditFn)(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len);

static int fail_msg(const char *msg){
  fprintf(stderr, "ERROR: %s\n", msg);
  return 1;
}

static cJSON *json_new(int type, const char *key){
  cJSON *item = calloc(1, sizeof(*item)); if (!item) return NULL;
  item->type = type;
  if (key){
    item->string = xstrdup(key);
    if (!item->string){ cJSON_Delete(item); return NULL; }
  }
  return item;
}

static cJSON *json_string(const char *key, const char *value){
  cJSON *item = json_new(cJSON_String, key); if (!item) return NULL;
  item->valuestring = xstrdup(value);
  if (!item->valuestring){ cJSON_Delete(item); return NULL; }
  return item;
}

static cJSON *json_number(const char *key, int value){
  cJSON *item = json_new(cJSON_Number, key); if (!item) return NULL;
  char text[32]; snprintf(text, sizeof(text), "%d", value);
  item->valuestring = xstrdup(text);
  if (!item->valuestring){ cJSON_Delete(item); return NULL; }
  return item;
}

static cJSON *json_bool(const char *key, int value){ return json_new(value ? cJSON_True : cJSON_False, key); }
static cJSON *json_object(const char *key){ return json_new(cJSON_Object, key); }
static cJSON *json_array(const char *key){ return json_new(cJSON_Array, key); }

static void json_add_child(cJSON *parent, cJSON *child){
  if (!parent->child){ parent->child = child; return; }
  cJSON *tail = parent->child;
  while (tail->next) tail = tail->next;
  tail->next = child;
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

static int json_set(cJSON *object, const char *key, cJSON *value){
  if (!value) return 0;
  cJSON *old = cJSON_GetObjectItemCaseSensitive(object, key);
  if (old) json_delete_child(object, old);
  json_add_child(object, value);
  return 1;
}

static cJSON *json_ensure_object(cJSON *root, const char *key){
  cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
  if (item && cJSON_IsObject(item)) return item;
  if (item) return NULL;
  item = json_object(key);
  if (item) json_add_child(root, item);
  return item;
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

static char *backend_backup_path_for(const char *path, const NetwatchPlatform *platform){
  for (int i = 0; i <= 999; i++){
    size_t n = strlen(path) + 16;
    char *candidate = malloc(n); if (!candidate) return NULL;
    if (i == 0) snprintf(candidate, n, "%s.bak", path);
    else snprintf(candidate, n, "%s.bak.%d", path, i);
    struct stat st;
    if (platform->stat_path(platform, candidate, &st) != 0){
      if (errno == ENOENT || errno == ENOTDIR) return candidate;
      free(candidate);
      return NULL;
    }
    free(candidate);
  }
  errno = EEXIST;
  return NULL;
}

static int write_changed_config(const char *config_path, const char *old_text, const char *new_text, const char *changed, const NetwatchPlatform *platform){
  char err[512] = {0};
  struct stat st;
  char *tmp_path = NULL, *backup_path = NULL;
  int rc = 1;
  (void)old_text;

  if (platform->stat_path(platform, config_path, &st) != 0){ fail_msg("failed to stat config"); goto done; }
  tmp_path = platform->temp_path_for(platform, config_path);
  if (!tmp_path){ fail_msg("failed to create temporary path"); goto done; }
  if (!platform->write_temp_file(platform, tmp_path, new_text, st.st_mode, err, sizeof(err))){ fail_msg(err); goto done; }
  if (!same_original_file(config_path, platform, &st)){ fail_msg("config changed while editing"); goto done; }

  backup_path = backend_backup_path_for(config_path, platform);
  if (!backup_path){ fail_msg("failed to choose backup path"); goto done; }
  if (!platform->copy_file(platform, config_path, backup_path, st.st_mode, err, sizeof(err))){ fail_msg(err); goto done; }
  if (!platform->rename_path(platform, tmp_path, config_path, err, sizeof(err))){
    fail_msg(err);
    platform->unlink_path(platform, backup_path);
    goto done;
  }
  free(tmp_path); tmp_path = NULL;
  platform->fsync_parent_dir(platform, config_path);

  printf("Config updated successfully.\n");
  printf("Changed: %s\n", changed);
  printf("Backup: %s\n", backup_path);
  printf("Validation: OK\n");
  printf("Daemon reload recommended: run netwatch --reload-daemon\n");
  rc = 0;

done:
  if (tmp_path){ platform->unlink_path(platform, tmp_path); free(tmp_path); }
  free(backup_path);
  return rc;
}

static int edit_config(const char *config_path, ConfigEditFn edit, void *ctx, const NetwatchPlatform *platform){
  if (!config_path || !*config_path) return fail_msg("config path is required");
  platform = netwatch_platform_or_default(platform);
  char err[512] = {0};
  char *original = platform->read_file(platform, config_path, err, sizeof(err));
  if (!original) return fail_msg(err);

  Config cfg = {0};
  if (!config_parse_text(&cfg, original, config_path, err, sizeof(err))){
    free(original);
    return fail_msg(err);
  }
  config_free(&cfg);

  cJSON *root = cJSON_Parse(original);
  if (!cJSON_IsObject(root)){
    cJSON_Delete(root); free(original);
    return fail_msg("config root must be object");
  }

  char changed[256] = {0};
  int rc = 1;
  char *updated = NULL;
  if (!edit(root, ctx, changed, sizeof(changed), err, sizeof(err))){ fail_msg(err); goto done; }
  if (!changed[0]){
    printf("Config is already up to date.\n");
    rc = 0; goto done;
  }
  updated = config_json_print(root);
  if (!updated){ fail_msg("out of memory serializing config"); goto done; }
  if (!config_parse_text(&cfg, updated, "updated config", err, sizeof(err))){
    fail_msg(err); goto done;
  }
  config_free(&cfg);
  rc = write_changed_config(config_path, original, updated, changed, platform);

done:
  free(updated);
  cJSON_Delete(root);
  free(original);
  return rc;
}

int config_backend_show(const char *config_path, const NetwatchPlatform *platform){
  if (!config_path || !*config_path) return fail_msg("config path is required");
  platform = netwatch_platform_or_default(platform);
  char err[512] = {0};
  char *text = platform->read_file(platform, config_path, err, sizeof(err));
  if (!text) return fail_msg(err);
  Config cfg = {0};
  if (!config_parse_text(&cfg, text, config_path, err, sizeof(err))){
    free(text); return fail_msg(err);
  }
  config_free(&cfg);
  cJSON *root = cJSON_Parse(text);
  free(text);
  if (!cJSON_IsObject(root)){ cJSON_Delete(root); return fail_msg("config root must be object"); }
  char *out = config_json_print(root);
  cJSON_Delete(root);
  if (!out) return fail_msg("out of memory serializing config");
  fputs(out, stdout);
  free(out);
  return 0;
}

typedef struct { int value; } BoolEdit;

static int edit_dry_run(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  BoolEdit *edit = ctx;
  cJSON *old = cJSON_GetObjectItemCaseSensitive(root, "dryRun");
  if (old && cJSON_IsBool(old) && (cJSON_IsTrue(old) ? 1 : 0) == edit->value) return 1;
  if (!json_set(root, "dryRun", json_bool("dryRun", edit->value))){
    set_error(err, err_len, "out of memory setting dryRun"); return 0;
  }
  snprintf(changed, changed_len, "dryRun -> %s", edit->value ? "true" : "false");
  return 1;
}

int config_backend_set_dry_run(const char *config_path, int value, const NetwatchPlatform *platform){
  BoolEdit edit = { .value = value ? 1 : 0 };
  return edit_config(config_path, edit_dry_run, &edit, platform);
}

typedef struct { const char *key; int value; } TopBoolEdit;

static int edit_top_bool(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  TopBoolEdit *edit = ctx;
  cJSON *old = cJSON_GetObjectItemCaseSensitive(root, edit->key);
  if (old && cJSON_IsBool(old) && (cJSON_IsTrue(old) ? 1 : 0) == edit->value) return 1;
  if (!json_set(root, edit->key, json_bool(edit->key, edit->value))){
    set_error(err, err_len, "out of memory setting %s", edit->key); return 0;
  }
  snprintf(changed, changed_len, "%s -> %s", edit->key, edit->value ? "true" : "false");
  return 1;
}

int config_backend_set_apple_system_trust(const char *config_path, int value, const NetwatchPlatform *platform){
  TopBoolEdit edit = { .key = "allowAppleSystemComponents", .value = value ? 1 : 0 };
  return edit_config(config_path, edit_top_bool, &edit, platform);
}

int config_backend_set_verbose_log(const char *config_path, int value, const NetwatchPlatform *platform){
  TopBoolEdit edit = { .key = "verboseLog", .value = value ? 1 : 0 };
  return edit_config(config_path, edit_top_bool, &edit, platform);
}

typedef struct { const char *key; const char *value; int require_absolute; } OptionalStringEdit;

static int edit_optional_string(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  OptionalStringEdit *edit = ctx;
  cJSON *old = cJSON_GetObjectItemCaseSensitive(root, edit->key);
  const char *value = edit->value ? edit->value : "";
  if (!*value){
    if (!old) return 1;
    json_delete_child(root, old);
    snprintf(changed, changed_len, "%s removed", edit->key);
    return 1;
  }
  if (edit->require_absolute && value[0] != '/'){
    set_error(err, err_len, "%s must be an absolute path or empty", edit->key); return 0;
  }
  if (old && cJSON_IsString(old) && old->valuestring && !strcmp(old->valuestring, value)) return 1;
  if (!json_set(root, edit->key, json_string(edit->key, value))){
    set_error(err, err_len, "out of memory setting %s", edit->key); return 0;
  }
  snprintf(changed, changed_len, "%s set", edit->key);
  return 1;
}

int config_backend_set_interface(const char *config_path, const char *value, const NetwatchPlatform *platform){
  OptionalStringEdit edit = { .key = "interface", .value = value, .require_absolute = 0 };
  return edit_config(config_path, edit_optional_string, &edit, platform);
}

int config_backend_set_log_path(const char *config_path, const char *value, const NetwatchPlatform *platform){
  OptionalStringEdit edit = { .key = "logPath", .value = value, .require_absolute = 1 };
  return edit_config(config_path, edit_optional_string, &edit, platform);
}

typedef struct { int seconds; } PollEdit;

static int edit_poll_interval(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  PollEdit *edit = ctx;
  cJSON *daemon = json_ensure_object(root, "daemon");
  if (!daemon){ set_error(err, err_len, "daemon must be an object"); return 0; }
  cJSON *old = cJSON_GetObjectItemCaseSensitive(daemon, "pollIntervalSeconds");
  if (old && cJSON_IsNumber(old) && atoi(old->valuestring) == edit->seconds) return 1;
  if (!json_set(daemon, "pollIntervalSeconds", json_number("pollIntervalSeconds", edit->seconds))){
    set_error(err, err_len, "out of memory setting daemon.pollIntervalSeconds"); return 0;
  }
  snprintf(changed, changed_len, "daemon.pollIntervalSeconds -> %d", edit->seconds);
  return 1;
}

int config_backend_set_poll_interval(const char *config_path, int seconds, const NetwatchPlatform *platform){
  if (seconds < 1) return fail_msg("poll interval must be a positive integer");
  PollEdit edit = { .seconds = seconds };
  return edit_config(config_path, edit_poll_interval, &edit, platform);
}

typedef struct { const char *key; int value; } DaemonBoolEdit;

static int edit_daemon_bool(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  DaemonBoolEdit *edit = ctx;
  cJSON *daemon = json_ensure_object(root, "daemon");
  if (!daemon){ set_error(err, err_len, "daemon must be an object"); return 0; }
  cJSON *old = cJSON_GetObjectItemCaseSensitive(daemon, edit->key);
  if (old && cJSON_IsBool(old) && (cJSON_IsTrue(old) ? 1 : 0) == edit->value) return 1;
  if (!json_set(daemon, edit->key, json_bool(edit->key, edit->value))){
    set_error(err, err_len, "out of memory setting daemon.%s", edit->key); return 0;
  }
  snprintf(changed, changed_len, "daemon.%s -> %s", edit->key, edit->value ? "true" : "false");
  return 1;
}

int config_backend_set_daemon_reload_on_sighup(const char *config_path, int value, const NetwatchPlatform *platform){
  DaemonBoolEdit edit = { .key = "reloadOnSighup", .value = value ? 1 : 0 };
  return edit_config(config_path, edit_daemon_bool, &edit, platform);
}

int config_backend_set_daemon_exit_on_config_error(const char *config_path, int value, const NetwatchPlatform *platform){
  DaemonBoolEdit edit = { .key = "exitOnConfigError", .value = value ? 1 : 0 };
  return edit_config(config_path, edit_daemon_bool, &edit, platform);
}

typedef struct { const char *key; const char **values; size_t value_count; } StringArrayEdit;

static int string_array_equals(cJSON *array, const char **values, size_t value_count){
  if (!cJSON_IsArray(array) || (size_t)cJSON_GetArraySize(array) != value_count) return 0;
  for (size_t i = 0; i < value_count; i++){
    cJSON *item = cJSON_GetArrayItem(array, (int)i);
    if (!cJSON_IsString(item) || !item->valuestring || strcmp(item->valuestring, values[i])) return 0;
  }
  return 1;
}

static cJSON *json_string_array(const char *key, const char **values, size_t value_count){
  cJSON *array = json_array(key); if (!array) return NULL;
  for (size_t i = 0; i < value_count; i++){
    cJSON *item = json_string(NULL, values[i]);
    if (!item){ cJSON_Delete(array); return NULL; }
    json_add_child(array, item);
  }
  return array;
}

static int edit_string_array(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  StringArrayEdit *edit = ctx;
  cJSON *old = cJSON_GetObjectItemCaseSensitive(root, edit->key);
  if (old && string_array_equals(old, edit->values, edit->value_count)) return 1;
  if (!json_set(root, edit->key, json_string_array(edit->key, edit->values, edit->value_count))){
    set_error(err, err_len, "out of memory setting %s", edit->key); return 0;
  }
  snprintf(changed, changed_len, "%s set", edit->key);
  return 1;
}

static int set_string_array_field(const char *config_path, const char *key, const char **values, size_t value_count, const NetwatchPlatform *platform){
  if (!values && value_count > 0) return fail_msg("invalid string array values");
  for (size_t i = 0; i < value_count; i++) if (!values[i]) return fail_msg("string array value is required");
  StringArrayEdit edit = { .key = key, .values = values, .value_count = value_count };
  return edit_config(config_path, edit_string_array, &edit, platform);
}

int config_backend_set_deny_patterns(const char *config_path, const char **values, size_t value_count, const NetwatchPlatform *platform){
  return set_string_array_field(config_path, "denyPatterns", values, value_count, platform);
}

int config_backend_set_allow_remote_hosts(const char *config_path, const char **values, size_t value_count, const NetwatchPlatform *platform){
  return set_string_array_field(config_path, "allowRemoteHosts", values, value_count, platform);
}

typedef struct { const char *section; const char *name; } RemoveEdit;

static int edit_remove_named(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  (void)err; (void)err_len;
  RemoveEdit *edit = ctx;
  cJSON *section = cJSON_GetObjectItemCaseSensitive(root, edit->section);
  if (!section || !cJSON_IsObject(section)) return 1;
  cJSON *item = cJSON_GetObjectItemCaseSensitive(section, edit->name);
  if (!item) return 1;
  json_delete_child(section, item);
  snprintf(changed, changed_len, "%s.%s removed", edit->section, edit->name);
  return 1;
}

typedef struct { const char *name; const char *path; } AllowProcessEdit;
typedef struct { const char *old_name; const char *new_name; const char **paths; size_t path_count; } SetAllowProcessEdit;

static int valid_allow_process_path(const char *path){
  if (!path || path[0] != '/') return 0;
  const char *star = strchr(path, '*');
  return !star || (star[1] == '\0' && !strchr(star + 1, '*'));
}

static int allow_value_has_path(cJSON *value, const char *path){
  if (cJSON_IsString(value)) return value->valuestring && !strcmp(value->valuestring, path);
  if (!cJSON_IsArray(value)) return 0;
  cJSON *item = NULL;
  cJSON_ArrayForEach(item, value){
    if (cJSON_IsString(item) && item->valuestring && !strcmp(item->valuestring, path)) return 1;
  }
  return 0;
}

static int edit_add_allow_process(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  AllowProcessEdit *edit = ctx;
  cJSON *allow = json_ensure_object(root, "allowProcesses");
  if (!allow){ set_error(err, err_len, "allowProcesses must be an object"); return 0; }
  cJSON *old = cJSON_GetObjectItemCaseSensitive(allow, edit->name);
  if (old && allow_value_has_path(old, edit->path)) return 1;
  if (!old){
    if (!json_set(allow, edit->name, json_string(edit->name, edit->path))){
      set_error(err, err_len, "out of memory adding allowProcesses rule"); return 0;
    }
  } else if (cJSON_IsString(old)){
    cJSON *array = json_array(edit->name);
    cJSON *old_path = json_string(NULL, old->valuestring);
    cJSON *new_path = json_string(NULL, edit->path);
    if (!array || !old_path || !new_path){
      cJSON_Delete(array); cJSON_Delete(old_path); cJSON_Delete(new_path);
      set_error(err, err_len, "out of memory extending allowProcesses rule"); return 0;
    }
    json_add_child(array, old_path);
    json_add_child(array, new_path);
    if (!json_set(allow, edit->name, array)){
      cJSON_Delete(array); set_error(err, err_len, "out of memory extending allowProcesses rule"); return 0;
    }
  } else if (cJSON_IsArray(old)){
    cJSON *new_path = json_string(NULL, edit->path);
    if (!new_path){ set_error(err, err_len, "out of memory extending allowProcesses rule"); return 0; }
    json_add_child(old, new_path);
  } else {
    set_error(err, err_len, "allowProcesses.%s must be string or array of strings", edit->name);
    return 0;
  }
  snprintf(changed, changed_len, "allowProcesses.%s added", edit->name);
  return 1;
}

int config_backend_add_allow_process(const char *config_path, const char *name, const char *path, const NetwatchPlatform *platform){
  if (!name || !*name) return fail_msg("allow process name is required");
  if (!valid_allow_process_path(path)) return fail_msg("allow process path must be absolute; wildcard is supported only as a final *");
  AllowProcessEdit edit = { name, path };
  return edit_config(config_path, edit_add_allow_process, &edit, platform);
}

static int allow_value_equals_paths(cJSON *value, const char **paths, size_t path_count){
  if (path_count == 1) return cJSON_IsString(value) && value->valuestring && !strcmp(value->valuestring, paths[0]);
  if (!cJSON_IsArray(value) || (size_t)cJSON_GetArraySize(value) != path_count) return 0;
  for (size_t i = 0; i < path_count; i++){
    cJSON *item = cJSON_GetArrayItem(value, (int)i);
    if (!cJSON_IsString(item) || !item->valuestring || strcmp(item->valuestring, paths[i])) return 0;
  }
  return 1;
}

static cJSON *allow_value_for_paths(const char *name, const char **paths, size_t path_count){
  if (path_count == 1) return json_string(name, paths[0]);
  cJSON *array = json_array(name); if (!array) return NULL;
  for (size_t i = 0; i < path_count; i++){
    cJSON *item = json_string(NULL, paths[i]);
    if (!item){ cJSON_Delete(array); return NULL; }
    json_add_child(array, item);
  }
  return array;
}

static int edit_set_allow_process(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  SetAllowProcessEdit *edit = ctx;
  cJSON *allow = json_ensure_object(root, "allowProcesses");
  if (!allow){ set_error(err, err_len, "allowProcesses must be an object"); return 0; }
  cJSON *old = cJSON_GetObjectItemCaseSensitive(allow, edit->old_name);
  cJSON *existing_new = cJSON_GetObjectItemCaseSensitive(allow, edit->new_name);
  if (strcmp(edit->old_name, edit->new_name) && existing_new){
    set_error(err, err_len, "allowProcesses.%s already exists", edit->new_name); return 0;
  }
  if (old && !strcmp(edit->old_name, edit->new_name) && allow_value_equals_paths(old, edit->paths, edit->path_count)) return 1;
  if (old) json_delete_child(allow, old);
  cJSON *value = allow_value_for_paths(edit->new_name, edit->paths, edit->path_count);
  if (!json_set(allow, edit->new_name, value)){
    cJSON_Delete(value); set_error(err, err_len, "out of memory setting allowProcesses rule"); return 0;
  }
  snprintf(changed, changed_len, "allowProcesses.%s set", edit->new_name);
  return 1;
}

int config_backend_set_allow_process(const char *config_path, const char *old_name, const char *new_name, const char **paths, size_t path_count, const NetwatchPlatform *platform){
  if (!old_name || !*old_name) return fail_msg("old allow process name is required");
  if (!new_name || !*new_name) return fail_msg("allow process name is required");
  if (!paths || path_count == 0) return fail_msg("at least one allow process path is required");
  for (size_t i = 0; i < path_count; i++){
    if (!valid_allow_process_path(paths[i])) return fail_msg("allow process path must be absolute; wildcard is supported only as a final *");
    for (size_t j = i + 1; j < path_count; j++){
      if (!strcmp(paths[i], paths[j])) return fail_msg("duplicate allow process path");
    }
  }
  SetAllowProcessEdit edit = { old_name, new_name, paths, path_count };
  return edit_config(config_path, edit_set_allow_process, &edit, platform);
}

int config_backend_remove_allow_process(const char *config_path, const char *name, const NetwatchPlatform *platform){
  if (!name || !*name) return fail_msg("allow process name is required");
  RemoveEdit edit = { .section = "allowProcesses", .name = name };
  return edit_config(config_path, edit_remove_named, &edit, platform);
}

typedef struct {
  const char *name;
  const char *path;
  const char *team_id;
  const char *signing_identifier;
} PublisherEdit;
typedef struct {
  const char *old_name;
  const char *new_name;
  const char **paths;
  size_t path_count;
  const char *team_id;
  const char *signing_identifier;
} SetPublisherEdit;

static int validate_publisher_path(const char *path, const char *team_id, const char *signing_identifier, const NetwatchPlatform *platform, char *err, size_t err_len){
  if (!path || path[0] != '/' || strchr(path, '*')) return set_error(err, err_len, "trusted publisher path must be an exact absolute executable path"), 0;
  if (platform->access_path(platform, path, F_OK) != 0) return set_error(err, err_len, "trusted publisher executable does not exist"), 0;
  CodeSignatureIdentity actual = {0};
  CodeSignatureIdentityResult result = platform->code_signature_identity(platform, path, &actual, err, err_len);
  if (result != CODE_SIGNATURE_IDENTITY_OK) return 0;
  if (strcmp(actual.team_id, team_id)) return set_error(err, err_len, "trusted publisher Team ID mismatch"), 0;
  if (strcmp(actual.signing_identifier, signing_identifier)) return set_error(err, err_len, "trusted publisher signing identifier mismatch"), 0;
  return 1;
}

static int validate_publisher_inputs(const char *name, const char **paths, size_t path_count, const char *team_id, const char *signing_identifier, const NetwatchPlatform *platform, char *err, size_t err_len){
  if (!name || !*name) return set_error(err, err_len, "trusted publisher name is required"), 0;
  if (!paths || path_count == 0) return set_error(err, err_len, "trusted publisher path is required"), 0;
  if (!team_id || !*team_id) return set_error(err, err_len, "team ID is required"), 0;
  if (!signing_identifier || !*signing_identifier) return set_error(err, err_len, "signing identifier is required"), 0;
  for (size_t i = 0; i < path_count; i++){
    if (!validate_publisher_path(paths[i], team_id, signing_identifier, platform, err, err_len)) return 0;
    for (size_t j = i + 1; j < path_count; j++) if (!strcmp(paths[i], paths[j])) return set_error(err, err_len, "duplicate trusted publisher path"), 0;
  }
  return 1;
}

static int edit_add_publisher(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  PublisherEdit *edit = ctx;
  cJSON *publishers = json_ensure_object(root, "trustedPublishers");
  cJSON *rule = json_object(edit->name);
  cJSON *paths = json_array("paths");
  if (!publishers || !rule || !paths
    || !json_set(rule, "paths", paths)
    || !json_set(rule, "teamId", json_string("teamId", edit->team_id))
    || !json_set(rule, "signingIdentifier", json_string("signingIdentifier", edit->signing_identifier))){
    cJSON_Delete(rule); set_error(err, err_len, "out of memory adding trusted publisher"); return 0;
  }
  cJSON *path_item = json_string(NULL, edit->path);
  if (!path_item){ cJSON_Delete(rule); set_error(err, err_len, "out of memory adding trusted publisher path"); return 0; }
  json_add_child(paths, path_item);
  if (!json_set(publishers, edit->name, rule)){
    cJSON_Delete(rule); set_error(err, err_len, "out of memory adding trusted publisher"); return 0;
  }
  snprintf(changed, changed_len, "trustedPublishers.%s added", edit->name);
  return 1;
}

int config_backend_add_trusted_publisher(const char *config_path, const char *name, const char *path, const char *team_id, const char *signing_identifier, const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  const char *paths[] = { path };
  PublisherEdit edit = { name, path, team_id, signing_identifier };
  char err[512] = {0};
  if (!validate_publisher_inputs(name, paths, 1, team_id, signing_identifier, platform, err, sizeof(err))) return fail_msg(err);
  return edit_config(config_path, edit_add_publisher, &edit, platform);
}

static int publisher_rule_equals(cJSON *rule, const SetPublisherEdit *edit){
  if (!cJSON_IsObject(rule)) return 0;
  cJSON *team = cJSON_GetObjectItemCaseSensitive(rule, "teamId");
  cJSON *identifier = cJSON_GetObjectItemCaseSensitive(rule, "signingIdentifier");
  return cJSON_IsString(team) && team->valuestring && !strcmp(team->valuestring, edit->team_id)
    && cJSON_IsString(identifier) && identifier->valuestring && !strcmp(identifier->valuestring, edit->signing_identifier)
    && string_array_equals(cJSON_GetObjectItemCaseSensitive(rule, "paths"), edit->paths, edit->path_count);
}

static cJSON *publisher_rule_for(const SetPublisherEdit *edit){
  cJSON *rule = json_object(edit->new_name);
  if (!rule
    || !json_set(rule, "paths", json_string_array("paths", edit->paths, edit->path_count))
    || !json_set(rule, "teamId", json_string("teamId", edit->team_id))
    || !json_set(rule, "signingIdentifier", json_string("signingIdentifier", edit->signing_identifier))){
    cJSON_Delete(rule); return NULL;
  }
  return rule;
}

static int edit_set_publisher(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  SetPublisherEdit *edit = ctx;
  cJSON *publishers = json_ensure_object(root, "trustedPublishers");
  if (!publishers){ set_error(err, err_len, "trustedPublishers must be an object"); return 0; }
  cJSON *old = cJSON_GetObjectItemCaseSensitive(publishers, edit->old_name);
  cJSON *existing_new = cJSON_GetObjectItemCaseSensitive(publishers, edit->new_name);
  if (strcmp(edit->old_name, edit->new_name) && existing_new){
    set_error(err, err_len, "trustedPublishers.%s already exists", edit->new_name); return 0;
  }
  if (old && !strcmp(edit->old_name, edit->new_name) && publisher_rule_equals(old, edit)) return 1;
  if (old) json_delete_child(publishers, old);
  cJSON *rule = publisher_rule_for(edit);
  if (!json_set(publishers, edit->new_name, rule)){
    cJSON_Delete(rule); set_error(err, err_len, "out of memory setting trusted publisher"); return 0;
  }
  snprintf(changed, changed_len, "trustedPublishers.%s set", edit->new_name);
  return 1;
}

int config_backend_set_trusted_publisher(const char *config_path, const char *old_name, const char *new_name, const char **paths, size_t path_count, const char *team_id, const char *signing_identifier, const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  if (!old_name || !*old_name) return fail_msg("old trusted publisher name is required");
  char err[512] = {0};
  if (!validate_publisher_inputs(new_name, paths, path_count, team_id, signing_identifier, platform, err, sizeof(err))) return fail_msg(err);
  SetPublisherEdit edit = { old_name, new_name, paths, path_count, team_id, signing_identifier };
  return edit_config(config_path, edit_set_publisher, &edit, platform);
}

int config_backend_remove_trusted_publisher(const char *config_path, const char *name, const NetwatchPlatform *platform){
  if (!name || !*name) return fail_msg("trusted publisher name is required");
  RemoveEdit edit = { .section = "trustedPublishers", .name = name };
  return edit_config(config_path, edit_remove_named, &edit, platform);
}

typedef struct {
  const char *name;
  const char *bundle_root;
  const char *team_id;
  const char **identifiers;
  size_t identifier_count;
  const char **prefixes;
  size_t prefix_count;
  int allow_subdirectories;
} AppBundleEdit;

static int valid_app_bundle_root(const char *path){
  size_t n = path ? strlen(path) : 0;
  return n >= 5 && path[0] == '/' && !strchr(path, '*') && !strcmp(path + n - 4, ".app");
}

static int validate_identity_values(const char **values, size_t count, const char *label,
  char *err, size_t err_len){
  for (size_t i = 0; i < count; i++){
    if (!values || !values[i] || !values[i][0] || strchr(values[i], '*')){
      set_error(err, err_len, "%s must contain non-empty values without wildcards", label);
      return 0;
    }
    for (size_t j = i + 1; j < count; j++){
      if (!strcmp(values[i], values[j])){
        set_error(err, err_len, "%s contains a duplicate value", label);
        return 0;
      }
    }
  }
  return 1;
}

static int validate_app_bundle_inputs(const AppBundleEdit *edit, const NetwatchPlatform *platform,
  char *err, size_t err_len){
  if (!edit->name || !edit->name[0]) return set_error(err, err_len, "trusted app bundle name is required"), 0;
  if (!valid_app_bundle_root(edit->bundle_root)){
    return set_error(err, err_len, "bundle root must be an exact absolute .app path"), 0;
  }
  struct stat st;
  if (platform->stat_path(platform, edit->bundle_root, &st) != 0 || !S_ISDIR(st.st_mode)){
    return set_error(err, err_len, "bundle root must exist and be a directory"), 0;
  }
  if (!edit->team_id || !edit->team_id[0]) return set_error(err, err_len, "team ID is required"), 0;
  if (!edit->identifier_count && !edit->prefix_count){
    return set_error(err, err_len, "at least one signing identifier or prefix is required"), 0;
  }
  if (!validate_identity_values(edit->identifiers, edit->identifier_count, "allowed signing identifiers", err, err_len)
    || !validate_identity_values(edit->prefixes, edit->prefix_count, "allowed signing identifier prefixes", err, err_len)) return 0;
  CodeSignatureIdentity actual = {0};
  CodeSignatureIdentityResult result = platform->code_signature_identity(
    platform, edit->bundle_root, &actual, err, err_len);
  if (result != CODE_SIGNATURE_IDENTITY_OK){
    if (!err || !err[0]) set_error(err, err_len, "app bundle signature is invalid or unavailable");
    return 0;
  }
  if (strcmp(actual.team_id, edit->team_id)) return set_error(err, err_len, "trusted app bundle Team ID mismatch"), 0;
  return 1;
}

static int edit_add_app_bundle(cJSON *root, void *ctx, char *changed, size_t changed_len,
  char *err, size_t err_len){
  AppBundleEdit *edit = ctx;
  cJSON *bundles = json_ensure_object(root, "trustedAppBundles");
  cJSON *rule = json_object(edit->name);
  if (!bundles || !rule
    || !json_set(rule, "bundleRoot", json_string("bundleRoot", edit->bundle_root))
    || !json_set(rule, "teamId", json_string("teamId", edit->team_id))
    || !json_set(rule, "allowedSigningIdentifiers", json_string_array(
      "allowedSigningIdentifiers", edit->identifiers, edit->identifier_count))
    || !json_set(rule, "allowedSigningIdentifierPrefixes", json_string_array(
      "allowedSigningIdentifierPrefixes", edit->prefixes, edit->prefix_count))
    || !json_set(rule, "allowSubdirectories", json_bool("allowSubdirectories", edit->allow_subdirectories))){
    cJSON_Delete(rule); set_error(err, err_len, "out of memory adding trusted app bundle"); return 0;
  }
  if (!json_set(bundles, edit->name, rule)){
    cJSON_Delete(rule); set_error(err, err_len, "out of memory adding trusted app bundle"); return 0;
  }
  snprintf(changed, changed_len, "trustedAppBundles.%s added", edit->name);
  return 1;
}

int config_backend_add_trusted_app_bundle(const char *config_path, const char *name,
  const char *bundle_root, const char *team_id, const char **identifiers, size_t identifier_count,
  const char **prefixes, size_t prefix_count, int allow_subdirectories,
  const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  AppBundleEdit edit = {
    name, bundle_root, team_id, identifiers, identifier_count, prefixes, prefix_count,
    allow_subdirectories ? 1 : 0
  };
  char err[512] = {0};
  if (!validate_app_bundle_inputs(&edit, platform, err, sizeof(err))) return fail_msg(err);
  return edit_config(config_path, edit_add_app_bundle, &edit, platform);
}

int config_backend_remove_trusted_app_bundle(const char *config_path, const char *name,
  const NetwatchPlatform *platform){
  if (!name || !*name) return fail_msg("trusted app bundle name is required");
  RemoveEdit edit = { .section = "trustedAppBundles", .name = name };
  return edit_config(config_path, edit_remove_named, &edit, platform);
}

typedef struct {
  const char *name;
  const char **roots;
  size_t root_count;
  const char **interpreters;
  size_t interpreter_count;
  int allow_subdirectories;
  int allow_by_cwd_only;
} WorkspaceEdit;
typedef struct {
  const char *old_name;
  WorkspaceEdit rule;
} SetWorkspaceEdit;

static int validate_workspace_inputs(const WorkspaceEdit *edit, const NetwatchPlatform *platform, char *err, size_t err_len){
  if (!edit->name || !*edit->name) return set_error(err, err_len, "trusted workspace name is required"), 0;
  if (!edit->roots || edit->root_count == 0) return set_error(err, err_len, "trusted workspace root is required"), 0;
  if (!edit->interpreters || edit->interpreter_count == 0) return set_error(err, err_len, "trusted workspace interpreter is required"), 0;
  for (size_t i = 0; i < edit->root_count; i++){
    if (!edit->roots[i] || edit->roots[i][0] != '/' || strchr(edit->roots[i], '*')) return set_error(err, err_len, "trusted workspace root must be an exact absolute path"), 0;
    struct stat st;
    if (platform->stat_path(platform, edit->roots[i], &st) != 0 || !S_ISDIR(st.st_mode)) return set_error(err, err_len, "trusted workspace root must exist and be a directory"), 0;
    for (size_t j = i + 1; j < edit->root_count; j++) if (!strcmp(edit->roots[i], edit->roots[j])) return set_error(err, err_len, "duplicate trusted workspace root"), 0;
  }
  for (size_t i = 0; i < edit->interpreter_count; i++){
    if (!edit->interpreters[i] || edit->interpreters[i][0] != '/' || strchr(edit->interpreters[i], '*')) return set_error(err, err_len, "trusted workspace interpreter must be an exact absolute path"), 0;
    if (platform->access_path(platform, edit->interpreters[i], X_OK) != 0) return set_error(err, err_len, "trusted workspace interpreter must exist and be executable"), 0;
    for (size_t j = i + 1; j < edit->interpreter_count; j++) if (!strcmp(edit->interpreters[i], edit->interpreters[j])) return set_error(err, err_len, "duplicate trusted workspace interpreter"), 0;
  }
  return 1;
}

static cJSON *workspace_rule_for(const WorkspaceEdit *edit){
  cJSON *rule = json_object(edit->name);
  if (!rule
    || !json_set(rule, "roots", json_string_array("roots", edit->roots, edit->root_count))
    || !json_set(rule, "allowSubdirectories", json_bool("allowSubdirectories", edit->allow_subdirectories))
    || !json_set(rule, "interpreters", json_string_array("interpreters", edit->interpreters, edit->interpreter_count))
    || !json_set(rule, "allowByCwdOnly", json_bool("allowByCwdOnly", edit->allow_by_cwd_only))){
    cJSON_Delete(rule); return NULL;
  }
  return rule;
}

static int edit_add_workspace(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  WorkspaceEdit *edit = ctx;
  cJSON *workspaces = json_ensure_object(root, "trustedWorkspaces");
  if (!workspaces){ set_error(err, err_len, "trustedWorkspaces must be an object"); return 0; }
  cJSON *rule = workspace_rule_for(edit);
  if (!json_set(workspaces, edit->name, rule)){
    cJSON_Delete(rule); set_error(err, err_len, "out of memory adding trusted workspace"); return 0;
  }
  snprintf(changed, changed_len, "trustedWorkspaces.%s added", edit->name);
  return 1;
}

int config_backend_add_trusted_workspace(const char *config_path, const char *name, const char *root, const char *interpreter, const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  const char *roots[] = { root };
  const char *interpreters[] = { interpreter };
  WorkspaceEdit edit = { name, roots, 1, interpreters, 1, 1, 0 };
  char err[512] = {0};
  if (!validate_workspace_inputs(&edit, platform, err, sizeof(err))) return fail_msg(err);
  return edit_config(config_path, edit_add_workspace, &edit, platform);
}

static int workspace_rule_equals(cJSON *rule, const WorkspaceEdit *edit){
  if (!cJSON_IsObject(rule)) return 0;
  cJSON *subdirs = cJSON_GetObjectItemCaseSensitive(rule, "allowSubdirectories");
  cJSON *cwd_only = cJSON_GetObjectItemCaseSensitive(rule, "allowByCwdOnly");
  return cJSON_IsBool(subdirs) && (cJSON_IsTrue(subdirs) ? 1 : 0) == edit->allow_subdirectories
    && cJSON_IsBool(cwd_only) && (cJSON_IsTrue(cwd_only) ? 1 : 0) == edit->allow_by_cwd_only
    && string_array_equals(cJSON_GetObjectItemCaseSensitive(rule, "roots"), edit->roots, edit->root_count)
    && string_array_equals(cJSON_GetObjectItemCaseSensitive(rule, "interpreters"), edit->interpreters, edit->interpreter_count);
}

static int edit_set_workspace(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  SetWorkspaceEdit *edit = ctx;
  cJSON *workspaces = json_ensure_object(root, "trustedWorkspaces");
  if (!workspaces){ set_error(err, err_len, "trustedWorkspaces must be an object"); return 0; }
  cJSON *old = cJSON_GetObjectItemCaseSensitive(workspaces, edit->old_name);
  cJSON *existing_new = cJSON_GetObjectItemCaseSensitive(workspaces, edit->rule.name);
  if (strcmp(edit->old_name, edit->rule.name) && existing_new){
    set_error(err, err_len, "trustedWorkspaces.%s already exists", edit->rule.name); return 0;
  }
  if (old && !strcmp(edit->old_name, edit->rule.name) && workspace_rule_equals(old, &edit->rule)) return 1;
  if (old) json_delete_child(workspaces, old);
  cJSON *rule = workspace_rule_for(&edit->rule);
  if (!json_set(workspaces, edit->rule.name, rule)){
    cJSON_Delete(rule); set_error(err, err_len, "out of memory setting trusted workspace"); return 0;
  }
  snprintf(changed, changed_len, "trustedWorkspaces.%s set", edit->rule.name);
  return 1;
}

int config_backend_set_trusted_workspace(const char *config_path, const char *old_name, const char *new_name, const char **roots, size_t root_count, const char **interpreters, size_t interpreter_count, int allow_subdirectories, int allow_by_cwd_only, const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  if (!old_name || !*old_name) return fail_msg("old trusted workspace name is required");
  WorkspaceEdit rule = { new_name, roots, root_count, interpreters, interpreter_count, allow_subdirectories ? 1 : 0, allow_by_cwd_only ? 1 : 0 };
  char err[512] = {0};
  if (!validate_workspace_inputs(&rule, platform, err, sizeof(err))) return fail_msg(err);
  SetWorkspaceEdit edit = { old_name, rule };
  return edit_config(config_path, edit_set_workspace, &edit, platform);
}

int config_backend_remove_trusted_workspace(const char *config_path, const char *name, const NetwatchPlatform *platform){
  if (!name || !*name) return fail_msg("trusted workspace name is required");
  RemoveEdit edit = { .section = "trustedWorkspaces", .name = name };
  return edit_config(config_path, edit_remove_named, &edit, platform);
}

int config_backend_reload_daemon(const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  char err[512] = {0};
  if (!platform->reload_daemon || !platform->reload_daemon(platform, NETWATCH_DAEMON_LABEL, err, sizeof(err))) return fail_msg(err[0] ? err : "daemon is not running");
  printf("Daemon reload requested.\n");
  return 0;
}
