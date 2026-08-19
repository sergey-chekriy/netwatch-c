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

typedef struct {
  const char *name;
  const char *path;
  const char *team_id;
  const char *signing_identifier;
} PublisherEdit;

static int validate_publisher_inputs(const PublisherEdit *edit, const NetwatchPlatform *platform, char *err, size_t err_len){
  if (!edit->name || !*edit->name) return set_error(err, err_len, "trusted publisher name is required"), 0;
  if (!edit->path || edit->path[0] != '/') return set_error(err, err_len, "trusted publisher path must be absolute"), 0;
  if (!edit->team_id || !*edit->team_id) return set_error(err, err_len, "team ID is required"), 0;
  if (!edit->signing_identifier || !*edit->signing_identifier) return set_error(err, err_len, "signing identifier is required"), 0;
  if (platform->access_path(platform, edit->path, F_OK) != 0) return set_error(err, err_len, "trusted publisher executable does not exist"), 0;
  CodeSignatureIdentity actual = {0};
  CodeSignatureIdentityResult result = platform->code_signature_identity(platform, edit->path, &actual, err, err_len);
  if (result != CODE_SIGNATURE_IDENTITY_OK) return 0;
  if (strcmp(actual.team_id, edit->team_id)) return set_error(err, err_len, "trusted publisher Team ID mismatch"), 0;
  if (strcmp(actual.signing_identifier, edit->signing_identifier)) return set_error(err, err_len, "trusted publisher signing identifier mismatch"), 0;
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
  PublisherEdit edit = { name, path, team_id, signing_identifier };
  char err[512] = {0};
  if (!validate_publisher_inputs(&edit, platform, err, sizeof(err))) return fail_msg(err);
  return edit_config(config_path, edit_add_publisher, &edit, platform);
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

int config_backend_remove_trusted_publisher(const char *config_path, const char *name, const NetwatchPlatform *platform){
  if (!name || !*name) return fail_msg("trusted publisher name is required");
  RemoveEdit edit = { .section = "trustedPublishers", .name = name };
  return edit_config(config_path, edit_remove_named, &edit, platform);
}

typedef struct { const char *name; const char *root; const char *interpreter; } WorkspaceEdit;

static int validate_workspace_inputs(const WorkspaceEdit *edit, const NetwatchPlatform *platform, char *err, size_t err_len){
  if (!edit->name || !*edit->name) return set_error(err, err_len, "trusted workspace name is required"), 0;
  if (!edit->root || edit->root[0] != '/') return set_error(err, err_len, "trusted workspace root must be absolute"), 0;
  if (!edit->interpreter || edit->interpreter[0] != '/') return set_error(err, err_len, "trusted workspace interpreter must be absolute"), 0;
  struct stat st;
  if (platform->stat_path(platform, edit->root, &st) != 0 || !S_ISDIR(st.st_mode)) return set_error(err, err_len, "trusted workspace root must exist and be a directory"), 0;
  if (platform->access_path(platform, edit->interpreter, X_OK) != 0) return set_error(err, err_len, "trusted workspace interpreter must exist and be executable"), 0;
  return 1;
}

static int edit_add_workspace(cJSON *root, void *ctx, char *changed, size_t changed_len, char *err, size_t err_len){
  WorkspaceEdit *edit = ctx;
  cJSON *workspaces = json_ensure_object(root, "trustedWorkspaces");
  cJSON *rule = json_object(edit->name);
  cJSON *roots = json_array("roots");
  cJSON *interpreters = json_array("interpreters");
  cJSON *root_item = json_string(NULL, edit->root);
  cJSON *interpreter_item = json_string(NULL, edit->interpreter);
  if (!workspaces || !rule || !roots || !interpreters || !root_item || !interpreter_item){
    cJSON_Delete(rule); cJSON_Delete(roots); cJSON_Delete(interpreters); cJSON_Delete(root_item); cJSON_Delete(interpreter_item);
    set_error(err, err_len, "out of memory adding trusted workspace"); return 0;
  }
  json_add_child(roots, root_item);
  json_add_child(interpreters, interpreter_item);
  if (!json_set(rule, "roots", roots)
    || !json_set(rule, "allowSubdirectories", json_bool("allowSubdirectories", 1))
    || !json_set(rule, "interpreters", interpreters)
    || !json_set(rule, "allowByCwdOnly", json_bool("allowByCwdOnly", 0))
    || !json_set(workspaces, edit->name, rule)){
    cJSON_Delete(rule); set_error(err, err_len, "out of memory adding trusted workspace"); return 0;
  }
  snprintf(changed, changed_len, "trustedWorkspaces.%s added", edit->name);
  return 1;
}

int config_backend_add_trusted_workspace(const char *config_path, const char *name, const char *root, const char *interpreter, const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  WorkspaceEdit edit = { name, root, interpreter };
  char err[512] = {0};
  if (!validate_workspace_inputs(&edit, platform, err, sizeof(err))) return fail_msg(err);
  return edit_config(config_path, edit_add_workspace, &edit, platform);
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
