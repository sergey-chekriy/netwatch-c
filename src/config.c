#include "config.h"
#include "util.h"
#include "cJSON.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void process_rules_free(ProcessRules *rules){
  if (!rules) return;
  for (size_t i = 0; i < rules->len; i++){
    free(rules->items[i].process);
    strlist_free(&rules->items[i].paths);
  }
  free(rules->items); *rules = (ProcessRules){0};
}

void config_free(Config *cfg){
  if (!cfg) return;
  free(cfg->interface); free(cfg->log_path);
  strlist_free(&cfg->deny_patterns);
  strlist_free(&cfg->allow_remote_hosts);
  process_rules_free(&cfg->allow_processes);
  trusted_publisher_rules_free(&cfg->trusted_publishers);
  *cfg = (Config){0};
}

static int process_rules_push(ProcessRules *rules, const char *process, StrList *paths){
  if (rules->len == rules->cap){
    size_t cap = rules->cap ? rules->cap * 2 : 16;
    ProcessRule *items = realloc(rules->items, cap * sizeof(*items));
    if (!items) return 0;
    rules->items = items; rules->cap = cap;
  }
  rules->items[rules->len] = (ProcessRule){ .process = xstrdup(process), .paths = *paths };
  if (!rules->items[rules->len].process) return 0;
  *paths = (StrList){0}; rules->len++; return 1;
}

static int parse_string_array(cJSON *json, StrList *out, const char *name, char *err, size_t err_len){
  if (!json) return 1;
  if (!cJSON_IsArray(json)){ set_error(err, err_len, "%s must be an array", name); return 0; }
  cJSON *item = NULL;
  cJSON_ArrayForEach(item, json){
    if (!cJSON_IsString(item)){ set_error(err, err_len, "%s must contain only strings", name); return 0; }
    if (!strlist_push(out, item->valuestring)){ set_error(err, err_len, "out of memory parsing %s", name); return 0; }
  }
  return 1;
}

static int parse_path_rule(cJSON *json, StrList *out, const char *process, char *err, size_t err_len){
  if (cJSON_IsString(json)){
    if (!strlist_push(out, json->valuestring)){ set_error(err, err_len, "out of memory parsing %s", process); return 0; }
    return 1;
  }
  if (cJSON_IsArray(json)) return parse_string_array(json, out, process, err, err_len);
  set_error(err, err_len, "allowProcesses.%s must be string or array of strings", process);
  return 0;
}

static int parse_allow_processes(cJSON *json, ProcessRules *out, char *err, size_t err_len){
  if (!json) return 1;
  if (!cJSON_IsObject(json)){
    set_error(err, err_len, "allowProcesses must be object: processName -> path or paths");
    return 0;
  }
  cJSON *item = NULL;
  cJSON_ArrayForEach(item, json){
    StrList paths = {0};
    if (!item->string || !parse_path_rule(item, &paths, item->string, err, err_len)){
      strlist_free(&paths); return 0;
    }
    if (!process_rules_push(out, item->string, &paths)){
      strlist_free(&paths); set_error(err, err_len, "out of memory parsing allowProcesses"); return 0;
    }
  }
  return 1;
}

static int parse_optional_string(cJSON *json, char **out, const char *name, char *err, size_t err_len){
  if (!json) return 1;
  if (!cJSON_IsString(json)){ set_error(err, err_len, "%s must be a string", name); return 0; }
  *out = xstrdup(json->valuestring);
  if (!*out){ set_error(err, err_len, "out of memory parsing %s", name); return 0; }
  return 1;
}

static int parse_optional_bool(cJSON *json, bool *out, const char *name, char *err, size_t err_len){
  if (!json) return 1;
  if (!cJSON_IsBool(json)){ set_error(err, err_len, "%s must be boolean", name); return 0; }
  *out = cJSON_IsTrue(json);
  return 1;
}

static int known_trusted_publisher_field(const char *field){
  static const char *known[] = { "paths", "teamId", "signingIdentifier", "requireValidSignature" };
  for (size_t i = 0; i < sizeof(known) / sizeof(*known); i++) if (field && !strcmp(field, known[i])) return 1;
  return 0;
}

static int parse_required_nonempty_string(cJSON *json, const char *where, const char **out, char *err, size_t err_len){
  if (!cJSON_IsString(json) || !json->valuestring || !json->valuestring[0]){
    set_error(err, err_len, "%s expected non-empty string", where);
    return 0;
  }
  *out = json->valuestring;
  return 1;
}

static int parse_trusted_publisher_paths(cJSON *json, StrList *out, const char *publisher, char *err, size_t err_len){
  char where[256];
  snprintf(where, sizeof(where), "trustedPublishers.%s.paths", publisher);
  if (!cJSON_IsArray(json)){ set_error(err, err_len, "%s expected non-empty array of exact executable paths", where); return 0; }
  if (cJSON_GetArraySize(json) <= 0){ set_error(err, err_len, "%s expected non-empty array of exact executable paths", where); return 0; }

  int index = 0;
  cJSON *path = NULL;
  cJSON_ArrayForEach(path, json){
    snprintf(where, sizeof(where), "trustedPublishers.%s.paths[%d]", publisher, index++);
    if (!cJSON_IsString(path) || !path->valuestring || !path->valuestring[0]){
      set_error(err, err_len, "%s expected non-empty string", where);
      return 0;
    }
    if (path->valuestring[0] != '/'){
      set_error(err, err_len, "%s expected absolute executable path", where);
      return 0;
    }
    if (strchr(path->valuestring, '*')){
      set_error(err, err_len, "%s wildcard paths are not supported for trusted publisher rules", where);
      return 0;
    }
    if (!strlist_push(out, path->valuestring)){
      set_error(err, err_len, "out of memory parsing %s", where);
      return 0;
    }
  }
  return 1;
}

static int parse_trusted_publisher_rule(cJSON *item, TrustedPublisherRules *out, char *err, size_t err_len){
  if (!item->string || !item->string[0]){
    set_error(err, err_len, "trustedPublishers entries must have non-empty names");
    return 0;
  }
  char where[256];
  snprintf(where, sizeof(where), "trustedPublishers.%s", item->string);
  if (!cJSON_IsObject(item)){ set_error(err, err_len, "%s must be an object", where); return 0; }
  for (cJSON *field = item->child; field; field = field->next){
    if (!known_trusted_publisher_field(field->string)){
      set_error(err, err_len, "%s.%s unsupported field", where, field->string ? field->string : "(unknown)");
      return 0;
    }
  }

  StrList paths = {0};
  const char *team_id = NULL, *signing_identifier = NULL;
  if (!parse_trusted_publisher_paths(cJSON_GetObjectItemCaseSensitive(item, "paths"), &paths, item->string, err, err_len)) goto fail;
  snprintf(where, sizeof(where), "trustedPublishers.%s.teamId", item->string);
  if (!parse_required_nonempty_string(cJSON_GetObjectItemCaseSensitive(item, "teamId"), where, &team_id, err, err_len)) goto fail;
  snprintf(where, sizeof(where), "trustedPublishers.%s.signingIdentifier", item->string);
  if (!parse_required_nonempty_string(cJSON_GetObjectItemCaseSensitive(item, "signingIdentifier"), where, &signing_identifier, err, err_len)) goto fail;

  cJSON *require_valid = cJSON_GetObjectItemCaseSensitive(item, "requireValidSignature");
  if (require_valid){
    snprintf(where, sizeof(where), "trustedPublishers.%s.requireValidSignature", item->string);
    if (!cJSON_IsBool(require_valid)){ set_error(err, err_len, "%s must be boolean", where); goto fail; }
    if (!cJSON_IsTrue(require_valid)){ set_error(err, err_len, "%s false is not supported for trusted publisher rules", where); goto fail; }
  }

  if (!trusted_publisher_rules_push(out, item->string, &paths, team_id, signing_identifier)){
    set_error(err, err_len, "out of memory parsing trustedPublishers");
    goto fail;
  }
  return 1;

fail:
  strlist_free(&paths);
  return 0;
}

static int parse_trusted_publishers(cJSON *json, TrustedPublisherRules *out, char *err, size_t err_len){
  if (!json) return 1;
  if (!cJSON_IsObject(json)){ set_error(err, err_len, "trustedPublishers must be an object"); return 0; }
  for (cJSON *item = json->child; item; item = item->next){
    if (!parse_trusted_publisher_rule(item, out, err, err_len)) return 0;
  }
  return 1;
}

static int parse_version(cJSON *json, char *err, size_t err_len){
  if (!json) return 1;
  if (!cJSON_IsNumber(json)){
    set_error(err, err_len, "version must be the number %d", NETWATCH_CONFIG_VERSION);
    return 0;
  }
  errno = 0;
  char *end = NULL;
  long version = strtol(json->valuestring, &end, 10);
  if (errno || !end || *end || version < INT_MIN || version > INT_MAX){
    set_error(err, err_len, "version must be an integer number");
    return 0;
  }
  if (version != NETWATCH_CONFIG_VERSION){
    set_error(err, err_len, "Unsupported config version: %ld\nSupported version: %d", version, NETWATCH_CONFIG_VERSION);
    return 0;
  }
  return 1;
}

int config_parse_text(Config *cfg, const char *text, const char *source, char *err, size_t err_len){
  *cfg = (Config){ .dry_run = true };
  cJSON *root = cJSON_Parse(text);
  if (!root){ set_error(err, err_len, "invalid JSON in %s", source); return 0; }
  if (!cJSON_IsObject(root)){ cJSON_Delete(root); set_error(err, err_len, "config root must be object"); return 0; }

  if (!parse_version(cJSON_GetObjectItemCaseSensitive(root, "version"), err, err_len)){
    cJSON_Delete(root); return 0;
  }

  cJSON *dry = cJSON_GetObjectItemCaseSensitive(root, "dryRun");
  if (dry){
    if (!cJSON_IsBool(dry)){ cJSON_Delete(root); set_error(err, err_len, "dryRun must be boolean"); return 0; }
    cfg->dry_run = cJSON_IsTrue(dry);
  }

  int ok = parse_optional_string(cJSON_GetObjectItemCaseSensitive(root, "interface"), &cfg->interface, "interface", err, err_len)
    && parse_optional_string(cJSON_GetObjectItemCaseSensitive(root, "logPath"), &cfg->log_path, "logPath", err, err_len)
    && parse_optional_bool(cJSON_GetObjectItemCaseSensitive(root, "allowAppleSystemComponents"), &cfg->allow_apple_system_components, "allowAppleSystemComponents", err, err_len)
    && parse_string_array(cJSON_GetObjectItemCaseSensitive(root, "denyPatterns"), &cfg->deny_patterns, "denyPatterns", err, err_len)
    && parse_string_array(cJSON_GetObjectItemCaseSensitive(root, "allowRemoteHosts"), &cfg->allow_remote_hosts, "allowRemoteHosts", err, err_len)
    && parse_allow_processes(cJSON_GetObjectItemCaseSensitive(root, "allowProcesses"), &cfg->allow_processes, err, err_len)
    && parse_trusted_publishers(cJSON_GetObjectItemCaseSensitive(root, "trustedPublishers"), &cfg->trusted_publishers, err, err_len);
  cJSON_Delete(root);
  if (!ok) config_free(cfg);
  return ok;
}

int config_load_with_platform(Config *cfg, const char *path, const NetwatchPlatform *platform, char *err, size_t err_len){
  platform = netwatch_platform_or_default(platform);
  char *text = platform->read_file(platform, path, err, err_len); if (!text) return 0;
  int ok = config_parse_text(cfg, text, path, err, err_len);
  free(text); return ok;
}

int config_load(Config *cfg, const char *path, char *err, size_t err_len){
  return config_load_with_platform(cfg, path, netwatch_platform_default(), err, err_len);
}
