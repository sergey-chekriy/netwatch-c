#include "config.h"
#include "util.h"
#include "cJSON.h"
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

int config_load(Config *cfg, const char *path, char *err, size_t err_len){
  *cfg = (Config){ .dry_run = true };
  char *text = read_file(path, err, err_len); if (!text) return 0;
  cJSON *root = cJSON_Parse(text); free(text);
  if (!root){ set_error(err, err_len, "invalid JSON in %s", path); return 0; }
  if (!cJSON_IsObject(root)){ cJSON_Delete(root); set_error(err, err_len, "config root must be object"); return 0; }

  cJSON *dry = cJSON_GetObjectItemCaseSensitive(root, "dryRun");
  if (dry){
    if (!cJSON_IsBool(dry)){ cJSON_Delete(root); set_error(err, err_len, "dryRun must be boolean"); return 0; }
    cfg->dry_run = cJSON_IsTrue(dry);
  }

  int ok = parse_optional_string(cJSON_GetObjectItemCaseSensitive(root, "interface"), &cfg->interface, "interface", err, err_len)
    && parse_optional_string(cJSON_GetObjectItemCaseSensitive(root, "logPath"), &cfg->log_path, "logPath", err, err_len)
    && parse_string_array(cJSON_GetObjectItemCaseSensitive(root, "denyPatterns"), &cfg->deny_patterns, "denyPatterns", err, err_len)
    && parse_string_array(cJSON_GetObjectItemCaseSensitive(root, "allowRemoteHosts"), &cfg->allow_remote_hosts, "allowRemoteHosts", err, err_len)
    && parse_allow_processes(cJSON_GetObjectItemCaseSensitive(root, "allowProcesses"), &cfg->allow_processes, err, err_len);
  cJSON_Delete(root);
  if (!ok) config_free(cfg);
  return ok;
}
