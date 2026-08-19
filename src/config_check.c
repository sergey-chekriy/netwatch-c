#include "config_check.h"
#include "config.h"
#include "cJSON.h"
#include "util.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct { char *where; char *message; } CheckIssue;
typedef struct { CheckIssue *items; size_t len; size_t cap; } CheckIssues;

static char *xvsprintf(const char *fmt, va_list ap){
  va_list copy;
  va_copy(copy, ap);
  int n = vsnprintf(NULL, 0, fmt, copy);
  va_end(copy);
  if (n < 0) return NULL;
  char *out = malloc((size_t)n + 1); if (!out) return NULL;
  vsnprintf(out, (size_t)n + 1, fmt, ap);
  return out;
}

static int issues_push(CheckIssues *issues, const char *where, const char *fmt, ...){
  if (issues->len == issues->cap){
    size_t cap = issues->cap ? issues->cap * 2 : 8;
    CheckIssue *items = realloc(issues->items, cap * sizeof(*items));
    if (!items) return 0;
    issues->items = items; issues->cap = cap;
  }
  va_list ap;
  va_start(ap, fmt);
  char *where_dup = xstrdup(where);
  char *message = xvsprintf(fmt, ap);
  va_end(ap);
  if (!where_dup || !message){ free(where_dup); free(message); return 0; }
  issues->items[issues->len] = (CheckIssue){ where_dup, message };
  issues->len++;
  return 1;
}

static void issues_free(CheckIssues *issues){
  for (size_t i = 0; i < issues->len; i++){
    free(issues->items[i].where);
    free(issues->items[i].message);
  }
  free(issues->items); *issues = (CheckIssues){0};
}

static void print_issue_text(const char *text){
  const char *line = text;
  while (*line){
    const char *end = strchr(line, '\n');
    if (!end){
      printf("  %s\n", line);
      return;
    }
    printf("  %.*s\n", (int)(end - line), line);
    line = end + 1;
  }
}

static void print_issues(const char *heading, const CheckIssues *issues){
  printf("%s:\n", heading);
  for (size_t i = 0; i < issues->len; i++){
    printf("  %s\n", issues->items[i].where);
    print_issue_text(issues->items[i].message);
  }
}

static int contains_ci(const char *s, const char *needle){
  if (!s || !needle) return 0;
  size_t n = strlen(needle); if (!n) return 0;
  for (; *s; s++){
    size_t i = 0;
    for (; i < n && s[i]; i++){
      if (tolower((unsigned char)s[i]) != tolower((unsigned char)needle[i])) break;
    }
    if (i == n) return 1;
  }
  return 0;
}

static int path_has_invalid_wildcard(const char *path){
  const char *star = strchr(path ? path : "", '*');
  return star && star[1];
}

static int path_has_wildcard(const char *path){ return path && strchr(path, '*'); }

static int malformed_path(const char *path){ return !path || path[0] != '/'; }

static int warn_duplicate_deny(cJSON *root, CheckIssues *warnings){
  cJSON *deny = cJSON_GetObjectItemCaseSensitive(root, "denyPatterns");
  if (!cJSON_IsArray(deny)) return 1;
  int n = cJSON_GetArraySize(deny);
  for (int i = 0; i < n; i++){
    cJSON *left = cJSON_GetArrayItem(deny, i);
    if (!cJSON_IsString(left)) continue;
    for (int j = i + 1; j < n; j++){
      cJSON *right = cJSON_GetArrayItem(deny, j);
      if (cJSON_IsString(right) && !strcmp(left->valuestring, right->valuestring)){
        if (!issues_push(warnings, "denyPatterns", "duplicate deny pattern: %s", left->valuestring)) return 0;
      }
    }
  }
  return 1;
}

static int warn_duplicate_allow_processes(cJSON *allow, CheckIssues *warnings){
  if (!cJSON_IsObject(allow)) return 1;
  for (cJSON *left = allow->child; left; left = left->next){
    if (!left->string) continue;
    for (cJSON *right = left->next; right; right = right->next){
      if (right->string && !strcmp(left->string, right->string)){
        if (!issues_push(warnings, "allowProcesses", "duplicate process entry: %s", left->string)) return 0;
      }
    }
  }
  return 1;
}

static int warn_duplicate_array_paths(cJSON *paths, const char *process, CheckIssues *warnings){
  if (!cJSON_IsArray(paths)) return 1;
  int n = cJSON_GetArraySize(paths);
  char where[256]; snprintf(where, sizeof(where), "allowProcesses.%s", process);
  for (int i = 0; i < n; i++){
    cJSON *left = cJSON_GetArrayItem(paths, i);
    if (!cJSON_IsString(left)) continue;
    for (int j = i + 1; j < n; j++){
      cJSON *right = cJSON_GetArrayItem(paths, j);
      if (cJSON_IsString(right) && !strcmp(left->valuestring, right->valuestring)){
        if (!issues_push(warnings, where, "duplicate allowed path: %s", left->valuestring)) return 0;
      }
    }
  }
  return 1;
}

static AppleTrustResult check_apple_trust(const NetwatchPlatform *platform, ConfigCheckVerifier verifier, const char *path){
  if (verifier) return verifier(path, NULL, 0);
  return platform->apple_trust_check(platform, path, NULL, 0);
}

static int warn_path(const char *process, const char *path, const Config *cfg, const NetwatchPlatform *platform, ConfigCheckVerifier verifier, CheckIssues *warnings){
  char where[256]; snprintf(where, sizeof(where), "allowProcesses.%s", process);
  if (path_has_invalid_wildcard(path)){
    if (!issues_push(warnings, where, "invalid wildcard usage: %s", path)) return 0;
  }
  if (malformed_path(path)){
    return issues_push(warnings, where, "expected absolute executable path: %s", path ? path : "(null)");
  }
  if (!path_has_wildcard(path) && platform->access_path(platform, path, F_OK) != 0){
    if (!issues_push(warnings, where, "executable does not currently exist: %s", path)) return 0;
  }
  if (cfg->allow_apple_system_components && !path_has_wildcard(path) && apple_trust_is_system_path(path)){
    AppleTrustResult result = check_apple_trust(platform, verifier, path);
    if (result != APPLE_TRUST_OK){
      if (!issues_push(warnings, where, "Apple trust verification did not pass: %s", apple_trust_result_name(result))) return 0;
    }
  }
  return 1;
}

static int warn_allow_paths(cJSON *allow, const Config *cfg, const NetwatchPlatform *platform, ConfigCheckVerifier verifier, CheckIssues *warnings){
  if (!cJSON_IsObject(allow)) return 1;
  for (cJSON *item = allow->child; item; item = item->next){
    if (!item->string) continue;
    if (cJSON_IsString(item)){
      if (!warn_path(item->string, item->valuestring, cfg, platform, verifier, warnings)) return 0;
    } else if (cJSON_IsArray(item)){
      if (!warn_duplicate_array_paths(item, item->string, warnings)) return 0;
      cJSON *path = NULL;
      cJSON_ArrayForEach(path, item){
        if (cJSON_IsString(path) && !warn_path(item->string, path->valuestring, cfg, platform, verifier, warnings)) return 0;
      }
    }
  }
  return 1;
}

static int warn_duplicate_trusted_publisher_paths(const Config *cfg, CheckIssues *warnings){
  for (size_t i = 0; i < cfg->trusted_publishers.len; i++){
    const TrustedPublisherRule *left_rule = &cfg->trusted_publishers.items[i];
    for (size_t j = 0; j < left_rule->paths.len; j++){
      for (size_t k = i; k < cfg->trusted_publishers.len; k++){
        const TrustedPublisherRule *right_rule = &cfg->trusted_publishers.items[k];
        size_t start = k == i ? j + 1 : 0;
        for (size_t l = start; l < right_rule->paths.len; l++){
          if (strcmp(left_rule->paths.items[j], right_rule->paths.items[l])) continue;
          char where[256];
          snprintf(where, sizeof(where), "trustedPublishers.%s.paths[%zu]", right_rule->name, l);
          if (!issues_push(warnings, where,
            "duplicate trusted publisher path also configured at trustedPublishers.%s.paths[%zu]: %s",
            left_rule->name, j, left_rule->paths.items[j])) return 0;
        }
      }
    }
  }
  return 1;
}

static int warn_trusted_publishers(const Config *cfg, const NetwatchPlatform *platform, CheckIssues *warnings){
  for (size_t i = 0; i < cfg->trusted_publishers.len; i++){
    const TrustedPublisherRule *rule = &cfg->trusted_publishers.items[i];
    for (size_t j = 0; j < rule->paths.len; j++){
      char where[256]; snprintf(where, sizeof(where), "trustedPublishers.%s.paths[%zu]", rule->name, j);
      const char *path = rule->paths.items[j];
      if (platform->access_path(platform, path, F_OK) != 0){
        if (!issues_push(warnings, where, "executable does not currently exist: %s", path)) return 0;
        continue;
      }
      TrustedPublisherCheck check = trusted_publisher_check_rule(rule, path, platform);
      if (check.result == TRUSTED_PUBLISHER_OK) continue;
      snprintf(where, sizeof(where), "trustedPublishers.%s", rule->name);
      if (check.result == TRUSTED_PUBLISHER_TEAM_ID_MISMATCH){
        if (!issues_push(warnings, where, "current executable Team ID does not match configured Team ID")) return 0;
      } else if (check.result == TRUSTED_PUBLISHER_SIGNING_IDENTIFIER_MISMATCH){
        if (!issues_push(warnings, where, "current executable signing identifier does not match configured signing identifier")) return 0;
      } else if (check.result == TRUSTED_PUBLISHER_INVALID_SIGNATURE){
        if (!issues_push(warnings, where, "current executable signature is invalid")) return 0;
      } else {
        if (!issues_push(warnings, where, "%s", trusted_publisher_result_name(check.result))) return 0;
      }
    }
  }
  return 1;
}

static int warn_trusted_workspaces(const Config *cfg, const NetwatchPlatform *platform, CheckIssues *warnings){
  for (size_t i = 0; i < cfg->trusted_workspaces.len; i++){
    const TrustedWorkspaceRule *rule = &cfg->trusted_workspaces.items[i];
    for (size_t j = 0; j < rule->roots.len; j++){
      char where[256]; snprintf(where, sizeof(where), "trustedWorkspaces.%s.roots[%zu]", rule->name, j);
      if (platform->access_path(platform, rule->roots.items[j], F_OK) != 0
        && !issues_push(warnings, where, "workspace root does not currently exist: %s", rule->roots.items[j])) return 0;
    }
    for (size_t j = 0; j < rule->interpreters.len; j++){
      char where[256]; snprintf(where, sizeof(where), "trustedWorkspaces.%s.interpreters[%zu]", rule->name, j);
      if (platform->access_path(platform, rule->interpreters.items[j], F_OK) != 0
        && !issues_push(warnings, where, "interpreter does not currently exist: %s", rule->interpreters.items[j])) return 0;
    }
  }
  return 1;
}

static int warn_shadowed_by_deny(cJSON *root, CheckIssues *warnings){
  cJSON *deny = cJSON_GetObjectItemCaseSensitive(root, "denyPatterns");
  cJSON *allow = cJSON_GetObjectItemCaseSensitive(root, "allowProcesses");
  if (!cJSON_IsArray(deny) || !cJSON_IsObject(allow)) return 1;

  cJSON *pattern = NULL;
  cJSON_ArrayForEach(pattern, deny){
    if (!cJSON_IsString(pattern) || !pattern->valuestring[0]) continue;
    for (cJSON *item = allow->child; item; item = item->next){
      if (!item->string) continue;
      char where[256]; snprintf(where, sizeof(where), "allowProcesses.%s", item->string);
      if (contains_ci(item->string, pattern->valuestring)){
        if (!issues_push(warnings, where, "shadowed by deny pattern: %s", pattern->valuestring)) return 0;
      }
      if (cJSON_IsString(item) && contains_ci(item->valuestring, pattern->valuestring)){
        if (!issues_push(warnings, where, "allowed path shadowed by deny pattern: %s", pattern->valuestring)) return 0;
      } else if (cJSON_IsArray(item)){
        cJSON *path = NULL;
        cJSON_ArrayForEach(path, item){
          if (cJSON_IsString(path) && contains_ci(path->valuestring, pattern->valuestring)){
            if (!issues_push(warnings, where, "allowed path shadowed by deny pattern: %s", pattern->valuestring)) return 0;
          }
        }
      }
    }
  }
  return 1;
}

static int collect_warnings(cJSON *root, const Config *cfg, const NetwatchPlatform *platform, ConfigCheckVerifier verifier, CheckIssues *warnings){
  cJSON *allow = cJSON_GetObjectItemCaseSensitive(root, "allowProcesses");
  return warn_duplicate_deny(root, warnings)
    && warn_duplicate_allow_processes(allow, warnings)
    && warn_allow_paths(allow, cfg, platform, verifier, warnings)
    && warn_duplicate_trusted_publisher_paths(cfg, warnings)
    && warn_trusted_publishers(cfg, platform, warnings)
    && warn_trusted_workspaces(cfg, platform, warnings)
    && warn_shadowed_by_deny(root, warnings);
}

static int print_invalid(const char *where, const char *message){
  printf("Config invalid:\n\nERROR:\n  %s\n", where);
  print_issue_text(message);
  return 1;
}

static int config_check_file_base(const char *config_path, const NetwatchPlatform *platform, ConfigCheckVerifier verifier){
  if (!config_path || !*config_path) return print_invalid("config", "config path is required");
  platform = netwatch_platform_or_default(platform);
  char err[512] = {0};
  char *text = platform->read_file(platform, config_path, err, sizeof(err));
  if (!text) return print_invalid(config_path, err);

  cJSON *root = cJSON_Parse(text);
  if (!root){
    free(text);
    return print_invalid("JSON", "invalid JSON syntax");
  }
  if (!cJSON_IsObject(root)){
    cJSON_Delete(root); free(text);
    return print_invalid("JSON", "config root must be object");
  }

  Config cfg = {0};
  if (!config_parse_text(&cfg, text, config_path, err, sizeof(err))){
    cJSON_Delete(root); free(text);
    return print_invalid("config", err);
  }

  CheckIssues warnings = {0};
  int ok = collect_warnings(root, &cfg, platform, verifier, &warnings);
  if (!ok){
    issues_free(&warnings);
    config_free(&cfg);
    cJSON_Delete(root);
    free(text);
    return print_invalid("config", "out of memory while checking config");
  }

  if (warnings.len){
    printf("Config valid with warnings:\n\n");
    print_issues("WARNING", &warnings);
  } else {
    printf("Config OK.\n");
  }

  issues_free(&warnings);
  config_free(&cfg);
  cJSON_Delete(root);
  free(text);
  return 0;
}

int config_check_file_with_platform(const char *config_path, const NetwatchPlatform *platform){
  return config_check_file_base(config_path, platform, NULL);
}

int config_check_file_with_verifier(const char *config_path, ConfigCheckVerifier verifier){
  return config_check_file_base(config_path, netwatch_platform_default(), verifier);
}

int config_check_file(const char *config_path){
  return config_check_file_with_platform(config_path, netwatch_platform_default());
}
