#include "trusted_app_bundle.h"
#include "platform.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

void trusted_app_bundle_rules_free(TrustedAppBundleRules *rules){
  if (!rules) return;
  for (size_t i = 0; i < rules->len; i++){
    free(rules->items[i].name);
    free(rules->items[i].bundle_root);
    free(rules->items[i].team_id);
    strlist_free(&rules->items[i].allowed_signing_identifiers);
    strlist_free(&rules->items[i].allowed_signing_identifier_prefixes);
  }
  free(rules->items); *rules = (TrustedAppBundleRules){0};
}

int trusted_app_bundle_rules_push(TrustedAppBundleRules *rules, const char *name, const char *bundle_root,
  const char *team_id, StrList *identifiers, StrList *prefixes, bool allow_subdirectories){
  if (rules->len == rules->cap){
    size_t cap = rules->cap ? rules->cap * 2 : 8;
    TrustedAppBundleRule *items = realloc(rules->items, cap * sizeof(*items));
    if (!items) return 0;
    rules->items = items; rules->cap = cap;
  }
  char *name_copy = xstrdup(name), *root_copy = xstrdup(bundle_root), *team_copy = xstrdup(team_id);
  if (!name_copy || !root_copy || !team_copy){
    free(name_copy); free(root_copy); free(team_copy);
    return 0;
  }
  rules->items[rules->len] = (TrustedAppBundleRule){
    .name = name_copy,
    .bundle_root = root_copy,
    .team_id = team_copy,
    .allowed_signing_identifiers = *identifiers,
    .allowed_signing_identifier_prefixes = *prefixes,
    .allow_subdirectories = allow_subdirectories
  };
  *identifiers = (StrList){0}; *prefixes = (StrList){0};
  rules->len++; return 1;
}

static int path_inside(const char *path, const char *root){
  size_t n = strlen(root);
  return !strncmp(path, root, n) && path[n] == '/';
}

static int identifier_allowed(const TrustedAppBundleRule *rule, const char *identifier){
  for (size_t i = 0; i < rule->allowed_signing_identifiers.len; i++){
    if (!strcmp(identifier, rule->allowed_signing_identifiers.items[i])) return 1;
  }
  for (size_t i = 0; i < rule->allowed_signing_identifier_prefixes.len; i++){
    const char *prefix = rule->allowed_signing_identifier_prefixes.items[i];
    if (!strncmp(identifier, prefix, strlen(prefix))) return 1;
  }
  return 0;
}

static TrustedAppBundleCheck check_result(TrustedAppBundleResult result, const TrustedAppBundleRule *rule){
  return (TrustedAppBundleCheck){ .result = result, .rule = rule };
}

static TrustedAppBundleResult map_identity_result(CodeSignatureIdentityResult result){
  switch (result){
    case CODE_SIGNATURE_IDENTITY_OK: return TRUSTED_APP_BUNDLE_OK;
    case CODE_SIGNATURE_IDENTITY_INVALID_SIGNATURE: return TRUSTED_APP_BUNDLE_INVALID_SIGNATURE;
    case CODE_SIGNATURE_IDENTITY_METADATA_UNAVAILABLE: return TRUSTED_APP_BUNDLE_METADATA_UNAVAILABLE;
    case CODE_SIGNATURE_IDENTITY_SECURITY_ERROR: return TRUSTED_APP_BUNDLE_SECURITY_ERROR;
  }
  return TRUSTED_APP_BUNDLE_SECURITY_ERROR;
}

TrustedAppBundleCheck trusted_app_bundle_check_rule(const TrustedAppBundleRule *rule, const char *path,
  const struct NetwatchPlatform *platform){
  if (!rule || !path || !*path) return check_result(TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED, NULL);
  int lexical_match = path_inside(path, rule->bundle_root);
  TrustedAppBundleCheck check = check_result(TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED, rule);
  if (!realpath(rule->bundle_root, check.canonical_bundle_root)){
    check.result = lexical_match ? TRUSTED_APP_BUNDLE_ROOT_UNAVAILABLE : TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED;
    return check;
  }
  if (!realpath(path, check.canonical_executable_path)){
    check.result = lexical_match ? TRUSTED_APP_BUNDLE_EXECUTABLE_UNAVAILABLE : TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED;
    return check;
  }
  if (!path_inside(check.canonical_executable_path, check.canonical_bundle_root)){
    check.result = lexical_match ? TRUSTED_APP_BUNDLE_EXECUTABLE_OUTSIDE_ROOT : TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED;
    return check;
  }
  if (!rule->allow_subdirectories){
    const char *relative = check.canonical_executable_path + strlen(check.canonical_bundle_root) + 1;
    if (strchr(relative, '/')){ check.result = TRUSTED_APP_BUNDLE_SUBDIRECTORY_NOT_ALLOWED; return check; }
  }
  if (!platform || !platform->code_signature_identity){
    check.result = TRUSTED_APP_BUNDLE_SECURITY_ERROR;
    return check;
  }
  check.result = map_identity_result(platform->code_signature_identity(
    platform, check.canonical_executable_path, &check.actual, NULL, 0));
  if (check.result != TRUSTED_APP_BUNDLE_OK) return check;
  if (strcmp(check.actual.team_id, rule->team_id)){
    check.result = TRUSTED_APP_BUNDLE_TEAM_ID_MISMATCH;
    return check;
  }
  if (!identifier_allowed(rule, check.actual.signing_identifier)){
    check.result = TRUSTED_APP_BUNDLE_SIGNING_IDENTIFIER_MISMATCH;
  }
  return check;
}

static int failure_rank(TrustedAppBundleResult result){
  switch (result){
    case TRUSTED_APP_BUNDLE_EXECUTABLE_OUTSIDE_ROOT: return 0;
    case TRUSTED_APP_BUNDLE_INVALID_SIGNATURE: return 1;
    case TRUSTED_APP_BUNDLE_METADATA_UNAVAILABLE: return 2;
    case TRUSTED_APP_BUNDLE_SECURITY_ERROR: return 3;
    case TRUSTED_APP_BUNDLE_TEAM_ID_MISMATCH: return 4;
    case TRUSTED_APP_BUNDLE_SIGNING_IDENTIFIER_MISMATCH: return 5;
    case TRUSTED_APP_BUNDLE_ROOT_UNAVAILABLE: return 6;
    case TRUSTED_APP_BUNDLE_EXECUTABLE_UNAVAILABLE: return 7;
    case TRUSTED_APP_BUNDLE_SUBDIRECTORY_NOT_ALLOWED: return 8;
    case TRUSTED_APP_BUNDLE_OK: return 9;
    case TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED: return 10;
  }
  return 10;
}

static int check_preferred(TrustedAppBundleCheck candidate, TrustedAppBundleCheck current){
  if (current.result == TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED) return 1;
  if (candidate.result == TRUSTED_APP_BUNDLE_OK || current.result == TRUSTED_APP_BUNDLE_OK){
    if (candidate.result != current.result) return candidate.result == TRUSTED_APP_BUNDLE_OK;
  } else if (failure_rank(candidate.result) != failure_rank(current.result)){
    return failure_rank(candidate.result) < failure_rank(current.result);
  }
  const char *candidate_name = candidate.rule && candidate.rule->name ? candidate.rule->name : "";
  const char *current_name = current.rule && current.rule->name ? current.rule->name : "";
  return strcmp(candidate_name, current_name) < 0;
}

TrustedAppBundleCheck trusted_app_bundle_check_path(const TrustedAppBundleRules *rules, const char *path,
  const struct NetwatchPlatform *platform){
  TrustedAppBundleCheck best = check_result(TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED, NULL);
  for (size_t i = 0; rules && i < rules->len; i++){
    TrustedAppBundleCheck check = trusted_app_bundle_check_rule(&rules->items[i], path, platform);
    if (check.result != TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED && check_preferred(check, best)) best = check;
  }
  return best;
}

const char *trusted_app_bundle_result_name(TrustedAppBundleResult result){
  switch (result){
    case TRUSTED_APP_BUNDLE_OK: return "trusted app bundle identity verified";
    case TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED: return "trusted app bundle path not matched";
    case TRUSTED_APP_BUNDLE_ROOT_UNAVAILABLE: return "trusted app bundle root cannot be canonicalized";
    case TRUSTED_APP_BUNDLE_EXECUTABLE_UNAVAILABLE: return "trusted app bundle executable cannot be canonicalized";
    case TRUSTED_APP_BUNDLE_EXECUTABLE_OUTSIDE_ROOT: return "trusted app bundle symlink escapes bundle root";
    case TRUSTED_APP_BUNDLE_SUBDIRECTORY_NOT_ALLOWED: return "trusted app bundle subdirectories are not allowed";
    case TRUSTED_APP_BUNDLE_INVALID_SIGNATURE: return "trusted app bundle code signature invalid";
    case TRUSTED_APP_BUNDLE_TEAM_ID_MISMATCH: return "trusted app bundle Team ID mismatch";
    case TRUSTED_APP_BUNDLE_SIGNING_IDENTIFIER_MISMATCH: return "trusted app bundle signing identifier mismatch";
    case TRUSTED_APP_BUNDLE_METADATA_UNAVAILABLE: return "trusted app bundle signature metadata unavailable";
    case TRUSTED_APP_BUNDLE_SECURITY_ERROR: return "trusted app bundle Security.framework error";
  }
  return "trusted app bundle Security.framework error";
}
