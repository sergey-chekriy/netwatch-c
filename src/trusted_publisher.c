#include "trusted_publisher.h"
#include "platform.h"
#include "util.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

void trusted_publisher_rules_free(TrustedPublisherRules *rules){
  if (!rules) return;
  for (size_t i = 0; i < rules->len; i++){
    free(rules->items[i].name);
    strlist_free(&rules->items[i].paths);
    free(rules->items[i].team_id);
    free(rules->items[i].signing_identifier);
  }
  free(rules->items); *rules = (TrustedPublisherRules){0};
}

int trusted_publisher_rules_push(TrustedPublisherRules *rules, const char *name, StrList *paths, const char *team_id, const char *signing_identifier){
  if (rules->len == rules->cap){
    size_t cap = rules->cap ? rules->cap * 2 : 8;
    TrustedPublisherRule *items = realloc(rules->items, cap * sizeof(*items));
    if (!items) return 0;
    rules->items = items; rules->cap = cap;
  }
  char *name_copy = xstrdup(name);
  char *team_copy = xstrdup(team_id);
  char *identifier_copy = xstrdup(signing_identifier);
  if (!name_copy || !team_copy || !identifier_copy){
    free(name_copy); free(team_copy); free(identifier_copy);
    return 0;
  }
  rules->items[rules->len] = (TrustedPublisherRule){
    .name = name_copy,
    .paths = *paths,
    .team_id = team_copy,
    .signing_identifier = identifier_copy,
    .require_valid_signature = true
  };
  *paths = (StrList){0};
  rules->len++; return 1;
}

static int same_path(const char *left, const char *right){
  if (!left || !right || !*left || !*right) return 0;
  if (!strcmp(left, right)) return 1;
  char left_real[PATH_MAX], right_real[PATH_MAX];
  if (realpath(left, left_real) && realpath(right, right_real)) return !strcmp(left_real, right_real);
  return 0;
}

static int path_inside(const char *path, const char *root){
  size_t n = strlen(root);
  return !strncmp(path, root, n) && path[n] == '/';
}

static int publisher_path_match(const char *path, const char *rule){
  size_t n = strlen(rule);
  if (n < 3 || strcmp(rule + n - 2, "/*")) return same_path(path, rule);

  char *root = malloc(n - 1);
  if (!root) return -1;
  memcpy(root, rule, n - 2); root[n - 2] = 0;
  char canonical_root[PATH_MAX], canonical_path[PATH_MAX];
  int lexical_match = path_inside(path, root);
  int root_ok = realpath(root, canonical_root) != NULL;
  free(root);
  if (!root_ok || !realpath(path, canonical_path)) return lexical_match ? -1 : 0;
  if (path_inside(canonical_path, canonical_root)) return 1;
  return lexical_match ? -1 : 0;
}

static TrustedPublisherCheck check_result(TrustedPublisherResult result, const TrustedPublisherRule *rule, const char *path){
  return (TrustedPublisherCheck){ .result = result, .rule = rule, .matched_path = path };
}

static int check_name_cmp(TrustedPublisherCheck left, TrustedPublisherCheck right){
  const char *left_name = left.rule && left.rule->name ? left.rule->name : "";
  const char *right_name = right.rule && right.rule->name ? right.rule->name : "";
  int name_cmp = strcmp(left_name, right_name);
  if (name_cmp) return name_cmp;
  const char *left_path = left.matched_path ? left.matched_path : "";
  const char *right_path = right.matched_path ? right.matched_path : "";
  return strcmp(left_path, right_path);
}

static int failure_rank(TrustedPublisherResult result){
  switch (result){
    case TRUSTED_PUBLISHER_INVALID_SIGNATURE: return 0;
    case TRUSTED_PUBLISHER_METADATA_UNAVAILABLE: return 1;
    case TRUSTED_PUBLISHER_SECURITY_ERROR: return 2;
    case TRUSTED_PUBLISHER_TEAM_ID_MISMATCH: return 3;
    case TRUSTED_PUBLISHER_SIGNING_IDENTIFIER_MISMATCH: return 4;
    case TRUSTED_PUBLISHER_OK: return 5;
    case TRUSTED_PUBLISHER_PATH_NOT_MATCHED: return 6;
  }
  return 6;
}

static int check_preferred(TrustedPublisherCheck candidate, TrustedPublisherCheck current){
  if (current.result == TRUSTED_PUBLISHER_PATH_NOT_MATCHED) return 1;
  if (candidate.result == TRUSTED_PUBLISHER_OK && current.result != TRUSTED_PUBLISHER_OK) return 1;
  if (candidate.result != TRUSTED_PUBLISHER_OK && current.result == TRUSTED_PUBLISHER_OK) return 0;
  if (candidate.result == TRUSTED_PUBLISHER_OK) return check_name_cmp(candidate, current) < 0;
  int candidate_rank = failure_rank(candidate.result);
  int current_rank = failure_rank(current.result);
  if (candidate_rank != current_rank) return candidate_rank < current_rank;
  return check_name_cmp(candidate, current) < 0;
}

static TrustedPublisherResult map_identity_result(CodeSignatureIdentityResult result){
  switch (result){
    case CODE_SIGNATURE_IDENTITY_OK: return TRUSTED_PUBLISHER_OK;
    case CODE_SIGNATURE_IDENTITY_INVALID_SIGNATURE: return TRUSTED_PUBLISHER_INVALID_SIGNATURE;
    case CODE_SIGNATURE_IDENTITY_METADATA_UNAVAILABLE: return TRUSTED_PUBLISHER_METADATA_UNAVAILABLE;
    case CODE_SIGNATURE_IDENTITY_SECURITY_ERROR: return TRUSTED_PUBLISHER_SECURITY_ERROR;
  }
  return TRUSTED_PUBLISHER_SECURITY_ERROR;
}

TrustedPublisherCheck trusted_publisher_check_rule(const TrustedPublisherRule *rule, const char *path, const struct NetwatchPlatform *platform){
  if (!rule || !path || !*path) return check_result(TRUSTED_PUBLISHER_PATH_NOT_MATCHED, NULL, NULL);
  const char *matched = NULL, *unsafe = NULL;
  for (size_t i = 0; i < rule->paths.len; i++){
    int match = publisher_path_match(path, rule->paths.items[i]);
    if (match > 0){ matched = rule->paths.items[i]; break; }
    if (match < 0 && !unsafe) unsafe = rule->paths.items[i];
  }
  if (!matched && unsafe) return check_result(TRUSTED_PUBLISHER_SECURITY_ERROR, rule, unsafe);
  if (!matched) return check_result(TRUSTED_PUBLISHER_PATH_NOT_MATCHED, NULL, NULL);
  if (!platform || !platform->code_signature_identity) return check_result(TRUSTED_PUBLISHER_SECURITY_ERROR, rule, matched);

  TrustedPublisherCheck check = check_result(TRUSTED_PUBLISHER_SECURITY_ERROR, rule, matched);
  CodeSignatureIdentityResult identity_result = platform->code_signature_identity(platform, path, &check.actual, NULL, 0);
  check.result = map_identity_result(identity_result);
  if (check.result != TRUSTED_PUBLISHER_OK) return check;
  if (strcmp(check.actual.team_id, rule->team_id)){ check.result = TRUSTED_PUBLISHER_TEAM_ID_MISMATCH; return check; }
  if (strcmp(check.actual.signing_identifier, rule->signing_identifier)){
    check.result = TRUSTED_PUBLISHER_SIGNING_IDENTIFIER_MISMATCH;
    return check;
  }
  return check;
}

TrustedPublisherCheck trusted_publisher_check_path(const TrustedPublisherRules *rules, const char *path, const struct NetwatchPlatform *platform){
  TrustedPublisherCheck best = check_result(TRUSTED_PUBLISHER_PATH_NOT_MATCHED, NULL, NULL);
  for (size_t i = 0; rules && i < rules->len; i++){
    TrustedPublisherCheck check = trusted_publisher_check_rule(&rules->items[i], path, platform);
    if (check.result != TRUSTED_PUBLISHER_PATH_NOT_MATCHED && check_preferred(check, best)) best = check;
  }
  return best;
}

const char *trusted_publisher_result_name(TrustedPublisherResult result){
  switch (result){
    case TRUSTED_PUBLISHER_OK: return "trusted publisher identity verified";
    case TRUSTED_PUBLISHER_PATH_NOT_MATCHED: return "trusted publisher path not matched";
    case TRUSTED_PUBLISHER_INVALID_SIGNATURE: return "trusted publisher code signature invalid";
    case TRUSTED_PUBLISHER_TEAM_ID_MISMATCH: return "trusted publisher Team ID mismatch";
    case TRUSTED_PUBLISHER_SIGNING_IDENTIFIER_MISMATCH: return "trusted publisher signing identifier mismatch";
    case TRUSTED_PUBLISHER_METADATA_UNAVAILABLE: return "trusted publisher signature metadata unavailable";
    case TRUSTED_PUBLISHER_SECURITY_ERROR: return "trusted publisher Security.framework error";
  }
  return "trusted publisher Security.framework error";
}
