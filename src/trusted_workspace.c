#include "trusted_workspace.h"
#include "platform.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void trusted_workspace_rules_free(TrustedWorkspaceRules *rules){
  if (!rules) return;
  for (size_t i = 0; i < rules->len; i++){
    free(rules->items[i].name);
    strlist_free(&rules->items[i].roots);
    strlist_free(&rules->items[i].interpreters);
  }
  free(rules->items); *rules = (TrustedWorkspaceRules){0};
}

int trusted_workspace_rules_push(TrustedWorkspaceRules *rules, const char *name, StrList *roots, bool allow_subdirectories, StrList *interpreters, bool allow_by_cwd_only){
  if (rules->len == rules->cap){
    size_t cap = rules->cap ? rules->cap * 2 : 8;
    TrustedWorkspaceRule *items = realloc(rules->items, cap * sizeof(*items));
    if (!items) return 0;
    rules->items = items; rules->cap = cap;
  }
  char *name_copy = xstrdup(name);
  if (!name_copy) return 0;
  rules->items[rules->len] = (TrustedWorkspaceRule){
    .name = name_copy,
    .roots = *roots,
    .allow_subdirectories = allow_subdirectories,
    .interpreters = *interpreters,
    .allow_by_cwd_only = allow_by_cwd_only
  };
  *roots = (StrList){0}; *interpreters = (StrList){0};
  rules->len++; return 1;
}

static int real_copy(const char *path, char out[PATH_MAX]){
  return path && *path && realpath(path, out) != NULL;
}

static int same_real_path(const char *left, const char *right){
  char left_real[PATH_MAX], right_real[PATH_MAX];
  return real_copy(left, left_real) && real_copy(right, right_real) && !strcmp(left_real, right_real);
}

static int path_inside_real_root(const char *root_real, const char *path_real, int allow_subdirectories){
  size_t n = strlen(root_real);
  if (!strcmp(root_real, path_real)) return 1;
  return allow_subdirectories && n > 1 && !strncmp(root_real, path_real, n) && path_real[n] == '/';
}

static int option_takes_value(const char *arg){
  static const char *opts[] = { "-c", "-e", "-m", "-r", "--eval", "--require", "--loader", "--import" };
  for (size_t i = 0; i < sizeof(opts) / sizeof(*opts); i++){
    size_t n = strlen(opts[i]);
    if (!strcmp(arg, opts[i])) return 1;
    if (!strncmp(arg, opts[i], n) && arg[n] == '=') return 0;
  }
  return 0;
}

static const char *script_arg_from_argv(const StrList *argv){
  for (size_t i = 1; argv && i < argv->len; i++){
    const char *arg = argv->items[i];
    if (!strcmp(arg, "--")) return i + 1 < argv->len ? argv->items[i + 1] : NULL;
    if (arg[0] != '-') return arg;
    if (option_takes_value(arg) && i + 1 < argv->len) i++;
  }
  return NULL;
}

static int resolve_script_path(const char *arg, const char *cwd, char out[PATH_MAX]){
  if (!arg || !*arg) return 0;
  if (arg[0] == '/') return real_copy(arg, out);
  char combined[PATH_MAX];
  int n = snprintf(combined, sizeof(combined), "%s/%s", cwd, arg);
  if (n < 0 || (size_t)n >= sizeof(combined)) return 0;
  return real_copy(combined, out);
}

static TrustedWorkspaceCheck check_result(TrustedWorkspaceResult result, const TrustedWorkspaceRule *rule){
  return (TrustedWorkspaceCheck){ .result = result, .rule = rule };
}

static TrustedWorkspaceCheck check_rule(const TrustedWorkspaceRule *rule, int pid, const char *interpreter_path, const NetwatchPlatform *platform){
  const char *matched_interpreter = NULL;
  for (size_t i = 0; i < rule->interpreters.len; i++){
    if (same_real_path(interpreter_path, rule->interpreters.items[i])){ matched_interpreter = rule->interpreters.items[i]; break; }
  }
  if (!matched_interpreter) return check_result(TRUSTED_WORKSPACE_INTERPRETER_NOT_MATCHED, NULL);

  TrustedWorkspaceCheck check = check_result(TRUSTED_WORKSPACE_CWD_UNAVAILABLE, rule);
  check.matched_interpreter = matched_interpreter;
  if (pid <= 0 || !platform || !platform->process_cwd || !platform->process_argv) return check;

  char *cwd = platform->process_cwd(platform, pid);
  if (!cwd) return check;
  if (!real_copy(cwd, check.cwd)){ free(cwd); return check; }
  free(cwd);

  const char *matched_root = NULL;
  for (size_t i = 0; i < rule->roots.len; i++){
    char root_real[PATH_MAX];
    if (real_copy(rule->roots.items[i], root_real)
      && path_inside_real_root(root_real, check.cwd, rule->allow_subdirectories)){
      snprintf(check.matched_root, sizeof(check.matched_root), "%s", root_real);
      matched_root = check.matched_root;
      break;
    }
  }
  if (!matched_root){ check.result = TRUSTED_WORKSPACE_CWD_OUTSIDE_ROOT; return check; }

  StrList argv = {0};
  char err[128] = {0};
  if (!platform->process_argv(platform, pid, &argv, err, sizeof(err))){
    strlist_free(&argv);
    check.result = rule->allow_by_cwd_only ? TRUSTED_WORKSPACE_OK : TRUSTED_WORKSPACE_SCRIPT_UNAVAILABLE;
    return check;
  }

  const char *script_arg = script_arg_from_argv(&argv);
  if (!resolve_script_path(script_arg, check.cwd, check.script_path)){
    strlist_free(&argv);
    check.result = rule->allow_by_cwd_only ? TRUSTED_WORKSPACE_OK : TRUSTED_WORKSPACE_SCRIPT_UNAVAILABLE;
    return check;
  }
  strlist_free(&argv);
  check.result = path_inside_real_root(matched_root, check.script_path, 1)
    ? TRUSTED_WORKSPACE_OK
    : TRUSTED_WORKSPACE_SCRIPT_OUTSIDE_ROOT;
  return check;
}

static int result_rank(TrustedWorkspaceResult result){
  switch (result){
    case TRUSTED_WORKSPACE_OK: return 0;
    case TRUSTED_WORKSPACE_SCRIPT_OUTSIDE_ROOT: return 1;
    case TRUSTED_WORKSPACE_SCRIPT_UNAVAILABLE: return 2;
    case TRUSTED_WORKSPACE_CWD_OUTSIDE_ROOT: return 3;
    case TRUSTED_WORKSPACE_CWD_UNAVAILABLE: return 4;
    case TRUSTED_WORKSPACE_PLATFORM_ERROR: return 5;
    case TRUSTED_WORKSPACE_INTERPRETER_NOT_MATCHED: return 6;
  }
  return 6;
}

static int check_preferred(TrustedWorkspaceCheck candidate, TrustedWorkspaceCheck current){
  if (current.result == TRUSTED_WORKSPACE_INTERPRETER_NOT_MATCHED) return 1;
  int cr = result_rank(candidate.result), rr = result_rank(current.result);
  if (cr != rr) return cr < rr;
  const char *cn = candidate.rule && candidate.rule->name ? candidate.rule->name : "";
  const char *rn = current.rule && current.rule->name ? current.rule->name : "";
  return strcmp(cn, rn) < 0;
}

TrustedWorkspaceCheck trusted_workspace_check_path(const TrustedWorkspaceRules *rules, int pid, const char *interpreter_path, const NetwatchPlatform *platform){
  TrustedWorkspaceCheck best = check_result(TRUSTED_WORKSPACE_INTERPRETER_NOT_MATCHED, NULL);
  for (size_t i = 0; rules && i < rules->len; i++){
    TrustedWorkspaceCheck check = check_rule(&rules->items[i], pid, interpreter_path, platform);
    if (check.result != TRUSTED_WORKSPACE_INTERPRETER_NOT_MATCHED && check_preferred(check, best)) best = check;
  }
  return best;
}

const char *trusted_workspace_result_name(TrustedWorkspaceResult result){
  switch (result){
    case TRUSTED_WORKSPACE_OK: return "trusted workspace script verified";
    case TRUSTED_WORKSPACE_INTERPRETER_NOT_MATCHED: return "trusted workspace interpreter not matched";
    case TRUSTED_WORKSPACE_CWD_UNAVAILABLE: return "trusted workspace cwd unavailable";
    case TRUSTED_WORKSPACE_CWD_OUTSIDE_ROOT: return "trusted workspace cwd outside root";
    case TRUSTED_WORKSPACE_SCRIPT_UNAVAILABLE: return "trusted workspace script path unavailable";
    case TRUSTED_WORKSPACE_SCRIPT_OUTSIDE_ROOT: return "trusted workspace script path outside root";
    case TRUSTED_WORKSPACE_PLATFORM_ERROR: return "trusted workspace platform error";
  }
  return "trusted workspace platform error";
}
