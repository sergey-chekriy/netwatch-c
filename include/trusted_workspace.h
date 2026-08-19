#ifndef NETWATCH_TRUSTED_WORKSPACE_H
#define NETWATCH_TRUSTED_WORKSPACE_H

#include "strlist.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

struct NetwatchPlatform;

typedef struct {
  char *name;
  StrList roots;
  bool allow_subdirectories;
  StrList interpreters;
  bool allow_by_cwd_only;
} TrustedWorkspaceRule;

typedef struct {
  TrustedWorkspaceRule *items;
  size_t len;
  size_t cap;
} TrustedWorkspaceRules;

typedef enum {
  TRUSTED_WORKSPACE_OK,
  TRUSTED_WORKSPACE_INTERPRETER_NOT_MATCHED,
  TRUSTED_WORKSPACE_CWD_UNAVAILABLE,
  TRUSTED_WORKSPACE_CWD_OUTSIDE_ROOT,
  TRUSTED_WORKSPACE_SCRIPT_UNAVAILABLE,
  TRUSTED_WORKSPACE_SCRIPT_OUTSIDE_ROOT,
  TRUSTED_WORKSPACE_PLATFORM_ERROR
} TrustedWorkspaceResult;

typedef struct {
  TrustedWorkspaceResult result;
  const TrustedWorkspaceRule *rule;
  const char *matched_interpreter;
  char matched_root[PATH_MAX];
  char cwd[PATH_MAX];
  char script_path[PATH_MAX];
} TrustedWorkspaceCheck;

void trusted_workspace_rules_free(TrustedWorkspaceRules *rules);
int trusted_workspace_rules_push(TrustedWorkspaceRules *rules, const char *name, StrList *roots, bool allow_subdirectories, StrList *interpreters, bool allow_by_cwd_only);
TrustedWorkspaceCheck trusted_workspace_check_path(const TrustedWorkspaceRules *rules, int pid, const char *interpreter_path, const struct NetwatchPlatform *platform);
const char *trusted_workspace_result_name(TrustedWorkspaceResult result);

#endif
