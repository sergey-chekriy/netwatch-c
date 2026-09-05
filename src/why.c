#include "why.h"
#include "config.h"
#include "util.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *path_basename(const char *path){
  const char *base = strrchr(path ? path : "", '/');
  return base && base[1] ? base + 1 : path;
}

static char *synthetic_line_for_pid(const char *proc, int pid){
  const char *tail = " 0 user 0u IPv4 TCP 0.0.0.0:0->0.0.0.0:0 (ESTABLISHED)";
  char pid_text[32]; snprintf(pid_text, sizeof(pid_text), "%d", pid);
  size_t n = strlen(proc) + strlen(pid_text) + strlen(tail) + 1;
  char *line = malloc(n); if (!line) return NULL;
  snprintf(line, n, "%s %s%s", proc, pid_text, tail + 2);
  return line;
}

static char *synthetic_line(const char *proc){ return synthetic_line_for_pid(proc, 0); }

static int matching_allow_rule(const Config *cfg, const char *path, const ProcessRule **rule_out){
  int matches = 0;
  *rule_out = NULL;
  for (size_t i = 0; i < cfg->allow_processes.len; i++){
    ProcessRule *rule = &cfg->allow_processes.items[i];
    for (size_t j = 0; j < rule->paths.len; j++){
      if (path_has_prefix_rule(path, rule->paths.items[j])){
        *rule_out = rule;
        matches++;
        break;
      }
    }
  }
  return matches;
}

static int explain_policy_for_proc(const Config *cfg, const char *proc, const char *path, const NetwatchPlatform *platform, PolicyAppleVerifier verifier, ConnectionPolicy *policy){
  char *line = synthetic_line(proc);
  if (!line) return 0;
  *policy = platform
    ? connection_policy_for_path_with_platform(line, proc, path, cfg, platform)
    : connection_policy_for_path_with_verifier(line, proc, path, cfg, verifier);
  free(line);
  return 1;
}

static int explain_policy_for_pid(const Config *cfg, int pid, const char *proc, const char *path, const NetwatchPlatform *platform, ConnectionPolicy *policy){
  char *line = synthetic_line_for_pid(proc, pid);
  if (!line) return 0;
  *policy = connection_policy_for_pid_path_with_platform(line, proc, path, pid, cfg, platform);
  free(line);
  return 1;
}

static const char *why_decision_name(ConnectionDecision decision){
  switch (decision){
    case CONNECTION_DENIED: return "DENIED";
    case CONNECTION_ALLOWED_LOCALHOST:
    case CONNECTION_ALLOWED_TRUSTED_PUBLISHER:
    case CONNECTION_ALLOWED_TRUSTED_APP_BUNDLE:
    case CONNECTION_ALLOWED_TRUSTED_WORKSPACE:
    case CONNECTION_ALLOWED_CONFIG: return "ALLOWED";
    case CONNECTION_ALLOWED_APPLE_SYSTEM: return "APPLE_SYSTEM";
    case CONNECTION_UNKNOWN: return "UNKNOWN";
  }
  return "UNKNOWN";
}

static const char *trust_source_name(ConnectionPolicy policy){
  if (policy.decision == CONNECTION_ALLOWED_TRUSTED_PUBLISHER) return "TRUSTED_PUBLISHER";
  if (policy.decision == CONNECTION_ALLOWED_TRUSTED_APP_BUNDLE) return "TRUSTED_APP_BUNDLE";
  if (policy.decision == CONNECTION_ALLOWED_TRUSTED_WORKSPACE) return "TRUSTED_WORKSPACE";
  if (policy.decision == CONNECTION_ALLOWED_APPLE_SYSTEM) return "APPLE_SYSTEM";
  if (policy.decision == CONNECTION_ALLOWED_CONFIG) return "CONFIG";
  if (policy.decision == CONNECTION_DENIED) return "DENY";
  return "NONE";
}

static void print_policy(ConnectionPolicy policy){
  printf("Decision: %s\n", why_decision_name(policy.decision));
  printf("Trust source: %s\n\nReason:\n", trust_source_name(policy));
  if (policy.decision == CONNECTION_DENIED){
    printf("  matched deny rule: %s\n", policy.matched_deny ? policy.matched_deny : "(unknown)");
  } else if (policy.trusted_publisher_checked){
    printf("  executable path matched trustedPublishers.%s\n", policy.matched_publisher ? policy.matched_publisher : "(unknown)");
    if (policy.trusted_publisher != TRUSTED_PUBLISHER_SECURITY_ERROR
      && policy.trusted_publisher != TRUSTED_PUBLISHER_METADATA_UNAVAILABLE
      && policy.trusted_publisher != TRUSTED_PUBLISHER_INVALID_SIGNATURE){
      printf("  code signature valid\n");
    }
    if (policy.trusted_publisher == TRUSTED_PUBLISHER_OK){
      printf("  Team ID matched\n");
      printf("  signing identifier matched\n");
    } else if (policy.trusted_publisher == TRUSTED_PUBLISHER_TEAM_ID_MISMATCH){
      printf("  Team ID mismatch\n");
      printf("\nExpected Team ID:\n  %s\n", policy.expected_team_id ? policy.expected_team_id : "(unknown)");
      printf("\nActual Team ID:\n  %s\n", policy.actual_team_id[0] ? policy.actual_team_id : "(unavailable)");
    } else if (policy.trusted_publisher == TRUSTED_PUBLISHER_SIGNING_IDENTIFIER_MISMATCH){
      printf("  signing identifier mismatch\n");
      printf("\nExpected signing identifier:\n  %s\n", policy.expected_signing_identifier ? policy.expected_signing_identifier : "(unknown)");
      printf("\nActual signing identifier:\n  %s\n", policy.actual_signing_identifier[0] ? policy.actual_signing_identifier : "(unavailable)");
    } else if (policy.trusted_publisher == TRUSTED_PUBLISHER_INVALID_SIGNATURE){
      printf("  code signature invalid\n");
    } else {
      printf("  %s\n", trusted_publisher_result_name(policy.trusted_publisher));
    }
  } else if (policy.trusted_app_bundle_checked){
    printf("Bundle rule: %s\n", policy.matched_app_bundle ? policy.matched_app_bundle : "(unknown)");
    if (policy.trusted_app_bundle == TRUSTED_APP_BUNDLE_OK){
      printf("Code signature valid\n");
      printf("Team ID matched\n");
      printf("Signing identifier matched\n");
      printf("Executable is inside bundle root\n");
    } else {
      printf("  %s\n", trusted_app_bundle_result_name(policy.trusted_app_bundle));
      if (policy.trusted_app_bundle == TRUSTED_APP_BUNDLE_TEAM_ID_MISMATCH){
        printf("\nExpected Team ID:\n  %s\n", policy.expected_team_id ? policy.expected_team_id : "(unknown)");
        printf("\nActual Team ID:\n  %s\n", policy.actual_team_id[0] ? policy.actual_team_id : "(unavailable)");
      } else if (policy.trusted_app_bundle == TRUSTED_APP_BUNDLE_SIGNING_IDENTIFIER_MISMATCH){
        printf("\nActual signing identifier:\n  %s\n",
          policy.actual_signing_identifier[0] ? policy.actual_signing_identifier : "(unavailable)");
      }
    }
    if (policy.matched_bundle_root) printf("\nBundle root:\n  %s\n", policy.matched_bundle_root);
  } else if (policy.trusted_workspace_checked){
    printf("  interpreter matched");
    if (policy.matched_workspace) printf(" trustedWorkspaces.%s", policy.matched_workspace);
    if (policy.matched_workspace_interpreter) printf(": %s", policy.matched_workspace_interpreter);
    printf("\n");
    if (policy.trusted_workspace == TRUSTED_WORKSPACE_OK){
      printf("  cwd is inside trusted workspace root\n");
      if (policy.trusted_workspace_script[0]) printf("  script path is inside trusted workspace root\n");
      else printf("  allowByCwdOnly accepted cwd-only workspace process\n");
    } else if (policy.trusted_workspace == TRUSTED_WORKSPACE_CWD_UNAVAILABLE){
      printf("  cwd is unavailable\n");
    } else if (policy.trusted_workspace == TRUSTED_WORKSPACE_CWD_OUTSIDE_ROOT){
      printf("  cwd is outside trusted workspace root\n");
    } else if (policy.trusted_workspace == TRUSTED_WORKSPACE_SCRIPT_UNAVAILABLE){
      printf("  script path is unavailable\n");
    } else if (policy.trusted_workspace == TRUSTED_WORKSPACE_SCRIPT_OUTSIDE_ROOT){
      printf("  cwd is inside trusted workspace root\n");
      printf("  script path is outside trusted workspace root\n");
    } else {
      printf("  %s\n", trusted_workspace_result_name(policy.trusted_workspace));
    }
    if (policy.matched_workspace_root[0]) printf("\nTrusted workspace root:\n  %s\n", policy.matched_workspace_root);
    if (policy.trusted_workspace_cwd[0]) printf("\nProcess cwd:\n  %s\n", policy.trusted_workspace_cwd);
    if (policy.trusted_workspace_script[0]) printf("\nResolved script path:\n  %s\n", policy.trusted_workspace_script);
  } else if (policy.decision == CONNECTION_ALLOWED_CONFIG){
    if (policy.matched_process) printf("  matched allowProcesses.%s\n", policy.matched_process);
    if (policy.matched_path) printf("  matched path: %s\n", policy.matched_path);
    if (policy.matched_remote_host) printf("  matched remote host prefix: %s\n", policy.matched_remote_host);
  } else if (policy.decision == CONNECTION_ALLOWED_APPLE_SYSTEM){
    printf("  approved Apple system root\n");
    printf("  Apple signature valid\n");
  } else {
    printf("  no deny rule matched\n");
    printf("  no allow rule matched\n");
    printf("  %s\n", policy.apple_trust_checked ? apple_trust_result_name(policy.apple_trust) : "not an automatically trusted Apple system component");
  }
}

static int parse_pid_target(const char *target, int *pid){
  for (const char *p = target; p && *p; p++) if (!isdigit((unsigned char)*p)) return 0;
  errno = 0;
  char *end = NULL;
  long value = strtol(target, &end, 10);
  if (errno || !end || *end || value <= 0 || value > INT_MAX) return 0;
  *pid = (int)value;
  return 1;
}

static int why_explain_base(const Config *cfg, const char *target, const NetwatchPlatform *platform, PolicyAppleVerifier verifier){
  if (!cfg || !target || !*target){ fprintf(stderr, "ERROR: pid or executable path is required\n"); return 1; }
  int target_pid = 0;
  if (parse_pid_target(target, &target_pid)){
    platform = netwatch_platform_or_default(platform);
    char *path = platform->process_path ? platform->process_path(platform, target_pid, "") : NULL;
    if (!path || !strcmp(path, "unknown")){
      free(path);
      fprintf(stderr, "ERROR: failed to resolve executable path for pid %d\n", target_pid);
      return 1;
    }
    ConnectionPolicy policy = {0};
    if (!explain_policy_for_pid(cfg, target_pid, path_basename(path), path, platform, &policy)){
      free(path);
      fprintf(stderr, "ERROR: out of memory explaining decision\n");
      return 1;
    }
    print_policy(policy);
    free(path);
    return 0;
  }
  if (target[0] != '/'){
    fprintf(stderr, "ERROR: unresolved process name: %s\nPass an absolute executable path.\n", target);
    return 1;
  }
  if (strchr(target, '*')){ fprintf(stderr, "ERROR: expected exact executable path, not wildcard: %s\n", target); return 1; }

  ConnectionPolicy policy = {0};
  if (!explain_policy_for_proc(cfg, path_basename(target), target, platform, verifier, &policy)){
    fprintf(stderr, "ERROR: out of memory explaining decision\n");
    return 1;
  }
  if (policy.decision == CONNECTION_DENIED){
    print_policy(policy);
    return 0;
  }
  if (policy.decision != CONNECTION_ALLOWED_CONFIG && !policy.trusted_publisher_checked
    && !policy.trusted_app_bundle_checked && !policy.trusted_workspace_checked){
    const ProcessRule *rule = NULL;
    int matches = matching_allow_rule(cfg, target, &rule);
    if (matches > 1){ fprintf(stderr, "ERROR: executable path matches multiple allowProcesses entries: %s\n", target); return 1; }
    if (matches == 1){
      if (!explain_policy_for_proc(cfg, rule->process, target, platform, verifier, &policy)){
        fprintf(stderr, "ERROR: out of memory explaining decision\n");
        return 1;
      }
      if (policy.decision == CONNECTION_DENIED || policy.decision == CONNECTION_ALLOWED_CONFIG){
        print_policy(policy);
        return 0;
      }
    }
  }
  print_policy(policy);
  return 0;
}

int why_explain_with_platform(const Config *cfg, const char *target, const NetwatchPlatform *platform){
  return why_explain_base(cfg, target, netwatch_platform_or_default(platform), NULL);
}

int why_explain(const Config *cfg, const char *target, PolicyAppleVerifier verifier){
  return why_explain_base(cfg, target, NULL, verifier);
}

int why_command_with_platform(const char *config_path, const char *target, const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  char err[512] = {0};
  Config cfg = {0};
  if (!config_load_with_platform(&cfg, config_path, platform, err, sizeof(err))){ fprintf(stderr, "ERROR: %s\n", err); return 1; }
  int rc = why_explain_with_platform(&cfg, target, platform);
  config_free(&cfg);
  return rc;
}

int why_command(const char *config_path, const char *target){
  return why_command_with_platform(config_path, target, netwatch_platform_default());
}
