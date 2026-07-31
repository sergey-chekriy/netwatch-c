#include "allow.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const ProcessRule *find_rule(const Config *cfg, const char *proc){
  for (size_t i = 0; i < cfg->allow_processes.len; i++){
    if (!strcmp(cfg->allow_processes.items[i].process, proc)) return &cfg->allow_processes.items[i];
  }
  return NULL;
}

static int localhost_listen(const char *line){
  return strstr(line, "LISTEN") && (strstr(line, "127.0.0.1") || strstr(line, "localhost"));
}

static const char *remote_allowed_match(const char *line, const Config *cfg){
  char *remote = remote_of(line); if (!remote) return 0;
  const char *match = NULL;
  for (size_t i = 0; i < cfg->allow_remote_hosts.len; i++){
    if (!strncmp(remote, cfg->allow_remote_hosts.items[i], strlen(cfg->allow_remote_hosts.items[i]))){ match = cfg->allow_remote_hosts.items[i]; break; }
  }
  free(remote); return match;
}

static const char *path_allowed_for_process(const char *proc, const char *path, const Config *cfg, const char **matched_process){
  const ProcessRule *rule = find_rule(cfg, proc);
  if (!rule || !path) return NULL;
  for (size_t i = 0; i < rule->paths.len; i++){
    if (path_has_prefix_rule(path, rule->paths.items[i])){
      if (matched_process) *matched_process = rule->process;
      return rule->paths.items[i];
    }
  }
  return NULL;
}

static ConnectionPolicy policy_result(ConnectionDecision decision){
  return (ConnectionPolicy){ .decision = decision };
}

static ConnectionPolicy publisher_policy_result(TrustedPublisherCheck check){
  ConnectionPolicy policy = policy_result(check.result == TRUSTED_PUBLISHER_OK
    ? CONNECTION_ALLOWED_TRUSTED_PUBLISHER
    : CONNECTION_UNKNOWN);
  policy.trusted_publisher_checked = true;
  policy.trusted_publisher = check.result;
  policy.matched_publisher = check.rule ? check.rule->name : NULL;
  policy.matched_publisher_path = check.matched_path;
  policy.expected_team_id = check.rule ? check.rule->team_id : NULL;
  policy.expected_signing_identifier = check.rule ? check.rule->signing_identifier : NULL;
  snprintf(policy.actual_team_id, sizeof(policy.actual_team_id), "%s", check.actual.team_id);
  snprintf(policy.actual_signing_identifier, sizeof(policy.actual_signing_identifier), "%s", check.actual.signing_identifier);
  return policy;
}

static ConnectionPolicy connection_policy_for_path_base(const char *line, const char *proc, const char *path, const Config *cfg, const NetwatchPlatform *platform, PolicyAppleVerifier verifier){
  const char *deny = strlist_find_contains_ci(&cfg->deny_patterns, line);
  if (deny){ ConnectionPolicy policy = policy_result(CONNECTION_DENIED); policy.matched_deny = deny; return policy; }

  TrustedPublisherCheck publisher = trusted_publisher_check_path(&cfg->trusted_publishers, path, platform);
  if (publisher.result != TRUSTED_PUBLISHER_PATH_NOT_MATCHED) return publisher_policy_result(publisher);

  if (localhost_listen(line)) return policy_result(CONNECTION_ALLOWED_LOCALHOST);

  const char *matched_process = NULL;
  const char *matched_path = path_allowed_for_process(proc, path, cfg, &matched_process);
  if (matched_path){
    ConnectionPolicy policy = policy_result(CONNECTION_ALLOWED_CONFIG);
    policy.matched_process = matched_process; policy.matched_path = matched_path;
    return policy;
  }
  const char *remote = remote_allowed_match(line, cfg);
  if (remote){ ConnectionPolicy policy = policy_result(CONNECTION_ALLOWED_CONFIG); policy.matched_remote_host = remote; return policy; }
  if (cfg->allow_apple_system_components){
    ConnectionPolicy policy = { .decision = CONNECTION_UNKNOWN, .apple_trust_checked = true };
    if (platform) policy.apple_trust = platform->apple_trust_check(platform, path, NULL, 0);
    else policy.apple_trust = (verifier ? verifier : apple_trust_check)(path, NULL, 0);
    if (policy.apple_trust == APPLE_TRUST_OK) policy.decision = CONNECTION_ALLOWED_APPLE_SYSTEM;
    return policy;
  }
  return policy_result(CONNECTION_UNKNOWN);
}

ConnectionPolicy connection_policy_for_path_with_platform(const char *line, const char *proc, const char *path, const Config *cfg, const NetwatchPlatform *platform){
  return connection_policy_for_path_base(line, proc, path, cfg, netwatch_platform_or_default(platform), NULL);
}

ConnectionPolicy connection_policy_for_path_with_verifier(const char *line, const char *proc, const char *path, const Config *cfg, PolicyAppleVerifier verifier){
  return connection_policy_for_path_base(line, proc, path, cfg, NULL, verifier);
}

ConnectionPolicy connection_policy_for_path(const char *line, const char *proc, const char *path, const Config *cfg){
  return connection_policy_for_path_with_platform(line, proc, path, cfg, netwatch_platform_default());
}

ConnectionPolicy connection_policy_with_platform(const char *line, const Config *cfg, PathCache *cache, const NetwatchPlatform *platform){
  const char *proc = process_name_of(line);
  int pid = 0;
  char *path = pid_of(line, &pid) ? process_path_cached_with_platform(cache, pid, proc, platform) : NULL;
  ConnectionPolicy policy = connection_policy_for_path_with_platform(line, proc, path, cfg, platform);
  free(path); return policy;
}

ConnectionPolicy connection_policy(const char *line, const Config *cfg, PathCache *cache){
  return connection_policy_with_platform(line, cfg, cache, netwatch_platform_default());
}

int connection_decision_allowed(ConnectionDecision decision){
  return decision == CONNECTION_ALLOWED_LOCALHOST
    || decision == CONNECTION_ALLOWED_TRUSTED_PUBLISHER
    || decision == CONNECTION_ALLOWED_CONFIG
    || decision == CONNECTION_ALLOWED_APPLE_SYSTEM;
}

bool connection_allowed(const char *line, const Config *cfg, PathCache *cache){
  return connection_decision_allowed(connection_policy(line, cfg, cache).decision);
}

const char *connection_decision_name(ConnectionDecision decision){
  switch (decision){
    case CONNECTION_DENIED: return "DENIED";
    case CONNECTION_ALLOWED_LOCALHOST: return "ALLOWED_LOCALHOST";
    case CONNECTION_ALLOWED_TRUSTED_PUBLISHER: return "TRUSTED_PUBLISHER";
    case CONNECTION_ALLOWED_CONFIG: return "ALLOWED_CONFIG";
    case CONNECTION_ALLOWED_APPLE_SYSTEM: return "APPLE_SYSTEM";
    case CONNECTION_UNKNOWN: return "UNKNOWN";
  }
  return "UNKNOWN";
}

const char *connection_decision_reason(ConnectionDecision decision){
  switch (decision){
    case CONNECTION_DENIED: return "explicit deny rule";
    case CONNECTION_ALLOWED_LOCALHOST: return "localhost listen";
    case CONNECTION_ALLOWED_TRUSTED_PUBLISHER: return "trusted publisher identity verified";
    case CONNECTION_ALLOWED_CONFIG: return "explicit config allow";
    case CONNECTION_ALLOWED_APPLE_SYSTEM: return "trusted Apple system component";
    case CONNECTION_UNKNOWN: return "not present in allowlist";
  }
  return "not present in allowlist";
}

static const char *display_name_for_path(const char *line, const char *path){
  if (path && strcmp(path, "unknown")){
    const char *base = strrchr(path, '/');
    if (base && base[1]) return base + 1;
    if (*path) return path;
  }
  return process_name_of(line);
}

char *describe_connection_with_platform(const char *line, PathCache *cache, ConnectionPolicy policy, const NetwatchPlatform *platform){
  const char *proc = process_name_of(line);
  int pid = 0;
  char *path = pid_of(line, &pid) ? process_path_cached_with_platform(cache, pid, proc, platform) : xstrdup("unknown");
  if (!path) return NULL;
  const char *name = display_name_for_path(line, path);
  const char *decision = connection_decision_name(policy.decision);
  const char *reason = policy.trusted_publisher_checked && policy.decision == CONNECTION_UNKNOWN
    ? trusted_publisher_result_name(policy.trusted_publisher)
    : connection_decision_reason(policy.decision);
  const char *apple = policy.apple_trust_checked ? apple_trust_result_name(policy.apple_trust) : "";
  const char *publisher = policy.matched_publisher ? policy.matched_publisher : "";
  const char *publisher_result = policy.trusted_publisher_checked ? trusted_publisher_result_name(policy.trusted_publisher) : "";
  size_t n = strlen(decision) + strlen(name) + strlen(line) + strlen(path) + strlen(reason) + strlen(apple)
    + strlen(publisher) + strlen(publisher_result) + strlen(policy.actual_team_id)
    + strlen(policy.actual_signing_identifier) + 180;
  char *out = malloc(n);
  if (out){
    snprintf(out, n, "[%s] %s\n  LINE: %s\n  PATH: %s\n  REASON: %s%s%s%s%s%s%s%s%s%s%s",
      decision, name, line, path, reason,
      policy.apple_trust_checked ? "\n  APPLE TRUST: " : "", apple,
      policy.trusted_publisher_checked ? "\n  TRUSTED PUBLISHER: " : "", publisher_result,
      policy.matched_publisher ? "\n  PUBLISHER RULE: " : "", publisher,
      policy.actual_team_id[0] ? "\n  ACTUAL TEAM ID: " : "", policy.actual_team_id,
      policy.actual_signing_identifier[0] ? "\n  ACTUAL SIGNING IDENTIFIER: " : "", policy.actual_signing_identifier);
  }
  free(path); return out;
}

char *describe_connection(const char *line, PathCache *cache, ConnectionPolicy policy){
  return describe_connection_with_platform(line, cache, policy, netwatch_platform_default());
}
