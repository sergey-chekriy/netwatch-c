#ifndef NETWATCH_ALLOW_H
#define NETWATCH_ALLOW_H

#include "config.h"
#include "process.h"
#include "apple_trust.h"
#include <stdbool.h>

typedef enum {
  CONNECTION_DENIED,
  CONNECTION_ALLOWED_LOCALHOST,
  CONNECTION_ALLOWED_TRUSTED_PUBLISHER,
  CONNECTION_ALLOWED_TRUSTED_WORKSPACE,
  CONNECTION_ALLOWED_CONFIG,
  CONNECTION_ALLOWED_APPLE_SYSTEM,
  CONNECTION_UNKNOWN
} ConnectionDecision;

typedef struct {
  ConnectionDecision decision;
  bool apple_trust_checked;
  AppleTrustResult apple_trust;
  bool trusted_publisher_checked;
  TrustedPublisherResult trusted_publisher;
  bool trusted_workspace_checked;
  TrustedWorkspaceResult trusted_workspace;
  const char *matched_deny;
  const char *matched_publisher;
  const char *matched_publisher_path;
  const char *matched_workspace;
  const char *matched_workspace_interpreter;
  const char *expected_team_id;
  const char *expected_signing_identifier;
  const char *matched_process;
  const char *matched_path;
  const char *matched_remote_host;
  char actual_team_id[CODE_SIGNATURE_FIELD_MAX];
  char actual_signing_identifier[CODE_SIGNATURE_FIELD_MAX];
  char matched_workspace_root[PATH_MAX];
  char trusted_workspace_cwd[PATH_MAX];
  char trusted_workspace_script[PATH_MAX];
} ConnectionPolicy;

typedef AppleTrustResult (*PolicyAppleVerifier)(const char *path, char *reason, size_t reason_size);

ConnectionPolicy connection_policy_for_path_with_platform(const char *line, const char *proc, const char *path, const Config *cfg, const NetwatchPlatform *platform);
ConnectionPolicy connection_policy_for_pid_path_with_platform(const char *line, const char *proc, const char *path, int pid, const Config *cfg, const NetwatchPlatform *platform);
ConnectionPolicy connection_policy_for_path_with_verifier(const char *line, const char *proc, const char *path, const Config *cfg, PolicyAppleVerifier verifier);
ConnectionPolicy connection_policy_for_path(const char *line, const char *proc, const char *path, const Config *cfg);
ConnectionPolicy connection_policy_with_platform(const char *line, const Config *cfg, PathCache *cache, const NetwatchPlatform *platform);
ConnectionPolicy connection_policy(const char *line, const Config *cfg, PathCache *cache);
bool connection_allowed(const char *line, const Config *cfg, PathCache *cache);
int connection_decision_allowed(ConnectionDecision decision);
const char *connection_decision_name(ConnectionDecision decision);
const char *connection_decision_reason(ConnectionDecision decision);
char *describe_connection_with_platform(const char *line, PathCache *cache, ConnectionPolicy policy, const NetwatchPlatform *platform);
char *describe_connection(const char *line, PathCache *cache, ConnectionPolicy policy);

#endif
