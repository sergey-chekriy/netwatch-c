#ifndef NETWATCH_TRUSTED_PUBLISHER_H
#define NETWATCH_TRUSTED_PUBLISHER_H

#include "strlist.h"
#include <stdbool.h>
#include <stddef.h>

#define CODE_SIGNATURE_FIELD_MAX 256

struct NetwatchPlatform;

typedef enum {
  CODE_SIGNATURE_IDENTITY_OK,
  CODE_SIGNATURE_IDENTITY_INVALID_SIGNATURE,
  CODE_SIGNATURE_IDENTITY_METADATA_UNAVAILABLE,
  CODE_SIGNATURE_IDENTITY_SECURITY_ERROR
} CodeSignatureIdentityResult;

typedef struct {
  char team_id[CODE_SIGNATURE_FIELD_MAX];
  char signing_identifier[CODE_SIGNATURE_FIELD_MAX];
} CodeSignatureIdentity;

typedef struct {
  char *name;
  StrList paths;
  char *team_id;
  char *signing_identifier;
  bool require_valid_signature;
} TrustedPublisherRule;

typedef struct {
  TrustedPublisherRule *items;
  size_t len;
  size_t cap;
} TrustedPublisherRules;

typedef enum {
  TRUSTED_PUBLISHER_OK,
  TRUSTED_PUBLISHER_PATH_NOT_MATCHED,
  TRUSTED_PUBLISHER_INVALID_SIGNATURE,
  TRUSTED_PUBLISHER_TEAM_ID_MISMATCH,
  TRUSTED_PUBLISHER_SIGNING_IDENTIFIER_MISMATCH,
  TRUSTED_PUBLISHER_METADATA_UNAVAILABLE,
  TRUSTED_PUBLISHER_SECURITY_ERROR
} TrustedPublisherResult;

typedef struct {
  TrustedPublisherResult result;
  const TrustedPublisherRule *rule;
  const char *matched_path;
  CodeSignatureIdentity actual;
} TrustedPublisherCheck;

void trusted_publisher_rules_free(TrustedPublisherRules *rules);
int trusted_publisher_rules_push(TrustedPublisherRules *rules, const char *name, StrList *paths, const char *team_id, const char *signing_identifier);
TrustedPublisherCheck trusted_publisher_check_rule(const TrustedPublisherRule *rule, const char *path, const struct NetwatchPlatform *platform);
TrustedPublisherCheck trusted_publisher_check_path(const TrustedPublisherRules *rules, const char *path, const struct NetwatchPlatform *platform);
const char *trusted_publisher_result_name(TrustedPublisherResult result);

#endif
