#ifndef NETWATCH_TRUSTED_APP_BUNDLE_H
#define NETWATCH_TRUSTED_APP_BUNDLE_H

#include "strlist.h"
#include "trusted_publisher.h"
#include <stdbool.h>
#include <limits.h>
#include <stddef.h>

struct NetwatchPlatform;

typedef struct {
  char *name;
  char *bundle_root;
  char *team_id;
  StrList allowed_signing_identifiers;
  StrList allowed_signing_identifier_prefixes;
  bool allow_subdirectories;
} TrustedAppBundleRule;

typedef struct {
  TrustedAppBundleRule *items;
  size_t len;
  size_t cap;
} TrustedAppBundleRules;

typedef enum {
  TRUSTED_APP_BUNDLE_OK,
  TRUSTED_APP_BUNDLE_PATH_NOT_MATCHED,
  TRUSTED_APP_BUNDLE_ROOT_UNAVAILABLE,
  TRUSTED_APP_BUNDLE_EXECUTABLE_UNAVAILABLE,
  TRUSTED_APP_BUNDLE_EXECUTABLE_OUTSIDE_ROOT,
  TRUSTED_APP_BUNDLE_SUBDIRECTORY_NOT_ALLOWED,
  TRUSTED_APP_BUNDLE_INVALID_SIGNATURE,
  TRUSTED_APP_BUNDLE_TEAM_ID_MISMATCH,
  TRUSTED_APP_BUNDLE_SIGNING_IDENTIFIER_MISMATCH,
  TRUSTED_APP_BUNDLE_METADATA_UNAVAILABLE,
  TRUSTED_APP_BUNDLE_SECURITY_ERROR
} TrustedAppBundleResult;

typedef struct {
  TrustedAppBundleResult result;
  const TrustedAppBundleRule *rule;
  CodeSignatureIdentity actual;
  char canonical_bundle_root[PATH_MAX];
  char canonical_executable_path[PATH_MAX];
} TrustedAppBundleCheck;

void trusted_app_bundle_rules_free(TrustedAppBundleRules *rules);
int trusted_app_bundle_rules_push(TrustedAppBundleRules *rules, const char *name, const char *bundle_root,
  const char *team_id, StrList *identifiers, StrList *prefixes, bool allow_subdirectories);
TrustedAppBundleCheck trusted_app_bundle_check_rule(const TrustedAppBundleRule *rule, const char *path,
  const struct NetwatchPlatform *platform);
TrustedAppBundleCheck trusted_app_bundle_check_path(const TrustedAppBundleRules *rules, const char *path,
  const struct NetwatchPlatform *platform);
const char *trusted_app_bundle_result_name(TrustedAppBundleResult result);

#endif
