#ifndef NETWATCH_APPLE_TRUST_H
#define NETWATCH_APPLE_TRUST_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  APPLE_TRUST_OK,
  APPLE_TRUST_NOT_SYSTEM_PATH,
  APPLE_TRUST_FILE_NOT_FOUND,
  APPLE_TRUST_INVALID_SIGNATURE,
  APPLE_TRUST_API_ERROR
} AppleTrustResult;

bool apple_trust_is_system_path(const char *path);
AppleTrustResult apple_trust_check(const char *path, char *reason, size_t reason_size);
const char *apple_trust_result_name(AppleTrustResult result);

#endif
