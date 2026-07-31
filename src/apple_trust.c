#include "apple_trust.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CSCommon.h>
#include <Security/SecRequirement.h>
#include <Security/SecStaticCode.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void set_reason(char *reason, size_t reason_size, const char *text){
  if (reason && reason_size) snprintf(reason, reason_size, "%s", text);
}

bool apple_trust_is_system_path(const char *path){
  static const char *roots[] = { "/System/", "/usr/libexec/", "/usr/lib/" };
  if (!path || path[0] != '/') return false;
  for (size_t i = 0; i < sizeof(roots) / sizeof(*roots); i++){
    if (!strncmp(path, roots[i], strlen(roots[i]))) return true;
  }
  return false;
}

const char *apple_trust_result_name(AppleTrustResult result){
  switch (result){
    case APPLE_TRUST_OK: return "approved system path and valid Apple signature";
    case APPLE_TRUST_NOT_SYSTEM_PATH: return "path is not an approved system path";
    case APPLE_TRUST_FILE_NOT_FOUND: return "executable path not found";
    case APPLE_TRUST_INVALID_SIGNATURE: return "Apple signature invalid";
    case APPLE_TRUST_API_ERROR: return "Apple trust verification error";
  }
  return "Apple trust verification error";
}

static AppleTrustResult file_error_result(void){
  return errno == ENOENT || errno == ENOTDIR ? APPLE_TRUST_FILE_NOT_FOUND : APPLE_TRUST_API_ERROR;
}

static AppleTrustResult verify_signature(const char *path){
  AppleTrustResult result = APPLE_TRUST_API_ERROR;
  CFStringRef path_string = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
  if (!path_string) return result;

  CFURLRef url = CFURLCreateWithFileSystemPath(NULL, path_string, kCFURLPOSIXPathStyle, false);
  CFRelease(path_string);
  if (!url) return result;

  SecStaticCodeRef code = NULL;
  OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
  CFRelease(url);
  if (status != errSecSuccess) return status == errSecCSStaticCodeNotFound ? APPLE_TRUST_FILE_NOT_FOUND : APPLE_TRUST_API_ERROR;

  SecRequirementRef requirement = NULL;
  status = SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &requirement);
  if (status == errSecSuccess){
    status = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    result = status == errSecSuccess ? APPLE_TRUST_OK : APPLE_TRUST_INVALID_SIGNATURE;
  }
  if (requirement) CFRelease(requirement);
  CFRelease(code);
  return result;
}

AppleTrustResult apple_trust_check(const char *path, char *reason, size_t reason_size){
  if (!apple_trust_is_system_path(path)){
    set_reason(reason, reason_size, apple_trust_result_name(APPLE_TRUST_NOT_SYSTEM_PATH));
    return APPLE_TRUST_NOT_SYSTEM_PATH;
  }

  struct stat st;
  if (stat(path, &st) != 0){
    AppleTrustResult result = file_error_result();
    set_reason(reason, reason_size, apple_trust_result_name(result));
    return result;
  }

  char resolved[PATH_MAX];
  if (!realpath(path, resolved)){
    AppleTrustResult result = file_error_result();
    set_reason(reason, reason_size, apple_trust_result_name(result));
    return result;
  }
  if (!apple_trust_is_system_path(resolved)){
    set_reason(reason, reason_size, apple_trust_result_name(APPLE_TRUST_NOT_SYSTEM_PATH));
    return APPLE_TRUST_NOT_SYSTEM_PATH;
  }

  AppleTrustResult result = verify_signature(resolved);
  set_reason(reason, reason_size, apple_trust_result_name(result));
  return result;
}
