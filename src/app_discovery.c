#include "app_discovery.h"
#include "util.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/CSCommon.h>
#include <Security/SecRequirement.h>
#include <Security/SecStaticCode.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct { char *data; size_t len; size_t cap; } JsonBuf;
typedef struct { DiscoveredApp *items; size_t len; size_t cap; } AppList;

static int buf_reserve(JsonBuf *buf, size_t add){
  if (buf->len + add + 1 <= buf->cap) return 1;
  size_t cap = buf->cap ? buf->cap * 2 : 4096;
  while (cap < buf->len + add + 1) cap *= 2;
  char *data = realloc(buf->data, cap); if (!data) return 0;
  buf->data = data; buf->cap = cap; return 1;
}

static int buf_add_n(JsonBuf *buf, const char *text, size_t len){
  if (!buf_reserve(buf, len)) return 0;
  memcpy(buf->data + buf->len, text, len);
  buf->len += len; buf->data[buf->len] = 0; return 1;
}

static int buf_add(JsonBuf *buf, const char *text){ return buf_add_n(buf, text, strlen(text)); }

static int json_string(JsonBuf *buf, const char *text){
  if (!buf_add(buf, "\"")) return 0;
  for (const unsigned char *p = (const unsigned char *)(text ? text : ""); *p; p++){
    char tmp[8];
    if (*p == '"' || *p == '\\'){
      tmp[0] = '\\'; tmp[1] = (char)*p;
      if (!buf_add_n(buf, tmp, 2)) return 0;
    } else if (*p == '\n'){
      if (!buf_add(buf, "\\n")) return 0;
    } else if (*p == '\r'){
      if (!buf_add(buf, "\\r")) return 0;
    } else if (*p == '\t'){
      if (!buf_add(buf, "\\t")) return 0;
    } else if (*p < 0x20){
      snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
      if (!buf_add(buf, tmp)) return 0;
    } else if (!buf_add_n(buf, (const char *)p, 1)) return 0;
  }
  return buf_add(buf, "\"");
}

static const char *json_bool(int value){ return value ? "true" : "false"; }

int app_discovery_print_json(const DiscoveredApp *apps, size_t app_count){
  JsonBuf buf = {0};
  if (!buf_add(&buf, "{\n  \"apps\": [\n")) goto fail;
  for (size_t i = 0; i < app_count; i++){
    const DiscoveredApp *app = &apps[i];
    if (!buf_add(&buf, "    {\n")
      || !buf_add(&buf, "      \"appleSigned\": ") || !buf_add(&buf, json_bool(app->apple_signed)) || !buf_add(&buf, ",\n")
      || !buf_add(&buf, "      \"bundlePath\": ") || !json_string(&buf, app->bundle_path) || !buf_add(&buf, ",\n")
      || !buf_add(&buf, "      \"displayName\": ") || !json_string(&buf, app->display_name) || !buf_add(&buf, ",\n")
      || !buf_add(&buf, "      \"executablePath\": ") || !json_string(&buf, app->executable_path) || !buf_add(&buf, ",\n")
      || !buf_add(&buf, "      \"parentBundlePath\": ")
      || (app->parent_bundle_path[0] ? !json_string(&buf, app->parent_bundle_path) : !buf_add(&buf, "null"))
      || !buf_add(&buf, ",\n")
      || !buf_add(&buf, "      \"signatureValid\": ") || !buf_add(&buf, json_bool(app->signature_valid)) || !buf_add(&buf, ",\n")
      || !buf_add(&buf, "      \"signedHelperCandidate\": ") || !buf_add(&buf, json_bool(app->signed_helper_candidate)) || !buf_add(&buf, ",\n")
      || !buf_add(&buf, "      \"signingIdentifier\": ") || !json_string(&buf, app->signing_identifier) || !buf_add(&buf, ",\n")
      || !buf_add(&buf, "      \"suitableTrustedPublisher\": ") || !buf_add(&buf, json_bool(app->suitable_trusted_publisher)) || !buf_add(&buf, ",\n")
      || !buf_add(&buf, "      \"teamId\": ") || !json_string(&buf, app->team_id) || !buf_add(&buf, "\n    }")) goto fail;
    if (i + 1 < app_count && !buf_add(&buf, ",")) goto fail;
    if (!buf_add(&buf, "\n")) goto fail;
  }
  if (!buf_add(&buf, "  ]\n}\n")) goto fail;
  fputs(buf.data, stdout);
  free(buf.data);
  return 0;

fail:
  free(buf.data);
  fprintf(stderr, "ERROR: out of memory printing app discovery JSON\n");
  return 1;
}

static int has_suffix(const char *text, const char *suffix){
  size_t a = strlen(text), b = strlen(suffix);
  return a >= b && !strcmp(text + a - b, suffix);
}

static void fallback_display_name(const char *bundle_path, char out[256]){
  const char *base = strrchr(bundle_path, '/');
  base = base ? base + 1 : bundle_path;
  snprintf(out, 256, "%s", base);
  size_t n = strlen(out);
  if (n > 4 && !strcmp(out + n - 4, ".app")) out[n - 4] = 0;
}

static int cfstring_to_buf(CFTypeRef value, char *out, size_t out_len){
  return value && CFGetTypeID(value) == CFStringGetTypeID() && CFStringGetCString((CFStringRef)value, out, out_len, kCFStringEncodingUTF8);
}

static void clean_display_name(char *text){
  char *w = text;
  for (char *r = text; *r;){
    unsigned char *p = (unsigned char *)r;
    if (p[0] == 0xe2 && p[1] && p[2] && p[1] == 0x80 && (p[2] == 0x8e || p[2] == 0x8f)){ r += 3; continue; }
    *w++ = *r++;
  }
  *w = 0;
}

static int bundle_metadata(const char *bundle_path, char display_name[256], char executable_path[PATH_MAX]){
  fallback_display_name(bundle_path, display_name);
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)bundle_path, strlen(bundle_path), true);
  if (!url) return 0;
  CFBundleRef bundle = CFBundleCreate(NULL, url);
  CFRelease(url);
  if (!bundle) return 0;
  CFTypeRef name = CFBundleGetValueForInfoDictionaryKey(bundle, CFSTR("CFBundleDisplayName"));
  if (!cfstring_to_buf(name, display_name, 256)){
    name = CFBundleGetValueForInfoDictionaryKey(bundle, kCFBundleNameKey);
    cfstring_to_buf(name, display_name, 256);
  }
  if (!display_name[0]) fallback_display_name(bundle_path, display_name);
  clean_display_name(display_name);
  CFURLRef exe = CFBundleCopyExecutableURL(bundle);
  int ok = exe && CFURLGetFileSystemRepresentation(exe, true, (UInt8 *)executable_path, PATH_MAX);
  if (exe) CFRelease(exe);
  CFRelease(bundle);
  return ok;
}

static int signature_check(const char *path, CFStringRef requirement_text){
  CFStringRef path_string = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
  if (!path_string) return 0;
  CFURLRef url = CFURLCreateWithFileSystemPath(NULL, path_string, kCFURLPOSIXPathStyle, false);
  CFRelease(path_string);
  if (!url) return 0;
  SecStaticCodeRef code = NULL;
  OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
  CFRelease(url);
  if (status != errSecSuccess) return 0;
  SecRequirementRef requirement = NULL;
  status = requirement_text ? SecRequirementCreateWithString(requirement_text, kSecCSDefaultFlags, &requirement) : errSecSuccess;
  int ok = 0;
  if (status == errSecSuccess) ok = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, requirement) == errSecSuccess;
  if (requirement) CFRelease(requirement);
  CFRelease(code);
  return ok;
}

static int signature_valid_for_path(const char *path){ return signature_check(path, NULL); }
static int signature_satisfies_requirement(const char *path, CFStringRef requirement_text){ return signature_check(path, requirement_text); }

static int app_list_push(AppList *list, const DiscoveredApp *app){
  if (list->len == list->cap){
    size_t cap = list->cap ? list->cap * 2 : 64;
    DiscoveredApp *items = realloc(list->items, cap * sizeof(*items));
    if (!items) return 0;
    list->items = items; list->cap = cap;
  }
  list->items[list->len++] = *app;
  return 1;
}

static int discover_bundle(const char *bundle_path, const char *display_prefix,
  const char *parent_bundle_path, char display_out[256], const NetwatchPlatform *platform, AppList *apps){
  DiscoveredApp app = {0};
  snprintf(app.bundle_path, sizeof(app.bundle_path), "%s", bundle_path);
  if (parent_bundle_path) snprintf(app.parent_bundle_path, sizeof(app.parent_bundle_path), "%s", parent_bundle_path);
  if (!bundle_metadata(bundle_path, app.display_name, app.executable_path)) return 1;
  if (display_out) snprintf(display_out, 256, "%s", app.display_name);
  if (display_prefix && *display_prefix){
    char child_name[256];
    snprintf(child_name, sizeof(child_name), "%s", app.display_name);
    snprintf(app.display_name, sizeof(app.display_name), "%s - %s", display_prefix, child_name);
  }
  app.signature_valid = signature_valid_for_path(app.executable_path);
  app.apple_signed = signature_satisfies_requirement(app.executable_path, CFSTR("anchor apple"));
  CodeSignatureIdentity identity = {0};
  char err[256] = {0};
  CodeSignatureIdentityResult result = platform->code_signature_identity(platform, app.executable_path, &identity, err, sizeof(err));
  if (result == CODE_SIGNATURE_IDENTITY_OK){
    snprintf(app.team_id, sizeof(app.team_id), "%s", identity.team_id);
    snprintf(app.signing_identifier, sizeof(app.signing_identifier), "%s", identity.signing_identifier);
  }
  app.suitable_trusted_publisher = app.signature_valid && !app.apple_signed && app.team_id[0] && app.signing_identifier[0];
  app.signed_helper_candidate = app.parent_bundle_path[0] && app.suitable_trusted_publisher;
  return app_list_push(apps, &app);
}

static char *join_path(const char *dir, const char *name){
  size_t n = strlen(dir) + strlen(name) + 2;
  char *out = malloc(n);
  if (out) snprintf(out, n, "%s/%s", dir, name);
  return out;
}

static int app_list_has_executable(const AppList *apps, const char *path){
  for (size_t i = 0; i < apps->len; i++) if (!strcmp(apps->items[i].executable_path, path)) return 1;
  return 0;
}

static int ignored_helper_file(const char *path){
  static const char *suffixes[] = { ".dylib", ".node", ".so", ".a" };
  for (size_t i = 0; i < sizeof(suffixes) / sizeof(*suffixes); i++){
    if (has_suffix(path, suffixes[i])) return 1;
  }
  return 0;
}

static int discover_helper_file(const char *path, const char *bundle_path, const char *display_name,
  const NetwatchPlatform *platform, AppList *apps){
  if (app_list_has_executable(apps, path)) return 1;
  CodeSignatureIdentity identity = {0};
  if (platform->code_signature_identity(platform, path, &identity, NULL, 0) != CODE_SIGNATURE_IDENTITY_OK) return 1;
  DiscoveredApp app = {0};
  const char *base = strrchr(path, '/');
  snprintf(app.display_name, sizeof(app.display_name), "%s - %s", display_name, base ? base + 1 : path);
  snprintf(app.bundle_path, sizeof(app.bundle_path), "%s", bundle_path);
  snprintf(app.parent_bundle_path, sizeof(app.parent_bundle_path), "%s", bundle_path);
  snprintf(app.executable_path, sizeof(app.executable_path), "%s", path);
  snprintf(app.team_id, sizeof(app.team_id), "%s", identity.team_id);
  snprintf(app.signing_identifier, sizeof(app.signing_identifier), "%s", identity.signing_identifier);
  app.signature_valid = 1;
  app.apple_signed = signature_satisfies_requirement(path, CFSTR("anchor apple"));
  app.suitable_trusted_publisher = !app.apple_signed;
  app.signed_helper_candidate = app.suitable_trusted_publisher;
  return app_list_push(apps, &app);
}

static int scan_helper_tree(const char *dir, const char *bundle_path, const char *display_name,
  int depth, int max_depth, int scan_files, const NetwatchPlatform *platform, AppList *apps){
  DIR *d = opendir(dir);
  if (!d) return errno == ENOENT ? 1 : 0;
  struct dirent *ent;
  while ((ent = readdir(d))){
    if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
    char *path = join_path(dir, ent->d_name);
    if (!path){ closedir(d); return 0; }
    struct stat st;
    if (lstat(path, &st) == 0){
      int nested_bundle = S_ISDIR(st.st_mode)
        && (has_suffix(ent->d_name, ".app") || has_suffix(ent->d_name, ".appex") || has_suffix(ent->d_name, ".xpc"));
      if (nested_bundle){
        if (!discover_bundle(path, display_name, bundle_path, NULL, platform, apps)){
          free(path); closedir(d); return 0;
        }
      } else if (S_ISDIR(st.st_mode) && depth < max_depth){
        if (!scan_helper_tree(path, bundle_path, display_name, depth + 1, max_depth, scan_files,
          platform, apps)){
          free(path); closedir(d); return 0;
        }
      } else if (scan_files && S_ISREG(st.st_mode) && (st.st_mode & 0111) && !ignored_helper_file(path)
        && !discover_helper_file(path, bundle_path, display_name, platform, apps)){
        free(path); closedir(d); return 0;
      }
    }
    free(path);
  }
  closedir(d);
  return 1;
}

static int scan_bundle_helpers(const char *bundle_path, const char *display_name,
  const NetwatchPlatform *platform, AppList *apps){
  static const struct { const char *path; int max_depth; int scan_files; } roots[] = {
    { "Contents/Frameworks", 4, 0 },
    { "Contents/Helpers", 4, 1 },
    { "Contents/XPCServices", 2, 0 },
    { "Contents/PlugIns", 2, 0 },
    { "Contents/Library/LoginItems", 3, 0 },
    { "Contents/Resources", 0, 1 },
    { "Contents/Resources/native", 2, 1 }
  };
  for (size_t i = 0; i < sizeof(roots) / sizeof(*roots); i++){
    char *root = join_path(bundle_path, roots[i].path);
    if (!root) return 0;
    int ok = scan_helper_tree(root, bundle_path, display_name, 0, roots[i].max_depth,
      roots[i].scan_files, platform, apps);
    free(root);
    if (!ok) return 0;
  }
  return 1;
}

static int scan_dir(const char *dir, int depth, const NetwatchPlatform *platform, AppList *apps){
  DIR *d = opendir(dir);
  if (!d) return errno == ENOENT ? 1 : 0;
  struct dirent *ent;
  while ((ent = readdir(d))){
    if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
    char *path = join_path(dir, ent->d_name);
    if (!path){ closedir(d); return 0; }
    struct stat st;
    if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)){
      if (has_suffix(ent->d_name, ".app")){
        char display_name[256] = {0};
        if (!discover_bundle(path, NULL, NULL, display_name, platform, apps)
          || !scan_bundle_helpers(path, display_name, platform, apps)){
          free(path); closedir(d); return 0;
        }
      } else if (depth < 5 && !scan_dir(path, depth + 1, platform, apps)){
        free(path); closedir(d); return 0;
      }
    }
    free(path);
  }
  closedir(d);
  return 1;
}

static int app_cmp(const void *a, const void *b){
  const DiscoveredApp *left = a, *right = b;
  int name = strcmp(left->display_name, right->display_name);
  return name ? name : strcmp(left->bundle_path, right->bundle_path);
}

int app_discovery_command_json(const NetwatchPlatform *platform){
  platform = netwatch_platform_or_default(platform);
  AppList apps = {0};
  const char *roots[] = { "/Applications", "/System/Applications", NULL };
  for (size_t i = 0; roots[i]; i++){
    if (!scan_dir(roots[i], 0, platform, &apps)){
      free(apps.items);
      fprintf(stderr, "ERROR: failed to scan %s\n", roots[i]);
      return 1;
    }
  }
  const char *home = home_dir();
  char user_apps[PATH_MAX];
  snprintf(user_apps, sizeof(user_apps), "%s/Applications", home);
  if (!scan_dir(user_apps, 0, platform, &apps)){
    free(apps.items);
    fprintf(stderr, "ERROR: failed to scan %s\n", user_apps);
    return 1;
  }
  qsort(apps.items, apps.len, sizeof(*apps.items), app_cmp);
  int rc = app_discovery_print_json(apps.items, apps.len);
  free(apps.items);
  return rc;
}
