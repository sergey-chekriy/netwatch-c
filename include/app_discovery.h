#ifndef NETWATCH_APP_DISCOVERY_H
#define NETWATCH_APP_DISCOVERY_H

#include "platform.h"
#include <limits.h>
#include <stddef.h>

typedef struct {
  char display_name[256];
  char bundle_path[PATH_MAX];
  char parent_bundle_path[PATH_MAX];
  char executable_path[PATH_MAX];
  char team_id[CODE_SIGNATURE_FIELD_MAX];
  char signing_identifier[CODE_SIGNATURE_FIELD_MAX];
  int signature_valid;
  int apple_signed;
  int suitable_trusted_publisher;
  int signed_helper_candidate;
} DiscoveredApp;

int app_discovery_print_json(const DiscoveredApp *apps, size_t app_count);
int app_discovery_command_json(const NetwatchPlatform *platform);

#endif
