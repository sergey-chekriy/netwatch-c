# netwatch-c Architecture

## 1. Purpose

`netwatch-c` is a small macOS network monitoring utility.

It periodically:

1. obtains active network connections;
2. resolves each process executable path;
3. checks deny and allow rules;
4. identifies trusted Apple system components;
5. identifies configured trusted third-party publishers;
6. logs unknown processes;
7. optionally disables Wi-Fi.

The program must remain:

- small;
- auditable;
- deterministic;
- dependency-light;
- macOS-focused;
- safe by default.

## 2. Current repository structure

```text
.
├── Makefile
├── README.md
├── examples/
│   └── netwatch.config.example.json
├── include/
├── scripts/
├── src/
└── third_party/
    └── cjson/
```

Existing modules:

- `config` - JSON configuration loading, validation, and defaults;
- `config_convert` - in-place config migration;
- `config_check` - standalone config validation command;
- `process` - process and executable-path discovery;
- `allow` - centralized deny/trusted-publisher/allow/Apple-trust decision logic;
- `trusted_publisher` - third-party signed identity rule verification;
- `why` - standalone explanation of one path decision;
- `monitor` - normal scan, logging, enforcement, dry-run, and stats orchestration;
- `audit` - non-enforcing observation report;
- `status` - launchd/runtime/config status command;
- `platform` - OS and filesystem boundary used by production code and tests;
- `logging` - log output;
- `wifi` - Wi-Fi disable functionality;
- `strlist` - string-list helpers;
- `util` - common utilities.

Do not rewrite unrelated modules.

## 3. New feature: automatic Apple system component recognition

The program may automatically trust a process only when both conditions are true:

```text
trusted Apple system component
=
approved system path
AND
valid Apple code signature
```

A system path alone is insufficient.

A valid signature alone is insufficient.

## 4. Trust decision order

Rules must be evaluated in this order:

```text
1. deny rule
2. trusted publisher rule
3. localhost LISTEN rule
4. explicit allow rule
5. trusted Apple system component
6. unknown process
```

Deny rules always have the highest priority.

An explicitly denied process must never be allowed because it has an Apple signature.

If an executable path matches a trusted publisher rule and identity verification fails, that
failure is terminal for the executable in that policy evaluation.

## 5. Result types

Use an explicit decision enum, for example:

```c
typedef enum {
    PROCESS_DENIED,
    PROCESS_ALLOWED_TRUSTED_PUBLISHER,
    PROCESS_ALLOWED_CONFIG,
    PROCESS_ALLOWED_APPLE_SYSTEM,
    PROCESS_UNKNOWN
} process_decision_t;
```

Do not represent decisions using ambiguous integer or boolean combinations.

The decision logic should also be able to provide a human-readable reason.

Examples:

```text
explicit deny rule
trusted publisher identity verified
trusted publisher Team ID mismatch
explicit allow rule
trusted Apple system component
Apple signature invalid
path is not an approved system path
not present in allowlist
```

## 6. Configuration

Add a configuration option:

```json
{
  "allowAppleSystemComponents": true
}
```

Requirements:

- type: boolean;
- default: `false`;
- missing option must preserve current behavior;
- invalid type must produce a configuration error;
- update the example config and README.

Defaulting to `false` avoids silently changing the security policy of existing installations.

## 7. Approved Apple system paths

Automatic Apple trust is considered only for executables located under explicitly approved roots.

Initial approved roots:

```text
/System/
/usr/libexec/
/usr/lib/
```

Path checking requirements:

- use a component-aware prefix check;
- `/System/...` must match;
- `/SystemMalware/...` must not match;
- `/usr/libexec/...` must match;
- `/usr/libexec-malicious/...` must not match;
- relative paths must not match;
- empty paths must not match;
- `/Applications`, `/Library`, `/usr/local`, `/opt`, and user directories must not be automatically trusted.

Do not use a broad rule such as:

```text
path starts with "/usr"
```

Do not automatically trust third-party applications installed under `/Applications`.

Apple applications outside the approved roots may still be allowed explicitly through the existing config.

## 8. Apple signature verification

Use the native macOS Security framework.

Do not implement trust by parsing output from:

```text
codesign
spctl
```

The production verifier should use native APIs such as:

```text
SecStaticCodeCreateWithPath
SecRequirementCreateWithString
SecStaticCodeCheckValidity
```

The implementation must verify the code against an Apple-specific requirement, preferably based on:

```text
anchor apple
```

Codex must inspect the available macOS SDK headers and validate the exact requirement and flags used.

Do not trust a process merely because:

- it has any valid signature;
- it has a Team Identifier;
- an authority string contains the word `Apple`;
- its executable name resembles a macOS daemon.

The verifier must fail closed:

```text
API error -> not trusted
invalid signature -> not trusted
missing executable -> not trusted
unreadable executable -> not trusted
```

Security-framework objects must be released correctly with `CFRelease`.

## 9. New module

Add a focused module:

```text
include/apple_trust.h
src/apple_trust.c
```

Suggested public API:

```c
#ifndef APPLE_TRUST_H
#define APPLE_TRUST_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    APPLE_TRUST_OK,
    APPLE_TRUST_NOT_SYSTEM_PATH,
    APPLE_TRUST_FILE_NOT_FOUND,
    APPLE_TRUST_INVALID_SIGNATURE,
    APPLE_TRUST_API_ERROR
} apple_trust_result_t;

bool apple_trust_is_system_path(const char *path);

apple_trust_result_t apple_trust_check(
    const char *path,
    char *reason,
    size_t reason_size
);

const char *apple_trust_result_name(apple_trust_result_t result);

#endif
```

Exact names may be adjusted to fit the existing code style.

Keep the module small and independently testable.

## 10. Integration with allow logic

The main policy decision should remain centralized.

Do not spread allow/deny decisions across `main.c`, `process.c`, and `apple_trust.c`.

Preferred responsibility split:

```text
process.c
    discovers PID, process name, path and connection

apple_trust.c
    evaluates system path and Apple signature

trusted_publisher.c
    evaluates configured third-party path, Team ID and signing identifier

allow.c
    applies policy priority and returns final decision

monitor.c
    orchestrates scanning, logging, statistics and Wi-Fi action

main.c
    parses CLI mode and dispatches to one module
```

`apple_trust.c` must not disable Wi-Fi and must not decide final policy priority.

Standalone commands (`--convert-config`, `--check-config`, `--why`, `--audit`, `--status`)
must exit before entering the normal monitoring workflow. `--status`, `--check-config`, and
`--why` must not start `lsof`, scan connections, or change Wi-Fi state.

## 10.1 Platform boundary

Production runtime OS actions go through `platform.c`.

The default platform implementation:

- invokes `lsof`, `networksetup`, and `launchctl` directly with `posix_spawnp`;
- does not invoke a shell for production command execution;
- resolves executable paths with `proc_pidpath` first and `lsof` only as a fallback;
- keeps filesystem operations for config conversion behind injectable callbacks;
- exposes Apple trust verification as an injectable callback for deterministic tests.

Tests should prefer fake platform callbacks or fake executables on `PATH` over invoking real
Wi-Fi, monitoring, or launchd side effects.

## 10.2 Trusted publisher verification

Trusted publisher rules are configured separately from path-only `allowProcesses`.

Policy order:

```text
deny
-> trusted publisher rule
-> localhost LISTEN
-> explicit path/remote allow
-> Apple system trust
-> unknown
```

If an executable path matches a trusted publisher rule, that rule is terminal: a failed
signature, Team ID, signing identifier, metadata, or Security.framework check returns
`unknown` and does not fall back to `allowProcesses` or Apple system trust.

If multiple trusted publisher rules match the same executable path, the evaluator checks all
matching rules. One successful rule allows the executable as `TRUSTED_PUBLISHER`; if none
succeed, evaluation fails closed with a deterministic diagnostic failure reason.

The `trusted_publisher` module compares:

- exact configured executable path, with `realpath()` equivalence where both paths exist;
- valid code signature;
- exact Team Identifier;
- exact signing identifier.

The platform layer obtains signed identity metadata with Security.framework. It validates the
signature before reading `kSecCodeInfoTeamIdentifier` and `kSecCodeInfoIdentifier`. The runtime
does not use executable hashes, certificate common names, display names, versions, or modification
times for trusted publisher decisions.

## 11. Process display name

`lsof` may truncate process names:

```text
transpare
assistant
Wallpaper
com.apple
```

When an executable path is available, derive a display name from the final path component.

Examples:

```text
/usr/libexec/transparencyd
-> transparencyd

/usr/libexec/ciphermld
-> ciphermld

.../Support/assistantd
-> assistantd

.../MacOS/WallpaperAerialsExtension
-> WallpaperAerialsExtension
```

Preserve the original `lsof` process name separately because existing config rules may depend on it.

Do not silently change the key used for existing allowlist matching unless backward compatibility is explicitly maintained.

Recommended model:

```c
typedef struct {
    int pid;
    char process_name[...];      /* original lsof name */
    char display_name[...];      /* basename of executable */
    char executable_path[...];
} process_info_t;
```

## 12. Logging

Logs should distinguish the final decision.

Examples:

```text
[APPLE_SYSTEM] assistantd
  PATH: /System/Library/PrivateFrameworks/.../assistantd
  REASON: approved system path and valid Apple signature
```

```text
[ALLOWED_CONFIG] Google Chrome
  PATH: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
```

```text
[DENIED] suspicious-process
  PATH: /Users/user/bin/suspicious-process
  REASON: explicit deny rule
```

```text
[UNKNOWN] unknown-process
  PATH: /Users/user/bin/unknown-process
  APPLE TRUST: path is not an approved system path
```

Avoid excessive normal-operation logging if the existing application is intentionally quiet.

Keep the current log format compatible where practical.

## 13. Caching

Signature checks may be cached, but caching is optional for the first implementation.

Correctness is more important than optimization.

If caching is implemented, the cache key must not be only the path.

Use enough file identity information to detect replacement, for example:

```text
path
device
inode
mtime
size
```

The cache may remain in memory for one process run.

Do not introduce a persistent trust database in this update.

## 14. Build system

Update the Makefile to:

- compile `src/apple_trust.c`;
- link the macOS Security framework;
- link CoreFoundation if required;
- preserve existing build commands.

Expected linker form:

```make
-framework Security
-framework CoreFoundation
```

Confirm requirements against the APIs actually used.

The project should continue to build using the current compiler command and macOS SDK.

## 15. Testing

Add tests for pure policy and path logic.

Required path tests:

```text
/System/Library/foo                     -> system path
/usr/libexec/ciphermld                  -> system path
/usr/lib/libSomething.dylib             -> system path

/SystemMalware/foo                      -> not system path
/usr/libexec-malicious/foo              -> not system path
/usr/local/bin/foo                      -> not system path
/Applications/Foo.app/...               -> not system path
/Library/AppleLike/foo                  -> not system path
relative/path                           -> not system path
empty path                              -> not system path
NULL                                    -> not system path
```

Required policy tests:

```text
deny + Apple trusted              -> denied
deny + explicit allow             -> denied
deny + trusted publisher          -> denied
trusted publisher + explicit allow -> trusted publisher
failed trusted publisher + allow  -> unknown
failed trusted publisher + Apple  -> unknown
explicit allow + Apple trusted    -> allowed by config
Apple trusted + feature enabled   -> allowed Apple system
Apple trusted + feature disabled  -> unknown
invalid Apple signature           -> unknown
non-system path + Apple signature -> unknown
```

Signature integration tests should use binaries expected to exist on macOS, for example:

```text
/usr/libexec/ciphermld
/usr/libexec/remindd
/bin/ls
```

Tests must not assume every optional daemon exists on every macOS version.

Skip a fixture cleanly when it is not present.

Also verify that an unsigned temporary executable is not recognized as an Apple system component.

## 16. Compatibility requirements

The update must preserve:

- existing configuration files;
- existing explicit allow rules;
- existing deny rules;
- current Wi-Fi disable behavior;
- current launchd installation;
- current executable-path matching behavior.

The new feature must be inactive unless enabled in configuration.

## 17. Security constraints

Never automatically trust based only on:

- process name;
- executable basename;
- PID owner;
- destination IP;
- TCP port;
- `/System` textual prefix without boundary checking;
- successful execution of the file;
- generic valid code signature.

Never invoke shell commands using an executable path supplied as interpolated shell text.

Fail closed on all unexpected errors.

## 18. Scope

In scope:

- Apple trust module;
- configuration option;
- policy integration;
- improved display names;
- Makefile update;
- tests;
- documentation.

Out of scope:

- persistent trust database;
- auto-editing the JSON allowlist;
- automatic trust for third-party signed software;
- IP/domain reputation;
- network packet inspection;
- Linux support;
- rewriting the network discovery implementation;
- changing the launchd architecture.

## 19. Implementation quality

Prefer:

- explicit control flow;
- small functions;
- clear enums;
- bounded string operations;
- early returns;
- deterministic ownership;
- correct CoreFoundation cleanup.

Avoid:

- deeply nested conditions;
- global mutable state;
- shelling out to security utilities;
- hidden fallback trust;
- large refactoring unrelated to this feature.
