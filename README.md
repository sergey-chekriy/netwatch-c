# netwatch-c

`netwatch-c` is a small macOS network connection watcher written in C.

The C version has no external package-manager dependencies. The JSON parser is vendored as source code under `third_party/cjson/`, so the tool can be built with the macOS C compiler and `make`.

See also Rust version: https://github.com/sergey-chekriy/netwatch-rs

It periodically checks active TCP connections, compares the process name and executable path against an allowlist, writes suspicious connections to a log, and can optionally turn Wi-Fi off when something unexpected is detected.

The tool is intentionally simple:

- `lsof` is used to read active network connections.
- macOS `proc_pidpath` is used to resolve the real executable path for a process.
- `lsof -a -p <PID> -d txt -Fn` is used as a fallback executable path resolver.
- `networksetup` is used to disable Wi-Fi.
- `launchd` can run the tool automatically on a schedule.
- `cJSON`-compatible JSON parsing is used to read the configuration file.

The default configuration runs in `dryRun` mode, so it only logs what it would do.

## Why

The goal is not to replace a firewall, EDR, antivirus, or Little Snitch-style tool.

The goal is to have a small, auditable, local watcher for a personal allowlist-based workflow. It is useful when you want to know when an unexpected process opens a network connection, especially after cleaning up a potentially compromised machine or when working in a more defensive environment.

## Features

- Checks active `ESTABLISHED` and `LISTEN` connections.
- Supports process allowlisting by both process name and executable path.
- Supports prefix path matching with `*`.
- Supports deny patterns that always take priority.
- Automatically allows localhost `LISTEN` connections.
- Can automatically trust Apple system components when explicitly enabled.
- Can verify configured third-party apps by signed publisher identity.
- Can trust explicitly selected signed helpers inside a verified `.app` bundle.
- Logs suspicious connections with executable path.
- Can disable Wi-Fi when suspicious activity is detected.
- Can print runtime statistics for a normal monitoring pass.
- Can run a non-enforcing audit report for observed connections.
- Can report launchd, runtime, and config status without monitoring.
- Can be run manually or through `launchd`.
- Supports only the safer path-based `allowProcesses` format.
- Does not support the old process-name-only allowlist format.

## Requirements

- macOS
- C compiler (`cc` / Apple Clang)
- `make`
- `lsof` and `networksetup`, both available on macOS by default

Install Xcode Command Line Tools if needed:

```bash
xcode-select --install
```

## Build

```bash
git clone https://github.com/YOUR-USER/netwatch-c.git
cd netwatch-c
make
```

The binary will be created here:

```bash
./netwatch
```

Run the built-in test suite:

```bash
make test
```

The runtime OS operations are routed through a small platform layer so tests can fake `lsof`, executable path lookup, Apple signature verification, filesystem failures, timestamps, and Wi-Fi disable actions. Normal commands still use the production macOS implementations. Production command execution uses direct `posix_spawnp()` calls, not shell command strings.

Build the optional macOS SwiftUI configurator:

```bash
make configurator
make configurator-test
```

The app bundle is created at `build/NetwatchConfigurator.app`. It is a thin GUI over the netwatch CLI backend and does not implement policy decisions itself. See [docs/configurator.md](docs/configurator.md).

## Manual install

Create the working directory:

```bash
mkdir -p ~/.watch
```

Copy the binary:

```bash
cp ./netwatch ~/.watch/netwatch
chmod +x ~/.watch/netwatch
```

Copy the example config if you do not already have one:

```bash
[ -f ~/.watch/netwatch.config.json ] || cp examples/netwatch.config.example.json ~/.watch/netwatch.config.json
```

Or use the Makefile install target:

```bash
make install
```

`make install` overwrites `~/.watch/netwatch`, but it does not overwrite an existing `~/.watch/netwatch.config.json`.

If the daemon is already running, restart it after replacing the binary. `--reload-daemon` reloads config only; it does not replace the running executable:

```bash
launchctl kickstart -k "gui/$(id -u)/com.serg.netwatch"
```

Edit the config before enabling automatic Wi-Fi shutdown:

```bash
nano ~/.watch/netwatch.config.json
```

Keep this while tuning the allowlist:

```json
"dryRun": true
```

Run manually:

```bash
~/.watch/netwatch ~/.watch/netwatch.config.json
```

Expected output when everything is allowed:

```text
[2026-06-16T13:31:35Z] OK
```

## Dry-run from the command line

Run the normal monitor path while suppressing Wi-Fi disable actions:

```bash
./netwatch --dry-run
./netwatch --dry-run /path/to/netwatch.config.json
```

`--dry-run` reads and validates the same config, scans the same connections, resolves the same executable paths, and uses the same policy decisions as normal monitoring. If suspicious connections are found, it logs what would have happened instead of calling `networksetup`:

```text
DRY RUN: would disable Wi-Fi
[UNKNOWN] foo
  LINE: foo  123 user  10u  IPv4 ... TCP 10.0.0.2:123->203.0.113.10:443 (ESTABLISHED)
  PATH: /tmp/foo
  REASON: not present in allowlist
```

This command-line flag overrides the config for that run only. It does not edit the config file.

## Once and daemon modes

One-shot mode runs one scan and exits. This is the historical behavior and remains the default:

```bash
./netwatch /path/to/netwatch.config.json
./netwatch --once --config /path/to/netwatch.config.json
```

Daemon mode stays in the foreground and repeats scans using the interval from config:

```bash
./netwatch --daemon --config /path/to/netwatch.config.json
```

`launchd` should manage the daemon process; `netwatch` does not fork or detach. Daemon mode is better for enforcement because the process stays warm, keeps using the same policy engine, and scans on its configured interval instead of waiting for launchd to start a new one-shot job.

Recommended intervals:

```text
300 seconds: balanced daemon monitoring
5-60 seconds: aggressive active protection
15-30 minutes: passive audit, not strong enforcement
```

`dryRun` works the same in daemon mode: suspicious connections are logged, Wi-Fi is never disabled, and monitoring continues.

Signals:

```bash
kill -TERM <pid>   # graceful stop
kill -INT <pid>    # graceful stop
kill -HUP <pid>    # reload config when daemon.reloadOnSighup is true
```

If reload fails and `daemon.exitOnConfigError` is `false`, the previous valid config remains active and the reload error is logged. If it is `true`, daemon mode exits non-zero.

## Runtime statistics

Run one normal monitoring pass and print counters afterward:

```bash
./netwatch --stats
./netwatch --stats /path/to/netwatch.config.json
```

`--stats` uses the same config, scan, policy, logging, and enforcement path as normal monitoring. It honors `dryRun`; if `dryRun` is `false` and suspicious connections are found, Wi-Fi disable can still be attempted. Keep `dryRun` enabled when you only want to inspect counters.

Example:

```text
Runtime statistics
Runtime seconds: 0
Scan cycles: 1
Connections scanned: 5
Unique processes: 4
Unique executable paths: 4
Apple-trusted decisions: 1
Trusted publisher matches: 1
Trusted publisher invalid signatures: 0
Trusted publisher Team ID mismatches: 0
Trusted publisher signing identifier mismatches: 0
Trusted publisher metadata failures: 0
Explicit allow matches: 1
Deny matches: 1
Unknown decisions: 2
Requested enforcement actions: 1
Successful Wi-Fi disable actions: 0
Failed Wi-Fi disable actions: 0
```

Definitions: one scan cycle is one successful `lsof` collection in the current invocation. Connections scanned counts connection lines evaluated by the policy engine. Unique processes count distinct `lsof` process names in that scan. Unique executable paths count resolved paths, excluding unresolved `unknown` paths. Requested enforcement actions count final Wi-Fi enforcement requests, so multiple suspicious connections in one scan count as one request.

## Runtime status

Show installation, launchd, process, and config status without starting monitoring:

```bash
./netwatch --status
```

This command checks the default launchd installation paths used by `scripts/install-macos.sh`:

```text
~/.watch/netwatch
~/.watch/netwatch.config.json
~/Library/LaunchAgents/com.serg.netwatch.plist
```

It does not run `lsof`, scan connections, enter monitoring loops, or change Wi-Fi state. Launchd loaded state is checked with `launchctl print gui/<uid>/com.serg.netwatch` using only the command exit status. Running process detection compares executable paths and excludes the status command process itself.

Example:

```text
netwatch version: unavailable
LaunchAgent label: com.serg.netwatch
LaunchAgent plist: /Users/serg/Library/LaunchAgents/com.serg.netwatch.plist
LaunchAgent installed: yes
Service loaded: yes
Running: no
PID: unavailable
Executable path: /Users/serg/.watch/netwatch
Running executable path: unavailable
Config: /Users/serg/.watch/netwatch.config.json
Config valid: yes
Config version: 2
Apple system trust: enabled
Trusted publisher rules: 0
Dry run: enabled
Audit mode: not configured
Recent startup error: none detected
```

`no` means the state was checked and is false. `unavailable` means the command could not safely determine the value, for example because a log file is missing or a platform query failed.

## Status snapshot JSON

Daemon mode writes a compact machine-readable snapshot for the macOS menu bar app:

```text
~/.watch/netwatch.status.json
```

This project uses the user-writable `~/.watch` path because the default install is a user LaunchAgent. The file is written atomically through a temporary file and `rename()`, with mode `0644`.

Print the current snapshot:

```bash
./netwatch --status-json
```

If the snapshot does not exist, `--status-json` exits non-zero with a clear error. It does not run `lsof`, scan connections, enter monitoring loops, or change Wi-Fi state.

Important fields:

```json
{
  "version": 1,
  "status": "attention",
  "daemonRunning": true,
  "configValid": true,
  "dryRun": true,
  "lastScanAt": 1700000000,
  "lastScanResult": "ok",
  "unknownCount": 0,
  "wouldDisableWifi": false,
  "wifiDisabled": false,
  "lastUnknownProcessSummary": null,
  "activeConfigPath": "/Users/serg/.watch/netwatch.config.json",
  "pollIntervalSeconds": 300
}
```

Only the most recent unknown process summary is stored. The snapshot does not include process history, environment variables, or unbounded process lists.

Menu bar status mapping:

| Status JSON | `dryRun` | Result ok | Fresh: `now - lastScanAt <= pollIntervalSeconds + 10s` | Color |
| --- | --- | --- | --- | --- |
| unavailable / unreadable / invalid | any | any | any | gray |
| off | yes | yes | green |
| off | yes | no | red |
| off | no | any | red |
| on | yes | yes | orange |
| on | yes | no | red |
| on | no | any | red |

`daemonRunning` is displayed in the menu but does not control the color. `Result ok` means `configValid=true`, `lastScanResult=ok`, `unknownCount=0`, `wouldDisableWifi=false`, and `wifiDisabled=false`. The menu bar app allows a 10-second freshness grace so a normal scheduled scan does not flash red while it is finishing. `dryRun=true` with a clean fresh scan is orange because protection is not enforcing; red is reserved for stale status or actual scan problems. In dry-run, `wifiDisabled` remains `false`; dry-run never disables Wi-Fi.
The menu also shows the indicator color as text for accessibility. A `Reason` line is shown only when there is a problem or the status snapshot is unavailable. Unknown process count is shown only when it is non-zero.
The menu bar app and SwiftUI configurator use the same Swift status presentation code for this mapping.
When the top menu row is `Netwatch: problem` or `Netwatch: unavailable`, clicking it opens a detail dialog with the exact reason, freshness, scan result, Wi-Fi action flags, and the most recent unknown process when present.
If the only issue is a stale last scan, such as after waking a laptop, the menu bar app requests a daemon refresh and shows `Netwatch: refreshing` for up to 20 seconds before treating it as a real problem.

## Menu bar status indicator

The repository includes a small native AppKit menu bar binary:

```text
packaging/menu-bar/NetwatchStatusBar.swift
```

Build it:

```bash
make statusbar
```

Install it for the current user:

```bash
make install-statusbar
cp packaging/launchd/com.serg.netwatch.statusbar.plist "$HOME/Library/LaunchAgents/com.serg.netwatch.statusbar.plist"
plutil -lint "$HOME/Library/LaunchAgents/com.serg.netwatch.statusbar.plist"
```

The example plist points to `/Users/serg/.watch/netwatch-statusbar`; adjust `ProgramArguments` if your install path is different.
`make install-statusbar` also installs `NetwatchConfigurator.app` into `~/.watch` so the status menu's `Configurator` item has a stable app bundle to open.

Run it directly:

```bash
~/.watch/netwatch-statusbar
```

A user LaunchAgent can keep it running:

```bash
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.serg.netwatch.statusbar.plist"
launchctl kickstart -k "gui/$(id -u)/com.serg.netwatch.statusbar"
launchctl print "gui/$(id -u)/com.serg.netwatch.statusbar"
```

Stop it:

```bash
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.serg.netwatch.statusbar.plist"
```

The indicator reads `~/.watch/netwatch.status.json`. It does not run scans, call `networksetup`, or change Wi-Fi state. The status popover refreshes every 5 seconds and includes the current status, dry-run state, last scan result, non-zero unknown process count, and most recent unknown process summary when present.

The `Dry run: on/off` menu item is clickable. It updates only the top-level `dryRun` value in the active config path reported by the status snapshot, writes the config through a temporary file and atomic `rename()`, then requests daemon reload with:

```bash
launchctl kill SIGHUP "gui/$(id -u)/com.serg.netwatch"
```

The popover shows an `Action` line after a save or reload error.

The `Interval: Ns` row is normally static. Click it to edit the seconds value in place, then press Enter to save `daemon.pollIntervalSeconds` or Esc to cancel. Accepted values are 30-1800 seconds. `Refresh` requests a daemon refresh with SIGHUP and then rereads the status snapshot; while waiting for the daemon response it appears as disabled `Refresh in progress...`. `View log` opens a built-in read-only log viewer for the configured `logPath`, or `$HOME/.watch/netwatch.log` when `logPath` is omitted. The log viewer's `Clear log file` button truncates that log file to zero bytes. `Configurator` opens the first `NetwatchConfigurator.app` found in `~/.watch`, `~/Applications`, `/Applications`, or this repository's `build/` directory.

## Audit mode

Collect observed connection decisions without disabling Wi-Fi:

```bash
./netwatch --audit
./netwatch --audit 60
```

Without a duration, audit mode performs one scan using `./netwatch.config.json` and prints a report. With a duration, the number is seconds; audit mode repeats scans until that duration expires. It uses the normal config parser, executable-path resolution, Apple trust checks, and policy engine, but it never calls `networksetup`.

The report includes runtime, scanned connection count, unique executable-path count, decision sections, repeated observation counts, and conservative exact-path allow suggestions for unknown non-Apple executables. Suggestions are not applied automatically and must be reviewed before adding them to the config.

Example:

```text
Audit report
Runtime seconds: 60
Connections scanned: 51
Unique executable paths: 8

APPLE SYSTEM
  /usr/libexec/trustd
    observations: 12

ALLOWED
  /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
    observations: 34

UNKNOWN
  /opt/homebrew/bin/python3
    observations: 5

Suggested allow entries (review before adding):

"Python":
  "/opt/homebrew/bin/python3"
```

## Configuration backend commands

These commands are intended for scripts, a future interactive configurator, and the macOS GUI. They do not start monitoring unless explicitly noted.

Discover installed `.app` bundles:

```bash
./netwatch --discover-apps --json
```

The JSON contains one item per discovered app or helper with `displayName`, `bundlePath`, `parentBundlePath`, `executablePath`, `teamId`, `signingIdentifier`, `signatureValid`, `appleSigned`, `suitableTrustedPublisher`, and `signedHelperCandidate`. Discovery scans `/Applications`, `/System/Applications`, `~/Applications`, and standard helper locations inside each app, including Frameworks, Helpers, XPCServices, PlugIns, LoginItems, direct executables in `Contents/Resources`, and `Resources/native`. It never adds rules automatically.

Show a config in deterministic format:

```bash
./netwatch --config-show --config /path/to/netwatch.config.json
```

Edit selected config fields:

```bash
./netwatch --config-set-dry-run true --config /path/to/netwatch.config.json
./netwatch --config-set-dry-run false --config /path/to/netwatch.config.json
./netwatch --config-set-poll-interval 300 --config /path/to/netwatch.config.json
./netwatch --config-set-apple-system-trust true --config /path/to/netwatch.config.json
./netwatch --config-set-interface "Wi-Fi" --config /path/to/netwatch.config.json
./netwatch --config-set-log-path "/Users/serg/.watch/netwatch.log" --config /path/to/netwatch.config.json
./netwatch --config-set-verbose-log false --config /path/to/netwatch.config.json
./netwatch --config-set-daemon-reload-on-sighup true --config /path/to/netwatch.config.json
./netwatch --config-set-daemon-exit-on-config-error false --config /path/to/netwatch.config.json
./netwatch --config-set-deny-patterns --value "bad-host" --value ":4444" --config /path/to/netwatch.config.json
./netwatch --config-set-allow-remote-hosts --value "17." --value "149.154." --config /path/to/netwatch.config.json
```

For `logPath`, pass an empty string to remove the field and use the default log location. For deny and remote-host lists, omit `--value` to write an empty array.

Add or remove trusted publisher rules:

```bash
./netwatch --config-add-trusted-publisher "Google Chrome" \
  --path "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --team-id "EXPECTED_TEAM_ID" \
  --signing-identifier "com.google.Chrome" \
  --config /path/to/netwatch.config.json

./netwatch --config-set-trusted-publisher "Google Chrome" \
  --name "Google Chrome" \
  --path "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --team-id "EXPECTED_TEAM_ID" \
  --signing-identifier "com.google.Chrome" \
  --config /path/to/netwatch.config.json

./netwatch --config-remove-trusted-publisher "Google Chrome" \
  --config /path/to/netwatch.config.json
```

Adding a trusted publisher requires the executable to exist and its current Security.framework identity to match the provided Team ID and signing identifier. The command does not infer or invent identity values.

Add or remove a signed app bundle rule:

```bash
./netwatch --config-add-trusted-app-bundle "ChatGPT" \
  --bundle-root "/Applications/ChatGPT.app" \
  --team-id "2DC432GLL2" \
  --signing-identifier "com.openai.codex" \
  --signing-identifier-prefix "com.openai.codex." \
  --allow-subdirectories true \
  --config /path/to/netwatch.config.json

./netwatch --config-remove-trusted-app-bundle "ChatGPT" \
  --config /path/to/netwatch.config.json
```

The add command verifies that the `.app` exists, its signature is valid, and its Team ID matches before writing the rule. Repeat `--signing-identifier` and `--signing-identifier-prefix` as needed. Nothing is trusted automatically.

Add or remove trusted workspace rules:

```bash
./netwatch --config-add-trusted-workspace "project scripts" \
  --root "/Users/serg/project" \
  --interpreter "/usr/local/bin/node" \
  --config /path/to/netwatch.config.json

./netwatch --config-set-trusted-workspace "project scripts" \
  --name "project scripts" \
  --root "/Users/serg/project" \
  --interpreter "/usr/local/bin/node" \
  --allow-subdirectories true \
  --allow-by-cwd-only false \
  --config /path/to/netwatch.config.json

./netwatch --config-remove-trusted-workspace "project scripts" \
  --config /path/to/netwatch.config.json
```

Workspace additions require an existing directory root and an existing executable interpreter. The set command can rename a rule and edit roots, interpreters, `allowSubdirectories`, and `allowByCwdOnly`.

Add or remove legacy path-only allow rules:

```bash
./netwatch --config-add-allow-process "ssh" \
  --path "/usr/bin/ssh" \
  --config /path/to/netwatch.config.json

./netwatch --config-add-allow-process "Some App" \
  --path "/Applications/Some App.app/Contents/*" \
  --config /path/to/netwatch.config.json

./netwatch --config-set-allow-process "ssh" \
  --name "remote tools" \
  --path "/usr/bin/ssh" \
  --path "/usr/bin/scp" \
  --config /path/to/netwatch.config.json

./netwatch --config-remove-allow-process "Some App" \
  --config /path/to/netwatch.config.json
```

Path-only rules preserve the existing `allowProcesses` semantics and are weaker than `trustedPublishers` and `trustedAppBundles`: they do not verify Team ID or signing identifier. Use them for explicit legacy/manual rules, optional local tools such as `/usr/bin/ssh` or `/usr/bin/scp`, Apple executables outside automatic Apple roots, or apps without usable signed identity. The configurator recommends a signed app bundle rule instead of a path-only bundle wildcard when signed identity is available.

WhatsApp may start signed extensions such as `ServiceExtension.appex` separately from the main app. Prefer adding the discovered `WhatsApp - ServiceExtension` item as a trusted publisher. Manual equivalent:

```bash
./netwatch --config-add-trusted-publisher "WhatsApp ServiceExtension" \
  --path "/Applications/WhatsApp.app/Contents/PlugIns/ServiceExtension.appex/Contents/MacOS/ServiceExtension" \
  --team-id "57T9237FN3" \
  --signing-identifier "net.whatsapp.WhatsApp.ServiceExtension" \
  --config /path/to/netwatch.config.json
```

If you use a path-only fallback for that extension, the process key must match the `lsof` name, usually `ServiceEx`, not `WhatsApp`.

Config editing commands validate the existing config, modify only the requested field, validate the updated config, create a backup, write a same-directory temporary file, flush it, atomically replace the original with `rename()`, and preserve unrelated fields. Output uses the same deterministic JSON formatting as config conversion. Repeated config backend edits use the first available backup name from `config.json.bak` through `config.json.bak.999`.

Reload a running daemon after edits:

```bash
./netwatch --reload-daemon
```

This sends the existing daemon reload signal and does not start or stop the daemon. If the daemon is not running, it exits non-zero with a clear error.

Recommended workflow:

1. `./netwatch --discover-apps --json`
2. Add one reviewed trusted publisher, trusted app bundle, or trusted workspace rule.
3. `./netwatch --check-config /path/to/netwatch.config.json`
4. `./netwatch --reload-daemon`

## Convert an existing config

To migrate an existing config to automatic Apple system-component trust:

```bash
./netwatch --convert-config /path/to/netwatch.config.json
```

The converter validates the existing config, adds:

```json
"version": 2,
"allowAppleSystemComponents": true
```

It preserves unrelated fields, deny rules, remote-host rules, and third-party allow entries. It removes explicit Apple system-component allow entries only when the configured path is an exact existing executable path and the same Security.framework verifier used at runtime confirms it as a trusted Apple system component. Wildcards, missing paths, unverified paths, third-party paths, and ambiguous entries are preserved.

The converter preserves `trustedPublishers` and `trustedAppBundles` entries unchanged. It never invents Team IDs, never invents signing identifiers, and never migrates `allowProcesses` entries into signed trust rules automatically.

Before replacing the file, the converter writes a byte-for-byte backup using the first available name:

```text
config.json.bak
config.json.bak.1
config.json.bak.2
config.json.bak.3
```

The converted file is written through a same-directory temporary file, flushed, and atomically installed with `rename()`. The original permissions are preserved. If no conversion is needed, it prints `Config is already up to date.`, creates no backup, and does not rewrite the file.

Converted configs are written with stable two-space indentation, `\n` line endings, a final newline, and deterministic object key ordering. Array element order is preserved.

Sample output:

```text
--- /Users/serg/.watch/netwatch.config.json.bak
+++ /Users/serg/.watch/netwatch.config.json
@@
 {
+  "version": 2,
+  "allowAppleSystemComponents": true,
   "allowProcesses": {
-    "assistant": "/usr/libexec/assistantd",
     "Google": "/Applications/Google Chrome.app/Contents/*"
   }
 }
Config converted successfully.
Backup: /Users/serg/.watch/netwatch.config.json.bak
Removed trusted Apple entries: 1
Preserved allow entries: 1
Preserved unverified or ambiguous entries: 0
```

Running the command again is idempotent. To restore, copy the chosen backup over the config:

```bash
cp /path/to/config.json.bak /path/to/config.json
```

If numbered backups exist, choose the backup file you want to restore.

## Check a config

Validate a config without starting monitoring:

```bash
./netwatch --check-config /path/to/netwatch.config.json
```

Exit status is `0` for a valid config, including valid configs with warnings. Invalid JSON, unsupported schema versions, wrong required types, unsupported `allowProcesses`, `trustedPublishers`, or `trustedAppBundles` value types, unreadable files, and command-line usage errors return non-zero.

The checker reuses the normal config parser, then reports warnings for duplicate allow or deny entries where detectable, duplicate trusted publisher exact paths, invalid wildcard placement, malformed or missing executable paths and app bundle roots, Apple trust verification failures for Apple-system-looking allow entries when automatic Apple trust is enabled, trusted publisher identity mismatches for currently installed executables, and deny rules that appear to shadow allow entries.

Examples:

```text
Config OK.
```

```text
Config valid with warnings:

WARNING:
  allowProcesses.Google
  executable does not currently exist: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
```

```text
Config invalid:

ERROR:
  allowProcesses.Google
  allowProcesses.Google must be string or array of strings
```

`--check-config` exits before `lsof`, process scanning, monitoring loops, launchd-specific runtime behavior, or Wi-Fi changes.

## Explain a decision

Explain how the current policy classifies one executable path without starting monitoring:

```bash
./netwatch --why <pid-or-executable-path>
```

This command loads `./netwatch.config.json`, uses the same policy engine as monitoring, and prints one of:

```text
DENIED
ALLOWED
APPLE_SYSTEM
UNKNOWN
```

Examples:

```text
Decision: ALLOWED
Trust source: CONFIG

Reason:
  matched allowProcesses.Google
  matched path: /Applications/Google Chrome.app/Contents/*
```

```text
Decision: ALLOWED
Trust source: TRUSTED_PUBLISHER

Reason:
  executable path matched trustedPublishers.Google Chrome
  code signature valid
  Team ID matched
  signing identifier matched
```

```text
Decision: ALLOWED
Trust source: TRUSTED_APP_BUNDLE

Reason:
Bundle rule: ChatGPT
Team ID matched
Signing identifier matched
Executable is inside bundle root
```

```text
Decision: UNKNOWN
Trust source: NONE

Reason:
  executable path matched trustedPublishers.Google Chrome
  code signature valid
  Team ID mismatch

Expected Team ID:
  EXPECTED_TEAM_ID

Actual Team ID:
  ACTUAL_TEAM_ID
```

```text
Decision: UNKNOWN
Trust source: NONE

Reason:
  no deny rule matched
  no allow rule matched
  not an automatically trusted Apple system component
```

Explicit deny still has priority over every trust source:

```text
deny -> trusted publisher -> trusted app bundle -> trusted workspace -> localhost LISTEN -> explicit allow -> Apple system trust -> unknown
```

`--why` exits before `lsof`, process scanning, monitoring loops, launchd-specific runtime behavior, or Wi-Fi changes. It accepts an absolute executable path or a PID. Use a PID when explaining interpreter-based trusted workspace rules because cwd and argv are process metadata.

## Configuration

Example:

```json
{
  "version": 2,
  "dryRun": true,
  "daemon": {
    "pollIntervalSeconds": 300,
    "reloadOnSighup": true,
    "exitOnConfigError": false
  },
  "allowAppleSystemComponents": true,
  "trustedPublishers": {},
  "trustedAppBundles": {},
  "trustedWorkspaces": {},
  "interface": "Wi-Fi",
  "logPath": "/Users/serg/.watch/netwatch.log",
  "verboseLog": false,

  "denyPatterns": [
    "144.172.104.196",
    "165.140.86.183",
    ":1247",
    ":2246",
    ".task",
    "parser",
    "font3",
    "plog3",
    "npm-compiler"
  ],

  "allowProcesses": {
    "WhatsApp": "/Applications/WhatsApp.app/Contents/MacOS/WhatsApp",
    "ChatGPT": "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
    "ChatGPTHe": "/Applications/ChatGPT.app/Contents/Resources/ChatGPTHelper",
    "Google": "/Applications/Google Chrome.app/Contents/*",
    "firefox": "/Applications/Firefox.app/Contents/MacOS/firefox",
    "ssh": "/usr/bin/ssh"
  },

  "allowRemoteHosts": []
}
```

### `version`

Current config schema version:

```json
"version": 2
```

Configs without `version` are still accepted for backward compatibility. If `version` is present, it must be the number `2`. Unsupported older or future versions are rejected with an error showing the supported version.

### `dryRun`

When `dryRun` is `true`, the tool only logs what it would do:

```json
"dryRun": true
```

When `dryRun` is `false`, the tool disables Wi-Fi if suspicious connections are found:

```json
"dryRun": false
```

Use `dryRun: true` until the allowlist is stable.

### `daemon`

Daemon mode settings:

```json
"daemon": {
  "pollIntervalSeconds": 300,
  "reloadOnSighup": true,
  "exitOnConfigError": false
}
```

All fields are optional. Defaults are 300 seconds, reload on SIGHUP enabled, and keep the previous valid config after a bad reload. `pollIntervalSeconds` must be at least 1.

### `allowAppleSystemComponents`

When `allowAppleSystemComponents` is `true`, the tool can automatically allow Apple-signed system components whose executable path is under one of these roots:

```text
/System/
/usr/libexec/
/usr/lib/
```

The default is `false`, so existing configs keep their current behavior:

```json
"allowAppleSystemComponents": false
```

Automatic trust requires both an approved system path and a valid Apple code signature checked with macOS Security.framework. Apple apps outside those roots, third-party apps, unsigned files, invalid signatures, and verification errors are not automatically trusted.

### `trustedPublishers`

`trustedPublishers` is for selected third-party apps that should be allowed by stable signed identity instead of executable hash:

```json
"trustedPublishers": {
  "Google Chrome": {
    "paths": [
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    ],
    "teamId": "EXPECTED_TEAM_ID",
    "signingIdentifier": "com.google.Chrome"
  }
}
```

Each entry requires exact executable `paths`, `teamId`, and `signingIdentifier`. `requireValidSignature` may be omitted or set to `true`; `false` is rejected. Wildcard paths are not supported for trusted publisher rules. Path matching is exact; when both paths exist, `netwatch` also accepts `realpath()`-equivalent paths so symlinked references to the same executable do not create a separate identity. Use `allowProcesses` for path-only rules and suffix wildcards.

Runtime verification uses Security.framework to require all of these at the same time:

```text
configured executable path
valid code signature
exact Team Identifier
exact signing identifier
```

Hashes are intentionally not used for allow/block decisions. Normal app updates can change binary contents, executable hash, version, and modification time while preserving Team ID, signing identifier, and executable path.

The Team ID is always bound to the configured executable path. A matching Team ID on a different path is not trusted. If multiple trusted publisher rules match one executable path, any successful rule allows it as `TRUSTED_PUBLISHER`; if all matching rules fail, the executable is treated as unknown and is not allowed later by a matching `allowProcesses` path or Apple system trust. `--check-config` warns about duplicate exact publisher paths so ambiguous configs can be cleaned up.

To inspect identity for an installed app while preparing a rule:

```bash
codesign -dv "/Applications/Google Chrome.app" 2>&1 | grep -E "Identifier|TeamIdentifier"
codesign --verify --deep --strict --verbose=2 "/Applications/Google Chrome.app"
```

These commands are only documentation aids. `netwatch` itself uses Security.framework and does not shell out to `codesign`.

Manual migration is optional: move one reviewed path from `allowProcesses` into `trustedPublishers`, fill in the observed Team ID and signing identifier, then run `./netwatch --check-config /path/to/config.json`. Existing `allowProcesses` rules remain supported for paths not covered by a trusted publisher rule.

### `trustedAppBundles`

`trustedAppBundles` allows signed executables below one explicitly selected macOS app bundle without relying on a path-only wildcard:

```json
"trustedAppBundles": {
  "ChatGPT": {
    "bundleRoot": "/Applications/ChatGPT.app",
    "teamId": "2DC432GLL2",
    "allowedSigningIdentifiers": [
      "com.openai.codex"
    ],
    "allowedSigningIdentifierPrefixes": [
      "com.openai.codex."
    ],
    "allowSubdirectories": true
  }
}
```

`bundleRoot` must be an exact absolute `.app` path. At least one exact identifier or prefix is required. Runtime trust requires the executable and bundle root to canonicalize successfully, the canonical executable to remain inside the canonical bundle root, a valid non-ad-hoc code signature with identity metadata, an exact Team ID match, and an exact or prefix signing identifier match. A symlink that escapes the bundle is rejected.

If a path belongs to a configured bundle but any of these checks fails, the decision is unknown and weaker `trustedWorkspaces`, `allowProcesses`, remote-host, or Apple-system rules are not considered. `trustedAppBundles` is independent from the weaker path-only app bundle wildcard in `allowProcesses`.

### `trustedWorkspaces`

`trustedWorkspaces` is for interpreter-based scripts. It lets you allow `node`, `python`, `ruby`, `bash`, or another interpreter only when the process cwd and resolved script path are inside an explicitly trusted project root:

```json
"trustedWorkspaces": {
  "autotrade-data-scripts": {
    "roots": [
      "/Users/serg/Docs/work/autotrade/my_auto_trade/backtrading/upbot"
    ],
    "allowSubdirectories": true,
    "interpreters": [
      "/Users/serg/.local/share/fnm/node-versions/v24.16.0/installation/bin/node"
    ],
    "allowByCwdOnly": false
  }
}
```

Each rule requires non-empty `roots`, `allowSubdirectories`, and `interpreters`. `allowByCwdOnly` is optional and defaults to `false`. Wildcards and relative paths are rejected. Runtime matching canonicalizes paths with `realpath()` where practical, so `/trusted/app2` does not match `/trusted/app` and symlinked scripts that escape the root are rejected.

For a trusted workspace allow, all of these must pass:

```text
interpreter executable path matches
process cwd is inside the matched root
resolved script path is inside the same matched root
```

Relative script paths from argv are resolved against cwd. If the script path cannot be resolved, the rule fails closed unless `allowByCwdOnly` is explicitly `true`. Do not add a global `allowProcesses` entry for `node`, `python`, `ruby`, or `bash`; use `trustedWorkspaces` for project-scoped interpreter trust.

### `interface`

The Wi-Fi interface name used by `networksetup`:

```json
"interface": "Wi-Fi"
```

On most Macs this is `Wi-Fi`.

### `logPath`

Path to the log file:

```json
"logPath": "/Users/serg/.watch/netwatch.log"
```

The tool logs suspicious connections, dry-run/enforcement messages, and errors. It does not write `OK` runs to the log.

### `verboseLog`

When `verboseLog` is `false` or omitted, the log keeps only problems: suspicious connections, dry-run/enforcement messages, and errors. When `true`, it also writes routine successful trusted publisher, trusted app bundle, and trusted workspace decisions:

```json
"verboseLog": false
```

### `denyPatterns`

Deny patterns are matched against the raw `lsof` connection line. They always have priority over allowlists.

Example:

```json
"denyPatterns": [
  "144.172.104.196",
  ":2246",
  ".task",
  "parser"
]
```

If a connection line contains one of these patterns, it is treated as suspicious even if the process is otherwise allowed.

### `allowProcesses`

Required format:

```json
"allowProcesses": {
  "WhatsApp": "/Applications/WhatsApp.app/Contents/MacOS/WhatsApp",
  "Google": "/Applications/Google Chrome.app/Contents/*"
}
```

The key is the process name as shown by `lsof`. Note that macOS often truncates process names in `lsof`, for example:

```text
ChatGPTHe
WeatherWi
ONLYOFFIC
editors_h
```

The value is the expected executable path.

A trailing `*` means prefix match:

```json
"Google": "/Applications/Google Chrome.app/Contents/*"
```

Multiple paths can be allowed for the same process:

```json
"ollama": [
  "/Applications/Ollama.app/Contents/*",
  "/usr/local/bin/ollama",
  "/opt/homebrew/bin/ollama"
]
```

The old process-name-only format is not supported in the C version because it only checks the process name and is less secure:

```json
"allowProcesses": ["WhatsApp", "Google", "ssh"]
```

Use the path-based object format instead.

### `allowRemoteHosts`

Remote host prefixes can also be allowed:

```json
"allowRemoteHosts": [
  "149.154.",
  "151.101."
]
```

This is useful for known CDNs or services, but process path allowlisting is usually safer than remote IP allowlisting because IP ranges can change.

## How the decision logic works

For each active connection:

```text
1. If the line matches denyPatterns → suspicious
2. Else if executable path matches trustedPublishers and publisher identity verifies → allowed
3. Else if executable path matches trustedPublishers but verification fails → suspicious
4. Else if executable path is inside trustedAppBundles and signed bundle identity verifies → allowed
5. Else if executable path belongs to trustedAppBundles but verification fails → suspicious
6. Else if interpreter path matches trustedWorkspaces and cwd/script verify → allowed
7. Else if interpreter path matches trustedWorkspaces but cwd/script verification fails → suspicious
8. Else if it is localhost LISTEN → allowed
9. Else if process name and executable path match allowProcesses → allowed
10. Else if remote host starts with one of allowRemoteHosts → allowed
11. Else if allowAppleSystemComponents is true and the executable is a trusted Apple system component → allowed
12. Else → suspicious
```

When suspicious connections are found, the log entry looks like this:

```text
DRY RUN: would disable Wi-Fi
[UNKNOWN] WhatsApp
  LINE: WhatsApp  12562 serg  120u  IPv4 ... TCP 10.33.0.2:60589->31.13.72.48:5222 (ESTABLISHED)
  PATH: /Applications/WhatsApp.app/Contents/MacOS/WhatsApp
  REASON: not present in allowlist
  APPLE TRUST: path is not an approved system path
  PID: 12562
  PPID: 1
  COMMAND LINE: /Applications/WhatsApp.app/Contents/MacOS/WhatsApp
  RUNTIME CWD: /Users/serg
  REMOTE ENDPOINT: 31.13.72.48:5222
  PARENT COMMAND: launchd
```

Successful trusted publisher decisions are logged distinctly from ordinary path-only allows:

```text
[TRUSTED_PUBLISHER] Google Chrome
  PATH: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
  REASON: trusted publisher identity verified
  TRUSTED PUBLISHER: trusted publisher identity verified
  PUBLISHER RULE: Google Chrome
  ACTUAL TEAM ID: EXPECTED_TEAM_ID
  ACTUAL SIGNING IDENTIFIER: com.google.Chrome
```

Successful signed app helper decisions use the separate `[TRUSTED_APP_BUNDLE]` source and include the bundle rule, bundle root, Team ID, and signing identifier. As with other successful trust decisions, these routine entries are written only when `verboseLog` is `true`.

Successful trusted workspace decisions are logged separately:

```text
[TRUSTED_WORKSPACE] node
  PATH: /Users/serg/.local/share/fnm/node-versions/v24.16.0/installation/bin/node
  REASON: trusted workspace script verified
  TRUSTED WORKSPACE: trusted workspace script verified
  WORKSPACE RULE: autotrade-data-scripts
  WORKSPACE ROOT: /Users/serg/Docs/work/autotrade/my_auto_trade/backtrading/upbot
  CWD: /Users/serg/Docs/work/autotrade/my_auto_trade/backtrading/upbot
  SCRIPT: /Users/serg/Docs/work/autotrade/my_auto_trade/backtrading/upbot/script.js
```

## Install as a launchd job

The repository includes a helper script:

```bash
./scripts/install-macos.sh
```

It expects:

```text
~/.watch/netwatch
~/.watch/netwatch.config.json
```

It creates:

```text
~/Library/LaunchAgents/com.serg.netwatch.plist
```

The default interval is 1800 seconds, or 30 minutes.

For continuous foreground daemon mode, use the example plist:

```text
packaging/launchd/com.sergey.netwatch.plist
```

It runs:

```bash
/usr/local/bin/netwatch --daemon --config /etc/netwatch/config.json
```

Copy it to the appropriate LaunchDaemon or LaunchAgent location, adjust paths, then load it with `launchctl`. The repository does not automatically install this example plist.

Check status:

```bash
~/.watch/netwatch --status
```

You can also query launchd directly:

```bash
launchctl list | grep -i netwatch
```

In `launchctl list`, a `-` PID means the job is not currently running. This is normal because the tool runs, checks connections, and exits. `0` in the status column means the last run completed successfully.

Inspect the plist:

```bash
plutil -p ~/Library/LaunchAgents/com.serg.netwatch.plist
```

## Migrating from scheduled one-shot execution to LaunchDaemon

Keep `dryRun` enabled while migrating so the new daemon logs decisions without disabling Wi-Fi:

```json
"dryRun": true
```

Find old scheduled one-shot runs before installing the daemon:

```bash
crontab -l | grep -i netwatch
launchctl list | grep -i netwatch
grep -R "netwatch" "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null
```

Unload the old job only after you have identified the exact plist path. For a user LaunchAgent:

```bash
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.serg.netwatch.plist"
```

For a machine-level LaunchDaemon:

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.serg.netwatch.plist
```

Install the new daemon plist by copying and editing the example. Adjust `ProgramArguments` before loading it:

```bash
sudo cp packaging/launchd/com.sergey.netwatch.plist /Library/LaunchDaemons/com.sergey.netwatch.plist
sudo plutil -lint /Library/LaunchDaemons/com.sergey.netwatch.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.sergey.netwatch.plist
```

Manage the daemon:

```bash
sudo launchctl print system/com.sergey.netwatch
sudo launchctl kickstart -k system/com.sergey.netwatch
sudo launchctl bootout system /Library/LaunchDaemons/com.sergey.netwatch.plist
sudo kill -HUP <pid>
~/.watch/netwatch --status
```

Verify that only one `netwatch` instance is active:

```bash
pgrep -af netwatch
launchctl list | grep -i netwatch
sudo launchctl print system/com.sergey.netwatch | grep -E "pid|state|last exit"
```

Daemon mode also keeps a single-instance lock for the same config path. If a second daemon is started for that config, it exits with a clear error instead of running another monitor loop.

## Remove launchd job

```bash
./scripts/remove-macos.sh
```

Or manually:

```bash
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.serg.netwatch.plist" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/com.serg.netwatch.plist"
```

## Logs

Main log:

```bash
tail -50 ~/.watch/netwatch.log
```

Launchd stdout/stderr logs:

```bash
tail -50 ~/.watch/netwatch.launchd.out.log
tail -50 ~/.watch/netwatch.launchd.err.log
```

The main log is written for suspicious connections, dry-run/enforcement messages, and errors. With `verboseLog: true`, it also records successful trusted publisher, trusted app bundle, and trusted workspace decisions. Successful `OK` checks are printed during manual runs but not appended to the main log.

## Tuning the allowlist

Start with:

```json
"dryRun": true
```

Run manually:

```bash
~/.watch/netwatch ~/.watch/netwatch.config.json
```

For every suspicious but legitimate process, inspect it:

```bash
ps -p <PID> -o pid,ppid,user,lstart,etime,comm,command
lsof -p <PID> | head -80
```

Then add the exact executable path to `allowProcesses`.

Prefer exact paths when possible:

```json
"WhatsApp": "/Applications/WhatsApp.app/Contents/MacOS/WhatsApp"
```

Use prefix paths for apps with many helpers:

```json
"Google": "/Applications/Google Chrome.app/Contents/*"
```

Avoid allowlisting very broad process names unless the path is also narrow. For example, avoid this:

```json
"com.apple": "/System/*"
```

A safer Safari/WebKit example:

```json
"com.apple": "/System/Volumes/Preboot/Cryptexes/App/System/Library/StagedFrameworks/Safari/*"
```
logPath

Path to the log file:

```json
"logPath": "/Users/your_user_name/.watch/netwatch.log"
```

Use an absolute path. Do not use ~/.watch/netwatch.log in the JSON config, because ~ is expanded by the shell, not by the tool.

If logPath is omitted in netwatch.config.json, the tool uses:

```text
$HOME/.watch/netwatch.log
```

The tool logs suspicious connections, dry-run/enforcement messages, and errors. With `verboseLog: true`, it also records successful trusted publisher, trusted app bundle, and trusted workspace decisions. It does not write OK runs to the log.

## JSON parser note

The repository includes a small `cJSON`-compatible parser under `third_party/cjson/` so the tool can be built without external package-manager dependencies.

It supports the JSON features needed by this tool:

- objects
- arrays
- strings
- booleans
- `null`

The configuration file does not use JSON numbers.

If you prefer the official `cJSON` implementation, replace these files with official upstream files:

```text
third_party/cjson/cJSON.c
third_party/cjson/cJSON.h
```

## Safety notes

This tool is intentionally defensive and simple, but it is not a full security product.

Important limitations:

- It checks periodically, not continuously.
- It sees active connections at the time it runs.
- It relies on `lsof` output for connection listing.
- It can produce false positives until the allowlist is tuned.
- Disabling Wi-Fi can interrupt active work.


Recommended workflow:

1. Start with `dryRun: true`.
2. Tune the allowlist.
3. Review logs for several days.
4. Only then consider `dryRun: false`.

## License

MIT
