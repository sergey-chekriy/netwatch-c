# Netwatch Configurator

`NetwatchConfigurator.app` is a convenience macOS SwiftUI UI for editing and checking a netwatch config. The netwatch CLI remains the security authority: the app calls backend commands and does not implement allow/block policy, signature verification, Wi-Fi enforcement, daemon installation, or privileged writes.

## Build

```bash
make configurator
make configurator-test
```

The app bundle is written to:

```bash
build/NetwatchConfigurator.app
```

When testing a freshly rebuilt app, quit any existing configurator process with
`Cmd+Q` first, or start a separate fresh instance:

```bash
open -n build/NetwatchConfigurator.app
```

The bundle includes the locally built `./netwatch` binary as a helper. At runtime the app searches for `netwatch` in this order:

1. bundled helper in the app resources;
2. `/usr/local/bin/netwatch`;
3. `/opt/homebrew/bin/netwatch`;
4. `PATH` entries.

You can also set the binary path in Settings.

## Config Path

The default config path is:

```bash
~/.watch/netwatch.config.json
```

Settings lets you choose another path. Config changes are made through netwatch backend commands such as:

```bash
netwatch --config-set-dry-run true --config /path/to/netwatch.config.json
netwatch --config-set-poll-interval 300 --config /path/to/netwatch.config.json
netwatch --config-set-apple-system-trust true --config /path/to/netwatch.config.json
netwatch --config-set-deny-patterns --value "bad-host" --config /path/to/netwatch.config.json
```

Those backend commands validate the current config, validate the updated config, create a backup, and atomically replace the file. The SwiftUI app does not write JSON directly.

If the selected config file is not writable by the current user, the app shows a permission error. It does not use privilege escalation or install a privileged helper.

## Dashboard

Dashboard reads:

```bash
netwatch --status-json
```

It shows daemon state, protection status, dryRun, last scan, unknown process count, Wi-Fi enforcement state, active config path, and poll interval.

Status colors:

| Dry run | Result ok | Fresh scan | Indicator |
| --- | --- | --- | --- |
| unavailable / unreadable / invalid | any | any | gray |
| off | yes | yes | green |
| off | yes | no | red |
| off | no | any | red |
| on | yes | yes | orange |
| on | yes | no | red |
| on | no | any | red |

`daemonRunning` is displayed but does not control the color. `Result ok` means `configValid=true`, `lastScanResult=ok`, `unknownCount=0`, `wouldDisableWifi=false`, and `wifiDisabled=false`. `dryRun=true` with a clean fresh scan is orange because protection is not enforcing; red is reserved for stale status or actual scan problems.

The dashboard can refresh status, check config, open the config file, open the watch directory, and reload the daemon.

## Settings

Settings can edit the known scalar and list fields without hand-editing JSON:

- `dryRun`;
- `daemon.pollIntervalSeconds`;
- `allowAppleSystemComponents`;
- `interface`;
- `logPath`;
- `daemon.reloadOnSighup`;
- `daemon.exitOnConfigError`;
- `denyPatterns`;
- `allowRemoteHosts`.

List fields are edited as one value per line. Empty lines are ignored. An empty `logPath` removes the field and lets netwatch use its default log path.

## Applications

Applications uses:

```bash
netwatch --discover-apps --json
```

It displays installed `.app` bundles with display name, bundle path, executable path, signature status, Team ID, signing identifier, Apple-signed flag, and whether the app is suitable for `trustedPublishers`.

Adding or editing a trusted publisher is always an explicit user action and calls backend commands such as:

```bash
netwatch --config-add-trusted-publisher "<name>" \
  --path "<executable-path>" \
  --team-id "<team-id>" \
  --signing-identifier "<identifier>" \
  --config /path/to/netwatch.config.json

netwatch --config-set-trusted-publisher "<old-name>" \
  --name "<new-name>" \
  --path "<executable-path>" \
  --team-id "<team-id>" \
  --signing-identifier "<identifier>" \
  --config /path/to/netwatch.config.json
```

The app never auto-trusts all discovered apps and never invents Team IDs or signing identifiers. Configured trusted publisher rules can be renamed, edited, or removed from the Applications screen.

The Applications screen also shows matching path-only `allowProcesses` rules and can remove them. It can add either the exact executable path or an app-bundle wildcard such as `/Applications/Opera.app/Contents/*`. Use the wildcard for apps whose helper processes also need to be covered. Path-only allows are legacy/manual rules and are weaker than trusted publisher verification.

## Path-only Allows

The Path-only Allows screen lists `allowProcesses` entries and supports adding, editing, or removing rules. It also has one-click presets for common Apple command-line tools such as `ssh` and `scp`:

```bash
netwatch --config-add-allow-process "<name>" \
  --path "/Applications/Foo.app/Contents/*" \
  --config /path/to/netwatch.config.json

netwatch --config-set-allow-process "<old-name>" \
  --name "<new-name>" \
  --path "/usr/bin/ssh" \
  --path "/usr/bin/scp" \
  --config /path/to/netwatch.config.json

netwatch --config-remove-allow-process "<name>" \
  --config /path/to/netwatch.config.json
```

Use this for explicit path-only exceptions such as local tools, `/usr/bin/ssh`, `/usr/bin/scp`, optional app helpers, or apps that do not currently provide trusted publisher metadata on this machine. Prefer `trustedPublishers` for signed third-party apps when exact executable identity is known.

## Workspaces

Workspaces manages `trustedWorkspaces` through backend commands. Rules can be added, edited, renamed, or removed:

```bash
netwatch --config-add-trusted-workspace "<name>" \
  --root "<folder-path>" \
  --interpreter "<executable-path>" \
  --config /path/to/netwatch.config.json

netwatch --config-set-trusted-workspace "<old-name>" \
  --name "<new-name>" \
  --root "<folder-path>" \
  --interpreter "<executable-path>" \
  --allow-subdirectories true \
  --allow-by-cwd-only false \
  --config /path/to/netwatch.config.json
```

The edit form supports multiple roots and multiple interpreters, one path per line. `allowSubdirectories` and `allowByCwdOnly` are saved through the backend and validated before writing.

The app does not globally allow interpreters such as `node`, `python`, `ruby`, or `bash`.

## Daemon Reload

Reload daemon calls:

```bash
netwatch --reload-daemon
```

This asks the already running daemon to reload config. It does not start, stop, install, or remove launchd jobs.

## Diagnostics

Diagnostics shows:

- config check output;
- raw status JSON;
- last backend command output;
- recent UI/backend errors;
- reload daemon action.

The app uses `Process` with argument arrays. It does not execute shell strings.
