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
- Logs suspicious connections with executable path.
- Can disable Wi-Fi when suspicious activity is detected.
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

## Configuration

Example:

```json
{
  "dryRun": true,
  "interface": "Wi-Fi",
  "logPath": "/Users/serg/.watch/netwatch.log",

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

The tool logs suspicious connections and errors. It does not write `OK` runs to the log.

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
2. Else if it is localhost LISTEN → allowed
3. Else if process name and executable path match allowProcesses → allowed
4. Else if remote host starts with one of allowRemoteHosts → allowed
5. Else → suspicious
```

When suspicious connections are found, the log entry looks like this:

```text
DRY RUN: would disable Wi-Fi
WhatsApp  12562 serg  120u  IPv4 ... TCP 10.33.0.2:60589->31.13.72.48:5222 (ESTABLISHED)
  PATH: /Applications/WhatsApp.app/Contents/MacOS/WhatsApp
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

Check status:

```bash
launchctl list | grep -i netwatch
```

A normal result may look like this:

```text
-       0       com.serg.netwatch
```

The `-` means the job is not currently running. This is normal because the tool runs, checks connections, and exits. `0` means the last run completed successfully.

Inspect the plist:

```bash
plutil -p ~/Library/LaunchAgents/com.serg.netwatch.plist
```

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

The main log is written only for suspicious connections and errors. Successful `OK` checks are printed during manual runs but not appended to the main log.

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

The tool logs suspicious connections and errors. It does not write OK runs to the log.

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
