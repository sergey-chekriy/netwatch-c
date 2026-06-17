#!/usr/bin/env bash
set -euo pipefail

LABEL="com.serg.netwatch"
WATCH_DIR="$HOME/.watch"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
BIN="$WATCH_DIR/netwatch"
CFG="$WATCH_DIR/netwatch.config.json"

mkdir -p "$WATCH_DIR" "$HOME/Library/LaunchAgents"
[ -x "$BIN" ] || { echo "ERROR: missing executable: $BIN"; exit 1; }
[ -f "$CFG" ] || { echo "ERROR: missing config: $CFG"; exit 1; }

launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
      <string>$BIN</string>
      <string>$CFG</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$WATCH_DIR</string>
    <key>StartInterval</key>
    <integer>1800</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$WATCH_DIR/netwatch.launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>$WATCH_DIR/netwatch.launchd.err.log</string>
  </dict>
</plist>
PLIST

launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl kickstart -k "gui/$(id -u)/$LABEL"
echo "OK: installed $LABEL"
launchctl print "gui/$(id -u)/$LABEL" | grep -E "state =|runs =|last exit code|run interval" || true
