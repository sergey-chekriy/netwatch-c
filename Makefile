APP := netwatch
STATUSBAR_APP := netwatch-statusbar
STATUSBAR_SRC := packaging/menu-bar/NetwatchStatusBar.swift
STATUSBAR_SHARED_SRC := macos/NetwatchConfigurator/NetwatchConfiguratorCore/Models/NetwatchStatusPresentation.swift
CONFIGURATOR_DIR := macos/NetwatchConfigurator
CONFIGURATOR_APP := build/NetwatchConfigurator.app
CONFIGURATOR_BIN := $(CONFIGURATOR_DIR)/.build/release/NetwatchConfigurator
CC ?= cc
SWIFTC ?= /usr/bin/swiftc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS := -Iinclude -Ithird_party/cjson -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=
LDLIBS ?= -framework Security -framework CoreFoundation
SRC := $(wildcard src/*.c) third_party/cjson/cJSON.c
OBJ := $(SRC:.c=.o)
HDR := $(wildcard include/*.h) third_party/cjson/cJSON.h
TEST_APP := tests/netwatch_tests
TEST_SRC := tests/netwatch_tests.c src/allow.c src/apple_trust.c src/app_discovery.c src/audit.c src/config.c src/config_backend.c src/config_check.c src/config_convert.c src/daemon.c src/logging.c src/monitor.c src/platform.c src/process.c src/status.c src/status_snapshot.c src/strlist.c src/trusted_publisher.c src/trusted_workspace.c src/util.c src/wifi.c src/why.c third_party/cjson/cJSON.c
PREFIX ?= $(HOME)/.watch
CONFIGURATOR_INSTALL_APP := $(PREFIX)/NetwatchConfigurator.app

.PHONY: all clean install uninstall run test statusbar install-statusbar configurator install-configurator configurator-test

all: $(APP)

$(APP): $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) $(LDLIBS) -o $@

%.o: %.c $(HDR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TEST_APP): $(TEST_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_SRC) $(LDFLAGS) $(LDLIBS) -o $@

install: $(APP)
	mkdir -p "$(PREFIX)"
	cp $(APP) "$(PREFIX)/.$(APP).tmp"
	chmod +x "$(PREFIX)/.$(APP).tmp"
	mv -f "$(PREFIX)/.$(APP).tmp" "$(PREFIX)/$(APP)"
	[ -f "$(PREFIX)/netwatch.config.json" ] || cp examples/netwatch.config.example.json "$(PREFIX)/netwatch.config.json"

statusbar: $(STATUSBAR_SRC) $(STATUSBAR_SHARED_SRC)
	$(SWIFTC) -O -framework AppKit $(STATUSBAR_SHARED_SRC) $(STATUSBAR_SRC) -o $(STATUSBAR_APP)

install-statusbar: statusbar install-configurator
	mkdir -p "$(PREFIX)"
	cp $(STATUSBAR_APP) "$(PREFIX)/.$(STATUSBAR_APP).tmp"
	chmod +x "$(PREFIX)/.$(STATUSBAR_APP).tmp"
	mv -f "$(PREFIX)/.$(STATUSBAR_APP).tmp" "$(PREFIX)/$(STATUSBAR_APP)"

configurator: $(APP)
	swift build --package-path "$(CONFIGURATOR_DIR)" -c release --product NetwatchConfigurator
	rm -rf "$(CONFIGURATOR_APP)"
	mkdir -p "$(CONFIGURATOR_APP)/Contents/MacOS" "$(CONFIGURATOR_APP)/Contents/Resources"
	cp "$(CONFIGURATOR_BIN)" "$(CONFIGURATOR_APP)/Contents/MacOS/NetwatchConfigurator"
	cp "$(CONFIGURATOR_DIR)/NetwatchConfigurator/Resources/Info.plist" "$(CONFIGURATOR_APP)/Contents/Info.plist"
	cp "$(APP)" "$(CONFIGURATOR_APP)/Contents/Resources/netwatch"

install-configurator: configurator
	rm -rf "$(PREFIX)/.NetwatchConfigurator.app.tmp"
	cp -R "$(CONFIGURATOR_APP)" "$(PREFIX)/.NetwatchConfigurator.app.tmp"
	rm -rf "$(CONFIGURATOR_INSTALL_APP)"
	mv "$(PREFIX)/.NetwatchConfigurator.app.tmp" "$(CONFIGURATOR_INSTALL_APP)"

configurator-test:
	swift run --package-path "$(CONFIGURATOR_DIR)" NetwatchConfiguratorSelfTest

uninstall:
	rm -f "$(PREFIX)/$(APP)"

run: $(APP)
	./$(APP) examples/netwatch.config.example.json

test: $(APP) $(TEST_APP)
	NETWATCH_BIN=./$(APP) ./$(TEST_APP)

clean:
	rm -f $(APP) $(STATUSBAR_APP) $(OBJ) $(TEST_APP)
	rm -rf "$(CONFIGURATOR_APP)"
