APP := netwatch
CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS := -Iinclude -Ithird_party/cjson -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=
LDLIBS ?= -framework Security -framework CoreFoundation
SRC := $(wildcard src/*.c) third_party/cjson/cJSON.c
OBJ := $(SRC:.c=.o)
TEST_APP := tests/netwatch_tests
TEST_SRC := tests/netwatch_tests.c src/allow.c src/apple_trust.c src/audit.c src/config.c src/config_check.c src/config_convert.c src/logging.c src/monitor.c src/platform.c src/process.c src/status.c src/strlist.c src/trusted_publisher.c src/trusted_workspace.c src/util.c src/wifi.c src/why.c third_party/cjson/cJSON.c
PREFIX ?= $(HOME)/.watch

.PHONY: all clean install uninstall run test

all: $(APP)

$(APP): $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) $(LDLIBS) -o $@

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TEST_APP): $(TEST_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_SRC) $(LDFLAGS) $(LDLIBS) -o $@

install: $(APP)
	mkdir -p "$(PREFIX)"
	cp $(APP) "$(PREFIX)/$(APP)"
	chmod +x "$(PREFIX)/$(APP)"
	[ -f "$(PREFIX)/netwatch.config.json" ] || cp examples/netwatch.config.example.json "$(PREFIX)/netwatch.config.json"

uninstall:
	rm -f "$(PREFIX)/$(APP)"

run: $(APP)
	./$(APP) examples/netwatch.config.example.json

test: $(APP) $(TEST_APP)
	NETWATCH_BIN=./$(APP) ./$(TEST_APP)

clean:
	rm -f $(APP) $(OBJ) $(TEST_APP)
