APP := netwatch
CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS := -Iinclude -Ithird_party/cjson -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=
SRC := $(wildcard src/*.c) third_party/cjson/cJSON.c
OBJ := $(SRC:.c=.o)
PREFIX ?= $(HOME)/.watch

.PHONY: all clean install uninstall run

all: $(APP)

$(APP): $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

install: $(APP)
	mkdir -p "$(PREFIX)"
	cp $(APP) "$(PREFIX)/$(APP)"
	chmod +x "$(PREFIX)/$(APP)"
	[ -f "$(PREFIX)/netwatch.config.json" ] || cp examples/netwatch.config.example.json "$(PREFIX)/netwatch.config.json"

uninstall:
	rm -f "$(PREFIX)/$(APP)"

run: $(APP)
	./$(APP) examples/netwatch.config.example.json

clean:
	rm -f $(APP) $(OBJ)
