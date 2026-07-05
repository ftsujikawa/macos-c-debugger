CC      = clang
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -g -Iinclude
LDFLAGS =
CODESIGN_IDENTITY ?= -
ENTITLEMENTS      = cdbg.entitlements

SRCS = src/main.c \
       src/debugger.c \
       src/process.c \
       src/breakpoint.c \
       src/memory.c \
       src/regs.c \
       src/lineno.c \
       src/syms.c \
       src/expr.c

OBJS = $(SRCS:src/%.c=build/%.o)
TARGET = build/cdbg

.PHONY: all clean run sign examples

all: $(TARGET)

examples: $(TARGET) build/target

build/target: examples/target.c | build
	$(CC) -g -o $@ $<

$(TARGET): $(OBJS) | build
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	/usr/bin/codesign -s "$(CODESIGN_IDENTITY)" --entitlements $(ENTITLEMENTS) --force $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

clean:
	rm -rf build

run: $(TARGET)
	./$(TARGET)
