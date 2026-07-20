CC      = clang
BISON   = bison
FLEX    = flex
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -g -Iinclude -Ibuild/gen
GENCFLAGS = -std=c11 -g -Iinclude -Ibuild/gen -Wno-unused-function -Wno-unused-parameter
LDFLAGS =
CODESIGN_IDENTITY ?= -
ENTITLEMENTS      = cdbg.entitlements

SRCS = src/main.c \
       src/debugger.c \
       src/process.c \
       src/breakpoint.c \
       src/watchpoint.c \
       src/memory.c \
       src/regs.c \
       src/lineno.c \
       src/syms.c \
       src/expr.c \
       src/ast.c \
       src/ast_eval.c

OBJS = $(SRCS:src/%.c=build/%.o)

# flex/bison-generated command-line parser (src/cmd_lexer.l, src/cmd_grammar.y)
# and expression parser (src/ast_expr.l, src/ast_expr.y)
GENOBJS = build/cmd_grammar.tab.o build/cmd_lexer.yy.o \
          build/ast_expr.tab.o build/ast_expr.yy.o

TARGET = build/cdbg

.PHONY: all clean run sign examples

all: $(TARGET)

examples: $(TARGET) build/target build/target_threads

build/target: examples/target.c | build
	$(CC) -g -o $@ $<

build/target_threads: examples/target_threads.c | build
	$(CC) -g -o $@ $<

$(TARGET): $(OBJS) $(GENOBJS) | build
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	/usr/bin/codesign -s "$(CODESIGN_IDENTITY)" --entitlements $(ENTITLEMENTS) --force $@

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

build/gen/cmd_grammar.tab.c build/gen/cmd_grammar.tab.h: src/cmd_grammar.y | build/gen
	$(BISON) -d -o build/gen/cmd_grammar.tab.c $<

build/gen/cmd_lexer.yy.c: src/cmd_lexer.l build/gen/cmd_grammar.tab.h | build/gen
	$(FLEX) -o $@ $<

build/cmd_grammar.tab.o: build/gen/cmd_grammar.tab.c | build
	$(CC) $(GENCFLAGS) -c -o $@ $<

build/cmd_lexer.yy.o: build/gen/cmd_lexer.yy.c | build
	$(CC) $(GENCFLAGS) -c -o $@ $<

build/gen/ast_expr.tab.c build/gen/ast_expr.tab.h: src/ast_expr.y | build/gen
	$(BISON) -d -o build/gen/ast_expr.tab.c $<

build/gen/ast_expr.yy.c: src/ast_expr.l build/gen/ast_expr.tab.h | build/gen
	$(FLEX) -o $@ $<

build/ast_expr.tab.o: build/gen/ast_expr.tab.c | build
	$(CC) $(GENCFLAGS) -c -o $@ $<

build/ast_expr.yy.o: build/gen/ast_expr.yy.c | build
	$(CC) $(GENCFLAGS) -c -o $@ $<

build build/gen:
	mkdir -p $@

clean:
	rm -rf build

run: $(TARGET)
	./$(TARGET)
