CLANG ?= clang
CC ?= cc
ARCH_INCLUDE ?= /usr/include/$(shell $(CC) -dumpmachine)
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
BPF_CFLAGS = -O2 -g -target bpf -I$(ARCH_INCLUDE) -Iebpf/include -Iebpf/bpf
LIBS = $(shell pkg-config --libs libbpf) -lelf -lz

.PHONY: all clean p0
all: build/p0.bpf.o build/p0
build:
	mkdir -p $@
build/p0.bpf.o: tests/netns/p0.bpf.c | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
build/p0: tests/netns/p0.c | build
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)
p0: all
	sudo python3 tests/netns/p0.py
clean:
	rm -rf build
