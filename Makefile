.PHONY: all build build-release test clean example run-example

UNAME_S := $(shell uname -s)
CC ?= cc

ifeq ($(UNAME_S),Darwin)
	RPATH_FLAG = -Wl,-rpath,@loader_path/target/release
	LDLIBS = -lpthread -lm
else
	RPATH_FLAG = -Wl,-rpath,./target/release
	LDLIBS = -lpthread -ldl -lm
endif

# Build library in debug mode
build:
	cargo build

# Build library in release mode
build-release:
	cargo build --release

# Run tests
test:
	cargo test

# Compile C example
example: build-release
	$(CC) -o example example.c \
		-I. \
		-L./target/release \
		-lleanvm_xmss_c \
		$(LDLIBS) \
		$(RPATH_FLAG)

# Run example
run-example: example
	./example

# Clean
clean:
	cargo clean
	rm -f example
	rm -rf include

# Build everything (library + example)
all: build-release example
