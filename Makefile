CC=mips-unknown-linux-gnu-gcc
MARCH=r3000
CFLAGS=-march=${MARCH}
HELPER=./5268ac_toolchain
ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

all: clean test

docker:
	docker build $(ROOT_DIR)

toolchain:
	docker run -i dockcross/linux-mips >$(HELPER)
	chmod +x $(HELPER)

test:
	[ -f $(HELPER) ] || $(MAKE) toolchain 
	$(HELPER) $(CC) $(CFLAGS) test.c -o test
	$(HELPER) qemu-mips-static test

clean:
	[ -e test ] && rm test
