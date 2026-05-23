CC=mips-unknown-linux-gnu-gcc
MARCH=r3000
CFLAGS=-march=${MARCH}
DOCKER_IMAGE=5268ac
HELPER=./$(DOCKER_IMAGE)
ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

all: docker toolchain test libtest

docker:
	DEFAULT_DOCKCROSS_IMAGE=$(DOCKER_IMAGE) docker build -t $(DOCKER_IMAGE) $(ROOT_DIR)

vanilla_toolchain:
	docker run -i dockcross/linux-mips >$(HELPER)
	chmod +x $(HELPER)

toolchain:
	docker run -i $(DOCKER_IMAGE) >$(HELPER)
	chmod +x $(HELPER)

test:
	[ -f $(HELPER) ] || $(MAKE) toolchain 
	$(HELPER) $(CC) $(CFLAGS) test.c -o test
	$(HELPER) qemu-mips-static test

libtest:
	[ -f $(HELPER) ] || $(MAKE) toolchain 
	$(HELPER) $(CC) $(CFLAGS) libtest.c -o libtest -L/firmware/_install.pkgstream.extracted/_18AE08E.extracted/cpio-root/lib -Ilibc
	$(HELPER) qemu-mips-static libtest

clean:
	[ -f $(HELPER) ] && rm $(HELPER)
	[ -f test ] && rm test
	[ -f libtest ] && rm libtest
