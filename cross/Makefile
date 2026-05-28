CC=mips-unknown-linux-gnu-gcc
VENDOR_CC=mips-unknown-linux-uclibc-gcc
MARCH=r3000
CFLAGS=-march=${MARCH}
VENDOR_CFLAGS=-march=${MARCH} -pipe
# Legacy dockcross wrapper (pkgstream-in-image); lab image is `5268ac` — see docker/qemu-mips/.
DOCKER_IMAGE=5268ac-dockcross
HELPER=./$(DOCKER_IMAGE)
ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(ROOT_DIR)/..)
VENDOR_GCC := $(REPO_ROOT)/work_corpus/toolchain/output/host/usr/bin/$(VENDOR_CC)
SYSROOT_533857 := $(REPO_ROOT)/work_corpus/toolchain/sysroots/version_11.14.1.533857
COLLECTION_533857 := version:11.14.1.533857

all: docker toolchain test libtest

.PHONY: vendor-toolchain vendor-test abi-check fingerprint sysroot-533857 link-sysroot-533857 firmware-link-test
vendor-toolchain:
	$(MAKE) -C $(ROOT_DIR)/buildroot PROFILE=toolchain cross_compiler

vendor-test: vendor-toolchain
	test -x $(VENDOR_GCC)
	$(VENDOR_GCC) --version
	$(VENDOR_GCC) $(VENDOR_CFLAGS) $(ROOT_DIR)/test.c -o $(ROOT_DIR)/vendor_test
	@echo "Built $(ROOT_DIR)/vendor_test with Buildroot 2011.11 uClibc toolchain"

abi-check:
	$(MAKE) -C $(ROOT_DIR)/buildroot PROFILE=toolchain abi-check

fingerprint:
	$(MAKE) -C $(ROOT_DIR)/buildroot fingerprint

sysroot-533857:
	python $(REPO_ROOT)/docker/qemu-mips/scripts/stage_rootfs.py \
		--collection "$(COLLECTION_533857)" \
		--paths bin lib usr/lib etc/ld.so.cache \
		--out $(SYSROOT_533857)

link-sysroot-533857: sysroot-533857 vendor-toolchain
	docker run --rm --entrypoint /bin/bash -e TERM=dumb \
		-v "$(REPO_ROOT):/work" buildroot_2011.11 \
		-c "sed -i 's/\r$$//' /work/cross/prepare_link_sysroot.sh && /work/cross/prepare_link_sysroot.sh"

firmware-link-test: link-sysroot-533857
	docker run --rm --entrypoint /bin/bash -e TERM=dumb \
		-v "$(REPO_ROOT):/work" buildroot_2011.11 \
		-c "sed -i 's/\r$$//' /work/cross/firmware_link_test.sh && /work/cross/firmware_link_test.sh"

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
