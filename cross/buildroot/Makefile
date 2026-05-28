# Buildroot profiles for 5268AC (default: 11.14.1.533857 toolchain).
ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(ROOT_DIR)/../..)
include $(ROOT_DIR)/versions.mk

.PHONY: all help fetch sync-config docker fingerprint source cross_compiler toolchain sdk \
	install-sdk vendor-gcc-version abi-check qemu-abi-check target diff-firmware olddefconfig

all: help

help:
	@echo "Buildroot profiles for 5268AC (corpus 11.14.1.533857)"
	@echo ""
	@echo "  PROFILE=toolchain (default) — gcc 4.6.2 / uClibc 0.9.32 (matches device ELFs)"
	@echo "  PROFILE=stock           — Buildroot 2013.05 stock target for diff vs firmware"
	@echo ""
	@echo "  make fingerprint        Corpus os-release + ELF .comment evidence"
	@echo "  make fetch              Clone buildroot-$(BR2_VERSION) @ $(BR2_COMMIT)"
	@echo "  make docker             Image $(DOCKER_IMAGE)"
	@echo "  make source             Populate work_corpus/toolchain/dl/"
	@echo "  make cross_compiler     Host mips-unknown-linux-uclibc-gcc (long)"
	@echo "  make sdk                Export host/ tarball (toolchain profile)"
	@echo "  make target             Build stock target/ (stock profile only)"
	@echo "  make abi-check          Compare vs corpus busybox"
	@echo "  make diff-firmware      Stock target/ vs staged firmware sysroot"
	@echo ""
	@echo "Active: PROFILE=$(PROFILE) BR2_VERSION=$(BR2_VERSION) O=$(BR_OUTPUT)"

fetch:
	@mkdir -p $(REPO_ROOT)/work_corpus/toolchain
	@if [ -d "$(BR_TREE)/.git" ]; then \
		cd "$(BR_TREE)" && git fetch --tags origin && \
		(git rev-parse --verify $(BR2_COMMIT) >/dev/null 2>&1 && git checkout $(BR2_COMMIT) || git checkout $(BR2_VERSION)); \
	else \
		git clone --branch $(BR2_VERSION) --depth 1 https://git.buildroot.net/buildroot "$(BR_TREE)"; \
		cd "$(BR_TREE)" && (git checkout $(BR2_COMMIT) 2>/dev/null || true); \
	fi
	@$(MAKE) sync-config

sync-config:
	@test -d "$(BR_TREE)" || (echo "Run: make -C cross/buildroot fetch" && exit 1)
	@test -f "$(ROOT_DIR)/configs/$(BR_CONFIG_FILE)" || (echo "Missing config $(BR_CONFIG_FILE)" && exit 1)
	cp "$(ROOT_DIR)/configs/$(BR_CONFIG_FILE)" "$(BR_TREE)/.config"
	@if [ "$(PROFILE)" = "stock" ]; then \
		echo "Stock profile: run 'make olddefconfig' inside Docker after sync."; \
	fi

olddefconfig: docker sync-config
	$(DOCKER_RUN) make olddefconfig

docker:
	docker build $(DOCKER_BUILD_ARGS) -t $(DOCKER_IMAGE) -f $(ROOT_DIR)/Dockerfile $(ROOT_DIR)

fingerprint:
	$(DOCKER_RUN) bash -c "sed -i 's/\r$$//' /work/cross/buildroot/corpus_fingerprint.sh && /work/cross/buildroot/corpus_fingerprint.sh"

source: docker sync-config
	@if [ "$(PROFILE)" = "stock" ]; then $(MAKE) olddefconfig; fi
	$(DOCKER_RUN) make source

cross_compiler: docker sync-config
	$(DOCKER_RUN) make cross_compiler

toolchain: cross_compiler

sdk: cross_compiler
	@mkdir -p $(SDK_DIR)
	@tar -czf $(SDK_DIR)/mips-unknown-linux-uclibc-gcc4.6.2-buildroot-$(BR2_VERSION)-host.tar.gz \
		-C $(BR_OUTPUT) host
	@echo "Wrote $(SDK_DIR)/mips-unknown-linux-uclibc-gcc4.6.2-buildroot-$(BR2_VERSION)-host.tar.gz"

install-sdk: sdk
	@mkdir -p $(REPO_ROOT)/work_corpus/toolchain/host
	tar -xzf $(SDK_DIR)/mips-unknown-linux-uclibc-gcc4.6.2-buildroot-$(BR2_VERSION)-host.tar.gz \
		-C $(REPO_ROOT)/work_corpus/toolchain/host --strip-components=1

target: docker sync-config
	$(DOCKER_RUN) make target

diff-firmware:
	$(DOCKER_RUN) bash -c "sed -i 's/\r$$//' /work/cross/buildroot/diff_firmware.sh && STOCK=/work/work_corpus/toolchain/output-2013.05/target FIRMWARE=/work/work_corpus/toolchain/sysroots/version_11.14.1.533857 /work/cross/buildroot/diff_firmware.sh"

vendor-gcc-version: cross_compiler
	$(DOCKER_RUN) $(VENDOR_GCC) --version

abi-check: cross_compiler
	$(DOCKER_RUN) bash -c "sed -i 's/\r$$//' /work/cross/buildroot/abi_check.sh && VENDOR_ELF=/work/work_corpus/sbom/version_11.14.1.533857/sources/7_0001_att-5268-11.14.1.533857_prod_lightspeed-install_embedded_squashfs_0x0000b01c_21709742.bin_ddb4802f5c035ce7/bin/busybox BR_OUTPUT=/work/work_corpus/toolchain/output /work/cross/buildroot/abi_check.sh"

qemu-abi-check:
	$(DOCKER_RUN) bash -c "sed -i 's/\r$$//' /work/cross/buildroot/qemu_abi_check.sh && /work/cross/buildroot/qemu_abi_check.sh"
