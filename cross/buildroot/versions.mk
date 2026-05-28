# Build profiles for 5268AC firmware collections.
# Default PROFILE=toolchain matches 11.14.1.533857 ELF .comment (2011.11 / gcc 4.6.2).

PROFILE ?= toolchain

ifeq ($(PROFILE),toolchain)
  BR2_VERSION := 2011.11
  BR2_COMMIT := c29253ef2e2a473e597637b7ada9fb268dfa8767
  BR_CONFIG_FILE := 2011.11-mips-uclibc-5268ac.config
  BR_OUTPUT_SUFFIX :=
  DOCKER_UBUNTU := 12.04
  DOCKER_APT_MIRROR := old-releases.ubuntu.com
else ifeq ($(PROFILE),stock)
  # os-release on 11.14.1.533857; upstream stock rootfs for diff vs firmware.
  BR2_VERSION := 2013.05
  BR2_COMMIT := 404c597
  BR_CONFIG_FILE := 2013.05-mips-from-5268ac-arch.config
  BR_OUTPUT_SUFFIX := -2013.05
  DOCKER_UBUNTU := 14.04
  DOCKER_APT_MIRROR := archive.ubuntu.com
else
  $(error Unknown PROFILE=$(PROFILE); use toolchain or stock)
endif

DOCKER_IMAGE := buildroot_$(BR2_VERSION)
BR_TREE := $(REPO_ROOT)/work_corpus/toolchain/buildroot-$(BR2_VERSION)
BR_OUTPUT := $(REPO_ROOT)/work_corpus/toolchain/output$(BR_OUTPUT_SUFFIX)
BR_DL := $(REPO_ROOT)/work_corpus/toolchain/dl
SDK_DIR := $(REPO_ROOT)/work_corpus/toolchain/sdk
HOST_BIN := $(BR_OUTPUT)/host/usr/bin
VENDOR_GCC := $(HOST_BIN)/mips-unknown-linux-uclibc-gcc

DOCKER_BUILD_ARGS := --build-arg UBUNTU_VERSION=$(DOCKER_UBUNTU) \
	--build-arg APT_MIRROR=$(DOCKER_APT_MIRROR) \
	--build-arg ENTRYPOINT_REV=8

DOCKER_RUN := docker run --rm \
	-e TERM=dumb \
	-v "$(REPO_ROOT):/work" \
	-v "$(ROOT_DIR):/patches:ro" \
	-e BR_TREE=/work/work_corpus/toolchain/buildroot-$(BR2_VERSION) \
	-e BR_DL_DIR=/work/work_corpus/toolchain/dl \
	-e BR_OUTPUT=/work/work_corpus/toolchain/output$(BR_OUTPUT_SUFFIX) \
	-e BR_CONFIG=/patches/configs/$(BR_CONFIG_FILE) \
	$(DOCKER_IMAGE)
