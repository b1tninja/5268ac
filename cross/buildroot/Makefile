ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BR2_VERSION := 2011.11
DOCKER_IMAGE := buildroot_$(BR2_VERSION)

all: docker

#fetch:
#	[ -d $(ROOT_DIR)/.git ] && git fetch || git clone --bare git://git.buildroot.net/buildroot

docker:
	docker build -t $(DOCKER_IMAGE) $(ROOT_DIR)
