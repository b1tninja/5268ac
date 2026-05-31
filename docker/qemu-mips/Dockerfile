# 5268AC MIPS user-mode lab (dockcross + qemu-mips-static + firmware sysroots).
# Build from repo root: docker build -t 5268ac -f docker/qemu-mips/Dockerfile .

FROM dockcross/linux-mips:latest

LABEL org.opencontainers.image.title="5268ac"
LABEL org.opencontainers.image.description="5268AC gateway lab: MIPS cross toolchain, qemu-mips-static, corpus firmware sysroots."

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        bzip2 \
        ca-certificates \
        curl \
        file \
        gcc \
        git \
        gzip \
        iproute2 \
        make \
        patch \
        python3 \
        python3-pip \
        python3-venv \
        squashfs-tools \
        tar \
        tcpdump \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Scapy for L2/DHCP scripts; dissect for stage-rootfs (SquashFS carve extract).
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    scapy \
    "dissect.squashfs>=1.12"

COPY docker/qemu-mips/entrypoint.sh /usr/local/bin/5268ac-entrypoint
COPY docker/qemu-mips/scripts/qemu_prep_sysroot.sh /usr/local/bin/qemu-prep-sysroot
RUN sed -i 's/\r$//' /usr/local/bin/5268ac-entrypoint /usr/local/bin/qemu-prep-sysroot \
    && chmod +x /usr/local/bin/5268ac-entrypoint /usr/local/bin/qemu-prep-sysroot

WORKDIR /work
ENTRYPOINT ["5268ac-entrypoint"]
CMD ["shell"]
