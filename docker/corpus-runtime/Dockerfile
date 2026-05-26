FROM python:3.12-slim-bookworm AS runtime-base

ARG SYFT_INSTALL_URL=https://raw.githubusercontent.com/anchore/syft/main/install.sh
ARG GRYPE_INSTALL_URL=https://raw.githubusercontent.com/anchore/grype/main/install.sh
ARG VMLINUX_TO_ELF_REF=master

LABEL org.opencontainers.image.title="5268ac corpus runtime"
LABEL org.opencontainers.image.description="Full runtime for 5268ac corpus indexing, ELF analysis, SBOM generation, and vulnerability scanning."

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        binutils \
        bzip2 \
        ca-certificates \
        coreutils \
        curl \
        elfutils \
        file \
        g++ \
        gcc \
        git \
        gzip \
        jq \
        libmagic1 \
        make \
        patch \
        squashfs-tools \
        tar \
        unzip \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL "$SYFT_INSTALL_URL" | sh -s -- -b /usr/local/bin \
    && curl -sSfL "$GRYPE_INSTALL_URL" | sh -s -- -b /usr/local/bin \
    && syft version \
    && grype version

COPY tools/pkgstream_mirror.py /usr/local/bin/pkgstream-mirror
RUN sed -i 's/\r$//' /usr/local/bin/pkgstream-mirror \
    && chmod +x /usr/local/bin/pkgstream-mirror

FROM runtime-base AS pkgstream-cache

ARG PKGSTREAM_MIRROR_OUT=/opt/pkgstream-mirror/gateway.c01.sbcglobal.net
COPY pkgstreams /opt/pkgstreams
RUN pkgstream-mirror \
    --pkgstreams /opt/pkgstreams \
    --out "$PKGSTREAM_MIRROR_OUT" \
    --jsonl

FROM runtime-base AS runtime

WORKDIR /opt/5268ac
COPY . /opt/5268ac

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install -r requirements.txt \
    && python -m pip install -e ".[dissect,eapol,socks]" \
    && python -m pip install "git+https://github.com/marin-m/vmlinux-to-elf.git@${VMLINUX_TO_ELF_REF}" \
    && python -m pip install capstone lief

COPY docker/corpus-runtime/entrypoint.sh /usr/local/bin/corpus-runtime-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/corpus-runtime-entrypoint \
    && chmod +x /usr/local/bin/corpus-runtime-entrypoint

WORKDIR /work
ENTRYPOINT ["corpus-runtime-entrypoint"]
CMD ["--help"]

FROM runtime-base AS runtime-with-pkgstreams

ARG VMLINUX_TO_ELF_REF=master
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PKGSTREAM_MIRROR_ROOT=/opt/pkgstream-mirror/gateway.c01.sbcglobal.net

COPY --from=pkgstream-cache /opt/pkgstream-mirror /opt/pkgstream-mirror

WORKDIR /opt/5268ac
COPY . /opt/5268ac

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install -r requirements.txt \
    && python -m pip install -e ".[dissect,eapol,socks]" \
    && python -m pip install "git+https://github.com/marin-m/vmlinux-to-elf.git@${VMLINUX_TO_ELF_REF}" \
    && python -m pip install capstone lief

COPY docker/corpus-runtime/entrypoint.sh /usr/local/bin/corpus-runtime-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/corpus-runtime-entrypoint \
    && chmod +x /usr/local/bin/corpus-runtime-entrypoint

WORKDIR /work
ENTRYPOINT ["corpus-runtime-entrypoint"]
CMD ["--help"]
