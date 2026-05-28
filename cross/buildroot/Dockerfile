# Period-correct host for Buildroot (2011.11 on 12.04, 2013.05 on 14.04).
ARG UBUNTU_VERSION=12.04
ARG APT_MIRROR=old-releases.ubuntu.com
FROM ubuntu:${UBUNTU_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

RUN if [ "${APT_MIRROR}" = "old-releases.ubuntu.com" ]; then \
      sed -i \
        -e 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
        -e 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
        /etc/apt/sources.list; \
    fi && \
    sed -i 's/main$/main universe/' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    bash \
    bc \
    binutils \
    bzip2 \
    ca-certificates \
    cpio \
    g++ \
    gcc \
    git \
    gzip \
    libncurses5-dev \
    make \
    patch \
    perl \
    python \
    rsync \
    sed \
    tar \
    wget \
    bison \
    flex \
    libssl-dev \
    gettext \
    texinfo \
    file \
    gawk \
    && rm -rf /var/lib/apt/lists/*

ARG ENTRYPOINT_REV=8
COPY entrypoint.sh /usr/local/bin/buildroot-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/buildroot-entrypoint && \
    chmod +x /usr/local/bin/buildroot-entrypoint

WORKDIR /br

ENTRYPOINT ["/usr/local/bin/buildroot-entrypoint"]
CMD ["bash"]
