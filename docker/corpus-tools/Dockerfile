FROM alpine:3.22

ARG SYFT_INSTALL_URL=https://raw.githubusercontent.com/anchore/syft/main/install.sh
ARG GRYPE_INSTALL_URL=https://raw.githubusercontent.com/anchore/grype/main/install.sh

LABEL org.opencontainers.image.title="5268ac corpus tools"
LABEL org.opencontainers.image.description="Helper image for firmware corpus third-party tools: syft and grype."

RUN apk add --no-cache \
        bash \
        bzip2 \
        ca-certificates \
        coreutils \
        curl \
        file \
        gzip \
        jq \
        tar \
        unzip \
        xz \
    && curl -sSfL "$SYFT_INSTALL_URL" | sh -s -- -b /usr/local/bin \
    && curl -sSfL "$GRYPE_INSTALL_URL" | sh -s -- -b /usr/local/bin \
    && syft version \
    && grype version

COPY entrypoint.sh /usr/local/bin/corpus-tools-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/corpus-tools-entrypoint \
    && chmod +x /usr/local/bin/corpus-tools-entrypoint

WORKDIR /work
ENTRYPOINT ["corpus-tools-entrypoint"]
CMD ["bash"]
