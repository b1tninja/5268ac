FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="5268ac corpus MCP"
LABEL org.opencontainers.image.description="Streamable HTTP MCP server for the 5268ac firmware corpus index."

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    CORPUS_MCP_HOST=0.0.0.0 \
    CORPUS_MCP_PORT=8100 \
    CORPUS_MCP_TRANSPORT=streamable-http \
    CORPUS_DB=/work/work_corpus/corpus/index.sqlite \
    CORPUS_REPO_ROOT=/work

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        squashfs-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/5268ac
COPY requirements.txt pyproject.toml README.md /opt/5268ac/
COPY corpus /opt/5268ac/corpus
COPY lib2spy /opt/5268ac/lib2spy

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install -r requirements.txt \
    && python -m pip install -e ".[dissect,mcp]"

COPY docker/corpus-mcp/entrypoint.sh /usr/local/bin/corpus-mcp-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/corpus-mcp-entrypoint \
    && chmod +x /usr/local/bin/corpus-mcp-entrypoint

WORKDIR /work
EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import socket; s=socket.create_connection(('127.0.0.1', 8100), 2); s.close()"

ENTRYPOINT ["corpus-mcp-entrypoint"]
CMD ["serve"]
