# Aegis Edge: protection service for client sites. Build from the repository root:
#   docker build -f deploy/Dockerfile -t aegis-edge .
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 AEGIS_HOME=/data \
    AEGIS_LIBINJECTION=/usr/local/lib/aegis/_libinjection.so
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY aegis ./aegis
# libinjection (second SQLi/XSS detector) is compiled here; gcc is removed in the same layer.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
 && pip install --no-cache-dir ".[edge]" \
 && aegis build-engine --output /usr/local/lib/aegis/_libinjection.so \
 && apt-get purge -y gcc libc6-dev && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /data aegis && mkdir -p /data && chown aegis /data
USER aegis
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/_aegis/health', timeout=4)"
CMD ["aegis", "edge", "serve", "--host", "0.0.0.0", "--port", "8080"]
