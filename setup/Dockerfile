FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c AS dockercli

FROM python:3.11-slim-bookworm@sha256:ee710afcfb733f4a750d9be683cf054b5cd247b6c5f5237a6849ea568b90ab15

# Compose v2.29.0 is checksum-verified against the release checksums.txt.
# docker compose is needed to create profile-gated tunnel containers after the
# operator saves a WG config (restart alone is a no-op if they were never up).
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && mkdir -p /usr/local/lib/docker/cli-plugins \
    && arch="$(uname -m)" \
    && case "$arch" in \
         x86_64)  sum=fb3f6c317056ec54e8756851663ca788521f7a9c60afb8a595bc7a05ffaa8951 ;; \
         aarch64) sum=49941418051846d72c74dd8df1f8b4ff753ca74d29986361d937384fbfb63569 ;; \
         *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/docker/compose/releases/download/v2.29.0/docker-compose-linux-${arch}" \
         -o /usr/local/lib/docker/cli-plugins/docker-compose \
    && echo "${sum}  /usr/local/lib/docker/cli-plugins/docker-compose" | sha256sum -c - \
    && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Note: this container runs as root by design.
#
# Why? It needs to write into /data (bind-mounted /var/lib/darkwebapp on the
# host, owned root:root 0700 outside the writable subdirs) AND call the
# docker socket to restart services. The simplest path that handles both is
# to just run as root.
#
# This is acceptable because:
#   1. The setup profile is OFF by default. Operator opts in for a few minutes
#      to configure things, then `docker compose --profile setup stop setup`.
#   2. Mounting /var/run/docker.sock is already root-on-host equivalent.
#   3. The setup container is gated behind a bearer token (SETUP_AUTH_TOKEN)
#      and listens only on ${DARKWATCH_BIND_IP} — operator's chosen ingress.
#   4. Take the setup profile down when configuration is finished.

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DARKWEBAPP_DATA_ROOT=/data \
    SETUP_BIND_PORT=8090

EXPOSE 8090

# --no-access-log: the first visit is GET /?token=<SETUP_AUTH_TOKEN>, which
# would otherwise be written to `docker logs setup` in full.
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8090", "--no-access-log"]
