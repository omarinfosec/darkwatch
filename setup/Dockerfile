FROM docker:29-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb AS dockercli

FROM python:3.11-slim-bookworm@sha256:f06d01d4ba3f8ad5af45a3ec87df19c1d317d8e8961edc0fabda61811af6f7cf

# Compose v2.40.3 is checksum-verified against the release checksums.txt.
# docker compose is needed to create profile-gated tunnel containers after the
# operator saves a WG config (restart alone is a no-op if they were never up).
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && mkdir -p /usr/local/lib/docker/cli-plugins \
    && arch="$(uname -m)" \
    && case "$arch" in \
         x86_64)  sum=dba9d98e1ba5bfe11d88c99b9bd32fc4a0624a30fafe68eea34d61a3e42fd372 ;; \
         aarch64) sum=d26373b19e89160546d15407516cc59f453030d9bc5b43ba7faf16f7b4980137 ;; \
         *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/docker/compose/releases/download/v2.40.3/docker-compose-linux-${arch}" \
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
