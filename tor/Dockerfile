# Custom Tor sidecar for DarkWatch.
#
# Why not osminogin/tor-simple? That image's torrc doesn't enable an
# authenticated ControlPort, so darkwatch's NEWNYM circuit-rotation
# silently no-ops. Reusing the same circuit across investigations weakens
# egress isolation.
#
# This image:
#   - Templates torrc at start time from ${TOR_CONTROL_PASSWORD}
#   - Exposes SocksPort 9050, ControlPort 9051 with HashedControlPassword
#   - Runs as the unprivileged debian-tor user
#   - Debian trixie (stable): bookworm is LTS-only, and Tor comes from the
#     Debian package. Base pinned by digest (ops/pin-base-images.sh,
#     Dependabot refreshes it)

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tor \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# The tor package creates the debian-tor user, with the first free system
# uid at build time, so a new base can change it: ops/deploy.sh re-owns the
# tor-data volume to match. We make a config dir owned by it so the
# entrypoint can write torrc there.
RUN install -d -m 0700 -o debian-tor -g debian-tor /etc/tor/run

COPY entrypoint.sh healthcheck.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh

USER debian-tor

EXPOSE 9050 9051

# Healthy once a circuit is established (asked over the ControlPort).
HEALTHCHECK --interval=30s --timeout=6s --retries=3 --start-period=60s \
  CMD /usr/local/bin/healthcheck.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["tor", "-f", "/etc/tor/run/torrc"]
