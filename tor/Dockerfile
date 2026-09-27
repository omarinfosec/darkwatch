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
#   - Pinned by digest in compose once built locally

FROM debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tor \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# debian-tor user (uid 102) is created by the tor package. We make a
# config dir owned by it so the entrypoint can write torrc there.
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
