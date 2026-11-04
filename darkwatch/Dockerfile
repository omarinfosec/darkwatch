# ─── Build stage: produce static/ artifacts ───────────────────────────────
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS bundle
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Every download below is verified against a pinned SHA-256. Bumping a
# version means updating its checksum too (sha256sum of the new artifact).
ARG ESBUILD_VER=0.21.5
ARG ESBUILD_SHA256=d3c7e7e0991f28e987c8a8f1163ffebf326dfff80228afc7f12669a120591fe4
ARG TAILWIND_VER=3.4.10
ARG TAILWIND_SHA256=0c3e21d8479a4c53ffe1cfc7fe965f6b60d8cf597bdf34db132b8c65c6143541
ARG REACT_VER=18.3.1
ARG REACT_SHA256=8d9bed01a672e7eaf387942d781ad47c6a43089a30a0306060f9fd5ac7870347
ARG REACT_DOM_SHA256=031d4427a99f2f3f6cac18bbbf308594a67e4f47d10f4896fdec446505b040e0

# esbuild standalone binary (Go, no Node required)
RUN curl -fsSLo /tmp/esbuild.tgz \
      "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-${ESBUILD_VER}.tgz" && \
    echo "${ESBUILD_SHA256}  /tmp/esbuild.tgz" | sha256sum -c - && \
    tar -xzf /tmp/esbuild.tgz -C /tmp && \
    mv /tmp/package/bin/esbuild /usr/local/bin/ && \
    rm -rf /tmp/package /tmp/esbuild.tgz

# Tailwind CLI standalone binary (Rust+Go, no Node required)
RUN curl -fsSLo /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VER}/tailwindcss-linux-x64" && \
    echo "${TAILWIND_SHA256}  /usr/local/bin/tailwindcss" | sha256sum -c - && \
    chmod +x /usr/local/bin/tailwindcss

WORKDIR /build
COPY index.html tailwind.config.js ./
COPY src/ ./src/

RUN mkdir -p static && \
    # JSX transpile + minify. React stays external (provided by UMD globals
    # at runtime), so the bundle stays small. --sourcemap=linked writes
    # static/bundle.js.map next to the bundle so browser devtools resolve
    # stack traces back to original JSX line numbers — big DX win at ~200
    # KB extra, but the map only downloads when devtools is open.
    esbuild src/app.jsx \
      --bundle --minify --target=es2020 --sourcemap=linked \
      --jsx-factory=React.createElement --jsx-fragment=React.Fragment \
      --external:react --external:react-dom \
      --outfile=static/bundle.js && \
    # Tailwind purge + minify — only classes referenced in index.html and
    # src/app.jsx survive (~20 KB vs 3 MB CDN runtime).
    tailwindcss -c tailwind.config.js -i src/styles.css -o static/styles.css --minify && \
    # Self-host React UMD bundles so the runtime makes zero CDN calls.
    # Taken from the checksummed npm tarballs (unpkg serves the same files
    # but offers nothing to verify them against).
    curl -fsSLo /tmp/react.tgz "https://registry.npmjs.org/react/-/react-${REACT_VER}.tgz" && \
    echo "${REACT_SHA256}  /tmp/react.tgz" | sha256sum -c - && \
    curl -fsSLo /tmp/react-dom.tgz "https://registry.npmjs.org/react-dom/-/react-dom-${REACT_VER}.tgz" && \
    echo "${REACT_DOM_SHA256}  /tmp/react-dom.tgz" | sha256sum -c - && \
    tar -xzf /tmp/react.tgz -O package/umd/react.production.min.js > static/react.production.min.js && \
    tar -xzf /tmp/react-dom.tgz -O package/umd/react-dom.production.min.js > static/react-dom.production.min.js && \
    rm -f /tmp/react.tgz /tmp/react-dom.tgz


# ─── Runtime stage: Python + crawler ──────────────────────────────────────
# Pin to Bookworm explicitly. The plain `python:3.11-slim` tag now resolves
# to Debian Trixie, where Playwright's --with-deps auto-installer fails on
# packages it expects (libgdk-pixbuf2.0-0 was renamed, fonts-unifont
# replaced ttf-unifont, etc). Bookworm is what Playwright targets.
FROM python:3.11-slim-bookworm@sha256:f06d01d4ba3f8ad5af45a3ec87df19c1d317d8e8961edc0fabda61811af6f7cf

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc libxml2-dev libxslt-dev curl sqlite3 iputils-ping && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 999 darkwatch && \
    useradd -r -u 999 -g darkwatch -d /app -s /sbin/nologin darkwatch

WORKDIR /app

# requirements.lock is generated from requirements.in by ops/lock-deps.sh;
# --require-hashes fails the build on any file whose hash is not in it.
COPY requirements.lock .
# Wheel policy: cryptg and yara-python must install from wheels. cryptg's
# sdist needs a Rust toolchain this image does not have, and yara-python's
# compiles the bundled libyara; a pin with no cp311 wheel for the build
# platform should fail here rather than fall back to an untested source
# build. Not --only-binary=:all:, because pyaes (a Telethon dependency)
# ships only an sdist.
RUN pip install --no-cache-dir --require-hashes --only-binary=cryptg,yara-python \
        -r requirements.lock

# Headless Firefox for offline screenshot rendering.
ENV PLAYWRIGHT_BROWSERS_PATH=/app/.browsers
RUN playwright install --with-deps firefox

# Every top-level module, so a new one cannot be left out of the image
# (tests/images/smoke.sh imports them).
COPY *.py index.html config.json ./
COPY --from=bundle /build/static/ ./static/
COPY yara/ yara/

RUN mkdir -p data /loot/pages /loot/reports /loot/screenshots /loot/thumbnails && \
    chown -R darkwatch:darkwatch /app /loot

USER darkwatch

EXPOSE 8080

CMD ["python", "web.py"]
