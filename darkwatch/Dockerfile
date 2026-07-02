# ─── Build stage: produce static/ artifacts ───────────────────────────────
FROM debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252 AS bundle
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ARG ESBUILD_VER=0.21.5
ARG TAILWIND_VER=3.4.10
ARG REACT_VER=18.3.1

# esbuild standalone binary (Go, no Node required)
RUN curl -fsSL "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-${ESBUILD_VER}.tgz" \
      | tar -xz -C /tmp && \
    mv /tmp/package/bin/esbuild /usr/local/bin/ && \
    rm -rf /tmp/package

# Tailwind CLI standalone binary (Rust+Go, no Node required)
RUN curl -fsSLo /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VER}/tailwindcss-linux-x64" && \
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
    curl -fsSLo static/react.production.min.js \
      "https://unpkg.com/react@${REACT_VER}/umd/react.production.min.js" && \
    curl -fsSLo static/react-dom.production.min.js \
      "https://unpkg.com/react-dom@${REACT_VER}/umd/react-dom.production.min.js"


# ─── Runtime stage: Python + crawler ──────────────────────────────────────
# Pin to Bookworm explicitly. The plain `python:3.11-slim` tag now resolves
# to Debian Trixie, where Playwright's --with-deps auto-installer fails on
# packages it expects (libgdk-pixbuf2.0-0 was renamed, fonts-unifont
# replaced ttf-unifont, etc). Bookworm is what Playwright targets.
FROM python:3.11-slim-bookworm@sha256:ee710afcfb733f4a750d9be683cf054b5cd247b6c5f5237a6849ea568b90ab15

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc libxml2-dev libxslt-dev curl sqlite3 iputils-ping && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 999 darkwatch && \
    useradd -r -u 999 -g darkwatch -d /app -s /sbin/nologin darkwatch

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Headless Firefox for offline screenshot rendering.
ENV PLAYWRIGHT_BROWSERS_PATH=/app/.browsers
RUN playwright install --with-deps firefox

COPY darkwatch.py web.py threat_intel.py index.html config.json ./
COPY --from=bundle /build/static/ ./static/
COPY yara/ yara/

RUN mkdir -p data /loot/pages /loot/reports /loot/screenshots /loot/thumbnails && \
    chown -R darkwatch:darkwatch /app /loot

USER darkwatch

EXPOSE 8080

CMD ["python", "web.py"]
