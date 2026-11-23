# Base image (ffsbx-base:local): the Firefox build under test plus its Python launcher.
#   - Base image pinned by digest (python 3.12.16-slim-trixie).
#   - Every Python package pinned AND hash-checked (requirements.lock).
#   - The Firefox build is pinned by the sha256 seal inside invisible-core 68.80.0
#     (Firefox 159.0, build 20261121043125); `fetch` verifies it.
# Not pinned: Debian packages (trixie is a moving suite).
FROM --platform=linux/amd64 python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MALLOC_ARENA_MAX=2

# Runtime libraries for the patched Firefox engine (Debian 13 t64 names) and Xvfb.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        xvfb \
        libgtk-3-0t64 \
        libdbus-glib-1-2 \
        libasound2t64 \
        libx11-xcb1 \
        libxt6t64 \
        libpci3 \
        libnss3 \
        libnspr4 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        libxfixes3 \
        libxext6 \
        libxtst6 \
        libxss1 \
        libxkbcommon0 \
        libgbm1 \
        libdrm2 \
        libegl1 \
        libgl1 \
        libpango-1.0-0 \
        libcairo2 \
        libatk1.0-0t64 \
        libcups2t64 \
        libfontconfig1 \
        libfreetype6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.lock .
RUN pip install --no-deps --require-hashes -r requirements.lock && pip check

# Engine download into the image, sha256-verified against the seal.
RUN python -m invisible_playwright fetch && python -m invisible_playwright version

CMD ["python", "main.py"]
