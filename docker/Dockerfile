# Build/test environment for VxAtlas: pinned Ghidra + JDK + Python (PyGhidra).
# All versions and checksums come from the repo-root .env via docker compose.
ARG JDK_IMAGE
FROM ${JDK_IMAGE} AS ghidra

ARG GHIDRA_VERSION
ARG GHIDRA_BUILD_DATE
ARG GHIDRA_SHA256

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

# Official Ghidra release zip, verified against the pinned SHA-256.
RUN set -eu; \
    zip="ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip"; \
    curl -fsSL -o "/tmp/${zip}" \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${zip}"; \
    echo "${GHIDRA_SHA256}  /tmp/${zip}" | sha256sum -c -; \
    unzip -q "/tmp/${zip}" -d /opt; \
    mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra; \
    rm "/tmp/${zip}"

ENV GHIDRA_INSTALL_DIR=/opt/ghidra \
    VIRTUAL_ENV=/opt/venv \
    HOME=/cache/home \
    PIP_CACHE_DIR=/cache/pip \
    PATH=/opt/venv/bin:/opt/ghidra/support:${PATH}

# PyGhidra and JPype come from the wheels bundled with the pinned Ghidra release,
# so the Python bridge always matches the Ghidra version. Test/build tools come from PyPI.
RUN set -eu; \
    python3 -m venv /opt/venv; \
    pip install --no-cache-dir --no-index \
      --find-links /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist pyghidra; \
    pip install --no-cache-dir pytest build; \
    chmod -R a+rwX /opt/venv; \
    mkdir -p /cache/home /cache/pip && chmod -R a+rwX /cache

WORKDIR /work
