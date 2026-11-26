# syntax=docker/dockerfile:1
#
# Container image for faro-server, the self-hosted Faro instance.
#
# Build from the repository root (the whole Cargo workspace is the build
# context; deploy/Dockerfile.dockerignore keeps target/ and .git out of it):
#
#     docker build -f deploy/Dockerfile -t faro-server:local .
#
# or let deploy/docker-compose.yml build it. Multi-arch (amd64 + arm64):
#
#     docker buildx build -f deploy/Dockerfile \
#         --platform linux/amd64,linux/arm64 -t <registry>/faro-server:<tag> --push .
#
# Each platform is compiled natively for that platform (under QEMU emulation
# when it is not the build machine's own), so there is no cross-compiler
# setup to get wrong. Emulated arm64 builds are slow; building directly on
# the Raspberry Pi or another arm64 machine is faster.
#
# The web app (web/, SvelteKit) is built in its own Node stage and embedded
# into the binary; the build fails if it is missing (FARO_REQUIRE_WEB=1).
#
# Runtime layout:
#   /usr/local/bin/faro-server   the binary (ENTRYPOINT; default command `serve`)
#   /usr/share/faro/update-root.json
#                                the project's update root of trust, once it exists
#   /usr/share/faro/notices/     third-party licences: third-party.txt (the Rust
#                                crates) and third-party-web.txt (the web app's
#                                npm packages)
#   /data                        data directory (identity key, SQLite DB, blobs,
#                                ACME certificates): mount a volume here
#   port 8080                    the listen port inside the container, plain
#                                HTTP or, with FARO_TLS_ACME_DOMAIN set, HTTPS
#
# Prebuilt amd64 + arm64 images are published to ghcr.io/faro-project/faro-server
# by .github/workflows/container.yml. See docs/SELF-HOSTING.md.

# Web app: plain static files, the same on every platform, so it is built
# once on the build machine's own platform rather than under emulation.
FROM --platform=$BUILDPLATFORM node:24-trixie-slim AS web

WORKDIR /web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN --mount=type=cache,target=/root/.npm,sharing=locked npm ci
COPY web/ ./
# The logo files, which the web app imports from ../assets/brand, and the
# licence allowlist its third-party notices are checked against.
COPY assets/brand/ /assets/brand/
COPY deny.toml /deny.toml
RUN npm run build

# Third-party notices for faro-server's Rust crates, from Cargo.lock
# (release/notices/third-party.sh). The same for every platform, so made
# once on the build machine's own, like the web app.
FROM --platform=$BUILDPLATFORM rust:1.99.1-slim-trixie AS notices

WORKDIR /src
COPY release/notices/third-party.sh /tmp/third-party.sh
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked cargo-about --features cli \
        --version "$(/tmp/third-party.sh --cargo-about-version)"
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    release/notices/third-party.sh server /out/notices/third-party.txt

# Builder: Rust 1.99.1 on Debian 13 (trixie). The workspace needs Rust >= 1.94.
# The runtime stage below must use the same Debian release, because the
# binary links against that release's glibc.
FROM rust:1.99.1-slim-trixie AS builder

WORKDIR /src
COPY . .
COPY --from=web /web/build web/build

# Only a C compiler is needed beyond Rust (for ring and the bundled SQLite);
# the slim Rust image already ships gcc and libc6-dev. TLS is rustls with
# compiled-in root certificates, so there is no OpenSSL dependency.
#
# The registry cache only holds downloaded crate sources, which are the same
# on every platform, so sharing it between amd64 and arm64 builds is safe.
# The target directory is deliberately *not* a cache mount: it is
# per-platform and the build must produce a binary in this layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    FARO_REQUIRE_WEB=1 cargo build --release --locked -p faro-server --bin faro-server \
 && install -m 0755 target/release/faro-server /usr/local/bin/faro-server \
 && /usr/local/bin/faro-server version

# The project's update root of trust (docs/KEY-CEREMONY.md, "Shipping root
# 1"), for FARO_UPDATES_ROOT=/usr/share/faro/update-root.json. Until the key
# ceremony has committed release/update-root.json there is none, and the
# directory stays empty.
RUN mkdir -p /out/share/faro \
 && if [ -f release/update-root.json ]; then \
        install -m 0644 release/update-root.json /out/share/faro/update-root.json; \
    fi

# Runtime: Debian 13 slim, matching the builder's glibc. Kept to Debian
# rather than distroless so `docker compose exec faro faro-server backup`,
# restore with tar, and the bash health check all work in the container.
FROM debian:trixie-slim

# faro-server itself verifies TLS (SMTP, Postgres, ACME) against root
# certificates compiled into the binary; the OS store is installed for any
# tool an operator runs inside the container.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# A fixed, unprivileged UID/GID so a bind-mounted backup directory can be
# chowned to it on the host (`chown 10001:10001 backups`).
RUN groupadd --system --gid 10001 faro \
 && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home \
        --shell /usr/sbin/nologin faro \
 && mkdir -p /data /backups \
 && chown 10001:10001 /data /backups \
 && chmod 0700 /data

COPY --from=builder /usr/local/bin/faro-server /usr/local/bin/faro-server
COPY --from=builder /out/share/faro/ /usr/share/faro/
# Licences of the software in the image: the Rust crates in faro-server and
# the npm packages in the web app it serves (also at /licenses).
COPY --from=notices /out/notices/third-party.txt /usr/share/faro/notices/third-party.txt
COPY --from=web /web/build/third-party-licenses.txt /usr/share/faro/notices/third-party-web.txt
COPY --chmod=0755 deploy/healthcheck.sh /usr/local/bin/faro-healthcheck

# Defaults for the container. Everything else (public URL, TLS mode, SMTP)
# comes from FARO_* variables, see deploy/faro.env.example.
ENV FARO_DATA_DIR=/data \
    FARO_LISTEN=0.0.0.0:8080

# Docker copies /data's ownership (10001, mode 0700) into a new named volume.
VOLUME ["/data"]
WORKDIR /data
USER 10001:10001
EXPOSE 8080

# /.well-known/faro over plain HTTP; a TCP check when TLS is built in
# (see deploy/healthcheck.sh).
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/faro-healthcheck"]

# faro-server drains requests and stops its workers on SIGTERM; give it
# longer than Docker's 10 s default with `stop_grace_period` (compose) or
# `docker stop -t 30`.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/faro-server"]
CMD ["serve"]
