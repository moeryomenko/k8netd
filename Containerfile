# k8netd runtime image (plan: podman-quadlet-for-k8netd, D4/D5).
#
# Three stages:
#   1. build  — Rust toolchain pinned to the workspace channel
#               (rust-toolchain.toml), builds the k8netd release binary.
#   2. passt  — Debian suite that matches the distroless flavor below, so
#               passt's glibc symbol requirements agree with the runtime
#               exactly (grill decision D5).
#   3. run    — distroless/cc: glibc runtime, no shell, no package manager.
#
# Suite pairing: debian:trixie builder -> gcr.io/distroless/cc-debian13.
# If the distroless tag is unavailable at build time, fall back one suite on
# BOTH sides (debian:bookworm + cc-debian12); never mix suites.

# --- stage 1: build k8netd ---------------------------------------------------
FROM docker.io/library/rust:1.97.1 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --release --workspace

# --- stage 2: passt from the matching Debian suite ---------------------------
FROM docker.io/library/debian:trixie AS passt
RUN apt-get update \
    && apt-get install -y --no-install-recommends passt netbase \
    && rm -rf /var/lib/apt/lists/*
# passt reads /etc/ethertypes and /etc/services opportunistically; distroless
# ships neither, so carry them over rather than rely on graceful fallbacks.
COPY --from=build /etc/services /etc/services

# --- stage 3: distroless runtime ---------------------------------------------
FROM gcr.io/distroless/cc-debian13
COPY --from=build /src/target/release/k8netd /k8netd
COPY --from=passt /usr/bin/passt /usr/bin/passt
COPY --from=passt /etc/ethertypes /etc/ethertypes
COPY --from=passt /etc/services /etc/services
# Rootless podman maps the host user (1000) to container root, so files the
# daemon creates in the mounted /run/user/1000/k8snet appear owned by the
# host user — no USER directive needed (grill decision D2/D6).
ENTRYPOINT ["/k8netd"]
