# VERSIONS.md — pinned versions (single source of truth)

Bump all rows together when refreshing the image or toolchain. The
`Containerfile` and `deploy/k8netd.container` must stay in sync with this
table.

| Component | Pin | Used by | Source |
|---|---|---|---|
| Rust toolchain | 1.97.1 (stable) | workspace build + CI gate | `rust-toolchain.toml` |
| Rust builder image | `docker.io/library/rust:1.97.1` | `Containerfile` stage 1 | `Containerfile` |
| Debian builder suite | `debian:trixie` (passt stage) | `Containerfile` stage 2 | `Containerfile` |
| passt | Debian trixie archive version (`apt-get install passt`) | runtime WAN subprocesses | `Containerfile` stage 2 |
| Runtime base | `gcr.io/distroless/cc-debian13` | `Containerfile` stage 3 | `Containerfile` |
| Image tag | `localhost/k8netd:dev` | quadlet unit | `Makefile`, `deploy/k8netd.container` |

Suite-pairing rule: the Debian builder suite and the distroless flavor must
match (`trixie` <-> `cc-debian13`). If a tag is unavailable, move BOTH sides
one suite together — never mix.
