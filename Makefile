# CI gate for the k8netd workspace. Mirrors the cluster-api-hypervisor
# `make check` convention (lint + test) for the Rust toolchain.

.PHONY: check fmt-check clippy test image help

check: fmt-check clippy test ## Run fmt, clippy, and test (CI gate)

fmt-check: ## Verify formatting (cargo fmt --check)
	cargo fmt --check

clippy: ## Lint with clippy, deny warnings
	cargo clippy -- -D warnings

test: ## Run the test suite
	cargo test

help: ## Print this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-12s %s\n", $$1, $$2}'
IMAGE ?= localhost/k8netd:dev
# Artifact self-identification (baked via Containerfile build args): VERSION is
# the full ref name (release tag like v0.1.2, or "edge"/"dev"); REVISION is the
# commit the image was built from. CI overrides both; local builds default here.
VERSION ?= dev
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

image: ## Build the k8netd runtime image (podman)
	podman build --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) -t $(IMAGE) -f Containerfile .
