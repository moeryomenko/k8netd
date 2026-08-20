# CI gate for the k8netd workspace. Mirrors the cluster-api-hypervisor
# `make check` convention (lint + test) for the Rust toolchain.

.PHONY: check fmt-check clippy test help

check: fmt-check clippy test ## Run fmt, clippy, and test (CI gate)

fmt-check: ## Verify formatting (cargo fmt --check)
	cargo fmt --check

clippy: ## Lint with clippy, deny warnings
	cargo clippy -- -D warnings

test: ## Run the test suite
	cargo test

help: ## Print this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-12s %s\n", $$1, $$2}'