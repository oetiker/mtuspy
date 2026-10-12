# mtuspy Makefile

# The man page, built from docs/manual.md by build/man.mk (owned by repo-infra).
# man/ is gitignored: the page is a build artifact.
MAN_NAME = mtuspy
include build/man.mk

.PHONY: all build release debug run clean check fmt lint test help demo

# Default target
all: help

# =============================================================================
# Software Build
# =============================================================================

# Build release binary (runs fmt and clippy first)
release: fmt lint
	cargo build --release

# Build debug binary (runs fmt and clippy first)
debug: fmt lint
	cargo build

# Alias for debug build
build: debug

# Run with a test target (debug mode)
run: fmt lint
	cargo run -- $(ARGS)

# Format code
fmt:
	cargo fmt

# Run clippy linter
lint:
	cargo clippy -- -D warnings

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# =============================================================================
# Development Helpers
# =============================================================================

# Check everything before commit
check: fmt lint test
	@echo "All checks passed!"

# The README demo, docs/demo/mtuspy.webp, recorded by ansidrama from
# demo/mtuspy.toml. cargo metadata names the target directory, because
# CARGO_TARGET_DIR may move it out of the checkout.
demo:
	cargo build --release
	cd demo && PATH="$$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)/release:$$PATH" ansidrama record mtuspy.toml

# =============================================================================
# Help
# =============================================================================

help:
	@echo "mtuspy Makefile"
	@echo ""
	@echo "Build:"
	@echo "  make build        Build debug binary (runs fmt + clippy)"
	@echo "  make release      Build release binary (runs fmt + clippy)"
	@echo "  make run ARGS=..  Run with arguments (e.g. make run ARGS='example.com')"
	@echo "  make fmt          Format code"
	@echo "  make lint         Run clippy"
	@echo "  make test         Run tests"
	@echo "  make check        Format, lint, and test"
	@echo "  make man         Build the man page into man/ (needs pandoc)"
	@echo "  make demo        Record docs/demo/mtuspy.webp (needs ansidrama)"
	@echo "  make clean        Clean all build artifacts"
