# mtuspy Makefile

.PHONY: all build release debug run clean check fmt lint test help

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
	@echo "  make clean        Clean all build artifacts"
