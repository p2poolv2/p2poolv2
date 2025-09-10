# Set default log level if not provided through environment
export LOG_LEVEL := env_var_or_default("RUST_LOG", "info")

default: test

# Run tests for entire workspace or a specific package
# Usage: just test [package]
test package="":
	#!/usr/bin/env sh
	if [ -z "{{package}}" ]; then
		RUST_LOG={{LOG_LEVEL}} cargo nextest run --workspace
	else
		RUST_LOG={{LOG_LEVEL}} cargo nextest run -p {{package}}
	fi

debug-test package="" testname="":
	#!/usr/bin/env sh
	RUST_LOG=debug cargo test -p {{package}} {{testname}} -- --no-capture

cov:
	cargo llvm-cov --lcov

cov-html:
	cargo llvm-cov --html

cov-open:
	cargo llvm-cov --open

# Build entire workspace or a specific package
# Usage: just build [package]
build package="":
	#!/usr/bin/env sh
	if [ -z "{{package}}" ]; then
		cargo build --workspace
	else
		cargo build -p {{package}}
	fi

build-release:
	cargo build --workspace --release

# For log level use RUST_LOG=<<level>> just run
run config="config.toml":
	RUST_LOG={{LOG_LEVEL}} cargo run -p p2poolv2_node -- --config={{config}}

check:
	cargo check --workspace

# Run cli commands using p2poolv2-cli
# examples
# just cli --store-path ./store.db info
cli *args:
	cargo run -p p2poolv2_cli -- {{args}}

fmt:
	cargo fmt --all