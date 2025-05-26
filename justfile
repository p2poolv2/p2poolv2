# Set default log level if not provided through environment
export LOG_LEVEL := env_var_or_default("RUST_LOG", "info")

default: test

test:
	RUST_LOG={{LOG_LEVEL}} cargo nextest run --workspace

cov:
	cargo llvm-cov --lcov

cov-html:
	cargo llvm-cov --html

cov-open:
	cargo llvm-cov --open

build:
	cargo build --workspace

build-release:
	cargo build --release --workspace

# For log level use RUST_LOG=<<level>> just run
run config="config.toml":
	RUST_LOG={{LOG_LEVEL}} cargo run -p p2poolv2 -- --config={{config}}

check:
	cargo check

# Run cli commands using p2poolv2-cli
# examples
# just cli --store-path ./store.db info
cli *args:
	cargo run -p p2poolv2_cli -- {{args}}