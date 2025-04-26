# Set default log level if not provided through environment
export LOG_LEVEL := env_var_or_default("RUST_LOG", "info")

default: test

test:
	RUST_LOG={{LOG_LEVEL}} cargo nextest run

build:
	cargo build

# For log level use RUST_LOG=<<level>> just run
run config="config.toml":
	RUST_LOG={{LOG_LEVEL}} cargo run -- --config={{config}}

check:
	cargo check

# Run cli commands using p2poolv2-cli
# examples
# just cli --store-path ./store.db info
cli *args:
	cargo run --bin p2poolv2_cli -- {{args}}