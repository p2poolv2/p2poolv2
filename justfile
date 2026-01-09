set unstable := true

export P2POOL_CONFIG := env("P2POOL_CONFIG", "." / "config.toml")

# Set default log level if not provided through environment

export LOG_LEVEL := env("RUST_LOG", "info")
export RUST_BACKTRACE := env("RUST_BACKTRACE", "1")

_default:
    @{{ just_executable() }} --list

# Run tests for entire workspace or a specific package
test package="":
    cargo nextest run {{ if package == "" { "" } else { "-p " + package } }}

# Run a specific test in a package with debug logging and no output capture
debug-test package="p2poolv2_tests" testname="":
    RUST_LOG=debug cargo test --package {{ package }} -- {{ testname }} --show-output --no-capture

# Generates coverage report
cov:
    cargo llvm-cov --lcov

# Generates HTML coverage report
cov-html:
    cargo llvm-cov --html

# Opens the generated coverage report in the browser
cov-open:
    cargo llvm-cov --open

# Build entire workspace or a specific package
build package="":
    #!/usr/bin/env sh
    if [ -z "{{ package }}" ]; then
    	cargo build --workspace
    else
    	cargo build -p {{ package }}
    fi

# Build a release version of all packages and binaries in the workspace
build-release:
    cargo build --workspace --release

# Creates the p2pool docker image
dockerize:
    docker build -t p2poolv2 -f ./docker/Dockerfile.p2pool .

# Run using the docker image
docker-run EXTRA="": dockerize
    docker run \
        --rm \
        -it \
        -v $PWD/docker/data:/p2poolv2/data \
        -v $PWD/docker/config/:/p2poolv2/config \
        --add-host=host.docker.internal:host-gateway \
        {{ EXTRA }} \
        p2poolv2

# Explore the container image
docker-explore: (docker-run "--entrypoint bash")

# For log level use RUST_LOG=<<level>> just run
run config="config.toml":
	cargo run -p p2poolv2_node -- --config={{ config }}

alias dash := dashboard

# Run prometheus and grafana
[working-directory('docker')]
dashboard:
    docker compose -f prometheus-docker-compose.yml up -d --force-recreate --build

# Check the entire workspace
check:
    cargo check --workspace

# Run cli commands using p2poolv2-cli - e.g. just cli info
cli *args:
    cargo run -p p2poolv2_cli -- {{ args }}

# Format source code
fmt:
    cargo fmt --all
    just --fmt --unstable

# fix common warnings
fix:
    cargo fix
