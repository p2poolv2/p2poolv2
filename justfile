set unstable := true

dev_config := "." / "config-dev.toml"
default_config := "." / "config.toml"
target_config := if path_exists(dev_config) == "true" { dev_config } else { default_config }
export P2POOL_CONFIG := env("P2POOL_CONFIG", target_config)

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
[group("docker")]
dockerize:
    docker build -t p2poolv2 -f ./docker/Dockerfile.p2pool .

# Run using the docker image
[group("docker")]
docker-run EXTRA="": dockerize
    docker run \
        --rm \
        -it \
        -v $PWD/docker/data:/p2poolv2/data \
        -v $PWD/docker/config/:/p2poolv2/config \
        -v $P2POOL_CONFIG/:/p2poolv2/config.toml:ro \
        -e P2POOL_CONFIG=/p2poolv2/config.toml \
        --add-host=host.docker.internal:host-gateway \
        {{ EXTRA }} \
        p2poolv2

# Explore the container image
[group("docker")]
docker-explore: (docker-run "--entrypoint bash")

# Starts a service specified in docker container
[group("docker")]
[working-directory("docker")]
compose *services="all":
    docker compose --env-file .env up -d --build --force-recreate {{ if services == "all" { "" } else { services } }}

[group("docker")]
[working-directory("docker")]
compose-explore service="p2pool" index="0":
    docker compose exec --index {{ index }} {{ service }} bash

# For log level use RUST_LOG=<<level>> just run
run config=target_config:
    cargo run -p p2poolv2_node -- --config={{ config }}

# Run cargo flamegraph for detecting bottlenecks

# You will need perf installed as well as flamegraph installed
perf config="config.toml":
    CARGO_PROFILE_RELEASE_DEBUG=true CARGO_PROFILE_RELEASE_STRIP=false RUSTFLAGS="-C force-frame-pointers=yes" cargo flamegraph --no-buildid-cache -p p2poolv2_node -- --config={{ config }}

alias dash := dashboard

# Run prometheus and grafana
[group("docker")]
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

# Builds and opens local docs for all deps
doc:
    cargo doc --open --all
