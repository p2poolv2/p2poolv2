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

# Sets up the development environment with all needed files
@setup-dev:
    #!/usr/bin/env sh
    set -euo pipefail

    [ -f docker/.env ] || cp -v docker/.env.sample docker/.env
    [ -f config-dev.toml ] || cp -v config.toml config-dev.toml

    echo 'Edit the ./config-dev.toml file for your specific needs'
    echo 'You can easily run a local cluster with `just compose`'

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
    RUSTFLAGS='-C target-cpu=native' cargo build --workspace --release

run-release config=target_config:
    cargo run --release --package p2poolv2_node -- --config={{ config }}

# For log level use RUST_LOG=<<level>> just run
run config=target_config:
    cargo run --package p2poolv2_node -- --config={{ config }}

# Run cargo flamegraph for detecting bottlenecks

# You will need perf installed as well as flamegraph installed
perf config="config.toml":
    CARGO_PROFILE_RELEASE_DEBUG=true CARGO_PROFILE_RELEASE_STRIP=false RUSTFLAGS="-C force-frame-pointers=yes" cargo flamegraph --no-buildid-cache -p p2poolv2_node -- --config={{ config }}

# Check the entire workspace
check:
    cargo check --workspace

# Run cli commands using p2poolv2-cli - e.g. just cli info
cli *args:
    cargo run -p p2poolv2_node --bin p2poolv2_cli -- {{ args }}

# Format source code
fmt:
    cargo fmt --all
    just --fmt --unstable

# Run benchmarks for a package and bench target
bench package="p2poolv2_lib" name="pplns_window":
    cargo bench --package {{ package }} --bench {{ name }} --features test-utils

# Run benchmarks with symbols for profiling
bench-profile package="p2poolv2_lib" name="pplns_window":
    CARGO_PROFILE_BENCH_STRIP=none cargo bench --package {{ package }} --bench {{ name }} --features test-utils

# Generate flamegraph for a specific benchmark function
bench-flamegraph package="p2poolv2_lib" name="pplns_window" function="get_address_difficulty_map_full_window":
    CARGO_PROFILE_BENCH_STRIP=none cargo flamegraph -o flamegraph_{{ function }}.svg --bench {{ name }} --features test-utils -p {{ package }} -- --bench "{{ function }}" --profile-time 5

# Verify chain integrity in a store.db
verify_chain db_path:
    cargo run --bin verify_chain --features debug-tools -- {{ db_path }}

# fix common warnings
fix:
    cargo fix

# Builds and opens local docs for all deps
doc:
    cargo doc --open --all

# Creates the p2pool docker image
[group("docker")]
dockerize:
    docker build -t p2poolv2 -f ./docker/p2poolv2/Dockerfile .

# Run using the docker image
[group("docker")]
docker-run EXTRA="": dockerize
    docker run \
        --rm \
        -it \
        -v $PWD/docker/data:/p2poolv2/data \
        -v $PWD/docker/config/:/p2poolv2/config \
        -v $P2POOL_CONFIG:/p2poolv2/config.toml:ro \
        -e P2POOL_CONFIG=/p2poolv2/config.toml \
        --add-host=host.docker.internal:host-gateway \
        {{ EXTRA }} \
        p2poolv2

# Explore the container image
[group("docker")]
container-explore: (docker-run "--entrypoint bash")

# Starts a service specified in docker container
[group("docker")]
[working-directory("docker")]
compose *services="all":
    P2POOL_CONFIG={{ target_config }} docker compose --env-file .env up -d --build --force-recreate {{ if services == "all" { "" } else { services } }}

# Start a shell in a docker compose service
[group("docker")]
[working-directory("docker")]
compose-shell service="p2poolv2" index="0" program="bash":
    docker compose exec --index {{ index }} {{ service }} {{ program }}

alias dash := dashboard

# Run prometheus and grafana
[group("docker")]
[working-directory('docker')]
dashboard:
    docker compose -f docker-compose.metrics.yml up -d --force-recreate --build
