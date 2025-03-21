FROM mcr.microsoft.com/devcontainers/rust:1-bullseye

# Install additional packages
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    libssl-dev \
    pkg-config \
    build-essential \
    libclang-dev \
    clang \
    lldb \
    lld \
    librocksdb-dev \
    libzmq3-dev \
    libpq-dev \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Install Rust stable and necessary components
USER vscode
RUN rustup component add rustfmt clippy rust-src

# Create project directories
RUN mkdir -p /home/vscode/workspace
WORKDIR /home/vscode/workspace

# Set rust-related environment variables
ENV RUST_BACKTRACE=1
