#!/bin/bash

# Display help message if --help flag is provided
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
  echo "Usage: $0 [network] [docker-compose options]"
  echo ""
  echo "Options:"
  echo "  network             The Bitcoin network to use (signet or testnet4). Default: signet"
  echo "  docker-compose options  Any additional options to pass to docker-compose"
  echo ""
  echo "Examples:"
  echo "  $0                  Run on signet network"
  echo "  $0 testnet4         Run on testnet4 network"
  echo "  $0 signet bitcoind  Run bitcoind on signet network volume"
  exit 0
fi


# Default to signet if no network is specified
NETWORK=${1:-signet}

# Set ports based on network
if [ "$NETWORK" = "signet" ]; then
  BTC_P2P_PORT=38333
  BTC_RPC_PORT=38332
  BTC_ZMQ_PORT=28332
elif [ "$NETWORK" = "testnet4" ]; then
  BTC_P2P_PORT=48333
  BTC_RPC_PORT=48332
  BTC_ZMQ_PORT=28332 # Note: ZMQ port is the same for both networks
else
  echo "Unsupported network: $NETWORK. Use 'signet' or 'testnet4'."
  exit 1
fi

# Export variables for docker-compose
export NETWORK=$NETWORK
export BTC_P2P_PORT=$BTC_P2P_PORT
export BTC_RPC_PORT=$BTC_RPC_PORT
export BTC_ZMQ_PORT=$BTC_ZMQ_PORT

# Remove the first argument (network) to pass remaining args to docker-compose
shift

# Start network interfaces, so we can services one by one and let them connect to each other
docker compose up --no-start

# Stop all earlier instances to avoid conflicting services
# docker compose down "$@"

# Run docker-compose with the specified configuration
docker compose up "$@" --remove-orphans
