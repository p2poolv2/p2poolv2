#!/bin/bash

# Default to signet if no network is specified
NETWORK=${1:-signet}

# Set ports based on network
if [ "$NETWORK" = "signet" ]; then
  BTC_P2P_PORT=38333
  BTC_RPC_PORT=38332
elif [ "$NETWORK" = "testnet4" ]; then
  BTC_P2P_PORT=48333
  BTC_RPC_PORT=48332
else
  echo "Unsupported network: $NETWORK. Use 'signet' or 'testnet4'."
  exit 1
fi

# Export variables for docker-compose
export NETWORK=$NETWORK
export BTC_P2P_PORT=$BTC_P2P_PORT
export BTC_RPC_PORT=$BTC_RPC_PORT

# Remove the first argument (network) to pass remaining args to docker-compose
shift

# Stop all earlier instances to avoid conflicting services
docker compose down

# Run docker-compose with the specified configuration
docker compose up "$@"
