#!/bin/bash

set -euxo pipefail

BTC_RPC_HOST=${BTC_RPC_HOST:-${HOST:-bitcoind}}
BTC_RPC_USER=${BTC_RPC_USER:-p2pool}
BTC_RPC_PASSWORD=${BTC_RPC_PASSWORD:-p2pool}
BTC_NETWORK=${1:-${BTC_NETWORK:-signet}}
P2POOL_STRATUM_HOST=${P2POOL_STRATUM_HOST:-p2pool}
P2POOL_STRATUM_PORT=${P2POOL_STRATUM_PORT:-3333}

MINERD=/cpuminer/minerd
TARGET_HEIGHT=${TARGET_HEIGHT:-32} # We need to wait for the height to reach 16 to get past the ckpool ser_num issue, but we overshoot to 32 for extra safety

trap cleanup EXIT
trap cleanup INT

function cleanup() {
  echo "Cleaning up..."
  killall -9 $MINERD
  exit 0
}

# Set ports based on network
if [ "$BTC_NETWORK" = "signet" ]; then
  BTC_P2P_PORT=${BTC_P2P_PORT:-38333}
  BTC_RPC_PORT=${BTC_RPC_PORT:-38332}
  ADDR=${ADDR:-tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk}
elif [ "$BTC_NETWORK" = "testnet4" ]; then
  BTC_P2P_PORT=${BTC_P2P_PORT:-48333}
  BTC_RPC_PORT=${BTC_RPC_PORT:-48332}
  ADDR=${ADDR:-tb1q0afww6y0kgl4tyjjyv6xlttvfwdfqxvrfzz35f}
else
  echo "Unsupported network: $BTC_NETWORK. Use 'signet' or 'testnet4'."
  exit 1
fi

# Wait for bitcoind to be ready
echo "Waiting for bitcoind..."
while ! nc -z $BTC_RPC_HOST $BTC_RPC_PORT; do
  sleep 1
done
echo "Bitcoind is up"


function getheight() {
  curl -s --user "$BTC_RPC_USER:$BTC_RPC_PASSWORD" --data-binary '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' http://$BTC_RPC_HOST:$BTC_RPC_PORT | grep -o '"result":[0-9]*' | cut -d':' -f2
}

# Query bitcoin height
height=$(getheight)

echo "Current block height: $height"

if [ "$height" -lt $TARGET_HEIGHT ]; then
    echo "Height below $TARGET_HEIGHT, using direct mining without stratum"
    $MINERD --algo=sha256d \
        --url=http://${BTC_RPC_HOST}:${BTC_RPC_PORT} \
        --userpass="${BTC_RPC_USER}:${BTC_RPC_PASSWORD}" \
        --coinbase-addr=$ADDR \
        --no-stratum \
        --protocol-dump \
        --background &
    # Wait for height to reach 16
    while [ "$height" -lt $TARGET_HEIGHT ]; do
        height=$(getheight)
        echo "Current block height: $height"
    done
    echo "Height reached: $height"
    cleanup
fi

# Start minerd
exec $MINERD \
    --algo=sha256d \
    --url=stratum+tcp://$P2POOL_STRATUM_HOST:$P2POOL_STRATUM_PORT \
    --user=$ADDR \
    --pass=x \
    --debug \
    --protocol-dump \
    --retry-pause=10 \
    --retries=100 \
    --threads 1
