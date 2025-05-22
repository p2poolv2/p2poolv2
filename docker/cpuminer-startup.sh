#!/bin/bash

HOST=bitcoind
MINERD=/cpuminer/minerd
TARGET_HEIGHT=32 # We need to wait for the height to reach 16 to get past the ckpool ser_num issue, but we overshoot to 32 for extra safety

# Default to signet if no network is specified
NETWORK=${1:-signet}

# Set ports based on network
if [ "$NETWORK" = "signet" ]; then
  BTC_P2P_PORT=38333
  BTC_RPC_PORT=38332
  ADDR="tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk"
elif [ "$NETWORK" = "testnet4" ]; then
  BTC_P2P_PORT=48333
  BTC_RPC_PORT=48332
  ADDR="tb1q0afww6y0kgl4tyjjyv6xlttvfwdfqxvrfzz35f"
else
  echo "Unsupported network: $NETWORK. Use 'signet' or 'testnet4'."
  exit 1
fi

# Wait for bitcoind to be ready
echo "Waiting for bitcoind..."
while ! nc -z $HOST $BTC_RPC_PORT; do
  sleep 1
done
echo "Bitcoind is up"


# Query bitcoin height
height=$(curl -s --user p2pool:p2pool --data-binary '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' http://$HOST:$BTC_RPC_PORT | grep -o '"result":[0-9]*' | cut -d':' -f2)

echo "Current block height: $height"

if [ "$height" -lt $TARGET_HEIGHT ]; then
    echo "Height below $TARGET_HEIGHT, using direct mining without stratum"
    $MINERD --algo=sha256d --url=http://p2pool:p2pool@$HOST:$BTC_RPC_PORT --userpass=p2pool:p2pool --coinbase-addr=$ADDR --no-stratum --background &
    # Wait for height to reach 16
    while [ "$height" -lt $TARGET_HEIGHT ]; do
        height=$(curl -s --user p2pool:p2pool --data-binary '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' http://$HOST:$BTC_RPC_PORT | grep -o '"result":[0-9]*' | cut -d':' -f2)
        echo "Current block height: $height"
    done
    # Kill cpuminer when done
    killall minerd
fi

echo "Height reached: $height"

# Start minerd
exec /cpuminer/minerd --algo=sha256d --url=stratum+tcp://ckpool:3333 --user=$ADDR --pass=x --debug
