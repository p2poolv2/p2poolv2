#!/bin/ash
set -e

NETWORK=${NETWORK:-signet}
TARGET_HEIGHT=${TARGET_HEIGHT:-32}
RPC_HOST=${RPC_HOST:-bitcoind}

case "$NETWORK" in
  signet)
    RPC_PORT=38332
    ADDR="tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk"
    ;;
  testnet4)
    RPC_PORT=48332
    ADDR="tb1q0afww6y0kgl4tyjjyv6xlttvfwdfqxvrfzz35f"
    ;;
  *)
    echo "Unsupported network: $NETWORK"
    exit 1
    ;;
esac

CLI="bitcoin-cli -rpcconnect=$RPC_HOST -rpcport=$RPC_PORT -rpcuser=p2pool -rpcpassword=p2pool"

echo "Waiting for bitcoind RPC at $RPC_HOST:$RPC_PORT..."
until $CLI getblockcount > /dev/null 2>&1; do
  sleep 2
done
echo "Bitcoind RPC is ready"

HEIGHT=$($CLI getblockcount)
echo "Current block height: $HEIGHT"

if [ "$HEIGHT" -ge "$TARGET_HEIGHT" ]; then
  echo "Already at height $HEIGHT >= $TARGET_HEIGHT. Nothing to do."
  exit 0
fi

BLOCKS_NEEDED=$((TARGET_HEIGHT - HEIGHT))
echo "Mining $BLOCKS_NEEDED blocks to reach height $TARGET_HEIGHT..."

PYTHONPATH=/usr/local/lib/python3 python3 /usr/local/bin/signet-miner generate \
  --cli "$CLI" \
  --grind-cmd "bitcoin-util grind" \
  --address "$ADDR" \
  --max-blocks "$BLOCKS_NEEDED" \
  --min-nbits

HEIGHT=$($CLI getblockcount)
echo "Bootstrap complete. Block height: $HEIGHT"
