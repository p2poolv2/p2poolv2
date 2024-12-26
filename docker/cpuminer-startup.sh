#!/bin/bash

HOST=bitcoind
MINERD=/cpuminer/minerd
TARGET_HEIGHT=32 # We need to wait for the height to reach 16 to get past the ckpool ser_num issue, but we overshoot to 32 for extra safety

# Wait for bitcoind to be ready
echo "Waiting for bitcoind..."
while ! nc -z $HOST 38332; do
  sleep 1
done
echo "Bitcoind is up"

ADDR="tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d"

# Query bitcoin height
height=$(curl -s --user p2pool:p2pool --data-binary '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' http://$HOST:38332 | grep -o '"result":[0-9]*' | cut -d':' -f2)

echo "Current block height: $height"

if [ "$height" -lt $TARGET_HEIGHT ]; then
    echo "Height below $TARGET_HEIGHT, using direct mining without stratum"
    $MINERD --algo=sha256d --url=http://p2pool:p2pool@$HOST:38332 --userpass=p2pool:p2pool --coinbase-addr=$ADDR --no-stratum --background &
    # Wait for height to reach 16
    while [ "$height" -lt $TARGET_HEIGHT ]; do
        height=$(curl -s --user p2pool:p2pool --data-binary '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' http://$HOST:38332 | grep -o '"result":[0-9]*' | cut -d':' -f2)
        echo "Current block height: $height"
    done
    # Kill cpuminer when done
    killall minerd
fi

echo "Height reached: $height"

# Start minerd
exec /cpuminer/minerd --algo=sha256d --url=stratum+tcp://ckpool:3333 --user=$ADDR --pass=x --debug
