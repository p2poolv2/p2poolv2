# Mock Bitcoind JSON-RPC Server

This is a mock Bitcoin JSON-RPC 1.0 server for load testing, implemented with Node.js and the `jayson` package.

## Setup

```bash
cd load-tests/mock-bitcoind
npm install
npm start
```

The server listens on port 48332 by default.

## Testing with curl

### 1. hello
```
curl -s --user user:pass --data-binary '{"method":"hello","params":[],"id":1}' -H 'content-type:text/plain;' http://127.0.0.1:48332/
```

### 2. getblocktemplate
```
curl -s --user user:pass --data-binary '{"method":"getblocktemplate","params": [],"id":2}' -H 'content-type:text/plain;' http://127.0.0.1:48332/
```

### 3. submitblock
```
curl -s --user user:pass --data-binary '{"method":"submitblock","params":["blockhex"],"id":3}' -H 'content-type:text/plain;' http://127.0.0.1:48332/
```

Authentication fields are ignored by the mock server.
