# P2Pool v2 API Server

A REST API server for P2Pool v2 that provides access to mining pool data including shares, block templates, and PPLNS distribution.

## Features

- **Shares API**: Get shares by timestamp range with optional filtering
- **Block Template API**: Get current block template information
- **PPLNS Distribution API**: Get current PPLNS distribution calculations
- **Health Check**: Basic health monitoring endpoint

## Endpoints

### Health Check
- **GET** `/health` - Returns server health status

### Shares
- **GET** `/api/shares` - Get shares with optional query parameters:
  - `limit` (optional): Maximum number of shares to return (default: 100)
  - `start_time` (optional): Start timestamp in seconds (Unix timestamp)
  - `end_time` (optional): End timestamp in seconds (Unix timestamp)

### Block Template
- **GET** `/api/block-template` - Get current block template information

### PPLNS Distribution
- **GET** `/api/pplns-distribution` - Get current PPLNS distribution calculations

## Usage

### Standalone API Server

```bash
# Run the API server standalone
cargo run -p p2poolv2_api -- --config config.toml --port 8080
```

### Integration with Main Node

The API server can be integrated with the main P2Pool node to share the same data store and block template updates.

```rust
use p2poolv2_lib::api::ApiServer;
use p2poolv2_lib::config::StratumConfig;
use std::sync::Arc;

// Create API server
let api_server = ApiServer::new(chain_store, stratum_config, 8080);

// Update block template when new templates arrive
api_server.update_template(new_template).await;

// Start the API server
tokio::spawn(async move {
    if let Err(e) = api_server.start().await {
        tracing::error!("API server failed: {}", e);
    }
});
```

## Configuration

The API server uses the same configuration file as the main P2Pool node. Make sure to specify the correct store path and stratum configuration.

## Example Responses

### Shares Response
```json
[
  {
    "difficulty": 100,
    "btcaddress": "tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk",
    "workername": "worker1",
    "timestamp": 1640995200,
    "formatted_time": "2022-01-01 00:00:00 UTC"
  }
]
```

### Block Template Response
```json
{
  "version": 536870912,
  "rules": ["segwit"],
  "previousblockhash": "0000000000000000000000000000000000000000000000000000000000000000",
  "transactions": [],
  "coinbasevalue": 5000000000,
  "target": "0000000000000000000000000000000000000000000000000000000000000000",
  "height": 1,
  "bits": "1d00ffff"
}
```

### PPLNS Distribution Response
```json
{
  "total_difficulty": 1000.0,
  "total_amount_sat": 5000000000,
  "distribution": [
    {
      "address": "tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk",
      "amount_sat": 5000000000,
      "percentage": 100.0
    }
  ],
  "timestamp": 1640995200
}
```