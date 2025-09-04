# P2Pool v2 Atomic Swap

P2Pool v2 Atomic Swap is a Lightning Network node implementation that enables atomic swaps between on-chain Bitcoin and Lightning Network payments. It uses LDK (Lightning Development Kit) for Lightning Network functionality and provides a command-line interface for managing channels, payments, and atomic swaps.

## Features

- **Lightning Network Operations**: Create channels, send/receive payments, manage invoices
- **Atomic Swaps**: On-chain to Lightning Network atomic swaps with HTLC support
- **Hold Invoices**: Support for hold invoices and payment preimage management
- **Database Management**: Store and retrieve swap information using RocksDB
- **Multi-Network Support**: Bitcoin mainnet, testnet, testnet4, signet, and regtest

## Prerequisites

- Rust 1.83 or later
- Bitcoin node or Esplora API access
- Network connectivity for Lightning Network operations

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd p2pool-v2/p2poolv2_atomic_swap
```

2. Build the project:
```bash
cargo build --release
```

3. Run the application:
```bash
cargo run
```

## Configuration

The application uses a `config.toml` file for configuration. Create or modify the config file in the project root:

### Configuration File Structure

```toml
# Node Configuration
[node]
# Directory where LDK and BDK store their data
storage_dir_path = "data/ldk_node"

# Bitcoin network: Bitcoin, Testnet, Testnet4, Signet, Regtest
network = "Signet"

# Lightning Network listening address (IP:PORT)
listening_addresses = "127.0.0.1:9735"

# Node alias for network announcements (max 32 bytes UTF-8)
node_alias = "p2pool_mm_node"

# Esplora API URL for blockchain data
esplora_url = "https://mutinynet.com/api/"

# Rapid Gossip Sync server URL
rgs_server_url = "https://mutinynet.ltbl.io/snapshot"

# HTLC Configuration
[htlc]
# Database path for storing swap information
db_path = "data/htlc_db"

# Private key for HTLC operations (hex format)
private_key = "c929c768be0902d5bb7ae6e38bdc6b3b24cefbe93650da91975756a09e408460"

# RPC URL for HTLC blockchain operations
rpc_url = "https://mutinynet.com/api/"

# Bitcoin network for HTLC operations
bitcoin_network = "signet"

# Number of confirmations required for HTLC transactions
confirmation_threshold = 3

# Minimum buffer blocks before allowing refund
min_buffer_block_for_refund = 2
```

### Configuration Parameters

#### Node Section
- **storage_dir_path**: Directory where the Lightning node stores its data
- **network**: Bitcoin network to operate on (Bitcoin, Testnet, Testnet4, Signet, Regtest)
- **listening_addresses**: IP address and port for Lightning Network connections
- **node_alias**: Human-readable name for your node (appears in network announcements)
- **esplora_url**: Blockchain API endpoint for transaction data
- **rgs_server_url**: Rapid Gossip Sync server for network topology updates

#### HTLC Section
- **db_path**: Directory for storing atomic swap database
- **private_key**: Hexadecimal private key for HTLC operations (keep secure!)
- **rpc_url**: Blockchain RPC endpoint for HTLC operations
- **bitcoin_network**: Network identifier for Bitcoin operations
- **confirmation_threshold**: Required confirmations for transactions
- **min_buffer_block_for_refund**: Safety buffer for refund operations

## Data Directory Structure

The application creates the following directories:
```
data/
├── ldk_node/          # Lightning node data (channels, payments, etc.)
├── htlc_db/          # Atomic swap database
└── test/             # Test data (if applicable)
```

## CLI Commands

Once running, the application provides an interactive CLI with the following commands:

### Lightning Network Operations

- **`balance`** - Display on-chain and Lightning channel balances
- **`getaddress`** - Generate a new on-chain Bitcoin address
- **`onchaintransfer <address> <sats>`** - Send Bitcoin to an on-chain address
- **`onchaintransferall <address>`** - Send all on-chain funds to an address

### Channel Management

- **`openchannel <node_id> <address> <sats>`** - Open a Lightning channel
- **`listallchannels`** - List all open channels
- **`closechannel <channel_id> <node_id>`** - Close a channel cooperatively
- **`forceclosechannel <channel_id> <node_id> <reason>`** - Force-close a channel

### Payment Operations

- **`getinvoice <amount>`** - Generate a BOLT11 invoice (amount in sats)
- **`payinvoice <invoice>`** - Pay a BOLT11 invoice
- **`paymentid_status <payment_id>`** - Check payment status by ID
- **`getholdinvoice <amount_sats> <payment_hash>`** - Generate a hold invoice
- **`redeeminvoice <payment_hash> <preimage> <amount_msats>`** - Redeem a hold invoice

### Atomic Swap Operations

- **`fromchainswap`** - Initiate an on-chain to Lightning atomic swap (interactive)
- **`swapdb`** - Store or read swap data from database (interactive)
- **`redeemswap`** - Redeem an atomic swap (interactive)
- **`refundswap`** - Refund an atomic swap (interactive)

### Utility Commands

- **`help`** - Display all available commands
- **`exit`** - Exit the application

## Usage Examples

### Basic Setup

1. **Start the node:**
```bash
cargo run
```

2. **Check your node's balance:**
```
Lightning Node CLI> balance
```

3. **Generate a receiving address:**
```
Lightning Node CLI> getaddress
```

### Opening a Lightning Channel

```
Lightning Node CLI> openchannel 03abc123... 127.0.0.1:9736 100000
```

### Creating an Invoice

```
Lightning Node CLI> getinvoice 10000
```

### Atomic Swap Workflow

1. **Initiate a swap:**
```
Lightning Node CLI> fromchainswap
```

2. **Follow the interactive prompts to provide:**
   - Initiator public key
   - Responder public key
   - Timelock (blocks)
   - Amount to swap (sats)
   - Expected received amount (sats)

3. **Redeem the swap when ready:**
```
Lightning Node CLI> redeemswap
```

## Security Considerations

- **Private Keys**: Keep your HTLC private key secure and never share it
- **Network**: Use testnet/signet for testing before mainnet operations
- **Backups**: Regularly backup your `data/` directory
- **Timelocks**: Ensure sufficient timelock periods for atomic swaps
- **Confirmations**: Set appropriate confirmation thresholds for your use case

## Network Configuration Examples

### Mainnet
```toml
[node]
network = "Bitcoin"
esplora_url = "https://blockstream.info/api/"
```

### Testnet
```toml
[node]
network = "Testnet"
esplora_url = "https://blockstream.info/testnet/api/"
```

### Signet (Recommended for Testing)
```toml
[node]
network = "Signet"
esplora_url = "https://mutinynet.com/api/"
```

## Troubleshooting

### Common Issues

1. **Node won't start**: Check if the listening port is available
2. **Connection failures**: Verify network connectivity and firewall settings
3. **Database errors**: Ensure write permissions for data directories
4. **Invalid addresses**: Verify network compatibility (mainnet vs testnet addresses)

### Logs

Enable debug logging by setting the environment variable:
```bash
RUST_LOG=debug cargo run
```

## Development

### Building from Source
```bash
cargo build
```

### Running Tests
```bash
cargo test
```

### Development Dependencies
See `Cargo.toml` for complete dependency list including:
- `ldk-node` - Lightning Development Kit
- `tokio` - Async runtime
- `rocksdb` - Database storage
- `serde` - Serialization

## License

This project is licensed under the GNU General Public License v3.0. See the COPYING file for details.

## Contributing

Please read the AUTHORS file for contributor information and contribution guidelines.