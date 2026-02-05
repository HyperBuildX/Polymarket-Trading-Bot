# Polymarket Trading Bot

> Automated momentum-based trading bot for Polymarket 15-minute BTC/ETH/Solana/XRP Up/Down markets

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## 🎯 Overview

This bot automatically trades on Polymarket's 15-minute prediction markets for BTC, ETH, Solana, and XRP. It uses a **momentum-based strategy** that buys tokens when price reaches a trigger threshold after a minimum time has elapsed, then sells at a target price or redeems at market closure.

🎥 Watch the bot in action:

[![Polymarket Trading Bot Demo](https://img.youtube.com/vi/1nF556ypGXM/0.jpg)](https://youtu.be/1nF556ypGXM?si=3d4zmY6lKVj4fVhO)


### Core Strategy

**Buy Signal**: When token price reaches `trigger_price` (e.g., $0.87) **after** `min_elapsed_minutes` (e.g., 8 minutes) have passed in the 15-minute period.

**Sell Signal**: 
- Sell at `sell_price` (e.g., $0.98) when price reaches target
- Stop-loss at `stop_loss_price` (e.g., $0.80) if price drops
- Redeem at market closure if token wins (worth $1.00) or loses (worth $0.00)

**Rationale**: If a token reaches $0.87+ after 8+ minutes, there's strong momentum suggesting it will likely reach $0.98+ or $1.00 by market close.

---

## 🏗️ Architecture

### Core Components

```
┌─────────────────┐
│  MarketMonitor  │  ← Polls markets, generates snapshots
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ PriceDetector   │  ← Detects buy opportunities
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Trader      │  ← Executes trades, manages positions
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PolymarketApi  │  ← Handles all API interactions
└─────────────────┘
```

### Trading Flow

```
1. MarketMonitor polls markets every check_interval_ms (default: 1 second)
   ↓
2. PriceDetector analyzes prices:
   - Checks if min_elapsed_minutes have passed
   - Checks if price >= trigger_price
   - Checks if price <= max_buy_price
   - Checks if time_remaining >= min_time_remaining_seconds
   ↓
3. If all conditions met → BuyOpportunity detected
   ↓
4. Trader executes buy order:
   - Places market order (FOK - Fill or Kill)
   - Verifies balance (polls until tokens arrive)
   - Tracks position in pending_trades
   ↓
5. Background task monitors position:
   - Checks if price reached sell_price → Sell
   - Checks if price dropped to stop_loss_price → Sell
   - Checks if market closed → Redeem tokens
   ↓
6. Profit/loss recorded and logged
```

---

## 🚀 Quick Start

### Prerequisites

- **Rust 1.70+** - [Install Rust](https://www.rust-lang.org/tools/install)
- **Polymarket Account** - With API credentials
- **Polygon Wallet** - With USDC balance for trading
- **POL/MATIC** - For gas fees (recommended: 0.5+ POL)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd polymarket-copy-trading-bot

# Build the project
cargo build --release

# Run in simulation mode (default - safe for testing)
cargo run --release

# Run in production mode (real trades)
cargo run --release -- --no-simulation
```

---

## ⚙️ Configuration

### 1. Create `config.json`

The bot will create a default `config.json` if it doesn't exist. Edit it with your settings:

```json
{
  "polymarket": {
    "gamma_api_url": "https://gamma-api.polymarket.com",
    "clob_api_url": "https://clob.polymarket.com",
    "api_key": "your_api_key",
    "api_secret": "your_api_secret",
    "api_passphrase": "your_passphrase",
    "private_key": "0x...your_private_key_hex",
    "proxy_wallet_address": "0x...your_proxy_wallet",
    "signature_type": 2
  },
  "trading": {
    "eth_condition_id": null,
    "btc_condition_id": null,
    "solana_condition_id": null,
    "xrp_condition_id": null,
    "check_interval_ms": 1000,
    "fixed_trade_amount": 4.5,
    "min_elapsed_minutes": 8,
    "min_time_remaining_seconds": 30,
    "market_closure_check_interval_seconds": 10,
    "sell_price": 0.98,
    "max_buy_price": 0.95,
    "trigger_price": 0.87,
    "stop_loss_price": 0.80,
    "hedge_price": 0.5,
    "enable_eth_trading": true,
    "enable_solana_trading": true,
    "enable_xrp_trading": true
  }
}
```

### 2. Configuration Parameters

#### Polymarket API Settings

| Parameter | Description | Required |
|-----------|-------------|----------|
| `api_key` | Polymarket API key | Yes (for production) |
| `api_secret` | Polymarket API secret | Yes (for production) |
| `api_passphrase` | Polymarket API passphrase | Yes (for production) |
| `private_key` | Wallet private key (hex, with or without 0x) | Yes (for production) |
| `proxy_wallet_address` | Polymarket proxy wallet address | Optional |
| `signature_type` | 0=EOA, 1=Proxy, 2=GnosisSafe | Optional (default: 0) |

#### Trading Strategy Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `fixed_trade_amount` | USD amount per trade | 4.5 |
| `trigger_price` | Minimum price to trigger buy (e.g., 0.87 = $0.87) | 0.87 |
| `max_buy_price` | Maximum price to buy at (e.g., 0.95 = $0.95) | 0.95 |
| `min_elapsed_minutes` | Minutes that must pass before buying | 8 |
| `min_time_remaining_seconds` | Minimum seconds remaining to allow buy | 30 |
| `sell_price` | Target sell price (e.g., 0.98 = $0.98) | 0.98 |
| `stop_loss_price` | Stop-loss price (e.g., 0.80 = $0.80) | 0.80 |
| `check_interval_ms` | Market polling interval (milliseconds) | 1000 |
| `enable_eth_trading` | Enable ETH market trading | true |
| `enable_solana_trading` | Enable Solana market trading | false |
| `enable_xrp_trading` | Enable XRP market trading | false |

#### Market Discovery

The bot automatically discovers markets for each 15-minute period. You can optionally set `condition_id` values in config to use specific markets:

```json
{
  "trading": {
    "btc_condition_id": "0x...",
    "eth_condition_id": "0x...",
    "solana_condition_id": "0x...",
    "xrp_condition_id": "0x..."
  }
}
```

If not set, the bot will automatically discover markets using slug patterns like:
- `btc-updown-15m-{timestamp}`
- `eth-updown-15m-{timestamp}`
- `solana-updown-15m-{timestamp}` or `sol-updown-15m-{timestamp}`
- `xrp-updown-15m-{timestamp}`

---

## 📖 Core Logic Explained

### 1. Market Monitoring

The `MarketMonitor` continuously polls Polymarket API every `check_interval_ms` (default: 1 second) to:
- Fetch current market prices (BID/ASK)
- Calculate time remaining in the 15-minute period
- Generate `MarketSnapshot` with all market data

### 2. Opportunity Detection

The `PriceDetector` analyzes each snapshot and checks:

```rust
// Buy conditions (ALL must be true):
1. time_elapsed >= min_elapsed_minutes (e.g., 8 minutes)
2. bid_price >= trigger_price (e.g., $0.87)
3. bid_price <= max_buy_price (e.g., $0.95)
4. time_remaining >= min_time_remaining_seconds (e.g., 30 seconds)
5. No active position of same token type in this period
6. Reset state is "Ready" (after sell, price must drop below trigger first)
```

**Example Scenario**:
- 8 minutes have elapsed in a 15-minute period
- BTC Up token BID price = $0.88
- 7 minutes remaining (420 seconds > 30 seconds minimum)
- ✅ **Buy signal triggered!**

### 3. Trade Execution

When a buy opportunity is detected:

1. **Order Placement**: Places market order (FOK - Fill or Kill)
   - Order size: `fixed_trade_amount` USD (e.g., $4.50)
   - Type: Market order (immediate execution)
   - Side: BUY

2. **Balance Verification**: Polls balance every 2 seconds (max 60 seconds) until tokens arrive

3. **Position Tracking**: Adds trade to `pending_trades` HashMap:
   ```rust
   PendingTrade {
       token_id: "...",
       purchase_price: 0.88,
       units: 5.11,  // $4.50 / $0.88
       sell_price: 0.98,
       stop_loss_price: 0.80,
       // ... other fields
   }
   ```

### 4. Position Management

Background task (`check_pending_trades()`) runs every 500ms to:

1. **Check Sell Conditions**:
   - If ASK price >= `sell_price` → Place sell order
   - If ASK price <= `stop_loss_price` → Place sell order (stop-loss)

2. **Check Market Closure**:
   - If market closed → Redeem tokens
   - Winning token (correct outcome) = $1.00 per share
   - Losing token (wrong outcome) = $0.00 per share

3. **Retry Logic**:
   - Failed sell orders are retried (up to `sell_attempts` limit)
   - Failed redemptions are retried every 10 seconds

### 5. Reset Mechanism

After a successful buy-sell cycle:
- Price must drop **below** `trigger_price` before allowing another buy
- Prevents buying immediately after selling when price only dips slightly
- Ensures each buy is a fresh opportunity

---

## 🎮 Running the Bot

### Simulation Mode (Default - Safe)

```bash
# Run in simulation mode (no real trades)
cargo run --release

# Or explicitly:
cargo run --release -- --simulation
```

**Simulation Mode**:
- ✅ Detects opportunities
- ✅ Logs what trades would be made
- ✅ Tracks PnL in `simulation.toml`
- ❌ Does NOT place real orders
- ❌ Does NOT spend real money

### Production Mode (Real Trades)

```bash
# Run in production mode (real trades)
cargo run --release -- --no-simulation
```

**⚠️ WARNING**: Production mode will:
- ✅ Place real orders on Polymarket
- ✅ Spend real USDC from your wallet
- ✅ Execute real trades
- ⚠️ **Use at your own risk!**

### Other Binaries

The project includes several specialized binaries:

```bash
# Price monitor (logs prices to file)
cargo run --release --bin price_monitor

# Limit order bot
cargo run --release --bin polymarket-arbitrage-bot-limit

# Dual limit bot (0.45 price)
cargo run --release --bin main_dual_limit_045

# Test scripts
cargo run --release --bin test_sell
cargo run --release --bin test_redeem
cargo run --release --bin test_allowance
```

---

## 📊 Logging

### Console Output

The bot logs to both console and files:
- **Real-time updates**: Price checks, opportunity detection, trade execution
- **Structured events**: Buy orders, sell fills, redemptions

### Log Files

- **`history.toml`**: All trading events with timestamps
  ```
  [2024-01-15T10:30:00Z] BUY ORDER | Market: BTC Up | Period: 1705316400 | Price: $0.88 | Units: 5.11 | Cost: $4.50 | Status: SUCCESS
  [2024-01-15T10:35:00Z] SELL ORDER FILLED | Market: BTC Up | Sell Price: $0.98 | Revenue: $5.01 | Profit: $0.51
  ```

- **`price_monitor.toml`**: Price history (simulation mode only)

- **`simulation.toml`**: PnL tracking (simulation mode only)

---

## 🔍 Key Features

### ✅ Automatic Market Discovery

- Discovers new 15-minute markets automatically
- Handles market transitions between periods
- Supports BTC, ETH, Solana, and XRP markets

### ✅ Risk Management

- **Stop-loss protection**: Automatic sell if price drops too low
- **Time-based safety**: Won't buy if too little time remaining
- **Position limits**: One position per token type per period
- **Reset mechanism**: Prevents over-trading

### ✅ Robust Error Handling

- Retries failed orders
- Handles network errors gracefully
- Continues operating even if some markets fail
- Comprehensive error logging

### ✅ Production Ready

- Authentication with Polymarket API
- Proper order signing
- Balance verification
- Market closure detection
- Token redemption handling

---

## 🛠️ Development

### Project Structure

```
src/
├── main.rs          # Entry point, initialization
├── lib.rs           # Module exports
├── api.rs           # Polymarket API client
├── trader.rs       # Trading logic
├── detector.rs      # Opportunity detection
├── monitor.rs       # Market monitoring
├── models.rs        # Data structures
├── config.rs        # Configuration
├── simulation.rs    # Simulation tracking
└── bin/             # Additional binaries
    ├── main_limit.rs
    ├── main_dual_limit_045.rs
    └── test_*.rs
```

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Check for issues
cargo clippy

# Format code
cargo fmt
```

---

## ⚠️ Important Notes

### Market Periods

- Markets run in **15-minute periods** (900 seconds)
- Each period has a unique timestamp (rounded to nearest 15 minutes)
- New markets are discovered automatically at period boundaries

### Order Types

- **Market Orders (FOK)**: Immediate execution, fill or kill
- **Limit Orders**: Placed at specific price (used for sell orders)

### Token Redemption

- At market closure, winning tokens are worth **$1.00**
- Losing tokens are worth **$0.00**
- The bot automatically redeems tokens after market closure
- Redemption may take a few minutes to process on-chain

### Gas Fees

- Each transaction requires POL/MATIC for gas
- Recommended: Keep at least **0.5 POL** in wallet
- Gas costs vary with network congestion

---

## 🐛 Troubleshooting

### Bot not detecting opportunities

- Check `trigger_price` isn't too high
- Verify `min_elapsed_minutes` isn't too long
- Ensure markets are active and not closed
- Check logs for price updates

### Orders failing

- Verify USDC balance is sufficient
- Check POL balance for gas fees
- Ensure API credentials are correct
- Verify wallet has proper allowances

### Authentication errors

- Check `private_key` format (hex string)
- Verify `api_key`, `api_secret`, `api_passphrase` are correct
- Ensure `signature_type` matches your wallet type
- Check `proxy_wallet_address` if using proxy wallet

### Market discovery failing

- Markets may not exist for all periods
- Check Polymarket website for active markets
- Set `condition_id` manually in config if needed
- Bot will use fallback markets if discovery fails

---

## 📝 Example Configuration

### Conservative Strategy

```json
{
  "trading": {
    "fixed_trade_amount": 2.0,
    "trigger_price": 0.90,
    "max_buy_price": 0.93,
    "min_elapsed_minutes": 10,
    "sell_price": 0.99,
    "stop_loss_price": 0.85
  }
}
```

### Aggressive Strategy

```json
{
  "trading": {
    "fixed_trade_amount": 10.0,
    "trigger_price": 0.85,
    "max_buy_price": 0.95,
    "min_elapsed_minutes": 5,
    "sell_price": 0.97,
    "stop_loss_price": 0.75
  }
}
```

---

## 🔐 Security

- **Never commit `config.json`** with real credentials
- **Use environment variables** for sensitive data (future feature)
- **Test in simulation mode** before production
- **Start with small amounts** to verify everything works
- **Monitor logs** for unexpected behavior

---

## 📞 Support

If you have any questions or would like a more customized app for specific use cases, please feel free to contact us at the contact information below.
- E-Mail: admin@hyperbuildx.com
- Telegram: [@bettyjk_0915](https://t.me/bettyjk_0915)

---

**Keywords**: Polymarket bot, automated trading, prediction markets, momentum trading, BTC trading, ETH trading, Rust trading bot
