# Polymarket Trading Bot

> Automated dual limit-order bot for Polymarket 15-minute BTC/ETH/Solana/XRP Up/Down markets.

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## Overview

This bot trades on Polymarket’s 15-minute prediction markets for **BTC**, **ETH**, **Solana**, and **XRP**. The main strategy is a **dual limit-start** approach: at the start of each 15-minute period, it places limit buy orders for both Up and Down tokens at a fixed price (default **$0.45**). Filled positions are then managed with target sells, stop-loss, and redemption at market closure.

### Strategy Summary

| Phase | Behavior |
|-------|----------|
| **Market start** | Place limit buy orders for Up and Down tokens at `dual_limit_price` (e.g. $0.45). |
| **Position management** | Sell at target price, stop-loss if price drops, or redeem when the market closes. |
| **Markets** | BTC always; ETH, Solana, and XRP can be enabled or disabled in config. |

**Watch the bot in action:**

[![Polymarket Trading Bot Demo](https://img.youtube.com/vi/1nF556ypGXM/0.jpg)](https://youtu.be/1nF556ypGXM?si=3d4zmY6lKVj4fVhO)

---

## Architecture

```
┌─────────────────┐
│  MarketMonitor  │  Polls markets, builds snapshots
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Limit orders   │  At period start: place Up/Down limit buys at fixed price
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Trader      │  Executes orders, manages positions, redemptions
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PolymarketApi  │  CLOB/Gamma API, auth, signing
└─────────────────┘
```

---

## Quick Start

### Prerequisites

- **Rust 1.70+** — [Install Rust](https://www.rust-lang.org/tools/install)
- **Polymarket account** — API key, secret, passphrase
- **Polygon wallet** — USDC for trading, POL for gas (e.g. 0.5+ POL)

### Build and run

```bash
git clone <repository-url>
cd Polymarket-Trading-Bot-Rust

cargo build --release

# Simulation (no real orders)
cargo run --release

# Production (real trades)
cargo run --release -- --no-simulation
```

---

## Configuration

Create or edit `config.json` in the project directory.

### Example `config.json`

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
    "dual_limit_price": 0.45,
    "dual_limit_shares": null,
    "min_elapsed_minutes": 8,
    "min_time_remaining_seconds": 30,
    "market_closure_check_interval_seconds": 10,
    "sell_price": 0.98,
    "max_buy_price": 0.95,
    "trigger_price": 0.87,
    "stop_loss_price": 0.80,
    "enable_eth_trading": true,
    "enable_solana_trading": true,
    "enable_xrp_trading": true
  }
}
```

### API settings

| Parameter | Description | Required |
|-----------|-------------|----------|
| `api_key` | Polymarket API key | Yes (production) |
| `api_secret` | Polymarket API secret | Yes (production) |
| `api_passphrase` | Polymarket API passphrase | Yes (production) |
| `private_key` | Wallet private key (hex, with or without `0x`) | Yes (production) |
| `proxy_wallet_address` | Polymarket proxy wallet address | Optional |
| `signature_type` | `0` = EOA, `1` = Proxy, `2` = GnosisSafe | Optional (default: 0) |

### Trading settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `dual_limit_price` | Limit buy price for Up/Down at market start | 0.45 |
| `dual_limit_shares` | Fixed shares per limit order; if unset, uses `fixed_trade_amount / price` | null |
| `fixed_trade_amount` | USD size when shares not fixed by `dual_limit_shares` | 4.5 |
| `sell_price` | Target sell price | 0.98 |
| `stop_loss_price` | Stop-loss sell price | 0.80 |
| `check_interval_ms` | Market polling interval (ms) | 1000 |
| `enable_eth_trading` | Enable ETH 15m markets | true |
| `enable_solana_trading` | Enable Solana 15m markets | false |
| `enable_xrp_trading` | Enable XRP 15m markets | false |

### Market discovery

The bot discovers 15-minute markets by slug (e.g. `btc-updown-15m-{timestamp}`). You can pin markets by setting condition IDs:

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

---

## Running the bot

### Default binary (dual limit bot)

```bash
# Simulation (default)
cargo run --release

# Production
cargo run --release -- --no-simulation
```

Simulation mode logs intended trades and tracks PnL in `simulation.toml` without placing orders. Production mode places real orders and uses real funds; use with care.

### Other binaries

```bash
# Price monitor (log prices to file)
cargo run --release --bin price_monitor

# Test utilities
cargo run --release --bin test_sell
cargo run --release --bin test_redeem
cargo run --release --bin test_allowance
cargo run --release --bin test_limit_order
cargo run --release --bin test_merge
cargo run --release --bin test_predict_fun
```

---

## Logging

- **Console** — Real-time status, opportunities, and trade events.
- **`history.toml`** — Append-only log of trading events with timestamps.
- **`price_monitor.toml`** — Price history when running the price monitor (or simulation with price logging).
- **`simulation.toml`** — PnL and simulation state when running in simulation mode.

---

## Features

- **Automatic market discovery** — Finds 15-minute Up/Down markets for BTC, ETH, Solana, XRP; handles period rollover.
- **Dual limit at period start** — Places limit buys for both outcomes at a configurable price (e.g. $0.45).
- **Position management** — Target sell, stop-loss, and redemption at market close.
- **Configurable markets** — Enable/disable ETH, Solana, XRP; optional fixed condition IDs.
- **Simulation mode** — Test logic and PnL without sending orders.
- **Structured logging** — Console and file logging for debugging and audit.

---

## Project structure

```
src/
├── lib.rs              Library and shared modules
├── api.rs               Polymarket CLOB/Gamma API client
├── config.rs            Config and CLI args
├── detector.rs          Opportunity types and helpers
├── merge.rs             Merge utilities
├── models.rs            Data structures
├── monitor.rs           Market monitoring and snapshots
├── simulation.rs        Simulation PnL and state
├── trader.rs            Order execution and position management
└── bin/
    ├── main_dual_limit_045.rs   Main bot (default binary)
    ├── main_price_monitor.rs   Price monitor
    └── test_*.rs               Test utilities
```

### Commands

```bash
cargo build --release    # Release build
cargo check             # Check without full build
cargo test              # Run tests
cargo clippy            # Lints
cargo fmt               # Format code
```

---

## Operational notes

- **Periods** — Markets are 15 minutes (900 s); period timestamps are aligned to 900 s boundaries.
- **Orders** — Limit buys at market start; sells and redemptions use the trader’s normal logic (market/limit as implemented).
- **Redemption** — After resolution, winning tokens settle at $1.00, losing at $0.00; the bot redeems when the market is closed.
- **Gas** — Polygon gas (POL) is required; keep sufficient POL (e.g. 0.5+) for transactions.

---

## Troubleshooting

| Issue | Checks |
|-------|--------|
| No orders placed | Confirm markets are active; check `enable_*_trading` and condition IDs; review logs for discovery and timing. |
| Order failures | Sufficient USDC and POL; valid API credentials and `private_key`; correct `signature_type` and proxy settings if used. |
| Auth errors | Validate `api_key` / `api_secret` / `api_passphrase`; ensure `private_key` is hex; match `signature_type` to wallet type. |
| Market not found | Ensure Polymarket lists the 15m market for that asset; try setting the corresponding `*_condition_id` in config. |

---

## Security

- Do **not** commit `config.json` with real keys or secrets.
- Prefer simulation and small sizes when testing.
- Monitor logs and balances when running in production.

---

## Support

If you have any questions or would like a more customized app for specific use cases, please feel free to contact us at the contact information below.
- E-Mail: admin@hyperbuildx.com
- Telegram: [@bettyjk_0915](https://t.me/bettyjk_0915)

---

**Keywords**: Polymarket bot, automated trading, prediction markets, dual limit order, BTC trading, ETH trading, Rust trading bot.
