# Polymarket Trading Bot (TypeScript)

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

## Requirements

- Node.js >= 18
- `config.json` with Polymarket `private_key` (and optional API creds)

## Setup

```bash
npm install
cp config.json.example config.json   # or copy from Rust project
# Edit config.json: set polymarket.private_key (hex, with or without 0x)
```

## Usage

- **Simulation (default)** – no real orders, logs what would be placed:
  ```bash
  npm run dev
  # or
  npx tsx src/main-dual-limit-045.ts
  ```

- **Production** – place real limit orders:
  ```bash
  npx tsx src/main-dual-limit-045.ts --no-simulation
  ```

- **Config path**:
  ```bash
  npx tsx src/main-dual-limit-045.ts -c /path/to/config.json
  ```

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

## Features

- **Automatic market discovery** — Finds 15-minute Up/Down markets for BTC, ETH, Solana, XRP; handles period rollover.
- **Dual limit at period start** — Places limit buys for both outcomes at a configurable price (e.g. $0.45).
- **Position management** — Target sell, stop-loss, and redemption at market close.
- **Configurable markets** — Enable/disable ETH, Solana, XRP; optional fixed condition IDs.
- **Simulation mode** — Test logic and PnL without sending orders.
- **Structured logging** — Console and file logging for debugging and audit.


## Build

```bash
npm run build
node dist/main-dual-limit-045.js
```

## Security

- Do **not** commit `config.json` with real keys or secrets.
- Prefer simulation and small sizes when testing.
- Monitor logs and balances when running in production.

---

## Support

If you have any questions or would like a more customized app for specific use cases, please feel free to contact us at the contact information below.
- E-Mail: admin@hyperbuildx.com
- Telegram: [@bettyjk_0915](https://t.me/bettyjk_0915)