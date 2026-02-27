# Polymarket Trading Bot

A Rust trading bot for [Polymarket](https://polymarket.com) that trades 15-minute (and 5-minute) price prediction markets using limit orders and trailing strategies.

**Features:**
- **Dual Limit Same-Size (0.45)** — Place Up/Down limit buys at $0.45 at market start; hedge with market buy if only one fills (2-min / 4-min / early / standard).
- **Dual Limit 5-Minute BTC** — Same idea for BTC 5-minute markets with time-based bands and trailing stop.
- **Trailing Bot** — Wait for price &lt; 0.45, then trail with stop loss and trailing stop on the opposite side.
- **Backtest** — Replay strategy on historical price data in `history/`.
- **Test binaries** — Limit order, redeem, merge, allowance, sell, and prediction tests.

---

**Watch the bot in action:**

[![Polymarket Trading Bot Demo](https://img.youtube.com/vi/1nF556ypGXM/0.jpg)](https://youtu.be/1nF556ypGXM?si=3d4zmY6lKVj4fVhO)

---

## Quick reference

| Binary | Description |
|--------|-------------|
| `main_dual_limit_045_same_size` | Dual limit 0.45, same-size hedge (default) |
| `main_dual_limit_045_5m_btc` | Dual limit 0.45, BTC 5-minute only |
| `main_trailing` | Trailing stop bot |
| `backtest` | Backtest on history files |
| `test_*` | test_limit_order, test_redeem, test_merge, test_allowance, test_sell, test_predict_fun |

---

## Setup

1. **Install Rust** (if needed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Build:**
   ```bash
   cargo build --release
   ```

3. **Configure:** Copy `config.example.json` to `config.json` and set:
   - `polymarket`: `api_key`, `api_secret`, `api_passphrase`, `private_key`
   - Optional: `proxy_wallet_address`, `signature_type` (1 = POLY_PROXY, 2 = GNOSIS_SAFE)
   - `trading`: enable flags, `dual_limit_price`, `dual_limit_shares`, hedge/trailing params, etc.

---

## Bot versions

### 1. Dual Limit Same-Size Bot (0.45) — default

**Binary:** `main_dual_limit_045_same_size`

At market start (first ~5 s), places limit buys for BTC and enabled ETH/SOL/XRP Up/Down at $0.45. If **both** fill → done for that market. If **only one** fills, applies a **2-min / 4-min / early / standard** hedge: buy the unfilled side at market (same size), cancel the unfilled $0.45 limit.

**Low-price exit (0.05 / 0.99 or 0.02 / 0.99):** Two limit sells (cheap at $0.05 or $0.02, opposite at $0.99) are placed only when:
1. At least **10 minutes** have elapsed.
2. The market was hedged via **4-min, early, or standard** (not 2-min).
3. One side’s **bid** is below 0.10 (or below 0.03 for the 0.02/0.99 path when hedge price &lt; 0.60).

```bash
# Simulation
cargo run --bin main_dual_limit_045_same_size -- --simulation

# Production (default binary)
cargo run -- --no-simulation
```

### 2. Dual Limit 5-Minute BTC Bot

**Binary:** `main_dual_limit_045_5m_btc`

Dual limit at $0.45 for **BTC 5-minute markets only**. Two windows: **2-min** (2–3 min), **3-min** (≥3 min), with bands and trailing stop (e.g. buy when ask ≥ lowest_ask + 0.03).

```bash
cargo run --bin main_dual_limit_045_5m_btc -- --config config.json --simulation
cargo run --bin main_dual_limit_045_5m_btc -- --config config.json --no-simulation
```

### 3. Trailing Bot

**Binary:** `main_trailing`

Waits until one token’s price is **under 0.45**, then trails that token (trailing stop with 0.45 cap). After the first buy, uses **stop loss + trailing stop** for the opposite token.

```bash
cargo run --bin main_trailing -- --simulation
cargo run --bin main_trailing -- --no-simulation
```

### 4. Backtest

**Binary:** `backtest`

Replays the dual-limit strategy on `history/market_*_prices.toml`: limit buys at $0.45, simulated fills, hedge logic, PnL. Requires existing price history files.

```bash
cargo run --bin backtest -- --backtest
```

---

## Test binaries

| Binary | Purpose |
|--------|---------|
| `test_limit_order` | Place a limit order (e.g. `--price-cents 60 --shares 10`) |
| `test_redeem` | List/redeem winning tokens (`--list`, `--redeem-all`) |
| `test_merge` | Merge complete sets to USDC (`--merge`) |
| `test_allowance` | Check balance/allowance; set approval (`--approve-only`, `--list`) |
| `test_sell` | Test market sell |
| `test_predict_fun` | Test prediction/price logic |

Example:
```bash
cargo run --bin test_allowance -- --approve-only   # One-time approval for selling
cargo run --bin test_redeem -- --list
```

---

## Configuration

- **`--simulation`** / **`--no-simulation`** — No real orders in simulation.
- **`--config <path>`** — Config file (default: `config.json`).

**Config fields (summary):**
- **polymarket:** `gamma_api_url`, `clob_api_url`, `api_key`, `api_secret`, `api_passphrase`, `private_key`, optional `proxy_wallet_address`, `signature_type`.
- **trading:** `check_interval_ms`, `fixed_trade_amount`, `enable_btc_trading` / `enable_eth_trading` / etc., `dual_limit_price` (0.45), `dual_limit_shares`, `dual_limit_hedge_*`, `trailing_stop_point`, `trailing_shares`, etc.

---

## Notes

- Bots run until you stop them (Ctrl+C).
- Simulation mode logs trades but does not send orders.
- **Before selling**, set on-chain approval once per proxy wallet:  
  `cargo run --bin test_allowance -- --approve-only`

---

## Security

- Do **not** commit `config.json` with real keys or secrets.
- Prefer simulation and small sizes when testing.
- Monitor logs and balances when running in production.

## Support

If you have any questions or would like a more customized app for specific use cases, please feel free to contact us at the contact information below.
- E-Mail: admin@hyperbuildx.com
- Telegram: [@bettyjk_0915](https://t.me/bettyjk_0915)
