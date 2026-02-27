// Trailing bot: wait for one token under 0.45, then trail that token; trigger only when trigger_at <= 0.45; if price goes above 0.45 without triggering, reset and wait for under 0.45 again. After first buy, monitor opposite with stop loss + trailing stop.
// Records Up/Down bought prices and shares to history/trailing_trades.jsonl (sim and live).

use polymarket_trading_bot::*;
use anyhow::{Context, Result};
use clap::Parser;
use polymarket_trading_bot::config::{Args, Config};
use log::warn;
use std::sync::Arc;
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Utc;
use rust_decimal::prelude::ToPrimitive;

use polymarket_trading_bot::api::PolymarketApi;
use polymarket_trading_bot::monitor::MarketMonitor;
use polymarket_trading_bot::detector::{BuyOpportunity, TokenType};
use polymarket_trading_bot::trader::Trader;

/// Only start trailing when at least one token's price is in this range (market "near 0.5"). If no token is in range, wait; if market ends without match, next 15m market starts fresh.
const NEAR_HALF_MIN: f64 = 0.48;
const NEAR_HALF_MAX: f64 = 0.52;
/// Only start trailing when a token's price is under this. If trailed price goes above this without triggering, reset and wait again.
const TRAILING_ENTRY_MAX_PRICE: f64 = 0.45;
/// Trigger (lowest + trailing_stop_point) above this is ignored; lowest is set to this and trailing continues.
const TRAILING_TRIGGER_CAP: f64 = 0.45;
const STOP_LOSS_BUFFER: f64 = 0.1;
/// Minimum total cost for first buy (USD). If under this, we increase units so cost >= this.
const MIN_FIRST_BUY_COST: f64 = 1.0;

/// Returns (units, investment) so that investment = units * price >= MIN_FIRST_BUY_COST and units >= base_shares.
/// Rounds units up to 2 decimals for API.
fn first_buy_units_and_investment(base_shares: f64, price: f64) -> (f64, f64) {
    let min_units = (MIN_FIRST_BUY_COST / price).max(base_shares);
    let units = (min_units * 100.0).ceil() / 100.0;
    let investment = units * price;
    (units, investment)
}
/// 2-min / 4-min boundaries for second-token time windows.
const TRAILING_HEDGE_ELAPSED_SECONDS: u64 = 120;
const FOUR_MIN_ELAPSED_SECONDS: u64 = 240;
/// Slug segment to avoid Rust 2021 string literal parsing (no "- after quote).
const SLUG_MID: &str = concat!("-", "updown-15m-");

/// Time windows for second token are from first-buy time (not market start).
const SECONDS_2MIN_FROM_FIRST_BUY: u64 = 120;
const SECONDS_4MIN_FROM_FIRST_BUY: u64 = 240;

/// Returns true if opposite_price is below the ceiling for the current time-since-first-buy.
/// Stop loss is handled separately (always buys); this is only for trailing trigger.
/// - Within 2 min of first buy: opposite < (1 - first_bought - 0.05)
/// - Within 4 min of first buy: opposite < (1 - first_bought)
/// - After early_hedge_minutes from first buy: opposite < (1 - first_bought)
fn second_token_meets_price_ceiling(
    first_bought_price: f64,
    seconds_since_first_buy: u64,
    opposite_price: f64,
    early_hedge_after_seconds: u64,
) -> bool {
    let ceiling = if seconds_since_first_buy < SECONDS_2MIN_FROM_FIRST_BUY {
        1.0 - first_bought_price - 0.05
    } else if seconds_since_first_buy < SECONDS_4MIN_FROM_FIRST_BUY {
        1.0 - first_bought_price
    } else if seconds_since_first_buy >= early_hedge_after_seconds {
        1.0 - first_bought_price
    } else {
        1.0 - first_bought_price
    };
    opposite_price < ceiling
}

/// Human-readable description of the ceiling for the current time-since-first-buy (for skip logs).
fn second_token_ceiling_desc(
    first_bought_price: f64,
    seconds_since_first_buy: u64,
    early_hedge_after_seconds: u64,
) -> String {
    let (ceiling, label) = if seconds_since_first_buy < SECONDS_2MIN_FROM_FIRST_BUY {
        (1.0 - first_bought_price - 0.05, "within 2min of first buy")
    } else if seconds_since_first_buy < SECONDS_4MIN_FROM_FIRST_BUY {
        (1.0 - first_bought_price, "within 4min of first buy")
    } else if seconds_since_first_buy >= early_hedge_after_seconds {
        (1.0 - first_bought_price, "after early-hedge min from first buy")
    } else {
        (1.0 - first_bought_price, "4min to early-hedge from first buy")
    };
    format!("{} requires opposite price < {:.4}", label, ceiling)
}

/// Returns human-readable time-window label for trailing-stop logs.
fn trailing_window_label(
    time_elapsed: u64,
    early_hedge_after_seconds: u64,
    hedge_after_seconds: u64,
) -> &'static str {
    if time_elapsed < TRAILING_HEDGE_ELAPSED_SECONDS {
        "0-2min"
    } else if time_elapsed < FOUR_MIN_ELAPSED_SECONDS {
        "2-4min"
    } else if time_elapsed < early_hedge_after_seconds {
        "4min-early"
    } else if time_elapsed < hedge_after_seconds {
        "early-hedge"
    } else {
        "post-hedge"
    }
}

/// Per-market state for the trailing strategy.
#[derive(Debug, Clone)]
enum TrailingState {
    /// We've seen at least one token in [0.48, 0.52] for this market; waiting for one token to go under 0.45 to start trailing.
    WaitingForUnder45,
    /// Monitoring the token currently under 0.5; buy when price >= lowest + trailing_stop, but ignore trigger if price > highest (avoid buying at new high).
    MonitoringFirst { target_is_up: bool, lowest: f64, highest: f64 },
    /// First buy order in flight; next snapshots skip until we replace with FirstBought or revert to MonitoringFirst. Prevents duplicate first buys and allows second-token monitoring to start as soon as we insert FirstBought after success.
    FirstBuyPending {
        first_was_up: bool,
        first_price: f64,
        shares: f64,
        opposite_lowest: f64,
        first_buy_time_elapsed: u64,
        revert_target_is_up: bool,
        revert_lowest: f64,
        revert_highest: f64,
    },
    /// First token bought; monitoring opposite with stop loss and trailing stop. Time windows for second token are from first_buy_time_elapsed.
    FirstBought {
        first_was_up: bool,
        first_price: f64,
        shares: f64,
        opposite_lowest: f64,
        first_buy_time_elapsed: u64,
    },
    /// Both tokens bought; record to history and stop acting.
    Done,
}

/// Ask price for recording and calculation (we buy at ask). Falls back to bid if ask missing.
fn ask_f64(token: &polymarket_trading_bot::models::TokenPrice) -> f64 {
    token
        .ask
        .as_ref()
        .and_then(|d| d.to_f64())
        .or_else(|| token.bid.as_ref().and_then(|d| d.to_f64()))
        .unwrap_or(0.0)
}

fn token_type_for(market_name: &str, is_up: bool) -> TokenType {
    match (market_name, is_up) {
        ("BTC", true) => TokenType::BtcUp,
        ("BTC", false) => TokenType::BtcDown,
        ("ETH", true) => TokenType::EthUp,
        ("ETH", false) => TokenType::EthDown,
        ("SOL", true) => TokenType::SolanaUp,
        ("SOL", false) => TokenType::SolanaDown,
        ("XRP", true) => TokenType::XrpUp,
        ("XRP", false) => TokenType::XrpDown,
        _ => TokenType::BtcUp,
    }
}

/// Append one JSON line to history/trailing_trades.jsonl
fn record_trailing_trade(
    history_path: &str,
    period_timestamp: u64,
    condition_id: &str,
    market_name: &str,
    up_bought_price: f64,
    up_shares: f64,
    down_bought_price: f64,
    down_shares: f64,
    mode: &str,
) -> Result<()> {
    std::fs::create_dir_all("history").context("create history dir")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_path)
        .context("open trailing history file")?;
    let record = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "period_timestamp": period_timestamp,
        "condition_id": condition_id,
        "market": market_name,
        "up_bought_price": up_bought_price,
        "up_shares": up_shares,
        "down_bought_price": down_bought_price,
        "down_shares": down_shares,
        "mode": mode,
    });
    writeln!(file, "{}", record).context("write trailing history")?;
    file.flush().context("flush trailing history")?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let is_simulation = args.is_simulation();

    eprintln!("🚀 Starting Polymarket Trailing Bot");
    let mode_str = if is_simulation { "SIMULATION" } else { let s = "PRODUCTION"; s };
    eprintln!("Mode: {}", mode_str);

    let trailing_stop = config.trading.trailing_stop_point.unwrap_or(0.03);
    let shares = config
        .trading
        .trailing_shares
        .or(config.trading.dual_limit_shares)
        .unwrap_or_else(|| config.trading.fixed_trade_amount / 0.5);

    eprintln!(
        "Strategy: Start trading only when at least one token is near 0.5 ({}–{}). Then wait for token under {:.2}; start trailing. Trigger only when trigger_at <= {:.2}; if trigger_at > {:.2} set lowest = {:.2}. If price goes above {:.2} without trigger, reset and wait again. No match in a market → skip until next 15m market. Trailing stop = {:.4}; buy (min cost ${:.0}, base {} units). Opposite: stop loss >= (1 - bought_price + {:.2}) or trailing >= opposite_lowest + {:.4}. One hedge per market.",
        NEAR_HALF_MIN, NEAR_HALF_MAX, TRAILING_ENTRY_MAX_PRICE, TRAILING_TRIGGER_CAP, TRAILING_TRIGGER_CAP, TRAILING_TRIGGER_CAP, TRAILING_ENTRY_MAX_PRICE, trailing_stop, MIN_FIRST_BUY_COST, shares, STOP_LOSS_BUFFER, trailing_stop
    );

    let api = Arc::new(PolymarketApi::new(
        config.polymarket.gamma_api_url.clone(),
        config.polymarket.clob_api_url.clone(),
        config.polymarket.api_key.clone(),
        config.polymarket.api_secret.clone(),
        config.polymarket.api_passphrase.clone(),
        config.polymarket.private_key.clone(),
        config.polymarket.proxy_wallet_address.clone(),
        config.polymarket.signature_type,
    ));

    eprintln!("\n═══════════════════════════════════════════════════════════");
    eprintln!("🔐 Authenticating with Polymarket CLOB API...");
    eprintln!("═══════════════════════════════════════════════════════════");
    api.authenticate().await.context("Authentication failed")?;
    eprintln!("✅ Authentication successful!");
    eprintln!("═══════════════════════════════════════════════════════════\n");

    if is_simulation {
        eprintln!("💡 Simulation mode: no orders will be placed.");
        eprintln!("");
    }

    eprintln!("🔍 Discovering markets...");
    let (eth_market, btc_market, solana_market, xrp_market) = get_or_discover_markets(
        &api,
        config.trading.enable_eth_trading,
        config.trading.enable_solana_trading,
        config.trading.enable_xrp_trading,
    )
    .await?;

    let monitor = MarketMonitor::new(
        api.clone(),
        eth_market,
        btc_market,
        solana_market,
        xrp_market,
        config.trading.check_interval_ms,
        is_simulation,
        None,
        None,
        None,
        None,
        None,
        None,
    )?;
    let monitor_arc = Arc::new(monitor);

    let trader = Arc::new(Trader::new(
        api.clone(),
        config.trading.clone(),
        is_simulation,
        None,
    )?);

    let state: Arc<tokio::sync::Mutex<std::collections::HashMap<(u64, String), TrailingState>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let history_path = concat!("history/trailing_trades.", "jsonl");
    let enable_btc = config.trading.enable_btc_trading;
    let enable_eth = config.trading.enable_eth_trading;
    let enable_solana = config.trading.enable_solana_trading;
    let enable_xrp = config.trading.enable_xrp_trading;
    let early_hedge_after_seconds = config.trading.dual_limit_early_hedge_minutes.unwrap_or(5) * 60;
    let hedge_after_seconds = config.trading.dual_limit_hedge_after_minutes.unwrap_or(10) * 60;

    // When the current 15-minute period ends, discover new markets and update the monitor so it fetches prices for the new period.
    let api_for_period_check = api.clone();
    let monitor_for_period_check = monitor_arc.clone();
    let enable_eth_period = config.trading.enable_eth_trading;
    let enable_solana_period = config.trading.enable_solana_trading;
    let enable_xrp_period = config.trading.enable_xrp_trading;
    tokio::spawn(async move {
        loop {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_period = (current_time / 900) * 900;
            let current_market_timestamp = monitor_for_period_check.get_current_market_timestamp().await;
            let next_period_timestamp = current_market_timestamp + 900;
            let sleep_duration = if next_period_timestamp > current_time {
                next_period_timestamp - current_time
            } else {
                0
            };
            if sleep_duration > 0 && sleep_duration <= 1800 {
                tokio::time::sleep(tokio::time::Duration::from_secs(sleep_duration)).await;
            } else if sleep_duration == 0 {
                eprintln!("🔄 New 15-minute period: discovering markets for period {}...", current_period);
                match get_or_discover_markets(
                    api_for_period_check.as_ref(),
                    enable_eth_period,
                    enable_solana_period,
                    enable_xrp_period,
                )
                .await
                {
                    Ok((eth_market, btc_market, solana_market, xrp_market)) => {
                        let btc_id_log = btc_market.condition_id.chars().take(16).collect::<String>();
                        if let Err(e) = monitor_for_period_check
                            .update_markets(eth_market, btc_market, solana_market, xrp_market)
                            .await
                        {
                            warn!("Trailing bot: failed to update markets for new period: {}", e);
                        } else {
                            eprintln!("✅ Trailing bot: updated to new period markets (BTC: {}...)", btc_id_log);
                        }
                    }
                    Err(e) => {
                        warn!("Trailing bot: failed to discover markets for new period: {}", e);
                    }
                }
            } else {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    });

    monitor_arc
        .start_monitoring(move |snapshot| {
            let trader = trader.clone();
            let state = state.clone();
            let history_path = history_path.to_string();
            let trailing_stop = trailing_stop;
            let shares = shares;
            let enable_btc = enable_btc;
            let enable_eth = enable_eth;
            let enable_solana = enable_solana;
            let enable_xrp = enable_xrp;
            let is_simulation = is_simulation;
            let early_hedge_after_seconds = early_hedge_after_seconds;
            let hedge_after_seconds = hedge_after_seconds;

            async move {
                if snapshot.time_remaining_seconds == 0 {
                    return;
                }
                let time_elapsed = 900u64.saturating_sub(snapshot.time_remaining_seconds);

                let mut markets_full: Vec<(&str, &polymarket_trading_bot::models::MarketData, u64)> = Vec::new();
                if enable_btc {
                    markets_full.push(("BTC", &snapshot.btc_market, snapshot.period_timestamp));
                }
                if enable_eth {
                    markets_full.push(("ETH", &snapshot.eth_market, snapshot.period_timestamp));
                }
                if enable_solana {
                    markets_full.push(("SOL", &snapshot.solana_market, snapshot.period_timestamp));
                }
                if enable_xrp {
                    markets_full.push(("XRP", &snapshot.xrp_market, snapshot.period_timestamp));
                }

                for (market_name, market, period_ts) in markets_full {
                    let (Some(up_token), Some(down_token)) =
                        (market.up_token.as_ref(), market.down_token.as_ref())
                    else {
                        continue;
                    };
                    let up_ask = ask_f64(up_token);
                    let down_ask = ask_f64(down_token);
                    let key = (period_ts, market.condition_id.clone());

                    let mut guard = state.lock().await;
                    let s = guard.get_mut(&key);

                    match s {
                        None => {
                            // Only consider this market when at least one token is near 0.5 (0.48–0.52). Then wait for one token under 0.45 in a later snapshot.
                            let near_half = (up_ask >= NEAR_HALF_MIN && up_ask <= NEAR_HALF_MAX)
                                || (down_ask >= NEAR_HALF_MIN && down_ask <= NEAR_HALF_MAX);
                            if !near_half {
                                drop(guard);
                                continue;
                            }
                            // Market is "allowed"; wait for one token to go under 0.45 to start trailing.
                            polymarket_trading_bot::log_println!(
                                "▶ Trailing [{}] market near 0.5 (Up={:.4} Dn={:.4}) → waiting for one token under 0.45",
                                market_name, up_ask, down_ask
                            );
                            guard.insert(key.clone(), TrailingState::WaitingForUnder45);
                            drop(guard);
                            continue;
                        }
                        Some(TrailingState::WaitingForUnder45) => {
                            // We already saw near 0.5; now start trailing when one token is under 0.45.
                            let up_under = up_ask < TRAILING_ENTRY_MAX_PRICE;
                            let down_under = down_ask < TRAILING_ENTRY_MAX_PRICE;
                            if up_under && !down_under {
                                polymarket_trading_bot::log_println!(
                                    "▶ Trailing [{}] started: monitoring Up (ask={:.4}, under 0.45)",
                                    market_name, up_ask
                                );
                                guard.insert(
                                    key.clone(),
                                    TrailingState::MonitoringFirst {
                                        target_is_up: true,
                                        lowest: up_ask,
                                        highest: up_ask,
                                    },
                                );
                            } else if down_under && !up_under {
                                polymarket_trading_bot::log_println!(
                                    "▶ Trailing [{}] started: monitoring Down (ask={:.4}, under 0.45)",
                                    market_name, down_ask
                                );
                                guard.insert(
                                    key.clone(),
                                    TrailingState::MonitoringFirst {
                                        target_is_up: false,
                                        lowest: down_ask,
                                        highest: down_ask,
                                    },
                                );
                            } else if up_under && down_under {
                                let target_up = up_ask <= down_ask;
                                let side = if target_up { "Up" } else { let s = "Down"; s };
                                let low = if target_up { up_ask } else { down_ask };
                                polymarket_trading_bot::log_println!(
                                    "▶ Trailing [{}] started: monitoring {} (ask={:.4}, both under 0.45)",
                                    market_name, side, low
                                );
                                guard.insert(
                                    key.clone(),
                                    TrailingState::MonitoringFirst {
                                        target_is_up: target_up,
                                        lowest: low,
                                        highest: low,
                                    },
                                );
                            }
                            drop(guard);
                            continue;
                        }
                        Some(TrailingState::Done) => {
                            drop(guard);
                            continue;
                        }
                        Some(TrailingState::FirstBuyPending { .. }) => {
                            drop(guard);
                            continue;
                        }
                        Some(TrailingState::MonitoringFirst {
                            target_is_up,
                            lowest,
                            highest,
                        }) => {
                            if *target_is_up {
                                // If price went above 0.45 without triggering, reset and wait for under 0.45 again.
                                if up_ask > TRAILING_ENTRY_MAX_PRICE {
                                    polymarket_trading_bot::log_println!(
                                        "🔄 Trailing [{}] Up crossed 0.45 (ask={:.4}) without trigger → reset, wait for token under 0.45 again",
                                        market_name, up_ask
                                    );
                                    guard.remove(&key);
                                    drop(guard);
                                    continue;
                                }
                                let old_highest = *highest;
                                *lowest = (*lowest).min(up_ask);
                                *highest = (*highest).max(up_ask);
                                let trigger_at = *lowest + trailing_stop;
                                let window = trailing_window_label(time_elapsed, early_hedge_after_seconds, hedge_after_seconds);
                                if up_ask < trigger_at {
                                    polymarket_trading_bot::log_println!(
                                        "   Trailing [{}] Up: ask={:.4} lowest={:.4} highest={:.4} trigger_at={:.4} (+{:.3}) elapsed={}s [{}]",
                                        market_name, up_ask, *lowest, *highest, trigger_at, trailing_stop, time_elapsed, window
                                    );
                                    drop(guard);
                                    continue;
                                }
                                // Trigger above 0.45: ignore, set lowest = 0.45 and continue trailing.
                                if trigger_at > TRAILING_TRIGGER_CAP {
                                    polymarket_trading_bot::log_println!(
                                        "   Trailing [{}] Up: trigger_at {:.4} > 0.45 → ignore, set lowest = 0.45",
                                        market_name, trigger_at
                                    );
                                    *lowest = TRAILING_TRIGGER_CAP;
                                    drop(guard);
                                    continue;
                                }
                                // Ignore trigger if current ask is above previous highest (avoid buying at new high).
                                if up_ask > old_highest {
                                    *lowest = up_ask;
                                    polymarket_trading_bot::log_println!(
                                        "   Trailing [{}] Up: TRIGGER at ask {:.4} ignored (ask > highest {:.4}), updating highest and lowest to {:.4}",
                                        market_name, up_ask, old_highest, up_ask
                                    );
                                    drop(guard);
                                    continue;
                                }
                                polymarket_trading_bot::log_println!(
                                    "   Trailing [{}] Up: TRIGGER at ask {:.4} → executing buy",
                                    market_name, up_ask
                                );
                                let buy_price = up_ask;
                                let (first_units, investment) = first_buy_units_and_investment(shares, buy_price);
                                let revert_low = *lowest;
                                let revert_high = *highest;
                                guard.insert(
                                    key.clone(),
                                    TrailingState::FirstBuyPending {
                                        first_was_up: true,
                                        first_price: buy_price,
                                        shares: first_units,
                                        opposite_lowest: down_ask,
                                        first_buy_time_elapsed: time_elapsed,
                                        revert_target_is_up: true,
                                        revert_lowest: revert_low,
                                        revert_highest: revert_high,
                                    },
                                );
                                drop(guard);
                                let opp = BuyOpportunity {
                                    condition_id: market.condition_id.clone(),
                                    token_id: up_token.token_id.clone(),
                                    token_type: token_type_for(market_name, true),
                                    bid_price: buy_price,
                                    period_timestamp: snapshot.period_timestamp,
                                    time_remaining_seconds: snapshot.time_remaining_seconds,
                                    time_elapsed_seconds: time_elapsed,
                                    use_market_order: true,
                                    investment_amount_override: Some(investment),
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: Some(first_units),
                                };
                                let buy_result = trader.execute_buy(&opp).await;
                                let mut g = state.lock().await;
                                match buy_result {
                                    Err(e) => {
                                        warn!("Trailing first buy (Up) failed {}: {}", market_name, e);
                                        g.insert(
                                            key.clone(),
                                            TrailingState::MonitoringFirst {
                                                target_is_up: true,
                                                lowest: revert_low,
                                                highest: revert_high,
                                            },
                                        );
                                    }
                                    Ok(()) => {
                                        let window = trailing_window_label(time_elapsed, early_hedge_after_seconds, hedge_after_seconds);
                                        polymarket_trading_bot::log_println!(
                                            "📈 TRAILING first buy: {} Up at ${:.4} x {:.6} (cost ${:.2}) [{}]",
                                            market_name, buy_price, first_units, investment, window
                                        );
                                        g.insert(
                                            key.clone(),
                                            TrailingState::FirstBought {
                                                first_was_up: true,
                                                first_price: buy_price,
                                                shares: first_units,
                                                opposite_lowest: down_ask,
                                                first_buy_time_elapsed: time_elapsed,
                                            },
                                        );
                                    }
                                }
                                drop(g);
                                continue;
                            } else {
                                // If price went above 0.45 without triggering, reset and wait for under 0.45 again.
                                if down_ask > TRAILING_ENTRY_MAX_PRICE {
                                    polymarket_trading_bot::log_println!(
                                        "🔄 Trailing [{}] Down crossed 0.45 (ask={:.4}) without trigger → reset, wait for token under 0.45 again",
                                        market_name, down_ask
                                    );
                                    guard.remove(&key);
                                    drop(guard);
                                    continue;
                                }
                                let old_highest = *highest;
                                *lowest = (*lowest).min(down_ask);
                                *highest = (*highest).max(down_ask);
                                let trigger_at = *lowest + trailing_stop;
                                let window = trailing_window_label(time_elapsed, early_hedge_after_seconds, hedge_after_seconds);
                                if down_ask < trigger_at {
                                    polymarket_trading_bot::log_println!(
                                        "   Trailing [{}] Down: ask={:.4} lowest={:.4} highest={:.4} trigger_at={:.4} (+{:.3}) elapsed={}s [{}]",
                                        market_name, down_ask, *lowest, *highest, trigger_at, trailing_stop, time_elapsed, window
                                    );
                                    drop(guard);
                                    continue;
                                }
                                // Trigger above 0.45: ignore, set lowest = 0.45 and continue trailing.
                                if trigger_at > TRAILING_TRIGGER_CAP {
                                    polymarket_trading_bot::log_println!(
                                        "   Trailing [{}] Down: trigger_at {:.4} > 0.45 → ignore, set lowest = 0.45",
                                        market_name, trigger_at
                                    );
                                    *lowest = TRAILING_TRIGGER_CAP;
                                    drop(guard);
                                    continue;
                                }
                                // Ignore trigger if current ask is above previous highest (avoid buying at new high).
                                if down_ask > old_highest {
                                    *lowest = down_ask;
                                    polymarket_trading_bot::log_println!(
                                        "   Trailing [{}] Down: TRIGGER at ask {:.4} ignored (ask > highest {:.4}), updating highest and lowest to {:.4}",
                                        market_name, down_ask, old_highest, down_ask
                                    );
                                    drop(guard);
                                    continue;
                                }
                                polymarket_trading_bot::log_println!(
                                    "   Trailing [{}] Down: TRIGGER at ask {:.4} → executing buy",
                                    market_name, down_ask
                                );
                                let buy_price = down_ask;
                                let (first_units, investment) = first_buy_units_and_investment(shares, buy_price);
                                let revert_low = *lowest;
                                let revert_high = *highest;
                                guard.insert(
                                    key.clone(),
                                    TrailingState::FirstBuyPending {
                                        first_was_up: false,
                                        first_price: buy_price,
                                        shares: first_units,
                                        opposite_lowest: up_ask,
                                        first_buy_time_elapsed: time_elapsed,
                                        revert_target_is_up: false,
                                        revert_lowest: revert_low,
                                        revert_highest: revert_high,
                                    },
                                );
                                drop(guard);
                                let opp = BuyOpportunity {
                                    condition_id: market.condition_id.clone(),
                                    token_id: down_token.token_id.clone(),
                                    token_type: token_type_for(market_name, false),
                                    bid_price: buy_price,
                                    period_timestamp: snapshot.period_timestamp,
                                    time_remaining_seconds: snapshot.time_remaining_seconds,
                                    time_elapsed_seconds: time_elapsed,
                                    use_market_order: true,
                                    investment_amount_override: Some(investment),
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: Some(first_units),
                                };
                                let buy_result = trader.execute_buy(&opp).await;
                                let mut g = state.lock().await;
                                match buy_result {
                                    Err(e) => {
                                        warn!("Trailing first buy (Down) failed {}: {}", market_name, e);
                                        g.insert(
                                            key.clone(),
                                            TrailingState::MonitoringFirst {
                                                target_is_up: false,
                                                lowest: revert_low,
                                                highest: revert_high,
                                            },
                                        );
                                    }
                                    Ok(()) => {
                                        let window = trailing_window_label(time_elapsed, early_hedge_after_seconds, hedge_after_seconds);
                                        polymarket_trading_bot::log_println!(
                                            "📈 TRAILING first buy: {} Down at ${:.4} x {:.6} (cost ${:.2}) [{}]",
                                            market_name, buy_price, first_units, investment, window
                                        );
                                        g.insert(
                                            key.clone(),
                                            TrailingState::FirstBought {
                                                first_was_up: false,
                                                first_price: buy_price,
                                                shares: first_units,
                                                opposite_lowest: up_ask,
                                                first_buy_time_elapsed: time_elapsed,
                                            },
                                        );
                                    }
                                }
                                drop(g);
                                continue;
                            }
                        }
                        Some(TrailingState::FirstBought {
                            first_was_up,
                            first_price,
                            shares: first_shares,
                            opposite_lowest,
                            first_buy_time_elapsed,
                        }) => {
                            let first_price_val = *first_price;
                            let first_shares_val = *first_shares;
                            let first_buy_time_elapsed_val = *first_buy_time_elapsed;
                            let stop_loss_threshold = 1.0 - first_price_val + STOP_LOSS_BUFFER;
                            let (opposite_price, opp_token, opp_type, is_up) = if *first_was_up {
                                (down_ask, down_token, token_type_for(market_name, false), false)
                            } else {
                                (up_ask, up_token, token_type_for(market_name, true), true)
                            };
                            *opposite_lowest = (*opposite_lowest).min(opposite_price);
                            let trigger_stop_loss = opposite_price >= stop_loss_threshold;
                            let trailing_trigger_at = *opposite_lowest + trailing_stop;
                            let trigger_trailing = opposite_price >= trailing_trigger_at;
                            let side_str = if *first_was_up { "Down" } else { let s = "Up"; s };
                            if !trigger_stop_loss && !trigger_trailing {
                                polymarket_trading_bot::log_println!(
                                    "   Trailing [{}] opposite {}: price={:.4} opposite_lowest={:.4} stop_loss>= {:.4} trail>= {:.4} (waiting)",
                                    market_name, side_str, opposite_price, *opposite_lowest, stop_loss_threshold, trailing_trigger_at
                                );
                                drop(guard);
                                continue;
                            }
                            let seconds_since_first_buy = time_elapsed.saturating_sub(first_buy_time_elapsed_val);
                            // Stop loss: always buy when opposite >= (1 - first_bought + 0.05). Trailing: only buy if opposite is below the time-based ceiling (from first buy).
                            let allow_buy = if trigger_stop_loss {
                                true
                            } else {
                                second_token_meets_price_ceiling(
                                    first_price_val,
                                    seconds_since_first_buy,
                                    opposite_price,
                                    early_hedge_after_seconds,
                                )
                            };
                            if !allow_buy {
                                let cond_desc = second_token_ceiling_desc(
                                    first_price_val,
                                    seconds_since_first_buy,
                                    early_hedge_after_seconds,
                                );
                                let trigger_via = if trigger_stop_loss { "stop_loss" } else { "trailing" };
                                polymarket_trading_bot::log_println!(
                                    "   Trailing [{}] opposite {}: TRIGGER at {:.4} via {} skipped ({})",
                                    market_name, side_str, opposite_price, trigger_via, cond_desc
                                );
                                drop(guard);
                                continue;
                            }
                            let trigger_via = if trigger_stop_loss { "stop_loss" } else { "trailing" };
                            polymarket_trading_bot::log_println!(
                                "   Trailing [{}] opposite {}: TRIGGER at {:.4} via {} (stop_loss>= {:.4} trail>= {:.4}) → executing buy",
                                market_name, side_str, opposite_price, trigger_via, stop_loss_threshold, trailing_trigger_at
                            );
                            let first_was_up_val = *first_was_up;
                            let buy_price = opposite_price;
                            drop(guard);
                            let investment = first_shares_val * buy_price;
                            let opp = BuyOpportunity {
                                condition_id: market.condition_id.clone(),
                                token_id: opp_token.token_id.clone(),
                                token_type: opp_type,
                                bid_price: buy_price,
                                period_timestamp: snapshot.period_timestamp,
                                time_remaining_seconds: snapshot.time_remaining_seconds,
                                time_elapsed_seconds: time_elapsed,
                                use_market_order: true,
                                investment_amount_override: Some(investment),
                                is_individual_hedge: false,
                                is_standard_hedge: false,
                                dual_limit_shares: Some(first_shares_val),
                            };
                            if let Err(e) = trader.execute_buy(&opp).await {
                                warn!("Trailing second buy failed {}: {}", market_name, e);
                            } else {
                                let (up_price, up_shares, down_price, down_shares) = if first_was_up_val {
                                    (first_price_val, first_shares_val, buy_price, first_shares_val)
                                } else {
                                    (buy_price, first_shares_val, first_price_val, first_shares_val)
                                };
                                let mode = if is_simulation { "simulation" } else { let s = "live"; s };
                                if let Err(e) = record_trailing_trade(
                                    &history_path,
                                    snapshot.period_timestamp,
                                    &market.condition_id,
                                    market_name,
                                    up_price,
                                    up_shares,
                                    down_price,
                                    down_shares,
                                    mode,
                                ) {
                                    warn!("Failed to record trailing trade: {}", e);
                                }
                                let side_str = if is_up { "Up" } else { let s = "Down"; s };
                                let via_str = if trigger_stop_loss { "stop_loss" } else { "trailing" };
                                polymarket_trading_bot::log_println!(
                                    "📈 TRAILING second buy: {} {} at ${:.4} x {:.6} via {}",
                                    market_name,
                                    side_str,
                                    buy_price,
                                    first_shares_val,
                                    via_str
                                );
                                let mut g = state.lock().await;
                                g.insert(key.clone(), TrailingState::Done);
                            }
                        }
                    }
                }
            }
        })
        .await;
    Ok(())
}

async fn discover_market(
    api: &PolymarketApi,
    market_name: &str,
    slug_prefixes: &[&str],
    current_time: u64,
    seen_ids: &mut std::collections::HashSet<String>,
    include_previous: bool,
) -> Result<polymarket_trading_bot::models::Market> {
    let rounded_time = (current_time / 900) * 900;
    for (i, prefix) in slug_prefixes.iter().enumerate() {
        if i > 0 { }
        let slug = prefix.to_string() + SLUG_MID + &rounded_time.to_string();
        if let Ok(market) = api.get_market_by_slug(&slug).await {
            if !seen_ids.contains(&market.condition_id) && market.active && !market.closed {
                return Ok(market);
            }
        }
        if include_previous {
            for offset in 1..=3 {
                let try_time = rounded_time - (offset * 900);
                let try_slug = prefix.to_string() + SLUG_MID + &try_time.to_string();
                if let Ok(market) = api.get_market_by_slug(&try_slug).await {
                    if !seen_ids.contains(&market.condition_id) && market.active && !market.closed {
                        return Ok(market);
                    }
                }
            }
        }
    }
    return Err(anyhow::anyhow!(String::from_utf8(vec![68,105,115,99,111,118,101,114,121,32,101,114,114,111,114]).unwrap()));
}

async fn discover_solana_market(
    api: &PolymarketApi,
    current_time: u64,
    seen_ids: &mut std::collections::HashSet<String>,
) -> polymarket_trading_bot::models::Market {
    let solana_slugs = [std::str::from_utf8(&[115,111,108,97,110,97]).unwrap(), std::str::from_utf8(&[115,111,108]).unwrap()];
    if let Ok(market) = discover_market(api, std::str::from_utf8(&[83,111,108,97,110,97]).unwrap(), &solana_slugs, current_time, seen_ids, false).await {
        return market;
    }
    disabled_solana_market()
}

async fn discover_xrp_market(
    api: &PolymarketApi,
    current_time: u64,
    seen_ids: &mut std::collections::HashSet<String>,
) -> polymarket_trading_bot::models::Market {
    let xrp_slugs = [std::str::from_utf8(&[120, 114, 112]).unwrap()];
    if let Ok(market) = discover_market(api, std::str::from_utf8(&[88, 82, 80]).unwrap(), &xrp_slugs, current_time, seen_ids, false).await {
        return market;
    }
    disabled_xrp_market()
}

async fn get_or_discover_markets(
    api: &PolymarketApi,
    enable_eth: bool,
    enable_solana: bool,
    enable_xrp: bool,
) -> Result<(
    polymarket_trading_bot::models::Market,
    polymarket_trading_bot::models::Market,
    polymarket_trading_bot::models::Market,
    polymarket_trading_bot::models::Market,
)> {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut seen_ids = std::collections::HashSet::new();

    let eth_market = if enable_eth {
        discover_market(api, std::str::from_utf8(&[69,84,72]).unwrap(), &[std::str::from_utf8(&[101,116,104]).unwrap()], current_time, &mut seen_ids, true).await
            .unwrap_or_else(|_| disabled_eth_market())
    } else {
        disabled_eth_market()
    };
    seen_ids.insert(eth_market.condition_id.clone());

    let btc_slugs: [&str; 1] = [std::str::from_utf8(&[98, 116, 99]).unwrap()];
    let btc_name = std::str::from_utf8(&[66u8, 84, 67]).unwrap();
    let btc_market = discover_market(api, btc_name, &btc_slugs, current_time, &mut seen_ids, true).await
        .unwrap_or_else(|_| {
            polymarket_trading_bot::models::Market {
                condition_id: String::from_utf8(vec![100,117,109,109,121,95,98,116,99,95,102,97,108,108,98,97,99,107]).unwrap(),
                slug: String::from_utf8(vec![98,116,99,45,117,112,100,111,119,110,45,49,53,109,45,102,97,108,108,98,97,99,107]).unwrap(),
                active: false,
                closed: true,
                market_id: None,
                question: String::from_utf8_lossy(&[66,84,67,32,70,97,108,108,98,97,99,107]).into_owned(),
                resolution_source: None,
                end_date_iso: None,
                end_date_iso_alt: None,
                tokens: None,
                clob_token_ids: None,
                outcomes: None,
            }
        });
    seen_ids.insert(btc_market.condition_id.clone());

    let solana_market = if enable_solana {
        discover_solana_market(api, current_time, &mut seen_ids).await
    } else {
        disabled_solana_market()
    };
    let xrp_market = if enable_xrp {
        discover_xrp_market(api, current_time, &mut seen_ids).await
    } else {
        disabled_xrp_market()
    };

    Ok((eth_market, btc_market, solana_market, xrp_market))
}

fn disabled_eth_market() -> polymarket_trading_bot::models::Market {
    polymarket_trading_bot::models::Market {
        condition_id: String::from_utf8(vec![100,117,109,109,121,95,101,116,104,95,102,97,108,108,98,97,99,107]).unwrap(),
        slug: String::from_utf8(vec![101,116,104,45,117,112,100,111,119,110,45,49,53,109,45,102,97,108,108,98,97,99,107]).unwrap(),
        active: false,
        closed: true,
        market_id: None,
        question: String::from_utf8_lossy(&[69,84,72,32,68,105,115,97,98,108,101,100]).into_owned(),
        resolution_source: None,
        end_date_iso: None,
        end_date_iso_alt: None,
        tokens: None,
        clob_token_ids: None,
        outcomes: None,
    }
}

fn disabled_solana_market() -> polymarket_trading_bot::models::Market {
    polymarket_trading_bot::models::Market {
        condition_id: String::from_utf8(vec![100,117,109,109,121,95,115,111,108,97,110,97,95,102,97,108,108,98,97,99,107]).unwrap(),
        slug: String::from_utf8(vec![115,111,108,97,110,97,45,117,112,100,111,119,110,45,49,53,109,45,102,97,108,108,98,97,99,107]).unwrap(),
        active: false,
        closed: true,
        market_id: None,
        question: String::from_utf8_lossy(&[83,111,108,97,110,97,32,68,105,115,97,98,108,101,100]).into_owned(),
        resolution_source: None,
        end_date_iso: None,
        end_date_iso_alt: None,
        tokens: None,
        clob_token_ids: None,
        outcomes: None,
    }
}

fn disabled_xrp_market() -> polymarket_trading_bot::models::Market {
    polymarket_trading_bot::models::Market {
        condition_id: String::from_utf8(vec![100,117,109,109,121,95,120,114,112,95,102,97,108,108,98,97,99,107]).unwrap(),
        slug: String::from_utf8(vec![120,114,112,45,117,112,100,111,119,110,45,49,53,109,45,102,97,108,108,98,97,99,107]).unwrap(),
        active: false,
        closed: true,
        market_id: None,
        question: String::from_utf8_lossy(&[88,82,80,32,68,105,115,97,98,108,101,100]).into_owned(),
        resolution_source: None,
        end_date_iso: None,
        end_date_iso_alt: None,
        tokens: None,
        clob_token_ids: None,
        outcomes: None,
    }
}
