// Same-size hedge: place two limit orders (Up/Down at 0.45) at start. If both fill, stop. If one fills, use trailing stop to buy unfilled side as cheap as possible (2-min / 4-min / early / standard).
//
// Trading logic order: (1) On one fill → cancel opposite limit. (2) 2-min: ask-based band (before 2 min < 0.45, 2–4 min < 0.5, after 4 min < 0.65); trailing on ask; buy at ask; record in hedge_executed + hedge_price so low-price exit applies. (3) 4-min: skip if in hedge_executed or two_min; if bid > 0.75 → immediate market buy at ask; else if 0.5 < bid < 0.65 → trailing on bid, buy at ask. (4) Early: 0.65 < bid < 0.85, trailing on bid, buy at ask. (5) Standard: time >= hedge_after_seconds, both limits pending, unfilled bid >= hedge_price → buy at market. (6) Low-price exit: after 10 min, for any market in hedge_executed, if one side < 0.1 → place 0.05 and 0.99 limit sells (or 0.02/0.99 if hedge price < 0.60). No double hedge: once in hedge_executed we skip 4-min/early/standard; two_min_hedge_markets also skips 4-min/early.

use polymarket_trading_bot::*;
use anyhow::{Context, Result};
use clap::Parser;
use polymarket_trading_bot::config::{Args, Config};
use log::{warn, debug};
use std::sync::Arc;
use std::io::{self, Write};
use std::fs::{File, OpenOptions};
use std::sync::{Mutex, OnceLock};
use chrono::Utc;

use polymarket_trading_bot::api::PolymarketApi;
use polymarket_trading_bot::monitor::MarketMonitor;
use polymarket_trading_bot::detector::BuyOpportunity;
use polymarket_trading_bot::trader::Trader;

const LIMIT_PRICE: f64 = 0.45;
const PERIOD_DURATION: u64 = 900;
const DEFAULT_HEDGE_AFTER_MINUTES: u64 = 10;
const DEFAULT_HEDGE_PRICE: f64 = 0.8;
/// After this many seconds (2 min), if one side filled and unfilled price < 0.5, cancel limit and buy at market (only before 4 min).
const NINETY_SEC_AFTER_SECONDS: u64 = 120;
/// After this many seconds (4 min), check for mid-tier hedge when unfilled price is in (FOUR_MIN_HEDGE_MIN, FOUR_MIN_HEDGE_MAX).
const TWO_MIN_AFTER_SECONDS: u64 = 240;
/// 4-min hedge: unfilled price must be > this (so 0.5 < price < FOUR_MIN_HEDGE_MAX).
const FOUR_MIN_HEDGE_MIN_PRICE: f64 = 0.5;
/// 4-min hedge: unfilled price must be < this for trailing. If price drops below 0.5 after 4 min, use 2-min hedging mode.
const FOUR_MIN_HEDGE_MAX_PRICE: f64 = 0.65;
/// 4-min: if unfilled price goes over this, buy at market immediately (no trailing).
const FOUR_MIN_HEDGE_BUY_OVER_PRICE: f64 = 0.75;
/// Early hedge: unfilled price must be in (EARLY_HEDGE_MIN_PRICE, EARLY_HEDGE_MAX_PRICE). From 0.85 to end, standard hedge.
const EARLY_HEDGE_MIN_PRICE: f64 = 0.65;
const EARLY_HEDGE_MAX_PRICE: f64 = 0.85;
/// 2-min hedge: when unfilled token price is less than 0.5, cancel limit and buy at market.
const NINETY_SEC_HEDGE_MAX_PRICE: f64 = 0.5;
/// When one side price goes below this (post-hedge), place limit sell at SELL_LOW_PRICE for that token and SELL_HIGH_PRICE for opposite.
const LOW_PRICE_THRESHOLD: f64 = 0.1;
/// Limit sell price for the token whose price dropped under LOW_PRICE_THRESHOLD (post-hedge exit).
const SELL_LOW_PRICE: f64 = 0.05;
/// Limit sell price for the opposite token when we place the low-price exit.
const SELL_HIGH_PRICE: f64 = 0.99;
/// When both Up and Down filled at 0.45 (no hedge): if any token price goes below this, place sell at DUAL_FILLED_SELL_*.
const DUAL_FILLED_LOW_THRESHOLD: f64 = 0.03;
/// Limit sell price for the token under DUAL_FILLED_LOW_THRESHOLD (both-filled-at-limit case).
const DUAL_FILLED_SELL_LOW: f64 = 0.02;
/// Limit sell price for the opposite token when placing dual-filled low-price exit.
const DUAL_FILLED_SELL_HIGH: f64 = 0.99;
/// Set to true to enable limit selling when both positions were bought at 0.45 (dual-filled); false = disabled.
const DUAL_FILLED_LIMIT_SELL_ENABLED: bool = false;
/// Limit sell orders (0.01/0.99 and 0.05/0.99 exits) are only placed after this many seconds elapsed in the period.
const LIMIT_SELL_AFTER_SECONDS: u64 = 600; // 10 minutes
/// Hedge price threshold for which exit path we use: if hedge price >= this → place 0.05/0.99 limit sells when one side < LOW_PRICE_THRESHOLD; if hedge price < this → place 0.02/0.99 (cheaper exit for low-quality hedges).
const HEDGE_PRICE_MIN_FOR_LIMIT_SELL: f64 = 0.60;
/// Max price we will pay for the unfilled side when hedging. Total cost = 0.45 (limit) + hedge ≤ 1.0 for breakeven; if unfilled ask > this we skip hedge to avoid locking in a loss.
const MAX_HEDGE_PRICE: f64 = 0.54;

/// Set to true to temporarily disable all hedge logic (2-min, 4-min, early, standard).
const HEDGE_DISABLED: bool = false;
/// Set to true to temporarily disable only early hedge (e.g. 5-min hedge).
const EARLY_HEDGE_DISABLED: bool = false;
/// Set to true to temporarily disable only standard hedge (e.g. 10-min hedge).
const STANDARD_HEDGE_DISABLED: bool = false;

/// A writer that writes to both stderr (terminal) and a file
struct DualWriter {
    stderr: io::Stderr,
    file: Mutex<File>,
}

impl Write for DualWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.stderr.write_all(buf);
        let _ = self.stderr.flush();
        let mut file = self.file.lock().unwrap();
        file.write_all(buf)?;
        file.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stderr.flush()?;
        let mut file = self.file.lock().unwrap();
        file.flush()?;
        Ok(())
    }
}

unsafe impl Send for DualWriter {}
unsafe impl Sync for DualWriter {}

static HISTORY_FILE: OnceLock<Mutex<File>> = OnceLock::new();

fn init_history_file(file: File) {
    HISTORY_FILE.set(Mutex::new(file)).expect("History file already initialized");
}

pub fn log_to_history(message: &str) {
    eprint!("{}", message);
    let _ = io::stderr().flush();
    if let Some(file_mutex) = HISTORY_FILE.get() {
        if let Ok(mut file) = file_mutex.lock() {
            let _ = write!(file, "{}", message);
            let _ = file.flush();
        }
    }
}

pub fn log_trading_event(event: &str) {
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let message = format!("[{}] {}\n", timestamp, event);
    log_to_history(&message);
}

#[macro_export]
macro_rules! log_println {
    ($($arg:tt)*) => {
        {
            let message = format!($($arg)*);
            $crate::log_to_history(&format!("{}\n", message));
        }
    };
}

/// Replay historical prices and run trailing-stop hedge logic (no real orders).
/// Assumes one side (e.g. Up) filled at 0.45; runs 2-min / 4-min / early hedge checks on unfilled (Down) price.
fn run_trailing_stop_replay(
    snapshots: &[polymarket_trading_bot::backtest::PriceSnapshot],
    hedge_after_seconds: u64,
    early_hedge_after_seconds: u64,
    hedge_price: f64,
    trailing_stop_tolerance: f64,
) {
    const PERIOD: u64 = 900;
    let mut two_min_trailing: Option<f64> = None;
    let mut four_min_early_trailing: Option<f64> = None;
    let mut result: Option<(String, u64, f64)> = None; // "2-min"|"4-min"|"early", elapsed, price

    for s in snapshots {
        let time_elapsed = PERIOD.saturating_sub(s.time_remaining_seconds);
        let current_price = s.btc_down_bid.unwrap_or(0.0); // assume Up filled, unfilled = Down
        if current_price <= 0.0 {
            continue;
        }

        // 2-min: price < 0.5
        if time_elapsed >= NINETY_SEC_AFTER_SECONDS && current_price < NINETY_SEC_HEDGE_MAX_PRICE {
            let trailing_min = two_min_trailing.unwrap_or(current_price);
            let new_min = trailing_min.min(current_price);
            two_min_trailing = Some(new_min);
            if current_price <= new_min + trailing_stop_tolerance {
                result = Some(("2-min".to_string(), time_elapsed, current_price));
                break;
            }
        }

        // 4-min: 0.5 < price < 0.65
        if time_elapsed >= TWO_MIN_AFTER_SECONDS
            && current_price > FOUR_MIN_HEDGE_MIN_PRICE
            && current_price < FOUR_MIN_HEDGE_MAX_PRICE
            && current_price <= MAX_HEDGE_PRICE
        {
            let trailing_min = four_min_early_trailing.unwrap_or(current_price);
            let new_min = trailing_min.min(current_price);
            four_min_early_trailing = Some(new_min);
            if current_price <= new_min + trailing_stop_tolerance {
                result = Some(("4-min".to_string(), time_elapsed, current_price));
                break;
            }
        }

        // Early: 0.65 < price < hedge_price
        if time_elapsed >= early_hedge_after_seconds
            && current_price > EARLY_HEDGE_MIN_PRICE
            && current_price < hedge_price
            && current_price <= MAX_HEDGE_PRICE
        {
            let trailing_min = four_min_early_trailing.unwrap_or(current_price);
            let new_min = trailing_min.min(current_price);
            four_min_early_trailing = Some(new_min);
            if current_price <= new_min + trailing_stop_tolerance {
                result = Some(("early".to_string(), time_elapsed, current_price));
                break;
            }
        }

        // Standard: after hedge_after_seconds, price >= hedge_price would trigger (no trailing)
        if time_elapsed >= hedge_after_seconds && current_price >= hedge_price && current_price <= MAX_HEDGE_PRICE {
            result = Some(("standard".to_string(), time_elapsed, current_price));
            break;
        }
    }

    eprintln!("\n═══════════════════════════════════════════════════════════");
    eprintln!("📊 TRAILING STOP REPLAY RESULT (assumed: BTC Up filled at 0.45, unfilled = Down)");
    eprintln!("   Snapshots: {}", snapshots.len());
    if let Some((kind, elapsed, price)) = result {
        eprintln!("   Would hedge: {} at elapsed {}s ({}m {}s), price ${:.4}", kind, elapsed, elapsed / 60, elapsed % 60, price);
    } else {
        eprintln!("   No hedge triggered in this history.");
    }
    eprintln!("═══════════════════════════════════════════════════════════\n");
}

#[tokio::main]
async fn main() -> Result<()> {
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("history.toml")
        .context("Failed to open history.toml for logging")?;

    init_history_file(log_file.try_clone().context("Failed to clone history file")?);
    polymarket_trading_bot::init_history_file(log_file.try_clone().context("Failed to clone history file for lib.rs")?);

    let dual_writer = DualWriter {
        stderr: io::stderr(),
        file: Mutex::new(log_file),
    };

    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .target(env_logger::Target::Pipe(Box::new(dual_writer)))
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)?;

    // History-file replay: load prices and run trailing-stop hedge logic, then exit.
    if args.is_history_replay() {
        let path = args.history_file.as_ref().unwrap();
        let path_with_dir = std::path::Path::new("history").join(path.as_path());
        let to_load = if path_with_dir.exists() {
            path_with_dir
        } else {
            path.clone()
        };
        eprintln!("📂 History replay: loading {}", to_load.display());
        let snapshots = polymarket_trading_bot::backtest::load_price_history(&to_load)
            .context("Load history file for replay")?;
        if snapshots.is_empty() {
            anyhow::bail!("No price snapshots found in {}", to_load.display());
        }
        let hedge_after_seconds = config.trading.dual_limit_hedge_after_minutes.unwrap_or(DEFAULT_HEDGE_AFTER_MINUTES) * 60;
        let early_hedge_after_seconds = config.trading.dual_limit_early_hedge_minutes.unwrap_or(5) * 60;
        let hedge_price = config.trading.dual_limit_hedge_price.unwrap_or(DEFAULT_HEDGE_PRICE);
        let trailing_stop_tolerance = config.trading.trailing_stop_point.unwrap_or(0.02);
        run_trailing_stop_replay(&snapshots, hedge_after_seconds, early_hedge_after_seconds, hedge_price, trailing_stop_tolerance);
        return Ok(());
    }

    eprintln!("🚀 Starting Polymarket Dual Limit Same-Size Bot");
    eprintln!("📝 Logs are being saved to: history.toml");
    let is_simulation = args.is_simulation();
    eprintln!("Mode: {}", if is_simulation { "SIMULATION (live prices, no orders)" } else { "PRODUCTION (real orders)" });
    let limit_price = config.trading.dual_limit_price.unwrap_or(LIMIT_PRICE);
    let limit_shares = config.trading.dual_limit_shares;
    // Shares for all batch and hedge orders (dual_limit_shares or fixed_trade_amount/price). No balance checks needed.
    let hedge_shares = limit_shares.unwrap_or_else(|| config.trading.fixed_trade_amount / limit_price);
    let hedge_after_minutes = config
        .trading
        .dual_limit_hedge_after_minutes
        .unwrap_or(DEFAULT_HEDGE_AFTER_MINUTES);
    let early_hedge_after_minutes = config
        .trading
        .dual_limit_early_hedge_minutes
        .unwrap_or(5);
    let hedge_price = config
        .trading
        .dual_limit_hedge_price
        .unwrap_or(DEFAULT_HEDGE_PRICE);
    let trailing_stop_tolerance = config.trading.trailing_stop_point.unwrap_or(0.02);
    eprintln!(
        "Strategy: At market start, place limit buys for BTC, ETH, SOL, and XRP Up/Down at ${:.2}",
        limit_price
    );
    eprintln!(
        "If both orders fill: no further trading. If only one fills: early hedge after {} min or standard after {} min (unfilled >= ${:.2}); buy unfilled at market same size (1x), cancel unfilled limit.",
        early_hedge_after_minutes,
        hedge_after_minutes,
        hedge_price
    );
    let hedge_trailing_stop = config.trading.dual_limit_hedge_trailing_stop.unwrap_or(0.03);
    eprintln!("   2-min hedge: track lowest unfilled price; trigger when price >= lowest + {:.3} (buy at ask). Config: dual_limit_hedge_trailing_stop", hedge_trailing_stop);
    if let Some(shares) = limit_shares {
        eprintln!("Shares per order (config): {:.6}", shares);
    } else {
        eprintln!("Shares per order: fixed_trade_amount / price");
    }
    eprintln!(
        "✅ Trading enabled for BTC and {} 15-minute markets",
        enabled_markets_label(
            config.trading.enable_eth_trading,
            config.trading.enable_solana_trading,
            config.trading.enable_xrp_trading
        )
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
        eprintln!("💡 Simulation mode: fetching real-time prices, no orders will be placed.");
        eprintln!("   Use --no-simulation to run live. Use --history-file <name> to replay a history file.");
        eprintln!("");
    }

    eprintln!("🔍 Discovering BTC, ETH, Solana, and XRP markets...");
    let (eth_market_data, btc_market_data, solana_market_data, xrp_market_data) =
        get_or_discover_markets(
            &api,
            config.trading.enable_eth_trading,
            config.trading.enable_solana_trading,
            config.trading.enable_xrp_trading,
        ).await?;

    let chainlink_btc: Arc<tokio::sync::Mutex<Option<f64>>> = Arc::new(tokio::sync::Mutex::new(None));
    crate::rtds::spawn_chainlink_btc_task(chainlink_btc.clone());
    let monitor = MarketMonitor::new(
        api.clone(),
        eth_market_data,
        btc_market_data,
        solana_market_data,
        xrp_market_data,
        config.trading.check_interval_ms,
        is_simulation,
        None,
        Some(config.trading.enable_eth_trading),
        Some(config.trading.enable_solana_trading),
        Some(config.trading.enable_xrp_trading),
        Some(chainlink_btc),
        None,
    )?;
    let monitor_arc = Arc::new(monitor);

    let mut trading_config = config.trading.clone();
    trading_config.dual_filled_limit_sell_enabled = Some(DUAL_FILLED_LIMIT_SELL_ENABLED);
    let trader = Trader::new(
        api.clone(),
        trading_config,
        is_simulation,
        None,
    )?;
    let trader_arc = Arc::new(trader);
    let trader_clone = trader_arc.clone();

    crate::log_println!("🔄 Syncing pending trades with portfolio balance...");
    if let Err(e) = trader_clone.sync_trades_with_portfolio().await {
        warn!("Error syncing trades with portfolio: {}", e);
    }
    
    // Start a background task to check pending trades and limit order fills (for simulation mode)
    let trader_check = trader_clone.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(1000)); // Check every 1s for limit order fills
        let mut summary_interval = tokio::time::interval(tokio::time::Duration::from_secs(30)); // Print summary every 30 seconds
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = trader_check.check_pending_trades().await {
                        warn!("Error checking pending trades: {}", e);
                    }
                }
                _ = summary_interval.tick() => {
                    // trader_check.print_trade_summary().await; // Temporarily disabled
                }
            }
        }
    });

    // When snapshot sees time_remaining_seconds == 0, notify so period-check wakes and discovers new market immediately (avoids delay in simulation where callback does more work).
    let discovery_notify = Arc::new(tokio::sync::Notify::new());
    let last_notified_period: Arc<tokio::sync::Mutex<Option<u64>>> = Arc::new(tokio::sync::Mutex::new(None));

    // Background task to detect new 15-minute periods
    let monitor_for_period_check = monitor_arc.clone();
    let api_for_period_check = api.clone();
    let trader_for_period_reset = trader_clone.clone();
    let enable_eth = config.trading.enable_eth_trading;
    let enable_solana = config.trading.enable_solana_trading;
    let enable_xrp = config.trading.enable_xrp_trading;
    let simulation_tracker_for_market_start = if is_simulation {
        trader_clone.get_simulation_tracker()
    } else {
        None
    };
    let discovery_notify_for_task = discovery_notify.clone();
    tokio::spawn(async move {
        loop {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let current_period = (current_time / 900) * 900;
            let current_market_timestamp = monitor_for_period_check.get_current_market_timestamp().await;

            // Market ended: we're in a new period but monitor still has old market → discover new market and start trading.
            let market_ended = current_market_timestamp != current_period && current_market_timestamp != 0;
            if market_ended {
                eprintln!("🔄 Market finished (period {} ended). Discovering new market for period {}...",
                    current_market_timestamp, current_period);
            } else {
                let next_period_timestamp = current_period + 900;
                let sleep_duration = if next_period_timestamp > current_time {
                    next_period_timestamp - current_time
                } else {
                    0
                };

                if sleep_duration == 0 {
                    eprintln!("🔄 Next period already started, discovering new market...");
                } else {
                    // Sleep in 30s chunks, or until snapshot notifies (market ended) so we discover immediately.
                    let chunk = std::cmp::min(sleep_duration, 30);
                    if chunk > 0 {
                        tokio::select! {
                            _ = discovery_notify_for_task.notified() => {
                                eprintln!("🔄 Market end noticed by monitor — discovering new market now.");
                            }
                            _ = tokio::time::sleep(tokio::time::Duration::from_secs(chunk)) => {}
                        }
                        continue;
                    }
                }
            }

            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_period = (current_time / 900) * 900;

            eprintln!("🔄 New 15-minute period detected! (Period: {}) Discovering new markets...", current_period);

            let mut seen_ids = std::collections::HashSet::new();
            let (eth_id, btc_id) = monitor_for_period_check.get_current_condition_ids().await;
            seen_ids.insert(eth_id);
            seen_ids.insert(btc_id);

            let eth_result = if enable_eth {
                discover_market(&api_for_period_check, "ETH", &["eth"], current_time, &mut seen_ids, true).await
            } else {
                Ok(disabled_eth_market())
            };
            let btc_result = discover_market(&api_for_period_check, "BTC", &["btc"], current_time, &mut seen_ids, true).await;
            let solana_market = if enable_solana {
                discover_solana_market(&api_for_period_check, current_time, &mut seen_ids).await
            } else {
                disabled_solana_market()
            };
            let xrp_market = if enable_xrp {
                discover_xrp_market(&api_for_period_check, current_time, &mut seen_ids).await
            } else {
                disabled_xrp_market()
            };

            match (eth_result, btc_result) {
                (Ok(eth_market), Ok(btc_market)) => {
                    if let Err(e) = monitor_for_period_check.update_markets(eth_market.clone(), btc_market.clone(), solana_market.clone(), xrp_market.clone()).await {
                        warn!("Failed to update markets: {}", e);
                    } else {
                        eprintln!("✅ New markets loaded — starting trading for period {}", current_period);
                        if let Some(tracker) = &simulation_tracker_for_market_start {
                            tracker.log_market_start(
                                current_period,
                                &eth_market.condition_id,
                                &btc_market.condition_id,
                                &solana_market.condition_id,
                                &xrp_market.condition_id
                            ).await;
                        }
                        trader_for_period_reset.reset_period(current_period).await;
                    }
                }
                (Err(e), _) => warn!("Failed to discover new ETH market: {}", e),
                (_, Err(e)) => warn!("Failed to discover new BTC market: {}", e),
            }
        }
    });

    let last_placed_period = Arc::new(tokio::sync::Mutex::new(None::<u64>));
    let last_seen_period = Arc::new(tokio::sync::Mutex::new(None::<u64>));
    let enable_btc = config.trading.enable_btc_trading;
    let enable_eth = config.trading.enable_eth_trading;
    let enable_solana = config.trading.enable_solana_trading;
    let enable_xrp = config.trading.enable_xrp_trading;
    let hedge_after_seconds = hedge_after_minutes * 60;
    let early_hedge_after_seconds = early_hedge_after_minutes * 60;
    let hedge_price = hedge_price;
    let is_simulation = is_simulation;
    let config_for_trends = config.clone();
    let previous_prices: Arc<tokio::sync::Mutex<std::collections::HashMap<String, f64>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let early_hedge_executed: Arc<tokio::sync::Mutex<std::collections::HashSet<u64>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    let two_min_hedge_executed: Arc<tokio::sync::Mutex<std::collections::HashSet<u64>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    // Per-market hedge tracking: (period_timestamp, condition_id) when we've done cancel + market buy for that market.
    let hedge_executed_for_market: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    // Markets hedged via 2-min hedge only (skip low-price limit-sell logic for these).
    let two_min_hedge_markets: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    // Trailing stop: minimum unfilled BID seen per (period, condition_id) (legacy; 2-min now uses ask for trigger).
    let two_min_trailing_min: Arc<tokio::sync::Mutex<std::collections::HashMap<(u64, String), f64>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    // 2-min: minimum unfilled ASK seen (we buy at ask). Trigger when current_ask <= lowest_ask + trailing_stop.
    let two_min_trailing_min_ask: Arc<tokio::sync::Mutex<std::collections::HashMap<(u64, String), f64>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    // When we first cross into 4-min window, reset trailing min so we don't use 2-min-era lowest (use current price as new baseline).
    let two_min_trailing_reset_at_4min: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    // When one side fills we cancel the other side's limit immediately (no wait for hedge). Track to avoid double cancel.
    let opposite_limit_cancelled_for_market: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    let four_min_early_trailing_min: Arc<tokio::sync::Mutex<std::collections::HashMap<(u64, String), f64>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    // Markets where we already placed limit sell at 0.05 and 0.99 (one side under LOW_PRICE_THRESHOLD).
    let low_price_sell_placed_for_market: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    // Markets where we placed only the cheap (0.05) sell; opposite (0.99) failed — retry by placing only opposite.
    let low_price_cheap_sell_placed_for_market: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    // Both filled at 0.45 (no hedge): when one side price < 0.03, we place 0.02 and 0.99 limit sells (track here to avoid double place).
    let dual_filled_low_price_sell_placed_for_market: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    // Per (period, condition_id): price at which we hedged. If >= 0.60 we use 0.05/0.99 exit; if < 0.60 we use 0.01/0.99 exit.
    let hedge_price_per_market: Arc<tokio::sync::Mutex<std::collections::HashMap<(u64, String), f64>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    // Hedged with price < 0.60: when we placed 0.01/0.99 limit sells (track to avoid double place).
    let hedge_under_60_sell_placed_for_market: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    let api_for_callback = api.clone();
    let monitor_for_callback = monitor_arc.clone();
    let trader_for_discovery = trader_clone.clone();
    let simulation_tracker_for_discovery = if is_simulation { trader_clone.get_simulation_tracker() } else { None };

    monitor_arc.start_monitoring(move |snapshot| {
        let trader = trader_clone.clone();
        let api = api_for_callback.clone();
        let monitor_for_discovery = monitor_for_callback.clone();
        let trader_reset = trader_for_discovery.clone();
        let sim_tracker = simulation_tracker_for_discovery.clone();
        let last_placed_period = last_placed_period.clone();
        let last_seen_period = last_seen_period.clone();
        let enable_btc = enable_btc;
        let enable_eth = enable_eth;
        let enable_solana = enable_solana;
        let enable_xrp = enable_xrp;
        let hedge_after_seconds = hedge_after_seconds;
        let early_hedge_after_seconds = early_hedge_after_seconds;
        let hedge_price = hedge_price;
        let trailing_stop_tolerance = trailing_stop_tolerance;
        let is_simulation = is_simulation;
        let config = config_for_trends.clone();
        let fixed_trade_amount = config.trading.fixed_trade_amount;
        let previous_prices = previous_prices.clone();
        let _early_hedge_executed = early_hedge_executed.clone();
        let _two_min_hedge_executed = two_min_hedge_executed.clone();
        let hedge_executed_for_market = hedge_executed_for_market.clone();
        let two_min_hedge_markets = two_min_hedge_markets.clone();
        let two_min_trailing_min = two_min_trailing_min.clone();
        let two_min_trailing_min_ask = two_min_trailing_min_ask.clone();
        let two_min_trailing_reset_at_4min = two_min_trailing_reset_at_4min.clone();
        let opposite_limit_cancelled_for_market = opposite_limit_cancelled_for_market.clone();
        let four_min_early_trailing_min = four_min_early_trailing_min.clone();
        let low_price_sell_placed_for_market = low_price_sell_placed_for_market.clone();
        let low_price_cheap_sell_placed_for_market = low_price_cheap_sell_placed_for_market.clone();
        let dual_filled_low_price_sell_placed_for_market = dual_filled_low_price_sell_placed_for_market.clone();
        let hedge_price_per_market = hedge_price_per_market.clone();
        let hedge_under_60_sell_placed_for_market = hedge_under_60_sell_placed_for_market.clone();
        let discovery_notify = discovery_notify.clone();
        let last_notified_period = last_notified_period.clone();

        async move {
            if snapshot.time_remaining_seconds == 0 {
                // Run discovery immediately in callback so new market loads without waiting for background task.
                let should_run = {
                    let mut last = last_notified_period.lock().await;
                    if *last != Some(snapshot.period_timestamp) {
                        *last = Some(snapshot.period_timestamp);
                        discovery_notify.notify_one();
                        true
                    } else {
                        false
                    }
                };
                if should_run {
                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let current_period = (current_time / 900) * 900;
                    eprintln!("🔄 Market ended (0s). Discovering new market for period {}...", current_period);
                    match get_or_discover_markets(&api, enable_eth, enable_solana, enable_xrp).await {
                        Ok((eth_market, btc_market, solana_market, xrp_market)) => {
                            if let Err(e) = monitor_for_discovery.update_markets(eth_market.clone(), btc_market.clone(), solana_market.clone(), xrp_market.clone()).await {
                                warn!("Failed to update markets (on 0s): {}", e);
                            } else {
                                eprintln!("✅ New markets loaded — starting trading for period {}", current_period);
                                if let Some(tracker) = &sim_tracker {
                                    tracker.log_market_start(
                                        current_period,
                                        &eth_market.condition_id,
                                        &btc_market.condition_id,
                                        &solana_market.condition_id,
                                        &xrp_market.condition_id,
                                    ).await;
                                }
                                trader_reset.reset_period(current_period).await;
                            }
                        }
                        Err(e) => warn!("Discovery on market end failed: {}", e),
                    }
                }
                return;
            }
            // New market active — reset so we can run discovery again when this market ends.
            {
                let mut last = last_notified_period.lock().await;
                *last = None;
            }

            // Track period for logging; do NOT skip first snapshot (we need it to place limit orders in 0-2s window).
            {
                let mut seen = last_seen_period.lock().await;
                *seen = Some(snapshot.period_timestamp);
            }

            let time_elapsed_seconds = PERIOD_DURATION - snapshot.time_remaining_seconds;

            // Simulation: when price crosses 0.45 (ask <= 0.45), consider limit order filled using snapshot prices so trading continues in same snapshot.
            if is_simulation {
                if let Some(tracker) = trader.get_simulation_tracker() {
                    let mut current_prices = std::collections::HashMap::new();
                    if let Some(u) = snapshot.btc_market.up_token.as_ref() {
                        current_prices.insert(u.token_id.clone(), u.clone());
                    }
                    if let Some(d) = snapshot.btc_market.down_token.as_ref() {
                        current_prices.insert(d.token_id.clone(), d.clone());
                    }
                    if enable_eth {
                        if let Some(u) = snapshot.eth_market.up_token.as_ref() {
                            current_prices.insert(u.token_id.clone(), u.clone());
                        }
                        if let Some(d) = snapshot.eth_market.down_token.as_ref() {
                            current_prices.insert(d.token_id.clone(), d.clone());
                        }
                    }
                    if enable_solana {
                        if let Some(u) = snapshot.solana_market.up_token.as_ref() {
                            current_prices.insert(u.token_id.clone(), u.clone());
                        }
                        if let Some(d) = snapshot.solana_market.down_token.as_ref() {
                            current_prices.insert(d.token_id.clone(), d.clone());
                        }
                    }
                    if enable_xrp {
                        if let Some(u) = snapshot.xrp_market.up_token.as_ref() {
                            current_prices.insert(u.token_id.clone(), u.clone());
                        }
                        if let Some(d) = snapshot.xrp_market.down_token.as_ref() {
                            current_prices.insert(d.token_id.clone(), d.clone());
                        }
                    }
                    // So simulation tracker can fill orders placed with (possibly different) token_id at start, add price data keyed by each pending limit trade's token_id.
                    let pending_limits = trader.get_pending_limit_trades_for_period(snapshot.period_timestamp).await;
                    for trade in &pending_limits {
                        let token_price = match &trade.token_type {
                            polymarket_trading_bot::detector::TokenType::BtcUp => snapshot.btc_market.up_token.as_ref(),
                            polymarket_trading_bot::detector::TokenType::BtcDown => snapshot.btc_market.down_token.as_ref(),
                            polymarket_trading_bot::detector::TokenType::EthUp if enable_eth => snapshot.eth_market.up_token.as_ref(),
                            polymarket_trading_bot::detector::TokenType::EthDown if enable_eth => snapshot.eth_market.down_token.as_ref(),
                            polymarket_trading_bot::detector::TokenType::SolanaUp if enable_solana => snapshot.solana_market.up_token.as_ref(),
                            polymarket_trading_bot::detector::TokenType::SolanaDown if enable_solana => snapshot.solana_market.down_token.as_ref(),
                            polymarket_trading_bot::detector::TokenType::XrpUp if enable_xrp => snapshot.xrp_market.up_token.as_ref(),
                            polymarket_trading_bot::detector::TokenType::XrpDown if enable_xrp => snapshot.xrp_market.down_token.as_ref(),
                            _ => None,
                        };
                        if let Some(tp) = token_price {
                            current_prices.insert(trade.token_id.clone(), tp.clone());
                        }
                    }
                    tracker.check_limit_orders(&current_prices).await;
                }
                if let Err(e) = trader.sync_pending_trades_from_simulation().await {
                    warn!("Simulation: sync pending trades from tracker failed: {}", e);
                }
                // Log when ask crosses LIMIT_PRICE and one side is now filled — we cancel opposite and start trailing stop.
                for (market_name, condition_id, up_opt, down_opt, up_type, down_type) in [
                    ("BTC", &snapshot.btc_market.condition_id, snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref(), polymarket_trading_bot::detector::TokenType::BtcUp, polymarket_trading_bot::detector::TokenType::BtcDown),
                    ("ETH", &snapshot.eth_market.condition_id, snapshot.eth_market.up_token.as_ref(), snapshot.eth_market.down_token.as_ref(), polymarket_trading_bot::detector::TokenType::EthUp, polymarket_trading_bot::detector::TokenType::EthDown),
                    ("SOL", &snapshot.solana_market.condition_id, snapshot.solana_market.up_token.as_ref(), snapshot.solana_market.down_token.as_ref(), polymarket_trading_bot::detector::TokenType::SolanaUp, polymarket_trading_bot::detector::TokenType::SolanaDown),
                    ("XRP", &snapshot.xrp_market.condition_id, snapshot.xrp_market.up_token.as_ref(), snapshot.xrp_market.down_token.as_ref(), polymarket_trading_bot::detector::TokenType::XrpUp, polymarket_trading_bot::detector::TokenType::XrpDown),
                ] {
                    if market_name == "BTC" && !enable_btc { continue; }
                    if market_name == "ETH" && !enable_eth { continue; }
                    if market_name == "SOL" && !enable_solana { continue; }
                    if market_name == "XRP" && !enable_xrp { continue; }
                    if let (Some(up), Some(down)) = (up_opt, down_opt) {
                        let up_ask = up.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(0.0);
                        let down_ask = down.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(0.0);
                        let up_t = trader.get_pending_limit_trade_by_market(snapshot.period_timestamp, condition_id, &up_type).await;
                        let down_t = trader.get_pending_limit_trade_by_market(snapshot.period_timestamp, condition_id, &down_type).await;
                        if let (Some(ut), Some(dt)) = (up_t.as_ref(), down_t.as_ref()) {
                            let (u_filled, d_filled) = (ut.buy_order_confirmed, dt.buy_order_confirmed);
                            if u_filled && !d_filled && up_ask > 0.0 && up_ask <= LIMIT_PRICE {
                                crate::log_println!("SIM: ✅ {} Up limit filled at ${:.4} (ask ≤ {:.2}) — cancelling Down limit, trailing stop active for Down", market_name, up_ask, LIMIT_PRICE);
                            } else if !u_filled && d_filled && down_ask > 0.0 && down_ask <= LIMIT_PRICE {
                                crate::log_println!("SIM: ✅ {} Down limit filled at ${:.4} (ask ≤ {:.2}) — cancelling Up limit, trailing stop active for Up", market_name, down_ask, LIMIT_PRICE);
                            }
                        }
                    }
                }
            }

            // Only place dual limit orders when a NEW market has just started (first 5s of period).
            // Do not place when the bot is started in the middle of a market (elapsed > 5s).
            let mut opportunities: Vec<BuyOpportunity> = Vec::new();
            if time_elapsed_seconds <= 5 {
            {
                let mut last = last_placed_period.lock().await;
                if last.map(|p| p == snapshot.period_timestamp).unwrap_or(false) {
                        // already placed for this period
                    } else {
                *last = Some(snapshot.period_timestamp);

            if enable_btc {
                if let Some(btc_up) = snapshot.btc_market.up_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.btc_market.condition_id.clone(),
                        token_id: btc_up.token_id.clone(),
                        token_type: polymarket_trading_bot::detector::TokenType::BtcUp,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                                    investment_amount_override: None,
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: None,
                    });
                }
                if let Some(btc_down) = snapshot.btc_market.down_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.btc_market.condition_id.clone(),
                        token_id: btc_down.token_id.clone(),
                        token_type: polymarket_trading_bot::detector::TokenType::BtcDown,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                                    investment_amount_override: None,
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: None,
                    });
                }
            }
            if enable_eth {
                if let Some(eth_up) = snapshot.eth_market.up_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.eth_market.condition_id.clone(),
                        token_id: eth_up.token_id.clone(),
                        token_type: polymarket_trading_bot::detector::TokenType::EthUp,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                                    investment_amount_override: None,
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: None,
                    });
                }
                if let Some(eth_down) = snapshot.eth_market.down_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.eth_market.condition_id.clone(),
                        token_id: eth_down.token_id.clone(),
                        token_type: polymarket_trading_bot::detector::TokenType::EthDown,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                                    investment_amount_override: None,
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: None,
                    });
                }
            }
            if enable_solana {
                if let Some(solana_up) = snapshot.solana_market.up_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.solana_market.condition_id.clone(),
                        token_id: solana_up.token_id.clone(),
                        token_type: polymarket_trading_bot::detector::TokenType::SolanaUp,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                                    investment_amount_override: None,
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: None,
                    });
                }
                if let Some(solana_down) = snapshot.solana_market.down_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.solana_market.condition_id.clone(),
                        token_id: solana_down.token_id.clone(),
                        token_type: polymarket_trading_bot::detector::TokenType::SolanaDown,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                                    investment_amount_override: None,
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: None,
                    });
                }
            }

            if enable_xrp {
                if let Some(xrp_up) = snapshot.xrp_market.up_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.xrp_market.condition_id.clone(),
                        token_id: xrp_up.token_id.clone(),
                        token_type: polymarket_trading_bot::detector::TokenType::XrpUp,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                                    investment_amount_override: None,
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: None,
                    });
                }
                if let Some(xrp_down) = snapshot.xrp_market.down_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.xrp_market.condition_id.clone(),
                        token_id: xrp_down.token_id.clone(),
                        token_type: polymarket_trading_bot::detector::TokenType::XrpDown,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                                    investment_amount_override: None,
                                    is_individual_hedge: false,
                                    is_standard_hedge: false,
                                    dual_limit_shares: None,
                    });
                            }
                        }
                    }
                }
            }

            if opportunities.is_empty() {
                // continue - may still need to hedge later in the period
            } else {
                crate::log_println!("🎯 Market start detected - placing limit buys at ${:.2}", limit_price);
                
                // Check all positions in parallel first
                let position_check_handles: Vec<_> = opportunities.iter()
                    .map(|opp| {
                        let trader_clone = trader.clone();
                        let opp_clone = opp.clone();
                        let period = opp.period_timestamp;
                        let token_type = opp.token_type.clone();
                        tokio::spawn(async move {
                            let has_position = trader_clone.has_active_position(period, token_type).await;
                            (opp_clone, !has_position)
                        })
                    })
                    .collect();
                
                // Wait for all position checks to complete
                let mut checked_opportunities = Vec::new();
                for handle in position_check_handles {
                    if let Ok((opp, should_place)) = handle.await {
                        if should_place {
                            checked_opportunities.push(opp);
                        }
                    }
                }
                
                // Place all limit buy orders in one batch request, then retry any that failed
                if !checked_opportunities.is_empty() {
                    let batch_shares = hedge_shares;
                    crate::log_println!("📤 Placing {} limit buy orders in one batch...", checked_opportunities.len());
                    let mut failed = Vec::new();
                    for batch_attempt in 1..=3 {
                        match trader.execute_limit_buy_batch(
                            &checked_opportunities,
                            limit_price,
                            batch_shares,
                            false,
                            false,
                        ).await {
                            Ok(responses) => {
                                for (opp, resp) in checked_opportunities.iter().zip(responses.iter()) {
                                    let success = resp.message.as_deref().map_or(false, |m| m.starts_with("Order ID"));
                                    if success {
                                        crate::log_println!("   ✅ Limit buy order placed for {}", opp.token_type.display_name());
                                    } else {
                                        warn!("Limit buy rejected for {}: {:?}", opp.token_type.display_name(), resp.message);
                                        failed.push(opp.clone());
                                    }
                                }
                                break;
                            }
                            Err(e) => {
                                warn!("Batch limit buy failed (attempt {}/3): {}", batch_attempt, e);
                                if batch_attempt == 3 {
                                    failed = checked_opportunities.clone();
                                } else {
                                    crate::log_println!("   ⚠️ Retrying batch in 2s...");
                                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                }
                            }
                        }
                    }
                    // Retry any orders that were rejected in the batch (one by one)
                    if !failed.is_empty() {
                        crate::log_println!("🔄 Retrying {} limit buy order(s) individually...", failed.len());
                        for opp in failed {
                            let mut confirmed = false;
                            for attempt in 1..=3 {
                                match trader.execute_limit_buy(&opp, false, Some(batch_shares), false).await {
                                    Ok(()) => {
                                        crate::log_println!("   ✅ Limit buy order CONFIRMED for {} (retry)", opp.token_type.display_name());
                                        confirmed = true;
                                        break;
                                    }
                                    Err(e) => {
                                        warn!("Retry for {} failed: {}", opp.token_type.display_name(), e);
                                        if attempt < 3 {
                                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                        }
                                    }
                                }
                            }
                            if !confirmed {
                                warn!("   ❌ Limit buy for {} could not be confirmed after retries", opp.token_type.display_name());
                            }
                        }
                    } else {
                        crate::log_println!("✅ All {} limit buy orders placed", checked_opportunities.len());
                    }
                }
            }

            // Price tracking and trend analysis logging (simulation mode only)
            if is_simulation {
                let simulation_tracker_opt = trader.get_simulation_tracker();
                if let Some(simulation_tracker) = simulation_tracker_opt {
                    let trend_history_size = config.trading.dual_limit_trend_history_size.unwrap_or(60);
                    let min_samples = 10; // Increased minimum samples for longer trend analysis
                    
                    // Track prices for all markets
                    // BTC Market
                    if let Some(btc_up) = snapshot.btc_market.up_token.as_ref() {
                        if let Some(bid) = btc_up.bid {
                            let bid_f64 = f64::try_from(bid).unwrap_or(0.0);
                            if bid_f64 > 0.0 {
                                simulation_tracker.track_price(
                                    snapshot.period_timestamp,
                                    &btc_up.token_id,
                                    time_elapsed_seconds,
                                    bid_f64,
                                    trend_history_size,
                                ).await;
                            }
                        } else {
                            debug!("BTC Up token has no bid price");
                        }
                    } else {
                        debug!("BTC Up token not available");
                    }
                    if let Some(btc_down) = snapshot.btc_market.down_token.as_ref() {
                        if let Some(bid) = btc_down.bid {
                            let bid_f64 = f64::try_from(bid).unwrap_or(0.0);
                            if bid_f64 > 0.0 {
                                simulation_tracker.track_price(
                                    snapshot.period_timestamp,
                                    &btc_down.token_id,
                                    time_elapsed_seconds,
                                    bid_f64,
                                    trend_history_size,
                                ).await;
                            }
                        } else {
                            debug!("BTC Down token has no bid price");
                        }
                    } else {
                        debug!("BTC Down token not available");
                    }
                    
                    // ETH Market
                    if enable_eth {
                        if let Some(eth_up) = snapshot.eth_market.up_token.as_ref() {
                            if let Some(bid) = eth_up.bid {
                                let bid_f64 = f64::try_from(bid).unwrap_or(0.0);
                                simulation_tracker.track_price(
                                    snapshot.period_timestamp,
                                    &eth_up.token_id,
                                    time_elapsed_seconds,
                                    bid_f64,
                                    trend_history_size,
                                ).await;
                            }
                        }
                        if let Some(eth_down) = snapshot.eth_market.down_token.as_ref() {
                            if let Some(bid) = eth_down.bid {
                                let bid_f64 = f64::try_from(bid).unwrap_or(0.0);
                                simulation_tracker.track_price(
                                    snapshot.period_timestamp,
                                    &eth_down.token_id,
                                    time_elapsed_seconds,
                                    bid_f64,
                                    trend_history_size,
                                ).await;
                            }
                        }
                    }
                    
                    // SOL Market
                    if enable_solana {
                        if let Some(solana_up) = snapshot.solana_market.up_token.as_ref() {
                            if let Some(bid) = solana_up.bid {
                                let bid_f64 = f64::try_from(bid).unwrap_or(0.0);
                                simulation_tracker.track_price(
                                    snapshot.period_timestamp,
                                    &solana_up.token_id,
                                    time_elapsed_seconds,
                                    bid_f64,
                                    trend_history_size,
                                ).await;
                            }
                        }
                        if let Some(solana_down) = snapshot.solana_market.down_token.as_ref() {
                            if let Some(bid) = solana_down.bid {
                                let bid_f64 = f64::try_from(bid).unwrap_or(0.0);
                                simulation_tracker.track_price(
                                    snapshot.period_timestamp,
                                    &solana_down.token_id,
                                    time_elapsed_seconds,
                                    bid_f64,
                                    trend_history_size,
                                ).await;
                            }
                        }
                    }
                    
                    // XRP Market
                    if enable_xrp {
                        if let Some(xrp_up) = snapshot.xrp_market.up_token.as_ref() {
                            if let Some(bid) = xrp_up.bid {
                                let bid_f64 = f64::try_from(bid).unwrap_or(0.0);
                                simulation_tracker.track_price(
                                    snapshot.period_timestamp,
                                    &xrp_up.token_id,
                                    time_elapsed_seconds,
                                    bid_f64,
                                    trend_history_size,
                                ).await;
                            }
                        }
                        if let Some(xrp_down) = snapshot.xrp_market.down_token.as_ref() {
                            if let Some(bid) = xrp_down.bid {
                                let bid_f64 = f64::try_from(bid).unwrap_or(0.0);
                                simulation_tracker.track_price(
                                    snapshot.period_timestamp,
                                    &xrp_down.token_id,
                                    time_elapsed_seconds,
                                    bid_f64,
                                    trend_history_size,
                                ).await;
                            }
                        }
                    }
                    
                    // Log trend analysis periodically (every 30 seconds or at key intervals)
                    let should_log_trends = time_elapsed_seconds % 30 == 0 || 
                                          time_elapsed_seconds == 300 ||  // 5 minutes
                                          time_elapsed_seconds == 600;    // 10 minutes
                    
                    if should_log_trends {
                        let mut trend_count = 0;
                        
                        crate::log_println!("═══════════════════════════════════════════════════════════");
                        crate::log_println!("📊 TREND ANALYSIS REPORT - {}m {}s elapsed", 
                                          time_elapsed_seconds / 60, 
                                          time_elapsed_seconds % 60);
                        crate::log_println!("═══════════════════════════════════════════════════════════");
                        
                        // BTC Market
                        if let Some(btc_up) = snapshot.btc_market.up_token.as_ref() {
                            debug!("Logging trend for BTC Up token: {}", &btc_up.token_id[..16]);
                            simulation_tracker.log_trend_analysis(
                                snapshot.period_timestamp,
                                &btc_up.token_id,
                                &polymarket_trading_bot::detector::TokenType::BtcUp,
                                min_samples,
                            ).await;
                            trend_count += 1;
                        } else {
                            debug!("BTC Up token not available in snapshot");
                            crate::log_println!("⚠️  BTC Up: Token not available");
                        }
                        if let Some(btc_down) = snapshot.btc_market.down_token.as_ref() {
                            debug!("Logging trend for BTC Down token: {}", &btc_down.token_id[..16]);
                            simulation_tracker.log_trend_analysis(
                                snapshot.period_timestamp,
                                &btc_down.token_id,
                                &polymarket_trading_bot::detector::TokenType::BtcDown,
                                min_samples,
                            ).await;
                            trend_count += 1;
                        } else {
                            debug!("BTC Down token not available in snapshot");
                            crate::log_println!("⚠️  BTC Down: Token not available");
                        }
                        
                        // ETH Market
                        if enable_eth {
                            if let Some(eth_up) = snapshot.eth_market.up_token.as_ref() {
                                simulation_tracker.log_trend_analysis(
                                    snapshot.period_timestamp,
                                    &eth_up.token_id,
                                    &polymarket_trading_bot::detector::TokenType::EthUp,
                                    min_samples,
                                ).await;
                                trend_count += 1;
                            } else {
                                crate::log_println!("⚠️  ETH Up: Token not available");
                            }
                            if let Some(eth_down) = snapshot.eth_market.down_token.as_ref() {
                                simulation_tracker.log_trend_analysis(
                                    snapshot.period_timestamp,
                                    &eth_down.token_id,
                                    &polymarket_trading_bot::detector::TokenType::EthDown,
                                    min_samples,
                                ).await;
                                trend_count += 1;
                            } else {
                                crate::log_println!("⚠️  ETH Down: Token not available");
                            }
                        }
                        
                        // SOL Market
                        if enable_solana {
                            if let Some(solana_up) = snapshot.solana_market.up_token.as_ref() {
                                simulation_tracker.log_trend_analysis(
                                    snapshot.period_timestamp,
                                    &solana_up.token_id,
                                    &polymarket_trading_bot::detector::TokenType::SolanaUp,
                                    min_samples,
                                ).await;
                                trend_count += 1;
                            } else {
                                crate::log_println!("⚠️  SOL Up: Token not available");
                            }
                            if let Some(solana_down) = snapshot.solana_market.down_token.as_ref() {
                                simulation_tracker.log_trend_analysis(
                                    snapshot.period_timestamp,
                                    &solana_down.token_id,
                                    &polymarket_trading_bot::detector::TokenType::SolanaDown,
                                    min_samples,
                                ).await;
                                trend_count += 1;
                            } else {
                                crate::log_println!("⚠️  SOL Down: Token not available");
                            }
                        }
                        
                        // XRP Market
                        if enable_xrp {
                            if let Some(xrp_up) = snapshot.xrp_market.up_token.as_ref() {
                                simulation_tracker.log_trend_analysis(
                                    snapshot.period_timestamp,
                                    &xrp_up.token_id,
                                    &polymarket_trading_bot::detector::TokenType::XrpUp,
                                    min_samples,
                                ).await;
                                trend_count += 1;
                            } else {
                                crate::log_println!("⚠️  XRP Up: Token not available");
                            }
                            if let Some(xrp_down) = snapshot.xrp_market.down_token.as_ref() {
                                simulation_tracker.log_trend_analysis(
                                    snapshot.period_timestamp,
                                    &xrp_down.token_id,
                                    &polymarket_trading_bot::detector::TokenType::XrpDown,
                                    min_samples,
                                ).await;
                                trend_count += 1;
                            } else {
                                crate::log_println!("⚠️  XRP Down: Token not available");
                            }
                        }
                        
                        if trend_count == 0 {
                            crate::log_println!("⚠️  No tokens available for trend analysis");
                        }
                        
                        crate::log_println!("═══════════════════════════════════════════════════════════");
                    }
                }
            }

            // Simulation: show limit fill status, one-side-filled state, and trailing-stop / hedge trigger (so user sees at which price Up/Down can be bought and when hedge would fire).
            if is_simulation && (time_elapsed_seconds % 15 == 0 || time_elapsed_seconds <= 30) {
                // Re-sync so limit fill state is current (tracker may have filled this snapshot; sync updates pending_trades).
                if let Err(e) = trader.sync_pending_trades_from_simulation().await {
                    warn!("Simulation: sync before SIM status failed: {}", e);
                }
                let hedge_trailing_stop = config.trading.dual_limit_hedge_trailing_stop.unwrap_or(0.03);
                let mut sim_markets: Vec<(&str, &str, &polymarket_trading_bot::models::TokenPrice, &polymarket_trading_bot::models::TokenPrice, polymarket_trading_bot::detector::TokenType, polymarket_trading_bot::detector::TokenType)> = Vec::new();
                if enable_btc {
                    if let (Some(u), Some(d)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) {
                        sim_markets.push(("BTC", &snapshot.btc_market.condition_id, u, d, polymarket_trading_bot::detector::TokenType::BtcUp, polymarket_trading_bot::detector::TokenType::BtcDown));
                    }
                }
                if enable_eth {
                    if let (Some(u), Some(d)) = (snapshot.eth_market.up_token.as_ref(), snapshot.eth_market.down_token.as_ref()) {
                        sim_markets.push(("ETH", &snapshot.eth_market.condition_id, u, d, polymarket_trading_bot::detector::TokenType::EthUp, polymarket_trading_bot::detector::TokenType::EthDown));
                    }
                }
                if enable_solana {
                    if let (Some(u), Some(d)) = (snapshot.solana_market.up_token.as_ref(), snapshot.solana_market.down_token.as_ref()) {
                        sim_markets.push(("SOL", &snapshot.solana_market.condition_id, u, d, polymarket_trading_bot::detector::TokenType::SolanaUp, polymarket_trading_bot::detector::TokenType::SolanaDown));
                    }
                }
                if enable_xrp {
                    if let (Some(u), Some(d)) = (snapshot.xrp_market.up_token.as_ref(), snapshot.xrp_market.down_token.as_ref()) {
                        sim_markets.push(("XRP", &snapshot.xrp_market.condition_id, u, d, polymarket_trading_bot::detector::TokenType::XrpUp, polymarket_trading_bot::detector::TokenType::XrpDown));
                    }
                }
                for (market_name, condition_id, up_token, down_token, up_type, down_type) in &sim_markets {
                    let up_bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                    let up_ask = up_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(0.0);
                    let down_bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                    let down_ask = down_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(0.0);
                    let up_limit_fills = up_ask > 0.0 && up_ask <= LIMIT_PRICE;
                    let down_limit_fills = down_ask > 0.0 && down_ask <= LIMIT_PRICE;
                    let up_trade = trader.get_pending_limit_trade_by_market(snapshot.period_timestamp, condition_id, up_type).await;
                    let down_trade = trader.get_pending_limit_trade_by_market(snapshot.period_timestamp, condition_id, down_type).await;
                    let (up_filled, down_filled) = match (up_trade.as_ref(), down_trade.as_ref()) {
                        (Some(u), Some(d)) => (u.buy_order_confirmed, d.buy_order_confirmed),
                        _ => (false, false),
                    };
                    crate::log_println!("───────────────────────────────────────────────────────────────");
                    crate::log_println!("SIM [{}] ({}m {}s) | Up: bid=${:.4} ask=${:.4} → limit 0.45 fills: {} | Down: bid=${:.4} ask=${:.4} → limit 0.45 fills: {}",
                        market_name, time_elapsed_seconds / 60, time_elapsed_seconds % 60,
                        up_bid, up_ask, if up_limit_fills { "YES" } else { "no" },
                        down_bid, down_ask, if down_limit_fills { "YES" } else { "no" });
                    crate::log_println!("SIM [{}] Limit fill state: Up filled={} Down filled={}",
                        market_name, up_filled, down_filled);
                    if up_filled != down_filled {
                        let (unfilled_bid, unfilled_ask, unfilled_name) = if up_filled {
                            (down_bid, down_ask, "Down")
                        } else {
                            (up_bid, up_ask, "Up")
                        };
                        let price_key = (snapshot.period_timestamp, (*condition_id).to_string());
                        let lowest = two_min_trailing_min.lock().await.get(&price_key).copied().unwrap_or(unfilled_bid);
                        let trigger_price = lowest + hedge_trailing_stop;
                        // Trigger when price goes UP over lowest by hedge_trailing_stop (buy at ask on the bounce).
                        let would_trigger = unfilled_bid <= NINETY_SEC_HEDGE_MAX_PRICE && unfilled_bid >= trigger_price;
                        let already_hedged_2min = two_min_hedge_markets.lock().await.contains(&price_key);
                        if already_hedged_2min {
                            crate::log_println!("SIM [{}] One side filled → unfilled {} hedged (2-min market buy done).", market_name, unfilled_name);
                        } else {
                            crate::log_println!("SIM [{}] One side filled. Unfilled {} bid=${:.4} ask=${:.4}. Lowest=${:.4}, hedge when price >= lowest+{:.3}={:.4}. Would trigger now: {}",
                                market_name, unfilled_name, unfilled_bid, unfilled_ask, lowest, hedge_trailing_stop, trigger_price, would_trigger);
                        }
                    } else if up_filled && down_filled {
                        crate::log_println!("SIM [{}] Both sides filled at 0.45 (no hedge).", market_name);
                    } else {
                        crate::log_println!("SIM [{}] Waiting for limit fills (both unfilled).", market_name);
                    }
                }
                if !sim_markets.is_empty() {
                    crate::log_println!("───────────────────────────────────────────────────────────────");
                }
            }

            // As soon as one side is filled: cancel the other side's limit order (no wait for hedge). Then trailing-stop can buy the unfilled side before 2 min.
            if !HEDGE_DISABLED {
                let cancelled_guard = opposite_limit_cancelled_for_market.lock().await;
                let hedge_guard = hedge_executed_for_market.lock().await;
                let two_min_guard = two_min_hedge_markets.lock().await;
                let mut markets_to_cancel: Vec<(&str, &str, &polymarket_trading_bot::models::TokenPrice, &polymarket_trading_bot::models::TokenPrice, polymarket_trading_bot::detector::TokenType, polymarket_trading_bot::detector::TokenType)> = Vec::new();
                if enable_btc {
                    if let (Some(btc_up), Some(btc_down)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.btc_market.condition_id.clone());
                        if !cancelled_guard.contains(&key) && !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_cancel.push(("BTC", &snapshot.btc_market.condition_id, btc_up, btc_down, polymarket_trading_bot::detector::TokenType::BtcUp, polymarket_trading_bot::detector::TokenType::BtcDown));
                        }
                    }
                }
                if enable_eth {
                    if let (Some(eu), Some(ed)) = (snapshot.eth_market.up_token.as_ref(), snapshot.eth_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.eth_market.condition_id.clone());
                        if !cancelled_guard.contains(&key) && !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_cancel.push(("ETH", &snapshot.eth_market.condition_id, eu, ed, polymarket_trading_bot::detector::TokenType::EthUp, polymarket_trading_bot::detector::TokenType::EthDown));
                        }
                    }
                }
                if enable_solana {
                    if let (Some(su), Some(sd)) = (snapshot.solana_market.up_token.as_ref(), snapshot.solana_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.solana_market.condition_id.clone());
                        if !cancelled_guard.contains(&key) && !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_cancel.push(("SOL", &snapshot.solana_market.condition_id, su, sd, polymarket_trading_bot::detector::TokenType::SolanaUp, polymarket_trading_bot::detector::TokenType::SolanaDown));
                        }
                    }
                }
                if enable_xrp {
                    if let (Some(xu), Some(xd)) = (snapshot.xrp_market.up_token.as_ref(), snapshot.xrp_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.xrp_market.condition_id.clone());
                        if !cancelled_guard.contains(&key) && !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_cancel.push(("XRP", &snapshot.xrp_market.condition_id, xu, xd, polymarket_trading_bot::detector::TokenType::XrpUp, polymarket_trading_bot::detector::TokenType::XrpDown));
                        }
                    }
                }
                drop(cancelled_guard);
                drop(hedge_guard);
                drop(two_min_guard);
                for (market_name, condition_id, up_token, down_token, up_type, down_type) in &markets_to_cancel {
                    let up_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &up_token.token_id).await;
                    let down_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &down_token.token_id).await;
                    let (Some(up_t), Some(down_t)) = (up_trade.as_ref(), down_trade.as_ref()) else { continue };
                    let (up_filled, down_filled) = (up_t.buy_order_confirmed, down_t.buy_order_confirmed);
                    if up_filled == down_filled {
                        continue; // both or neither
                    }
                    let (unfilled_token, unfilled_type) = if !up_filled && down_filled {
                        (up_token, up_type.clone())
                    } else {
                        (down_token, down_type.clone())
                    };
                    let key = (snapshot.period_timestamp, (*condition_id).to_string());
                    for attempt in 1..=3 {
                        match trader.cancel_pending_limit_buy(snapshot.period_timestamp, &unfilled_token.token_id).await {
                            Ok(()) => {
                                crate::log_println!("   🗑️ One side filled: cancelled unfilled $0.45 limit for {} ({})", market_name, unfilled_type.display_name());
                                opposite_limit_cancelled_for_market.lock().await.insert(key.clone());
                                break;
                            }
                            Err(e) => {
                                warn!("Cancel unfilled limit (one-side-filled) failed for {} (attempt {}/3): {}", market_name, attempt, e);
                                if attempt < 3 {
                                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                }
                            }
                        }
                    }
                }
            }

            // 2-min hedge: if one side filled and unfilled price < 0.5, use trailing stop to buy unfilled side. Runs as soon as one side fills (including before 2 min).
            // If limit fills at 0.45 during this window, both sides filled → we skip and do nothing.
            if !HEDGE_DISABLED {
                let hedge_guard = hedge_executed_for_market.lock().await;
                let two_min_guard = two_min_hedge_markets.lock().await;
                let mut markets_to_check: Vec<(&str, &str, &polymarket_trading_bot::models::TokenPrice, &polymarket_trading_bot::models::TokenPrice, polymarket_trading_bot::detector::TokenType, polymarket_trading_bot::detector::TokenType)> = Vec::new();
                if enable_btc {
                    if let (Some(btc_up), Some(btc_down)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.btc_market.condition_id.clone());
                        if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_check.push(("BTC", &snapshot.btc_market.condition_id, btc_up, btc_down, polymarket_trading_bot::detector::TokenType::BtcUp, polymarket_trading_bot::detector::TokenType::BtcDown));
                        }
                    }
                }
                if enable_eth {
                    if let (Some(eu), Some(ed)) = (snapshot.eth_market.up_token.as_ref(), snapshot.eth_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.eth_market.condition_id.clone());
                        if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_check.push(("ETH", &snapshot.eth_market.condition_id, eu, ed, polymarket_trading_bot::detector::TokenType::EthUp, polymarket_trading_bot::detector::TokenType::EthDown));
                        }
                    }
                }
                if enable_solana {
                    if let (Some(su), Some(sd)) = (snapshot.solana_market.up_token.as_ref(), snapshot.solana_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.solana_market.condition_id.clone());
                        if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_check.push(("SOL", &snapshot.solana_market.condition_id, su, sd, polymarket_trading_bot::detector::TokenType::SolanaUp, polymarket_trading_bot::detector::TokenType::SolanaDown));
                        }
                    }
                }
                if enable_xrp {
                    if let (Some(xu), Some(xd)) = (snapshot.xrp_market.up_token.as_ref(), snapshot.xrp_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.xrp_market.condition_id.clone());
                        if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_check.push(("XRP", &snapshot.xrp_market.condition_id, xu, xd, polymarket_trading_bot::detector::TokenType::XrpUp, polymarket_trading_bot::detector::TokenType::XrpDown));
                        }
                    }
                }
                drop(hedge_guard);
                drop(two_min_guard);
                for (market_name, condition_id, up_token, down_token, up_type, down_type) in &markets_to_check {
                    let price_key = (snapshot.period_timestamp, (*condition_id).to_string());
                    let already_cancelled = opposite_limit_cancelled_for_market.lock().await.contains(&price_key);
                    let up_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &up_token.token_id).await;
                    let down_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &down_token.token_id).await;
                    // One side filled, other side either still pending or already cancelled (we remove cancelled from pending_trades).
                    let (unfilled_token, unfilled_type, _current_bid, current_ask, _filled_units, filled_side_price) = match (up_trade.as_ref(), down_trade.as_ref()) {
                        (Some(up_t), Some(down_t)) if up_t.buy_order_confirmed != down_t.buy_order_confirmed => {
                            if up_t.buy_order_confirmed {
                                let bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                let ask = down_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                (down_token, down_type.clone(), bid, ask, up_t.units, up_t.purchase_price)
                            } else {
                                let bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                let ask = up_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                (up_token, up_type.clone(), bid, ask, down_t.units, down_t.purchase_price)
                            }
                        }
                        (Some(up_t), None) if up_t.buy_order_confirmed && already_cancelled => {
                            // Up filled, Down cancelled (removed from pending)
                            let bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                            let ask = down_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                            (down_token, down_type.clone(), bid, ask, up_t.units, up_t.purchase_price)
                        }
                        (None, Some(down_t)) if down_t.buy_order_confirmed && already_cancelled => {
                            // Down filled, Up cancelled (removed from pending)
                            let bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                            let ask = up_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                            (up_token, up_type.clone(), bid, ask, down_t.units, down_t.purchase_price)
                        }
                        _ => continue,
                    };
                    // Before 4 min: if unfilled ask already >= 0.75, buy at market now (don't wait for 4-min block — price could go higher).
                    if time_elapsed_seconds < TWO_MIN_AFTER_SECONDS && current_ask >= FOUR_MIN_HEDGE_BUY_OVER_PRICE {
                        if hedge_shares >= 0.001 {
                            let investment_high = hedge_shares * current_ask;
                            crate::log_println!(
                                "🕐 EARLY HIGH PRICE (before 4 min): {} unfilled ask={:.4} >= {:.2}, buying {:.6} shares at market now (don't wait for 4 min)",
                                market_name, current_ask, FOUR_MIN_HEDGE_BUY_OVER_PRICE, hedge_shares
                            );
                            let opp_high = BuyOpportunity {
                                condition_id: condition_id.to_string(),
                                token_id: unfilled_token.token_id.clone(),
                                token_type: unfilled_type.clone(),
                                bid_price: current_ask,
                                period_timestamp: snapshot.period_timestamp,
                                time_remaining_seconds: snapshot.time_remaining_seconds,
                                time_elapsed_seconds,
                                use_market_order: true,
                                investment_amount_override: Some(investment_high),
                                is_individual_hedge: true,
                                is_standard_hedge: false,
                                dual_limit_shares: None,
                            };
                            let mut buy_ok_high = false;
                            for attempt in 1..=3 {
                                match trader.execute_buy(&opp_high).await {
                                    Ok(()) => {
                                        buy_ok_high = true;
                                        break;
                                    }
                                    Err(e) => {
                                        warn!("Early high-price hedge: market buy failed for {} (attempt {}/3): {}", market_name, attempt, e);
                                        if attempt < 3 {
                                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                        }
                                    }
                                }
                            }
                            if buy_ok_high {
                                trader.mark_limit_trade_filled_by_hedge(snapshot.period_timestamp, &unfilled_token.token_id).await;
                                if !already_cancelled {
                                    for attempt in 1..=3 {
                                        if let Ok(()) = trader.cancel_pending_limit_buy(snapshot.period_timestamp, &unfilled_token.token_id).await {
                                            crate::log_println!("   🗑️ Cancelled unfilled $0.45 limit order (early high price before 4 min)");
                                            break;
                                        }
                                        if attempt < 3 {
                                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                        }
                                    }
                                }
                                hedge_executed_for_market.lock().await.insert((snapshot.period_timestamp, (*condition_id).to_string()));
                                hedge_price_per_market.lock().await.insert((snapshot.period_timestamp, (*condition_id).to_string()), current_ask);
                                two_min_trailing_min_ask.lock().await.remove(&price_key);
                                continue;
                            }
                        }
                    }
                    let hedge_trailing_stop = config.trading.dual_limit_hedge_trailing_stop.unwrap_or(0.03);
                    // Check ASK against time-based threshold: before 2 min < 0.45, 2–4 min < 0.5, after 4 min < 0.65.
                    let (band_threshold, band_label) = if time_elapsed_seconds < NINETY_SEC_AFTER_SECONDS {
                        (LIMIT_PRICE, "before 2-min: ask < 0.45")
                    } else if time_elapsed_seconds < TWO_MIN_AFTER_SECONDS {
                        (NINETY_SEC_HEDGE_MAX_PRICE, "2-min: ask < 0.5")
                    } else {
                        (FOUR_MIN_HEDGE_MAX_PRICE, "4-min: ask < 0.65")
                    };
                    let mut allow_buy_above_band = false;
                    if current_ask >= band_threshold {
                        let lowest_before = two_min_trailing_min_ask.lock().await.get(&price_key).copied().unwrap_or(current_ask);
                        let bounce_threshold = band_threshold - hedge_trailing_stop;
                        if lowest_before <= bounce_threshold {
                            allow_buy_above_band = true;
                            crate::log_println!(
                                "   Trailing [{}] unfilled {}: ask={:.4} >= {:.2} ({}) but lowest_ask={:.4} <= {:.4} → allow buy (valid bounce)",
                                market_name, unfilled_type.display_name(), current_ask, band_threshold, band_label, lowest_before, bounce_threshold
                            );
                            // Fall through to trailing logic; do not update lowest_ask
                        } else {
                            two_min_trailing_min_ask.lock().await.insert(price_key.clone(), current_ask);
                            crate::log_println!(
                                "   Trailing [{}] unfilled {}: ask={:.4} >= {:.2} ({}) → update lowest_ask to {:.4}",
                                market_name, unfilled_type.display_name(), current_ask, band_threshold, band_label, current_ask
                            );
                            continue;
                        }
                    }
                    // When we first cross into 4-min window, reset trailing min so we use current price as new baseline (not 2-min-era lowest). Skip reset if we're allowing buy above band so we keep the low.
                    if time_elapsed_seconds >= TWO_MIN_AFTER_SECONDS && !allow_buy_above_band {
                        let mut reset_set = two_min_trailing_reset_at_4min.lock().await;
                        if !reset_set.contains(&price_key) {
                            reset_set.insert(price_key.clone());
                            drop(reset_set);
                            two_min_trailing_min_ask.lock().await.remove(&price_key);
                        }
                    }
                    // Trailing stop: track lowest ASK (we buy at ask). Trigger when current_ask >= lowest_ask + hedge_trailing_stop (ask bounced from low; we buy at current ask).
                    {
                        let mut min_map = two_min_trailing_min_ask.lock().await;
                        let trailing_min_ask = min_map.get(&price_key).copied().unwrap_or(current_ask);
                        let new_min_ask = trailing_min_ask.min(current_ask);
                        min_map.insert(price_key.clone(), new_min_ask);
                        if current_ask < new_min_ask + hedge_trailing_stop {
                            crate::log_println!(
                                "   Trailing [{}] unfilled {} (2-min): ask={:.4} lowest_ask={:.4} trigger_at={:.4} (+{:.3}) (waiting for bounce)",
                                market_name, unfilled_type.display_name(), current_ask, new_min_ask, new_min_ask + hedge_trailing_stop, hedge_trailing_stop
                            );
                            continue; // ask not yet bounced: need current_ask >= lowest_ask + trailing_stop to buy
                        }
                        // current_ask >= lowest_ask + hedge_trailing_stop — would trigger. Before 2 min: if ask >= 0.45, only buy if we had a valid dip (lowest_ask <= 0.45 - trailing_stop).
                        if time_elapsed_seconds < NINETY_SEC_AFTER_SECONDS && current_ask >= LIMIT_PRICE {
                            let bounce_threshold = LIMIT_PRICE - hedge_trailing_stop;
                            if new_min_ask <= bounce_threshold {
                                // Valid bounce from below (0.45 - trailing_stop); allow buy at current ask
                            } else {
                                min_map.insert(price_key.clone(), current_ask);
                                crate::log_println!(
                                    "   Trailing [{}] unfilled {} (2-min): ask={:.4} >= 0.45 (before 2 min) → skip buy, update lowest_ask to {:.4}",
                                    market_name, unfilled_type.display_name(), current_ask, current_ask
                                );
                                continue;
                            }
                        }
                        // trigger market buy at ask
                    }
                    if hedge_shares < 0.001 {
                        continue;
                    }
                    let lowest_ask = two_min_trailing_min_ask.lock().await.get(&price_key).copied().unwrap_or(current_ask);
                    crate::log_println!(
                        "   Trailing [{}] unfilled {} (2-min): TRIGGER ask={:.4} >= lowest_ask+{:.3} (lowest_ask={:.4}) → executing market buy",
                        market_name, unfilled_type.display_name(), current_ask, hedge_trailing_stop, lowest_ask
                    );
                    let investment = hedge_shares * current_ask;
                    if is_simulation {
                        crate::log_println!("SIM: ⏱️ 2-MIN HEDGE — lowest_ask=${:.4}, ask=${:.4} <= lowest_ask+{:.3}, buying {} at ask=${:.4}, {:.6} shares (limit side bought at ${:.4})",
                            lowest_ask, current_ask, hedge_trailing_stop, unfilled_type.display_name(), current_ask, hedge_shares, filled_side_price);
                    }
                    crate::log_println!("⏱️ 2-MIN HEDGE (same-size): {} {} unfilled; ask >= lowest_ask+{:.3}; buying at ask ${:.4}, {:.6} shares. Limit-filled side bought at ${:.4}", market_name, unfilled_type.display_name(), hedge_trailing_stop, current_ask, hedge_shares, filled_side_price);
                    let opp = BuyOpportunity {
                        condition_id: condition_id.to_string(),
                        token_id: unfilled_token.token_id.clone(),
                        token_type: unfilled_type.clone(),
                        bid_price: current_ask,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: true,
                        investment_amount_override: Some(investment),
                        is_individual_hedge: true,
                        is_standard_hedge: false,
                        dual_limit_shares: None,
                    };
                    let mut buy_ok = false;
                    for attempt in 1..=3 {
                        match trader.execute_buy(&opp).await {
                            Ok(()) => {
                                buy_ok = true;
                                break;
                            }
                            Err(e) => {
                                warn!("2-min hedge: market buy failed for {} (attempt {}/3): {}", market_name, attempt, e);
                                if attempt < 3 {
                                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                }
                            }
                        }
                    }
                    if !buy_ok {
                        warn!("2-min hedge: market buy failed after 3 attempts for {} - leaving limit order in place, will retry on next snapshot", market_name);
                        continue;
                    }
                    trader.mark_limit_trade_filled_by_hedge(snapshot.period_timestamp, &unfilled_token.token_id).await;
                    // Buy succeeded. Only try to cancel unfilled limit if we haven't already (we cancel when one side fills, so usually already cancelled).
                    if !already_cancelled {
                        let mut cancel_ok = false;
                        for attempt in 1..=3 {
                            match trader.cancel_pending_limit_buy(snapshot.period_timestamp, &unfilled_token.token_id).await {
                                Ok(()) => {
                                    crate::log_println!("   🗑️ Cancelled unfilled $0.45 limit order (2-min hedge)");
                                    cancel_ok = true;
                                    break;
                                }
                                Err(e) => {
                                    warn!("2-min hedge: cancel limit order failed (attempt {}/3): {} - limit may still be live!", attempt, e);
                                    if attempt < 3 {
                                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                    }
                                }
                            }
                        }
                        if !cancel_ok {
                            warn!("2-min hedge: could not cancel unfilled limit after 3 attempts - you may have double position for {}", market_name);
                        }
                    }
                    // 2-min hedge: track in two_min_hedge_markets and in hedge_executed_for_market so low-price exit (0.05/0.99) runs for 2-min hedges too.
                    let mut set2 = two_min_hedge_markets.lock().await;
                    set2.insert((snapshot.period_timestamp, (*condition_id).to_string()));
                    two_min_trailing_min.lock().await.remove(&price_key);
                    two_min_trailing_min_ask.lock().await.remove(&price_key);
                    drop(set2);
                    hedge_executed_for_market.lock().await.insert((snapshot.period_timestamp, (*condition_id).to_string()));
                    hedge_price_per_market.lock().await.insert((snapshot.period_timestamp, (*condition_id).to_string()), current_ask);
                }
            }

            // 4-min hedge: after 4 min, if one side filled and 0.5 < unfilled price < 0.65, hedge on uptick. If price drops below 0.5, 2-min mode applies (above).
            // Skip markets already hedged via 2-min (avoid double hedge). Only try markets not in hedge_executed_for_market.
            if !HEDGE_DISABLED && time_elapsed_seconds >= TWO_MIN_AFTER_SECONDS {
                let hedge_guard = hedge_executed_for_market.lock().await;
                let two_min_guard = two_min_hedge_markets.lock().await;
                    let mut markets_to_check: Vec<(&str, &str, &polymarket_trading_bot::models::TokenPrice, &polymarket_trading_bot::models::TokenPrice, polymarket_trading_bot::detector::TokenType, polymarket_trading_bot::detector::TokenType)> = Vec::new();
                    if enable_btc {
                        if let (Some(btc_up), Some(btc_down)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) {
                            let key = (snapshot.period_timestamp, snapshot.btc_market.condition_id.clone());
                            if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                                markets_to_check.push(("BTC", &snapshot.btc_market.condition_id, btc_up, btc_down, polymarket_trading_bot::detector::TokenType::BtcUp, polymarket_trading_bot::detector::TokenType::BtcDown));
                            }
                        }
                    }
                    if enable_eth {
                        if let (Some(eu), Some(ed)) = (snapshot.eth_market.up_token.as_ref(), snapshot.eth_market.down_token.as_ref()) {
                            let key = (snapshot.period_timestamp, snapshot.eth_market.condition_id.clone());
                            if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                                markets_to_check.push(("ETH", &snapshot.eth_market.condition_id, eu, ed, polymarket_trading_bot::detector::TokenType::EthUp, polymarket_trading_bot::detector::TokenType::EthDown));
                            }
                        }
                    }
                    if enable_solana {
                        if let (Some(su), Some(sd)) = (snapshot.solana_market.up_token.as_ref(), snapshot.solana_market.down_token.as_ref()) {
                            let key = (snapshot.period_timestamp, snapshot.solana_market.condition_id.clone());
                            if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                                markets_to_check.push(("SOL", &snapshot.solana_market.condition_id, su, sd, polymarket_trading_bot::detector::TokenType::SolanaUp, polymarket_trading_bot::detector::TokenType::SolanaDown));
                            }
                        }
                    }
                    if enable_xrp {
                        if let (Some(xu), Some(xd)) = (snapshot.xrp_market.up_token.as_ref(), snapshot.xrp_market.down_token.as_ref()) {
                            let key = (snapshot.period_timestamp, snapshot.xrp_market.condition_id.clone());
                            if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                                markets_to_check.push(("XRP", &snapshot.xrp_market.condition_id, xu, xd, polymarket_trading_bot::detector::TokenType::XrpUp, polymarket_trading_bot::detector::TokenType::XrpDown));
                            }
                        }
                    }
                drop(two_min_guard);
                drop(hedge_guard);
                for (market_name, condition_id, up_token, down_token, up_type, down_type) in &markets_to_check {
                        let price_key_4m = (snapshot.period_timestamp, (*condition_id).to_string());
                        let already_cancelled_4m = opposite_limit_cancelled_for_market.lock().await.contains(&price_key_4m);
                        let up_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &up_token.token_id).await;
                        let down_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &down_token.token_id).await;
                        let (unfilled_token, unfilled_type, current_bid, current_ask_4m, _filled_units) = match (up_trade.as_ref(), down_trade.as_ref()) {
                            (Some(up_t), Some(down_t)) if up_t.buy_order_confirmed != down_t.buy_order_confirmed => {
                                if down_t.buy_order_confirmed {
                                    let bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                    let ask = up_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                    (up_token, up_type.clone(), bid, ask, down_t.units)
                                } else {
                                    let bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                    let ask = down_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                    (down_token, down_type.clone(), bid, ask, up_t.units)
                                }
                            }
                            (Some(up_t), None) if up_t.buy_order_confirmed && already_cancelled_4m => {
                                let bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                let ask = down_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                (down_token, down_type.clone(), bid, ask, up_t.units)
                            }
                            (None, Some(down_t)) if down_t.buy_order_confirmed && already_cancelled_4m => {
                                let bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                let ask = up_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                (up_token, up_type.clone(), bid, ask, down_t.units)
                            }
                            _ => continue,
                        };
                        // 4-min: band checks use bid; we buy at market so use ask for investment and stored hedge price.
                        // 4-min: if price > 0.75, buy at market immediately (no trailing). Once hedged, trailing is not tracked for this market.
                        if current_bid > FOUR_MIN_HEDGE_BUY_OVER_PRICE {
                            if hedge_shares < 0.001 {
                                continue;
                            }
                            let investment_over = hedge_shares * current_ask_4m;
                            crate::log_println!("🕐 4-MIN HEDGE (price > {:.2}): {} unfilled at ask ${:.4}, buying {:.6} shares at market", FOUR_MIN_HEDGE_BUY_OVER_PRICE, market_name, current_ask_4m, hedge_shares);
                            let opp = BuyOpportunity {
                                condition_id: condition_id.to_string(),
                                token_id: unfilled_token.token_id.clone(),
                                token_type: unfilled_type.clone(),
                                bid_price: current_ask_4m,
                                period_timestamp: snapshot.period_timestamp,
                                time_remaining_seconds: snapshot.time_remaining_seconds,
                                time_elapsed_seconds,
                                use_market_order: true,
                                investment_amount_override: Some(investment_over),
                                is_individual_hedge: true,
                                is_standard_hedge: false,
                                dual_limit_shares: None,
                            };
                            let mut buy_ok = false;
                            for attempt in 1..=3 {
                                match trader.execute_buy(&opp).await {
                                    Ok(()) => {
                                        buy_ok = true;
                                        break;
                                    }
                                    Err(e) => {
                                        warn!("4-min hedge (price > {}): market buy failed for {} (attempt {}/3): {}", FOUR_MIN_HEDGE_BUY_OVER_PRICE, market_name, attempt, e);
                                        if attempt < 3 {
                                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                        }
                                    }
                                }
                            }
                            if !buy_ok {
                                warn!("4-min hedge (price > {}): market buy failed after 3 attempts for {}", FOUR_MIN_HEDGE_BUY_OVER_PRICE, market_name);
                                continue;
                            }
                            trader.mark_limit_trade_filled_by_hedge(snapshot.period_timestamp, &unfilled_token.token_id).await;
                            for attempt in 1..=3 {
                                if let Ok(()) = trader.cancel_pending_limit_buy(snapshot.period_timestamp, &unfilled_token.token_id).await {
                                    crate::log_println!("   🗑️ Cancelled unfilled $0.45 limit order (4-min, price > {:.2})", FOUR_MIN_HEDGE_BUY_OVER_PRICE);
                                    break;
                                }
                                if attempt < 3 {
                                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                }
                            }
                            let mut set = hedge_executed_for_market.lock().await;
                            set.insert((snapshot.period_timestamp, (*condition_id).to_string()));
                            drop(set);
                            hedge_price_per_market.lock().await.insert((snapshot.period_timestamp, (*condition_id).to_string()), current_ask_4m);
                            continue;
                        }
                        // 4-min band: 0.5 < unfilled bid < 0.65. If >= 0.65 early/standard handle. If <= 0.5 use 2-min mode.
                        if current_bid <= FOUR_MIN_HEDGE_MIN_PRICE || current_bid >= FOUR_MIN_HEDGE_MAX_PRICE {
                            continue;
                        }
                        if current_ask_4m > MAX_HEDGE_PRICE {
                            continue; // skip: would lock in loss (total cost > $1)
                        }
                        // Trailing stop: hedge when current bid at or below trailing_min + tolerance (track bid for band; pay ask when buying).
                        {
                            let mut min_map = four_min_early_trailing_min.lock().await;
                            let trailing_min = min_map.get(&price_key_4m).copied().unwrap_or(current_bid);
                            let new_min = trailing_min.min(current_bid);
                            min_map.insert(price_key_4m.clone(), new_min);
                            if current_bid > new_min + trailing_stop_tolerance {
                                crate::log_println!(
                                    "   Trailing [{}] unfilled {} (4-min): bid={:.4} lowest={:.4} trigger_at={:.4} (+{:.3}) (waiting)",
                                    market_name, unfilled_type.display_name(), current_bid, new_min, new_min + trailing_stop_tolerance, trailing_stop_tolerance
                                );
                                continue;
                            }
                        }
                        crate::log_println!(
                            "   Trailing [{}] unfilled {} (4-min): TRIGGER bid={:.4} <= lowest+{:.3} → executing hedge at ask {:.4}",
                            market_name, unfilled_type.display_name(), current_bid, trailing_stop_tolerance, current_ask_4m
                        );
                        if hedge_shares < 0.001 {
                            continue;
                        }
                        crate::log_println!("🕐 4-MIN HEDGE (same-size): {} unfilled at ask ${:.4} (0.5 < bid < 0.65), buying {:.6} shares; will cancel limit only after buy succeeds", market_name, current_ask_4m, hedge_shares);
                        let investment = hedge_shares * current_ask_4m;
                        let opp = BuyOpportunity {
                            condition_id: condition_id.to_string(),
                            token_id: unfilled_token.token_id.clone(),
                            token_type: unfilled_type.clone(),
                            bid_price: current_ask_4m,
                            period_timestamp: snapshot.period_timestamp,
                            time_remaining_seconds: snapshot.time_remaining_seconds,
                            time_elapsed_seconds,
                            use_market_order: true,
                            investment_amount_override: Some(investment),
                            is_individual_hedge: true,
                            is_standard_hedge: false,
                            dual_limit_shares: None,
                        };
                        let mut buy_ok = false;
                        for attempt in 1..=3 {
                            match trader.execute_buy(&opp).await {
                                Ok(()) => {
                                    buy_ok = true;
                                    break;
                                }
                                Err(e) => {
                                    warn!("10-min hedge: market buy failed for {} (attempt {}/3): {}", market_name, attempt, e);
                                    if attempt < 3 {
                                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                    }
                                }
                            }
                        }
                        if !buy_ok {
                            warn!("4-min hedge: market buy failed after 3 attempts for {} - leaving limit order in place, will retry on next snapshot", market_name);
                            continue;
                        }
                        trader.mark_limit_trade_filled_by_hedge(snapshot.period_timestamp, &unfilled_token.token_id).await;
                        // Buy succeeded: cancel unfilled limit to avoid double position.
                        let mut cancel_ok = false;
                        for attempt in 1..=3 {
                            match trader.cancel_pending_limit_buy(snapshot.period_timestamp, &unfilled_token.token_id).await {
                                Ok(()) => {
                                    crate::log_println!("   🗑️ Cancelled unfilled $0.45 limit order (4-min hedge)");
                                    cancel_ok = true;
                                    break;
                                }
                                Err(e) => {
                                    warn!("10-min hedge: cancel limit order failed (attempt {}/3): {} - limit may still be live!", attempt, e);
                                    if attempt < 3 {
                                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                    }
                                }
                            }
                        }
                        if !cancel_ok {
                            warn!("4-min hedge: could not cancel unfilled limit after 3 attempts - you may have double position for {}", market_name);
                        }
                        let mut set = hedge_executed_for_market.lock().await;
                        set.insert((snapshot.period_timestamp, (*condition_id).to_string()));
                        drop(set);
                        hedge_price_per_market.lock().await.insert((snapshot.period_timestamp, (*condition_id).to_string()), current_ask_4m);
                }
            }

            // Early hedge: after early_hedge_after_seconds, if one side filled and 0.65 < unfilled price < 0.85, buy on uptick. From 0.85 to end, standard hedge (buy at market). If price drops below 0.65, 4-min or 2-min mode applies.
            // Skip markets already hedged via 2-min (avoid double hedge). Only try markets not in hedge_executed_for_market.
            if !HEDGE_DISABLED && !EARLY_HEDGE_DISABLED && time_elapsed_seconds >= early_hedge_after_seconds {
                let hedge_guard = hedge_executed_for_market.lock().await;
                let two_min_guard = two_min_hedge_markets.lock().await;
                let mut markets_to_check: Vec<(&str, &str, &polymarket_trading_bot::models::TokenPrice, &polymarket_trading_bot::models::TokenPrice, polymarket_trading_bot::detector::TokenType, polymarket_trading_bot::detector::TokenType)> = Vec::new();
                if enable_btc {
                    if let (Some(btc_up), Some(btc_down)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.btc_market.condition_id.clone());
                        if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_check.push(("BTC", &snapshot.btc_market.condition_id, btc_up, btc_down, polymarket_trading_bot::detector::TokenType::BtcUp, polymarket_trading_bot::detector::TokenType::BtcDown));
                        }
                    }
                }
                if enable_eth {
                    if let (Some(eu), Some(ed)) = (snapshot.eth_market.up_token.as_ref(), snapshot.eth_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.eth_market.condition_id.clone());
                        if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_check.push(("ETH", &snapshot.eth_market.condition_id, eu, ed, polymarket_trading_bot::detector::TokenType::EthUp, polymarket_trading_bot::detector::TokenType::EthDown));
                        }
                    }
                }
                if enable_solana {
                    if let (Some(su), Some(sd)) = (snapshot.solana_market.up_token.as_ref(), snapshot.solana_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.solana_market.condition_id.clone());
                        if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_check.push(("SOL", &snapshot.solana_market.condition_id, su, sd, polymarket_trading_bot::detector::TokenType::SolanaUp, polymarket_trading_bot::detector::TokenType::SolanaDown));
                        }
                    }
                }
                if enable_xrp {
                    if let (Some(xu), Some(xd)) = (snapshot.xrp_market.up_token.as_ref(), snapshot.xrp_market.down_token.as_ref()) {
                        let key = (snapshot.period_timestamp, snapshot.xrp_market.condition_id.clone());
                        if !hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            markets_to_check.push(("XRP", &snapshot.xrp_market.condition_id, xu, xd, polymarket_trading_bot::detector::TokenType::XrpUp, polymarket_trading_bot::detector::TokenType::XrpDown));
                        }
                    }
                }
                drop(two_min_guard);
                drop(hedge_guard);
                for (market_name, condition_id, up_token, down_token, up_type, down_type) in &markets_to_check {
                        let price_key_early = (snapshot.period_timestamp, (*condition_id).to_string());
                        let already_cancelled_early = opposite_limit_cancelled_for_market.lock().await.contains(&price_key_early);
                        let up_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &up_token.token_id).await;
                        let down_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &down_token.token_id).await;
                        let (unfilled_token, unfilled_type, current_bid_early, current_ask_early, _filled_units) = match (up_trade.as_ref(), down_trade.as_ref()) {
                            (Some(up_t), Some(down_t)) if up_t.buy_order_confirmed != down_t.buy_order_confirmed => {
                                if down_t.buy_order_confirmed {
                                    let bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                    let ask = up_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                    (up_token, up_type.clone(), bid, ask, down_t.units)
                                } else {
                                    let bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                    let ask = down_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                    (down_token, down_type.clone(), bid, ask, up_t.units)
                                }
                            }
                            (Some(up_t), None) if up_t.buy_order_confirmed && already_cancelled_early => {
                                let bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                let ask = down_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                (down_token, down_type.clone(), bid, ask, up_t.units)
                            }
                            (None, Some(down_t)) if down_t.buy_order_confirmed && already_cancelled_early => {
                                let bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0);
                                let ask = up_token.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or(bid);
                                (up_token, up_type.clone(), bid, ask, down_t.units)
                            }
                            _ => continue,
                        };
                        // Early band: 0.65 < unfilled bid < 0.85. If >= 0.85 standard handles. If <= 0.65 use 4-min or 2-min. We buy at ask.
                        if current_bid_early <= EARLY_HEDGE_MIN_PRICE || current_bid_early >= EARLY_HEDGE_MAX_PRICE {
                            continue;
                        }
                        if current_ask_early > MAX_HEDGE_PRICE {
                            debug!("Skipping early hedge: unfilled ask {:.4} > MAX_HEDGE_PRICE {:.2} (would lock in loss)", current_ask_early, MAX_HEDGE_PRICE);
                            continue;
                        }
                        // Trailing stop: hedge when current bid at or below trailing_min + tolerance.
                        {
                            let mut min_map = four_min_early_trailing_min.lock().await;
                            let trailing_min = min_map.get(&price_key_early).copied().unwrap_or(current_bid_early);
                            let new_min = trailing_min.min(current_bid_early);
                            min_map.insert(price_key_early.clone(), new_min);
                            if current_bid_early > new_min + trailing_stop_tolerance {
                                crate::log_println!(
                                    "   Trailing [{}] unfilled {} (early): bid={:.4} lowest={:.4} trigger_at={:.4} (+{:.3}) (waiting)",
                                    market_name, unfilled_type.display_name(), current_bid_early, new_min, new_min + trailing_stop_tolerance, trailing_stop_tolerance
                                );
                                continue;
                            }
                        }
                        crate::log_println!(
                            "   Trailing [{}] unfilled {} (early): TRIGGER bid={:.4} <= lowest+{:.3} → executing hedge at ask {:.4}",
                            market_name, unfilled_type.display_name(), current_bid_early, trailing_stop_tolerance, current_ask_early
                        );
                        let investment = hedge_shares * current_ask_early;
                        crate::log_println!("🚨 EARLY HEDGE (same-size): {} at ask ${:.4}", market_name, current_ask_early);
                        let opp = BuyOpportunity {
                            condition_id: condition_id.to_string(),
                            token_id: unfilled_token.token_id.clone(),
                            token_type: unfilled_type.clone(),
                            bid_price: current_ask_early,
                            period_timestamp: snapshot.period_timestamp,
                            time_remaining_seconds: snapshot.time_remaining_seconds,
                            time_elapsed_seconds,
                            use_market_order: true,
                            investment_amount_override: Some(investment),
                            is_individual_hedge: true,
                            is_standard_hedge: false,
                            dual_limit_shares: None,
                        };
                        let mut buy_ok = false;
                        for attempt in 1..=3 {
                            match trader.execute_buy(&opp).await {
                                Ok(()) => {
                                    buy_ok = true;
                                    break;
                                }
                                Err(e) => {
                                    warn!("Early hedge: market buy failed for {} (attempt {}/3): {}", market_name, attempt, e);
                                    if attempt < 3 {
                                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                    }
                                }
                            }
                        }
                        if !buy_ok {
                            warn!("Early hedge: market buy failed after 3 attempts for {} - leaving limit order in place, will retry on next snapshot", market_name);
                            continue;
                        }
                        trader.mark_limit_trade_filled_by_hedge(snapshot.period_timestamp, &unfilled_token.token_id).await;
                        {
                            let mut set = hedge_executed_for_market.lock().await;
                            set.insert((snapshot.period_timestamp, (*condition_id).to_string()));
                            drop(set);
                            hedge_price_per_market.lock().await.insert((snapshot.period_timestamp, (*condition_id).to_string()), current_ask_early);
                            let mut cancel_ok = false;
                            for attempt in 1..=3 {
                                match trader.cancel_pending_limit_buy(snapshot.period_timestamp, &unfilled_token.token_id).await {
                                    Ok(()) => {
                                        crate::log_println!("   🗑️ Cancelled unfilled $0.45 limit order (early hedge)");
                                        cancel_ok = true;
                                        break;
                                    }
                                    Err(e) => {
                                        warn!("Early hedge: cancel limit order failed (attempt {}/3): {} - limit may still be live!", attempt, e);
                                        if attempt < 3 {
                                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                        }
                                    }
                                }
                            }
                            if !cancel_ok {
                                warn!("Early hedge: could not cancel unfilled limit after 3 attempts - you may have double position for {}", market_name);
                            }
                        }
                    }
            }

            // Hedge logic: after N minutes, if exactly one side filled, buy the other side at current price (if >= hedge_price).
            if !HEDGE_DISABLED && !STANDARD_HEDGE_DISABLED && time_elapsed_seconds >= hedge_after_seconds {
                async fn maybe_hedge_pair(
                    trader: &Trader,
                    condition_id: &str,
                    up: &Option<polymarket_trading_bot::models::TokenPrice>,
                    down: &Option<polymarket_trading_bot::models::TokenPrice>,
                    up_type: polymarket_trading_bot::detector::TokenType,
                    down_type: polymarket_trading_bot::detector::TokenType,
                    period_timestamp: u64,
                    time_remaining_seconds: u64,
                    time_elapsed_seconds: u64,
                    hedge_price: f64,
                    limit_shares: Option<f64>,
                    _limit_price: f64,
                    fixed_trade_amount: f64,
                    hedge_executed_for_market: Option<&Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>>>,
                    hedge_price_per_market: Option<&Arc<tokio::sync::Mutex<std::collections::HashMap<(u64, String), f64>>>>,
                ) {
                    let (Some(up), Some(down)) = (up.as_ref(), down.as_ref()) else { return; };

                    if let Some(set) = hedge_executed_for_market {
                        if set.lock().await.contains(&(period_timestamp, condition_id.to_string())) {
                            return;
                        }
                    }

                    let up_trade = trader.get_pending_limit_trade(period_timestamp, &up.token_id).await;
                    let down_trade = trader.get_pending_limit_trade(period_timestamp, &down.token_id).await;

                    let (Some(up_trade), Some(down_trade)) = (up_trade, down_trade) else {
                        return;
                    };

                    let up_filled = up_trade.buy_order_confirmed;
                    let down_filled = down_trade.buy_order_confirmed;

                    // Only act when exactly one side is filled
                    if up_filled == down_filled {
                        return;
                    }

                    let (filled_trade, unfilled_trade, unfilled_token_id, unfilled_token_type, unfilled_buy_price_opt) = if up_filled {
                        (up_trade, down_trade, down.token_id.clone(), down_type, down.bid)
                    } else {
                        (down_trade, up_trade, up.token_id.clone(), up_type, up.bid)
                    };

                    // Avoid re-hedging: if the unfilled order is already at/above hedge_price, do nothing.
                    if unfilled_trade.purchase_price >= hedge_price - 1e-9 {
                        return;
                    }

                    let Some(unfilled_buy_price) = unfilled_buy_price_opt else { return; };
                    let unfilled_buy_price_f64 = f64::try_from(unfilled_buy_price).unwrap_or(0.0);
                    
                    // If price is already >= hedge_price, buy immediately at current price (same amount as limit orders)
                    if unfilled_buy_price_f64 >= hedge_price {
                        // Same-size: buy the same number of SHARES as dual_limit_shares. USD = limit_shares * current_price so we get ~limit_shares shares.
                        let one_investment_amount = limit_shares
                            .map(|s| s * unfilled_buy_price_f64)
                            .unwrap_or(fixed_trade_amount);

                        crate::log_println!(
                            "🛑 Hedge trigger (same-size): {} filled, {} unfilled. BUY price {:.4} >= {:.2}. Buying {} at current price {:.4} with market order ({} shares worth: ${:.6})",
                            filled_trade.token_type.display_name(),
                            unfilled_token_type.display_name(),
                            unfilled_buy_price_f64,
                            hedge_price,
                            unfilled_token_type.display_name(),
                            unfilled_buy_price_f64,
                            limit_shares.map(|s| format!("{:.2}", s)).unwrap_or_else(|| "fixed_trade_amount".to_string()),
                            one_investment_amount
                        );

                        crate::log_println!("   📋 Standard hedge opportunity: investment_amount_override = ${:.2} (dual_limit_shares at current price; no limit sell)", one_investment_amount);
                        let opp = BuyOpportunity {
                            condition_id: condition_id.to_string(),
                            token_id: unfilled_token_id.clone(),
                            token_type: unfilled_token_type.clone(),
                            bid_price: unfilled_buy_price_f64, // Buy at current price
                            period_timestamp,
                            time_remaining_seconds,
                            time_elapsed_seconds,
                            use_market_order: true,
                            investment_amount_override: Some(one_investment_amount), // 1x same as limit orders
                            is_individual_hedge: true, // No limit sell - hold until closure
                            is_standard_hedge: false,
                            dual_limit_shares: None,
                        };

                        let mut buy_ok = false;
                        for attempt in 1..=3 {
                            match trader.execute_buy(&opp).await {
                                Ok(()) => {
                                    buy_ok = true;
                                    break;
                                }
                                Err(e) => {
                                    warn!("Standard hedge: market buy failed (attempt {}/3): {}", attempt, e);
                                    if attempt < 3 {
                                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                    }
                                }
                            }
                        }
                        if !buy_ok {
                            warn!("Standard hedge: market buy failed after 3 attempts - leaving limit order in place, will retry on next snapshot");
                            return;
                        }
                        trader.mark_limit_trade_filled_by_hedge(period_timestamp, &unfilled_token_id).await;
                        if let Some(set) = hedge_executed_for_market {
                            let mut guard = set.lock().await;
                            guard.insert((period_timestamp, condition_id.to_string()));
                        }
                        if let Some(map) = hedge_price_per_market {
                            map.lock().await.insert((period_timestamp, condition_id.to_string()), unfilled_buy_price_f64);
                        }
                        let mut cancel_ok = false;
                        for attempt in 1..=3 {
                            match trader.cancel_pending_limit_buy(period_timestamp, &unfilled_token_id).await {
                                Ok(()) => {
                                    crate::log_println!("   🗑️ Cancelled unfilled $0.45 limit order for {}", unfilled_token_type.display_name());
                                    cancel_ok = true;
                                    break;
                                }
                                Err(e) => {
                                    warn!("Standard hedge: cancel limit order failed (attempt {}/3): {} - limit may still be live!", attempt, e);
                                    if attempt < 3 {
                                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                    }
                                }
                            }
                        }
                        if !cancel_ok {
                            warn!("Standard hedge: could not cancel unfilled limit after 3 attempts - you may have double position");
                        }
                    }
                    // If price < hedge_price, continue monitoring (will check again on next snapshot)
                }

                let limit_price_val = config.trading.dual_limit_price.unwrap_or(LIMIT_PRICE);
                if enable_btc {
                    maybe_hedge_pair(
                        &trader,
                        &snapshot.btc_market.condition_id,
                        &snapshot.btc_market.up_token,
                        &snapshot.btc_market.down_token,
                        polymarket_trading_bot::detector::TokenType::BtcUp,
                        polymarket_trading_bot::detector::TokenType::BtcDown,
                        snapshot.period_timestamp,
                        snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        hedge_price,
                        limit_shares,
                        limit_price_val,
                        fixed_trade_amount,
                        Some(&hedge_executed_for_market),
                        Some(&hedge_price_per_market),
                    )
                    .await;
                }
                if enable_eth {
                    maybe_hedge_pair(
                        &trader,
                        &snapshot.eth_market.condition_id,
                        &snapshot.eth_market.up_token,
                        &snapshot.eth_market.down_token,
                        polymarket_trading_bot::detector::TokenType::EthUp,
                        polymarket_trading_bot::detector::TokenType::EthDown,
                        snapshot.period_timestamp,
                        snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        hedge_price,
                        limit_shares,
                        limit_price_val,
                        fixed_trade_amount,
                        Some(&hedge_executed_for_market),
                        Some(&hedge_price_per_market),
                    )
                    .await;
                }

                if enable_solana {
                    maybe_hedge_pair(
                        &trader,
                        &snapshot.solana_market.condition_id,
                        &snapshot.solana_market.up_token,
                        &snapshot.solana_market.down_token,
                        polymarket_trading_bot::detector::TokenType::SolanaUp,
                        polymarket_trading_bot::detector::TokenType::SolanaDown,
                        snapshot.period_timestamp,
                        snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        hedge_price,
                        limit_shares,
                        limit_price_val,
                        fixed_trade_amount,
                        Some(&hedge_executed_for_market),
                        Some(&hedge_price_per_market),
                    )
                    .await;
                }

                if enable_xrp {
                    maybe_hedge_pair(
                        &trader,
                        &snapshot.xrp_market.condition_id,
                        &snapshot.xrp_market.up_token,
                        &snapshot.xrp_market.down_token,
                        polymarket_trading_bot::detector::TokenType::XrpUp,
                        polymarket_trading_bot::detector::TokenType::XrpDown,
                        snapshot.period_timestamp,
                        snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        hedge_price,
                        limit_shares,
                        limit_price_val,
                        fixed_trade_amount,
                        Some(&hedge_executed_for_market),
                        Some(&hedge_price_per_market),
                    )
                    .await;
                }
            }

            // Dual-filled low-price exit: both Up and Down filled at 0.45 (no hedge). When any token price < 0.03, place limit sell 0.02 for that token and 0.99 for opposite. Only after 10 min elapsed. (Disabled when DUAL_FILLED_LIMIT_SELL_ENABLED is false.)
            if DUAL_FILLED_LIMIT_SELL_ENABLED && time_elapsed_seconds >= LIMIT_SELL_AFTER_SECONDS {
            {
                let hedge_guard = hedge_executed_for_market.lock().await;
                let dual_guard = dual_filled_low_price_sell_placed_for_market.lock().await;
                let mut markets_to_check: Vec<(&str, String, &polymarket_trading_bot::models::TokenPrice, &polymarket_trading_bot::models::TokenPrice, polymarket_trading_bot::detector::TokenType, polymarket_trading_bot::detector::TokenType)> = Vec::new();
                let period = snapshot.period_timestamp;
                if enable_btc {
                    if let (Some(u), Some(d)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) {
                        let cid = snapshot.btc_market.condition_id.clone();
                        if !hedge_guard.contains(&(period, cid.clone())) && !dual_guard.contains(&(period, cid.clone())) {
                            markets_to_check.push(("BTC", cid, u, d, polymarket_trading_bot::detector::TokenType::BtcUp, polymarket_trading_bot::detector::TokenType::BtcDown));
                        }
                    }
                }
                if enable_eth {
                    if let (Some(u), Some(d)) = (snapshot.eth_market.up_token.as_ref(), snapshot.eth_market.down_token.as_ref()) {
                        let cid = snapshot.eth_market.condition_id.clone();
                        if !hedge_guard.contains(&(period, cid.clone())) && !dual_guard.contains(&(period, cid.clone())) {
                            markets_to_check.push(("ETH", cid, u, d, polymarket_trading_bot::detector::TokenType::EthUp, polymarket_trading_bot::detector::TokenType::EthDown));
                        }
                    }
                }
                if enable_solana {
                    if let (Some(u), Some(d)) = (snapshot.solana_market.up_token.as_ref(), snapshot.solana_market.down_token.as_ref()) {
                        let cid = snapshot.solana_market.condition_id.clone();
                        if !hedge_guard.contains(&(period, cid.clone())) && !dual_guard.contains(&(period, cid.clone())) {
                            markets_to_check.push(("SOL", cid, u, d, polymarket_trading_bot::detector::TokenType::SolanaUp, polymarket_trading_bot::detector::TokenType::SolanaDown));
                        }
                    }
                }
                if enable_xrp {
                    if let (Some(u), Some(d)) = (snapshot.xrp_market.up_token.as_ref(), snapshot.xrp_market.down_token.as_ref()) {
                        let cid = snapshot.xrp_market.condition_id.clone();
                        if !hedge_guard.contains(&(period, cid.clone())) && !dual_guard.contains(&(period, cid.clone())) {
                            markets_to_check.push(("XRP", cid, u, d, polymarket_trading_bot::detector::TokenType::XrpUp, polymarket_trading_bot::detector::TokenType::XrpDown));
                        }
                    }
                }
                drop(hedge_guard);
                drop(dual_guard);

                for (market_name, condition_id, up_token, down_token, up_type, down_type) in &markets_to_check {
                    let up_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &up_token.token_id).await;
                    let down_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &down_token.token_id).await;
                    let (Some(up_t), Some(down_t)) = (up_trade.as_ref(), down_trade.as_ref()) else { continue };
                    if !up_t.buy_order_confirmed || !down_t.buy_order_confirmed {
                        continue;
                    }
                    let up_bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(1.0)).unwrap_or(1.0);
                    let down_bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(1.0)).unwrap_or(1.0);

                    let (cheap_token, cheap_type, opp_token, opp_type, initial_cheap_units, initial_opp_units) = if up_bid < DUAL_FILLED_LOW_THRESHOLD {
                        (up_token, up_type.clone(), down_token, down_type.clone(), up_t.units, down_t.units)
                    } else if down_bid < DUAL_FILLED_LOW_THRESHOLD {
                        (down_token, down_type.clone(), up_token, up_type.clone(), down_t.units, up_t.units)
                    } else {
                        continue;
                    };

                    use rust_decimal::Decimal;
                    use rust_decimal::prelude::ToPrimitive;
                    let cheap_balance_raw = match api.check_balance_only(&cheap_token.token_id).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("Dual-filled exit: could not fetch balance for {}: {}", cheap_type.display_name(), e);
                            continue;
                        }
                    };
                    let opp_balance_raw = match api.check_balance_only(&opp_token.token_id).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("Dual-filled exit: could not fetch balance for {}: {}", opp_type.display_name(), e);
                            continue;
                        }
                    };
                    let cheap_balance_f64 = cheap_balance_raw
                        .checked_div(Decimal::from(1_000_000u64))
                        .and_then(|d| d.to_f64())
                        .unwrap_or(0.0);
                    let opp_balance_f64 = opp_balance_raw
                        .checked_div(Decimal::from(1_000_000u64))
                        .and_then(|d| d.to_f64())
                        .unwrap_or(0.0);
                    let floor2 = |x: f64| (x * 100.0).floor() / 100.0;
                    let intended_size = initial_cheap_units.max(initial_opp_units);
                    let cheap_avail = (floor2(cheap_balance_f64) - 0.01).max(0.01);
                    let opp_avail = (floor2(opp_balance_f64) - 0.01).max(0.01);
                    let sell_size = floor2(intended_size.min(cheap_avail).min(opp_avail));
                    let sell_cheap_size = sell_size;
                    let sell_opp_size = sell_size;
                    if sell_size < 0.01 {
                        warn!("Dual-filled exit: {} insufficient balance or position (intended: {:.2}, cheap_avail: {:.2}, opp_avail: {:.2})", market_name, intended_size, cheap_avail, opp_avail);
                        continue;
                    }

                    crate::log_println!("📉 DUAL-FILLED EXIT: {} both filled at limit, one side under {:.2} ({} bid), placing limit sell {:.2} for that token and {:.2} for opposite", market_name, DUAL_FILLED_LOW_THRESHOLD, cheap_type.display_name(), DUAL_FILLED_SELL_LOW, DUAL_FILLED_SELL_HIGH);

                    if is_simulation {
                        crate::log_println!("   🎮 SIMULATION: would place limit sell {:.2} @ ${:.2} for {} and {:.2} @ ${:.2} for {}", sell_cheap_size, DUAL_FILLED_SELL_LOW, cheap_type.display_name(), sell_opp_size, DUAL_FILLED_SELL_HIGH, opp_type.display_name());
                        let mut set = dual_filled_low_price_sell_placed_for_market.lock().await;
                        set.insert((snapshot.period_timestamp, condition_id.clone()));
                        continue;
                    }

                    use polymarket_trading_bot::models::OrderRequest;
                    if let Err(e) = api.update_balance_allowance_for_sell(&cheap_token.token_id).await {
                        debug!("Dual-filled exit: refresh allowance for {}: {}", cheap_type.display_name(), e);
                    }
                    let sell_cheap = OrderRequest {
                        token_id: cheap_token.token_id.clone(),
                        side: "SELL".to_string(),
                        size: format!("{:.2}", sell_cheap_size),
                        price: format!("{:.2}", DUAL_FILLED_SELL_LOW),
                        order_type: "LIMIT".to_string(),
                    };
                    if let Err(e) = api.place_order(&sell_cheap).await {
                        warn!("Dual-filled exit: failed to place limit sell at {} for {}: {}", DUAL_FILLED_SELL_LOW, market_name, e);
                        continue;
                    }
                    crate::log_println!("   ✅ Limit sell at ${:.2} placed for {} ({:.2} shares)", DUAL_FILLED_SELL_LOW, cheap_type.display_name(), sell_cheap_size);

                    if let Err(e) = api.update_balance_allowance_for_sell(&opp_token.token_id).await {
                        debug!("Dual-filled exit: refresh allowance for {}: {}", opp_type.display_name(), e);
                    }
                    let sell_opp = OrderRequest {
                        token_id: opp_token.token_id.clone(),
                        side: "SELL".to_string(),
                        size: format!("{:.2}", sell_opp_size),
                        price: format!("{:.2}", DUAL_FILLED_SELL_HIGH),
                        order_type: "LIMIT".to_string(),
                    };
                    if let Err(e) = api.place_order(&sell_opp).await {
                        warn!("Dual-filled exit: failed to place limit sell at {} for opposite {}: {}", DUAL_FILLED_SELL_HIGH, market_name, e);
                        continue;
                    }
                    crate::log_println!("   ✅ Limit sell at ${:.2} placed for {} ({:.2} shares)", DUAL_FILLED_SELL_HIGH, opp_type.display_name(), sell_opp_size);

                    let mut set = dual_filled_low_price_sell_placed_for_market.lock().await;
                    set.insert((snapshot.period_timestamp, condition_id.clone()));
                }
            }
            }

            // Low-price exit: after hedge (except 2-min). If hedge price >= 0.60: when one side < LOW_PRICE_THRESHOLD, place 0.05/0.99. If hedge price < 0.60: when one side < 0.02, place 0.01/0.99. Only after 10 min elapsed.
            if time_elapsed_seconds >= LIMIT_SELL_AFTER_SECONDS {
            {
                let period = snapshot.period_timestamp;
                let hedge_guard = hedge_executed_for_market.lock().await;
                let two_min_guard = two_min_hedge_markets.lock().await;
                let low_guard = low_price_sell_placed_for_market.lock().await;
                let under_60_guard = hedge_under_60_sell_placed_for_market.lock().await;
                let hedge_price_guard = hedge_price_per_market.lock().await;
                let mut markets_to_check: Vec<(&str, String, &polymarket_trading_bot::models::TokenPrice, &polymarket_trading_bot::models::TokenPrice, polymarket_trading_bot::detector::TokenType, polymarket_trading_bot::detector::TokenType)> = Vec::new();
                let mut markets_to_check_under_60: Vec<(&str, String, &polymarket_trading_bot::models::TokenPrice, &polymarket_trading_bot::models::TokenPrice, polymarket_trading_bot::detector::TokenType, polymarket_trading_bot::detector::TokenType)> = Vec::new();
                let hedge_price_high = |cid: &String| {
                    hedge_price_guard.get(&(period, cid.clone())).map_or(true, |p| *p >= HEDGE_PRICE_MIN_FOR_LIMIT_SELL)
                };
                let hedge_price_low = |cid: &String| {
                    hedge_price_guard.get(&(period, cid.clone())).map_or(false, |p| *p < HEDGE_PRICE_MIN_FOR_LIMIT_SELL)
                };
                if enable_btc {
                    if let (Some(u), Some(d)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) {
                        let cid = snapshot.btc_market.condition_id.clone();
                        let key = (period, cid.clone());
                        if hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            if !low_guard.contains(&key) && hedge_price_high(&cid) {
                                markets_to_check.push(("BTC", cid.clone(), u, d, polymarket_trading_bot::detector::TokenType::BtcUp, polymarket_trading_bot::detector::TokenType::BtcDown));
                            } else if !under_60_guard.contains(&key) && hedge_price_low(&cid) {
                                markets_to_check_under_60.push(("BTC", cid, u, d, polymarket_trading_bot::detector::TokenType::BtcUp, polymarket_trading_bot::detector::TokenType::BtcDown));
                            }
                        }
                    }
                }
                if enable_eth {
                    if let (Some(u), Some(d)) = (snapshot.eth_market.up_token.as_ref(), snapshot.eth_market.down_token.as_ref()) {
                        let cid = snapshot.eth_market.condition_id.clone();
                        let key = (period, cid.clone());
                        if hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            if !low_guard.contains(&key) && hedge_price_high(&cid) {
                                markets_to_check.push(("ETH", cid.clone(), u, d, polymarket_trading_bot::detector::TokenType::EthUp, polymarket_trading_bot::detector::TokenType::EthDown));
                            } else if !under_60_guard.contains(&key) && hedge_price_low(&cid) {
                                markets_to_check_under_60.push(("ETH", cid, u, d, polymarket_trading_bot::detector::TokenType::EthUp, polymarket_trading_bot::detector::TokenType::EthDown));
                            }
                        }
                    }
                }
                if enable_solana {
                    if let (Some(u), Some(d)) = (snapshot.solana_market.up_token.as_ref(), snapshot.solana_market.down_token.as_ref()) {
                        let cid = snapshot.solana_market.condition_id.clone();
                        let key = (period, cid.clone());
                        if hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            if !low_guard.contains(&key) && hedge_price_high(&cid) {
                                markets_to_check.push(("SOL", cid.clone(), u, d, polymarket_trading_bot::detector::TokenType::SolanaUp, polymarket_trading_bot::detector::TokenType::SolanaDown));
                            } else if !under_60_guard.contains(&key) && hedge_price_low(&cid) {
                                markets_to_check_under_60.push(("SOL", cid, u, d, polymarket_trading_bot::detector::TokenType::SolanaUp, polymarket_trading_bot::detector::TokenType::SolanaDown));
                            }
                        }
                    }
                }
                if enable_xrp {
                    if let (Some(u), Some(d)) = (snapshot.xrp_market.up_token.as_ref(), snapshot.xrp_market.down_token.as_ref()) {
                        let cid = snapshot.xrp_market.condition_id.clone();
                        let key = (period, cid.clone());
                        if hedge_guard.contains(&key) && !two_min_guard.contains(&key) {
                            if !low_guard.contains(&key) && hedge_price_high(&cid) {
                                markets_to_check.push(("XRP", cid.clone(), u, d, polymarket_trading_bot::detector::TokenType::XrpUp, polymarket_trading_bot::detector::TokenType::XrpDown));
                            } else if !under_60_guard.contains(&key) && hedge_price_low(&cid) {
                                markets_to_check_under_60.push(("XRP", cid, u, d, polymarket_trading_bot::detector::TokenType::XrpUp, polymarket_trading_bot::detector::TokenType::XrpDown));
                            }
                        }
                    }
                }
                drop(hedge_guard);
                drop(two_min_guard);
                drop(low_guard);
                drop(under_60_guard);
                drop(hedge_price_guard);

                for (market_name, condition_id, up_token, down_token, up_type, down_type) in &markets_to_check {
                    // Use get_pending_trade_for_period_token so we find both the limit-filled side (_limit) and the hedge side (_individual_hedge / _standard_hedge).
                    let up_trade = trader.get_pending_trade_for_period_token(snapshot.period_timestamp, &up_token.token_id).await;
                    let down_trade = trader.get_pending_trade_for_period_token(snapshot.period_timestamp, &down_token.token_id).await;
                    let (Some(up_t), Some(down_t)) = (up_trade.as_ref(), down_trade.as_ref()) else { continue };
                    if !up_t.buy_order_confirmed || !down_t.buy_order_confirmed {
                        continue;
                    }
                    let up_bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(1.0)).unwrap_or(1.0);
                    let down_bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(1.0)).unwrap_or(1.0);

                    let (cheap_token, cheap_type, initial_cheap_units, opp_token, opp_type, initial_opp_units) = if up_bid < LOW_PRICE_THRESHOLD {
                        (up_token, up_type.clone(), up_t.units, down_token, down_type.clone(), down_t.units)
                    } else if down_bid < LOW_PRICE_THRESHOLD {
                        (down_token, down_type.clone(), down_t.units, up_token, up_type.clone(), up_t.units)
                    } else {
                        continue;
                    };

                    if initial_cheap_units < 0.001 || initial_opp_units < 0.001 {
                        continue;
                    }

                    // Fetch real on-chain balance for both tokens so we don't sell more than we hold
                    use rust_decimal::Decimal;
                    use rust_decimal::prelude::ToPrimitive;
                    let cheap_balance_raw = match api.check_balance_only(&cheap_token.token_id).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("Low-price exit: could not fetch balance for {}: {}", cheap_type.display_name(), e);
                            continue;
                        }
                    };
                    let opp_balance_raw = match api.check_balance_only(&opp_token.token_id).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("Low-price exit: could not fetch balance for {}: {}", opp_type.display_name(), e);
                            continue;
                        }
                    };
                    let cheap_balance_f64 = cheap_balance_raw
                        .checked_div(Decimal::from(1_000_000u64))
                        .and_then(|d| d.to_f64())
                        .unwrap_or(0.0);
                    let opp_balance_f64 = opp_balance_raw
                        .checked_div(Decimal::from(1_000_000u64))
                        .and_then(|d| d.to_f64())
                        .unwrap_or(0.0);
                    let floor2 = |x: f64| (x * 100.0).floor() / 100.0;
                    // Same-size hedge: sell the same number of shares on both sides. Use max of the two recorded positions as intended size (one may be understated if balance check failed at hedge time); cap by each balance.
                    let intended_size = initial_cheap_units.max(initial_opp_units);
                    let cheap_avail = (floor2(cheap_balance_f64) - 0.01).max(0.01);
                    let opp_avail = (floor2(opp_balance_f64) - 0.01).max(0.01);
                    let sell_size = floor2(intended_size.min(cheap_avail).min(opp_avail));
                    let sell_cheap_size = sell_size;
                    let sell_opp_size = sell_size;
                    if sell_size < 0.01 {
                        warn!("Low-price exit: {} insufficient balance or position (intended: {:.2}, cheap_avail: {:.2}, opp_avail: {:.2})", market_name, intended_size, cheap_avail, opp_avail);
                        continue;
                    }

                    crate::log_println!("📉 LOW-PRICE EXIT: {} one side under {:.2} ({} bid {:.4}), placing limit sell {:.2} for that token and {:.2} for opposite (sizes: {:.2}, {:.2} from balance)", market_name, LOW_PRICE_THRESHOLD, cheap_type.display_name(), if up_bid < LOW_PRICE_THRESHOLD { up_bid } else { down_bid }, SELL_LOW_PRICE, SELL_HIGH_PRICE, sell_cheap_size, sell_opp_size);

                    if is_simulation {
                        crate::log_println!("   🎮 SIMULATION: would place limit sell {:.2} shares at ${:.2} for {} and {:.2} shares at ${:.2} for {}", sell_cheap_size, SELL_LOW_PRICE, cheap_type.display_name(), sell_opp_size, SELL_HIGH_PRICE, opp_type.display_name());
                        let mut set = low_price_sell_placed_for_market.lock().await;
                        set.insert((snapshot.period_timestamp, condition_id.clone()));
                        continue;
                    }

                    use polymarket_trading_bot::models::OrderRequest;
                    let price_key = (snapshot.period_timestamp, condition_id.clone());
                    let cheap_only_placed = low_price_cheap_sell_placed_for_market.lock().await.contains(&price_key);

                    if !cheap_only_placed {
                        if let Err(e) = api.update_balance_allowance_for_sell(&cheap_token.token_id).await {
                            debug!("Low-price exit: refresh allowance for {}: {} (continuing)", cheap_type.display_name(), e);
                        }
                        let sell_cheap = OrderRequest {
                            token_id: cheap_token.token_id.clone(),
                            side: "SELL".to_string(),
                            size: format!("{:.2}", sell_cheap_size), // real balance minus 0.01, 2 decimals
                            price: format!("{:.2}", SELL_LOW_PRICE),
                            order_type: "LIMIT".to_string(),
                        };
                        match api.place_order(&sell_cheap).await {
                            Err(e) => {
                                warn!("Low-price exit: failed to place limit sell at {} for {}: {}", SELL_LOW_PRICE, market_name, e);
                                continue;
                            }
                            Ok(resp) => {
                                let oid = resp.order_id.as_deref().unwrap_or("N/A");
                                crate::log_println!("   ✅ Limit sell at ${:.2} placed for {} ({:.2} shares)", SELL_LOW_PRICE, cheap_type.display_name(), sell_cheap_size);
                                crate::log_println!("   ✅ Limit sell order CONFIRMED for {} (order_id: {})", cheap_type.display_name(), oid);
                            }
                        }
                        low_price_cheap_sell_placed_for_market.lock().await.insert(price_key.clone());
                    } else {
                        crate::log_println!("   📤 Retry: cheap sell already placed, placing opposite only");
                    }

                    if let Err(e) = api.update_balance_allowance_for_sell(&opp_token.token_id).await {
                        debug!("Low-price exit: refresh allowance for {}: {} (continuing)", opp_type.display_name(), e);
                    }
                    let sell_opp = OrderRequest {
                        token_id: opp_token.token_id.clone(),
                        side: "SELL".to_string(),
                        size: format!("{:.2}", sell_opp_size), // real balance minus 0.01, 2 decimals
                        price: format!("{:.2}", SELL_HIGH_PRICE),
                        order_type: "LIMIT".to_string(),
                    };
                    match api.place_order(&sell_opp).await {
                        Err(e) => {
                            warn!("Low-price exit: failed to place limit sell at {} for opposite {}: {} - will retry next snapshot", SELL_HIGH_PRICE, market_name, e);
                            continue;
                        }
                        Ok(resp) => {
                            let oid = resp.order_id.as_deref().unwrap_or("N/A");
                            crate::log_println!("   ✅ Limit sell at ${:.2} placed for {} ({:.2} shares)", SELL_HIGH_PRICE, opp_type.display_name(), sell_opp_size);
                            crate::log_println!("   ✅ Limit sell order CONFIRMED for {} (order_id: {})", opp_type.display_name(), oid);
                        }
                    }

                    let mut set = low_price_sell_placed_for_market.lock().await;
                    set.insert((snapshot.period_timestamp, condition_id.clone()));
                    low_price_cheap_sell_placed_for_market.lock().await.remove(&price_key);
                }

                // Hedged with price < 0.60: when one side < 0.03 (same as both-filled case), place limit sell 0.02 for that token and 0.99 for opposite
                for (market_name, condition_id, up_token, down_token, up_type, down_type) in &markets_to_check_under_60 {
                    let up_trade = trader.get_pending_trade_for_period_token(snapshot.period_timestamp, &up_token.token_id).await;
                    let down_trade = trader.get_pending_trade_for_period_token(snapshot.period_timestamp, &down_token.token_id).await;
                    let (Some(up_t), Some(down_t)) = (up_trade.as_ref(), down_trade.as_ref()) else { continue };
                    if !up_t.buy_order_confirmed || !down_t.buy_order_confirmed {
                        continue;
                    }
                    let up_bid = up_token.bid.map(|b| f64::try_from(b).unwrap_or(1.0)).unwrap_or(1.0);
                    let down_bid = down_token.bid.map(|b| f64::try_from(b).unwrap_or(1.0)).unwrap_or(1.0);

                    let (cheap_token, cheap_type, opp_token, opp_type, initial_cheap_units, initial_opp_units) = if up_bid < DUAL_FILLED_LOW_THRESHOLD {
                        (up_token, up_type.clone(), down_token, down_type.clone(), up_t.units, down_t.units)
                    } else if down_bid < DUAL_FILLED_LOW_THRESHOLD {
                        (down_token, down_type.clone(), up_token, up_type.clone(), down_t.units, up_t.units)
                    } else {
                        continue;
                    };

                    use rust_decimal::Decimal;
                    use rust_decimal::prelude::ToPrimitive;
                    let cheap_balance_raw = match api.check_balance_only(&cheap_token.token_id).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("Hedge-under-60 exit: could not fetch balance for {}: {}", cheap_type.display_name(), e);
                            continue;
                        }
                    };
                    let opp_balance_raw = match api.check_balance_only(&opp_token.token_id).await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("Hedge-under-60 exit: could not fetch balance for {}: {}", opp_type.display_name(), e);
                            continue;
                        }
                    };
                    let cheap_balance_f64 = cheap_balance_raw
                        .checked_div(Decimal::from(1_000_000u64))
                        .and_then(|d| d.to_f64())
                        .unwrap_or(0.0);
                    let opp_balance_f64 = opp_balance_raw
                        .checked_div(Decimal::from(1_000_000u64))
                        .and_then(|d| d.to_f64())
                        .unwrap_or(0.0);
                    let floor2 = |x: f64| (x * 100.0).floor() / 100.0;
                    let intended_size = initial_cheap_units.max(initial_opp_units);
                    let cheap_avail = (floor2(cheap_balance_f64) - 0.01).max(0.01);
                    let opp_avail = (floor2(opp_balance_f64) - 0.01).max(0.01);
                    let sell_size = floor2(intended_size.min(cheap_avail).min(opp_avail));
                    let sell_cheap_size = sell_size;
                    let sell_opp_size = sell_size;
                    if sell_size < 0.01 {
                        warn!("Hedge-under-60 exit: {} insufficient balance or position (intended: {:.2}, cheap_avail: {:.2}, opp_avail: {:.2})", market_name, intended_size, cheap_avail, opp_avail);
                        continue;
                    }

                    crate::log_println!("📉 HEDGE-UNDER-60 EXIT: {} hedged below {:.2}, one side under {:.2}, placing limit sell {:.2} / {:.2}", market_name, HEDGE_PRICE_MIN_FOR_LIMIT_SELL, DUAL_FILLED_LOW_THRESHOLD, DUAL_FILLED_SELL_LOW, DUAL_FILLED_SELL_HIGH);

                    if is_simulation {
                        crate::log_println!("   🎮 SIMULATION: would place limit sell {:.2} @ ${:.2} for {} and {:.2} @ ${:.2} for {}", sell_cheap_size, DUAL_FILLED_SELL_LOW, cheap_type.display_name(), sell_opp_size, DUAL_FILLED_SELL_HIGH, opp_type.display_name());
                        let mut set = hedge_under_60_sell_placed_for_market.lock().await;
                        set.insert((snapshot.period_timestamp, condition_id.clone()));
                        continue;
                    }

                    use polymarket_trading_bot::models::OrderRequest;
                    if let Err(e) = api.update_balance_allowance_for_sell(&cheap_token.token_id).await {
                        debug!("Hedge-under-60 exit: refresh allowance for {}: {}", cheap_type.display_name(), e);
                    }
                    let sell_cheap = OrderRequest {
                        token_id: cheap_token.token_id.clone(),
                        side: "SELL".to_string(),
                        size: format!("{:.2}", sell_cheap_size),
                        price: format!("{:.2}", DUAL_FILLED_SELL_LOW),
                        order_type: "LIMIT".to_string(),
                    };
                    if let Err(e) = api.place_order(&sell_cheap).await {
                        warn!("Hedge-under-60 exit: failed to place limit sell at {} for {}: {}", DUAL_FILLED_SELL_LOW, market_name, e);
                        continue;
                    }
                    crate::log_println!("   ✅ Limit sell at ${:.2} placed for {} ({:.2} shares)", DUAL_FILLED_SELL_LOW, cheap_type.display_name(), sell_cheap_size);

                    if let Err(e) = api.update_balance_allowance_for_sell(&opp_token.token_id).await {
                        debug!("Hedge-under-60 exit: refresh allowance for {}: {}", opp_type.display_name(), e);
                    }
                    let sell_opp = OrderRequest {
                        token_id: opp_token.token_id.clone(),
                        side: "SELL".to_string(),
                        size: format!("{:.2}", sell_opp_size),
                        price: format!("{:.2}", DUAL_FILLED_SELL_HIGH),
                        order_type: "LIMIT".to_string(),
                    };
                    if let Err(e) = api.place_order(&sell_opp).await {
                        warn!("Hedge-under-60 exit: failed to place limit sell at {} for opposite {}: {}", DUAL_FILLED_SELL_HIGH, market_name, e);
                        continue;
                    }
                    crate::log_println!("   ✅ Limit sell at ${:.2} placed for {} ({:.2} shares)", DUAL_FILLED_SELL_HIGH, opp_type.display_name(), sell_opp_size);

                    let mut set = hedge_under_60_sell_placed_for_market.lock().await;
                    set.insert((snapshot.period_timestamp, condition_id.clone()));
                }
            }
            }

        }
    }).await;

    Ok(())
}

// Copy helper functions from main.rs
async fn get_or_discover_markets(
    api: &PolymarketApi,
    enable_eth: bool,
    enable_solana: bool,
    enable_xrp: bool,
) -> Result<(polymarket_trading_bot::models::Market, polymarket_trading_bot::models::Market, polymarket_trading_bot::models::Market, polymarket_trading_bot::models::Market)> {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut seen_ids = std::collections::HashSet::new();

    let eth_market = if enable_eth {
        discover_market(api, "ETH", &["eth"], current_time, &mut seen_ids, true).await
            .unwrap_or_else(|_| {
                eprintln!("⚠️  Could not discover ETH market - using fallback");
                disabled_eth_market()
            })
    } else {
        disabled_eth_market()
    };
    seen_ids.insert(eth_market.condition_id.clone());

    eprintln!("🔍 Discovering BTC market...");
    let btc_market = discover_market(api, "BTC", &["btc"], current_time, &mut seen_ids, true).await
        .unwrap_or_else(|_| {
            eprintln!("⚠️  Could not discover BTC market - using fallback");
            polymarket_trading_bot::models::Market {
                condition_id: "dummy_btc_fallback".to_string(),
                slug: "btc-updown-15m-fallback".to_string(),
                active: false,
                closed: true,
                market_id: None,
                question: "BTC Trading Disabled".to_string(),
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

    if eth_market.condition_id == btc_market.condition_id && eth_market.condition_id != "dummy_eth_fallback" {
        anyhow::bail!("ETH and BTC markets have the same condition ID: {}. This is incorrect.", eth_market.condition_id);
    }
    if solana_market.condition_id != "dummy_solana_fallback" {
        if eth_market.condition_id == solana_market.condition_id && eth_market.condition_id != "dummy_eth_fallback" {
            anyhow::bail!("ETH and Solana markets have the same condition ID: {}. This is incorrect.", eth_market.condition_id);
        }
        if btc_market.condition_id == solana_market.condition_id {
            anyhow::bail!("BTC and Solana markets have the same condition ID: {}. This is incorrect.", btc_market.condition_id);
        }
    }
    if xrp_market.condition_id != "dummy_xrp_fallback" {
        if eth_market.condition_id == xrp_market.condition_id && eth_market.condition_id != "dummy_eth_fallback" {
            anyhow::bail!("ETH and XRP markets have the same condition ID: {}. This is incorrect.", eth_market.condition_id);
        }
        if btc_market.condition_id == xrp_market.condition_id {
            anyhow::bail!("BTC and XRP markets have the same condition ID: {}. This is incorrect.", btc_market.condition_id);
        }
        if solana_market.condition_id == xrp_market.condition_id && solana_market.condition_id != "dummy_solana_fallback" {
            anyhow::bail!("Solana and XRP markets have the same condition ID: {}. This is incorrect.", solana_market.condition_id);
        }
    }

    Ok((eth_market, btc_market, solana_market, xrp_market))
}

fn enabled_markets_label(enable_eth: bool, enable_solana: bool, enable_xrp: bool) -> String {
    let mut enabled = Vec::new();
    if enable_eth {
        enabled.push("ETH");
    }
    if enable_solana {
        enabled.push("Solana");
    }
    if enable_xrp {
        enabled.push("XRP");
    }
    if enabled.is_empty() {
        "no additional".to_string()
    } else {
        enabled.join(", ")
    }
}

fn disabled_eth_market() -> polymarket_trading_bot::models::Market {
    polymarket_trading_bot::models::Market {
        condition_id: "dummy_eth_fallback".to_string(),
        slug: "eth-updown-15m-fallback".to_string(),
        active: false,
        closed: true,
        market_id: None,
        question: "ETH Trading Disabled".to_string(),
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
        condition_id: "dummy_solana_fallback".to_string(),
        slug: "solana-updown-15m-fallback".to_string(),
        active: false,
        closed: true,
        market_id: None,
        question: "Solana Trading Disabled".to_string(),
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
        condition_id: "dummy_xrp_fallback".to_string(),
        slug: "xrp-updown-15m-fallback".to_string(),
        active: false,
        closed: true,
        market_id: None,
        question: "XRP Trading Disabled".to_string(),
        resolution_source: None,
        end_date_iso: None,
        end_date_iso_alt: None,
        tokens: None,
        clob_token_ids: None,
        outcomes: None,
    }
}

async fn discover_solana_market(
    api: &PolymarketApi,
    current_time: u64,
    seen_ids: &mut std::collections::HashSet<String>,
) -> polymarket_trading_bot::models::Market {
    eprintln!("🔍 Discovering Solana market...");
    if let Ok(market) = discover_market(api, "Solana", &["solana", "sol"], current_time, seen_ids, false).await {
        return market;
    }
    eprintln!("⚠️  Could not discover Solana 15-minute market. Using fallback - Solana trading disabled.");
    disabled_solana_market()
}

async fn discover_xrp_market(
    api: &PolymarketApi,
    current_time: u64,
    seen_ids: &mut std::collections::HashSet<String>,
) -> polymarket_trading_bot::models::Market {
    eprintln!("🔍 Discovering XRP market...");
    if let Ok(market) = discover_market(api, "XRP", &["xrp"], current_time, seen_ids, false).await {
        return market;
    }
    eprintln!("⚠️  Could not discover XRP 15-minute market. Using fallback - XRP trading disabled.");
    disabled_xrp_market()
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
        if i > 0 {
            eprintln!("🔍 Trying {} market with slug prefix '{}'...", market_name, prefix);
        }
        let slug = format!("{}-updown-15m-{}", prefix, rounded_time);
        if let Ok(market) = api.get_market_by_slug(&slug).await {
            if !seen_ids.contains(&market.condition_id) && market.active && !market.closed {
                eprintln!("Found {} market by slug: {} | Condition ID: {}", market_name, market.slug, market.condition_id);
                return Ok(market);
            }
        }

        if include_previous {
            for offset in 1..=3 {
                let try_time = rounded_time - (offset * 900);
                let try_slug = format!("{}-updown-15m-{}", prefix, try_time);
                eprintln!("Trying previous {} market by slug: {}", market_name, try_slug);
                if let Ok(market) = api.get_market_by_slug(&try_slug).await {
                    if !seen_ids.contains(&market.condition_id) && market.active && !market.closed {
                        eprintln!("Found {} market by slug: {} | Condition ID: {}", market_name, market.slug, market.condition_id);
                        return Ok(market);
                    }
                }
            }
        }
    }

    let tried = slug_prefixes.join(", ");
    anyhow::bail!(
        "Could not find active {} 15-minute up/down market (tried prefixes: {}).",
        market_name,
        tried
    )
}
