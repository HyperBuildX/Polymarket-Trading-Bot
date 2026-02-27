// 5-minute BTC dual limit (0.45) same-size: BTC only. Place batch limit orders ASAP when new market detected. When one side fills → cancel opposite limit immediately and start trailing stop (2-min / 3-min). No reentry: we never place re-entry orders (e.g. $0.05 limit after hedge); after trailing triggers we stop. No ETH/SOL/XRP.

use polymarket_trading_bot::*;
use anyhow::{Context, Result};
use clap::Parser;
use polymarket_trading_bot::config::{Args, Config};
use log::warn;
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
const PERIOD_DURATION_5M: u64 = 300;
const DEFAULT_HEDGE_PRICE: f64 = 0.85;
/// 2-min window: active when time_elapsed in [NINETY_SEC_AFTER_SECONDS, THREE_MIN_AFTER_SECONDS) i.e. 2 min to 3 min.
const NINETY_SEC_AFTER_SECONDS: u64 = 120;
/// 3-min window: active when time_elapsed >= THREE_MIN_AFTER_SECONDS.
const THREE_MIN_AFTER_SECONDS: u64 = 180;
/// 4-min: from here we commit to hedge: if ask >= hedge_price buy now; if ask < hedge_price keep trailing (bounce trigger).
const FOUR_MIN_AFTER_SECONDS: u64 = 240;
/// Only place limit orders when we're within this many seconds of period start (so we don't place mid-period when bot starts).
const NEW_MARKET_PLACE_WINDOW_SECONDS: u64 = 15;
/// 2-min band = 1 - dual_limit_price - 0.1 (e.g. 0.45 when limit is 0.45). 3-min band = 1 - dual_limit_price (e.g. 0.55).
const BAND_2MIN_OFFSET: f64 = 0.1;
/// Trailing-buy mode: monitor the token whose ask is above this threshold (0.55).
const TRAILING_BUY_FIRST_TOKEN_THRESHOLD: f64 = 0.55;
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

    eprintln!("🚀 Starting Polymarket Dual Limit 5-Minute BTC Bot (2-min + 3-min trailing)");
    eprintln!("📝 Logs are being saved to: history.toml");
    let is_simulation = args.is_simulation();
    eprintln!("Mode: {}", if is_simulation { "SIMULATION" } else { "PRODUCTION" });
    let limit_price = config.trading.dual_limit_price.unwrap_or(LIMIT_PRICE);
    let limit_shares = config.trading.dual_limit_shares;
    let hedge_price = config.trading.dual_limit_hedge_price.unwrap_or(DEFAULT_HEDGE_PRICE);
    let band_2min = 1.0 - limit_price - BAND_2MIN_OFFSET;
    let band_3min = 1.0 - limit_price;
    let use_trailing_buy_mode = config.trading.dual_limit_trailing_buy_mode.unwrap_or(false);
    if use_trailing_buy_mode {
        eprintln!(
            "Strategy: TRAILING-BUY MODE (no limit orders). Monitor token with ask > {:.2}; track highest, buy first token when ask <= highest - trailing_stop. Then second trailing for opposite token (band = 1 - first_bought_price).",
            TRAILING_BUY_FIRST_TOKEN_THRESHOLD
        );
    } else {
        eprintln!(
            "Strategy: LIMIT-ORDER MODE. As soon as new 5m market is detected, place limit buys for BTC Up/Down at ${:.2}. Before 3 min: band {:.2} (1-limit-0.1), trailing. 3–4 min: band {:.2} (1-limit), ask < {:.2}. From 4 min: buy at market when ask >= {:.2}; if ask < {:.2} keep checking until ask >= {:.2}.",
            limit_price, band_2min, band_3min, hedge_price, hedge_price, hedge_price, hedge_price
        );
    }
    if let Some(shares) = limit_shares {
        eprintln!("Shares per order (config): {:.6}", shares);
    } else {
        eprintln!("Shares per order: fixed_trade_amount / price");
    }
    eprintln!("✅ Trading: BTC 5-minute market only (no ETH/SOL/XRP 5m markets)");

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

    eprintln!("🔍 Discovering BTC 5-minute market...");
    let (eth_market_data, btc_market_data, solana_market_data, xrp_market_data) =
        get_or_discover_markets_5m_btc(&api).await?;

    let trailing_status_line = Arc::new(tokio::sync::Mutex::new(String::new()));
    let monitor = MarketMonitor::new(
        api.clone(),
        eth_market_data,
        btc_market_data,
        solana_market_data,
        xrp_market_data,
        config.trading.check_interval_ms,
        is_simulation,
        Some(PERIOD_DURATION_5M),
        None,
        None,
        None,
        None,
        Some(trailing_status_line.clone()),
    )?;
    let monitor_arc = Arc::new(monitor);

    let trader = Trader::new(
        api.clone(),
        config.trading.clone(),
        is_simulation,
        None,
    )?;
    let trader_arc = Arc::new(trader);
    let trader_clone = trader_arc.clone();

    crate::log_println!("🔄 Syncing pending trades with portfolio...");
    if let Err(e) = trader_clone.sync_trades_with_portfolio().await {
        warn!("Error syncing trades with portfolio: {}", e);
    }

    let trader_check = trader_clone.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(1000));
        loop {
            interval.tick().await;
            if let Err(e) = trader_check.check_pending_trades().await {
                warn!("Error checking pending trades: {}", e);
            }
        }
    });

    // Background task to detect new 5-minute periods
    let monitor_for_period_check = monitor_arc.clone();
    let api_for_period_check = api.clone();
    let trader_for_period_reset = trader_clone.clone();
    let simulation_tracker_for_market_start = if is_simulation {
        trader_clone.get_simulation_tracker()
    } else {
        None
    };
    tokio::spawn(async move {
        loop {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_period = (current_time / PERIOD_DURATION_5M) * PERIOD_DURATION_5M;
            let current_market_timestamp = monitor_for_period_check.get_current_market_timestamp().await;

            if current_market_timestamp != current_period && current_market_timestamp != 0 {
                eprintln!("🔄 Market period mismatch: current market {}, current period {}",
                    current_market_timestamp, current_period);
            } else {
                let next_period_timestamp = current_period + PERIOD_DURATION_5M;
                let sleep_duration = next_period_timestamp.saturating_sub(current_time);
                eprintln!("⏰ Current 5m period: {}, next in {} seconds", current_market_timestamp, sleep_duration);
                if sleep_duration > 0 && sleep_duration <= PERIOD_DURATION_5M {
                    tokio::time::sleep(tokio::time::Duration::from_secs(sleep_duration)).await;
                } else if sleep_duration == 0 {
                    eprintln!("🔄 Next 5m period started, discovering new market...");
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            }

            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_period = (current_time / PERIOD_DURATION_5M) * PERIOD_DURATION_5M;

            eprintln!("🔄 New 5-minute period detected! (Period: {}) Discovering BTC 5m market...", current_period);

            let mut seen_ids = std::collections::HashSet::new();
            let (_, btc_id) = monitor_for_period_check.get_current_condition_ids().await;
            seen_ids.insert(btc_id);

            let btc_result = discover_btc_5m_market(&api_for_period_check, current_time, &mut seen_ids).await;
            let eth_market = disabled_eth_market();
            let solana_market = disabled_solana_market();
            let xrp_market = disabled_xrp_market();

            match btc_result {
                Ok(btc_market) => {
                    if let Err(e) = monitor_for_period_check.update_markets(
                        eth_market.clone(),
                        btc_market.clone(),
                        solana_market.clone(),
                        xrp_market.clone(),
                    ).await {
                        warn!("Failed to update markets: {}", e);
                    } else {
                        if let Some(tracker) = &simulation_tracker_for_market_start {
                            tracker.log_market_start(
                                current_period,
                                &eth_market.condition_id,
                                &btc_market.condition_id,
                                &solana_market.condition_id,
                                &xrp_market.condition_id,
                            ).await;
                        }
                        trader_for_period_reset.reset_period(current_period).await;
                    }
                }
                Err(e) => warn!("Failed to discover BTC 5m market: {}", e),
            }
        }
    });

    let last_placed_period = Arc::new(tokio::sync::Mutex::new(None::<u64>));
    let last_seen_period = Arc::new(tokio::sync::Mutex::new(None::<u64>));
    let hedge_price = hedge_price;
    let config_for_callback = config.clone();
    let limit_price = limit_price;
    let hedge_executed_for_market: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    let two_min_hedge_markets: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    let two_min_trailing_min_ask: Arc<tokio::sync::Mutex<std::collections::HashMap<(u64, String), f64>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let two_min_trailing_reset_at_3min: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    let opposite_limit_cancelled_for_market: Arc<tokio::sync::Mutex<std::collections::HashSet<(u64, String)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
    // Trailing-buy mode: (market_key) -> (is_up: bool, highest_ask: f64) for the token we're monitoring (ask > 0.55).
    let trailing_buy_first_highest: Arc<tokio::sync::Mutex<std::collections::HashMap<(u64, String), (bool, f64)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    // After first token buy: (market_key) -> (bought_price: f64, first_was_up: bool).
    let trailing_buy_first_bought: Arc<tokio::sync::Mutex<std::collections::HashMap<(u64, String), (f64, bool)>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let api_for_callback = api.clone();

    monitor_arc.start_monitoring(move |snapshot| {
        let trader = trader_clone.clone();
        let _api = api_for_callback.clone();
        let last_placed_period = last_placed_period.clone();
        let last_seen_period = last_seen_period.clone();
        let config = config_for_callback.clone();
        let limit_price = limit_price;
        let limit_shares = config.trading.dual_limit_shares;
        let hedge_executed_for_market = hedge_executed_for_market.clone();
        let two_min_hedge_markets = two_min_hedge_markets.clone();
        let two_min_trailing_min_ask = two_min_trailing_min_ask.clone();
        let two_min_trailing_reset_at_3min = two_min_trailing_reset_at_3min.clone();
        let opposite_limit_cancelled_for_market = opposite_limit_cancelled_for_market.clone();
        let trailing_status_line = trailing_status_line.clone();
        let use_trailing_buy_mode = use_trailing_buy_mode;
        let trailing_buy_first_highest = trailing_buy_first_highest.clone();
        let trailing_buy_first_bought = trailing_buy_first_bought.clone();

        async move {
            // Clear trailing status each tick; set below when we're in trailing.
            {
                let mut s = trailing_status_line.lock().await;
                *s = String::new();
            }
            if snapshot.time_remaining_seconds == 0 {
                return;
            }
            {
                let mut seen = last_seen_period.lock().await;
                *seen = Some(snapshot.period_timestamp);
            }

            // 2/3/4 min windows are based on ELAPSED time (minutes since period start), not remaining.
            let time_elapsed_seconds = PERIOD_DURATION_5M.saturating_sub(snapshot.time_remaining_seconds);

            // ─── Trailing-buy mode: no limit orders; monitor token with ask > 0.55, first-token highest trailing, then second-token lowest trailing (band = 1 - first_bought_price).
            if use_trailing_buy_mode {
                let (Some(btc_up), Some(btc_down)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) else { return };
                let key = (snapshot.period_timestamp, snapshot.btc_market.condition_id.clone());
                let price_key = (snapshot.period_timestamp, snapshot.btc_market.condition_id.clone());
                {
                    let h = hedge_executed_for_market.lock().await;
                    if h.contains(&key) {
                        drop(h);
                        two_min_trailing_min_ask.lock().await.remove(&price_key);
                        *trailing_status_line.lock().await = String::new();
                        return;
                    }
                }
                let trailing_stop_point = config.trading.trailing_stop_point.unwrap_or(0.02);
                let hedge_trailing_stop = config.trading.dual_limit_hedge_trailing_stop.unwrap_or(0.03);
                let hedge_price = hedge_price;
                let run_4min = time_elapsed_seconds >= FOUR_MIN_AFTER_SECONDS;

                if let Some((first_price, first_was_up)) = trailing_buy_first_bought.lock().await.get(&key).copied() {
                    // Second trailing: opposite token. Band = 1 - first_bought_price. Track lowest, trigger when ask >= lowest + hedge_trailing_stop.
                    let (opposite_token, opposite_type, opposite_ask) = if first_was_up {
                        let ask = btc_down.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or_else(|| btc_down.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0));
                        (btc_down, polymarket_trading_bot::detector::TokenType::BtcDown, ask)
                    } else {
                        let ask = btc_up.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or_else(|| btc_up.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0));
                        (btc_up, polymarket_trading_bot::detector::TokenType::BtcUp, ask)
                    };
                    let band_second = 1.0 - first_price;
                    let hedge_shares = limit_shares.unwrap_or_else(|| config.trading.fixed_trade_amount / first_price);

                    if run_4min && opposite_ask >= hedge_price {
                        // 4-min: buy opposite at market now
                        if !trader.is_simulation() {
                            if let Some(bal) = trader.get_token_balance_shares(&opposite_token.token_id).await {
                                if bal >= hedge_shares - 0.01 {
                                    hedge_executed_for_market.lock().await.insert(key.clone());
                                    two_min_trailing_min_ask.lock().await.remove(&price_key);
                                    *trailing_status_line.lock().await = String::new();
                                    return;
                                }
                            }
                        }
                        hedge_executed_for_market.lock().await.insert(key.clone());
                        two_min_trailing_min_ask.lock().await.remove(&price_key);
                        *trailing_status_line.lock().await = String::new();
                        let investment = hedge_shares * opposite_ask;
                        let opp = BuyOpportunity {
                            condition_id: snapshot.btc_market.condition_id.clone(),
                            token_id: opposite_token.token_id.clone(),
                            token_type: opposite_type.clone(),
                            bid_price: opposite_ask,
                            period_timestamp: snapshot.period_timestamp,
                            time_remaining_seconds: snapshot.time_remaining_seconds,
                            time_elapsed_seconds,
                            use_market_order: true,
                            investment_amount_override: Some(investment),
                            is_individual_hedge: true,
                            is_standard_hedge: false,
                            dual_limit_shares: Some(hedge_shares),
                        };
                        if let Err(e) = trader.execute_buy(&opp).await {
                            warn!("Trailing-buy 4-min second token failed: {}", e);
                            hedge_executed_for_market.lock().await.remove(&key);
                        }
                        return;
                    }

                    {
                        let trailing_lowest = two_min_trailing_min_ask.lock().await.get(&price_key).copied().unwrap_or(opposite_ask);
                        let trigger = trailing_lowest + hedge_trailing_stop;
                        let mut s = trailing_status_line.lock().await;
                        *s = format!("trail: {} ask={:.2} low={:.2} trig={:.2} band={:.2} (2nd)", opposite_type.display_name(), opposite_ask, trailing_lowest, trigger, band_second);
                    }
                    if opposite_ask >= band_second {
                        let lowest_before = two_min_trailing_min_ask.lock().await.get(&price_key).copied().unwrap_or(opposite_ask);
                        let bounce_threshold = band_second - hedge_trailing_stop;
                        if lowest_before > bounce_threshold {
                            if opposite_ask < lowest_before {
                                two_min_trailing_min_ask.lock().await.insert(price_key.clone(), opposite_ask);
                            }
                            return;
                        }
                    }
                    let mut min_map = two_min_trailing_min_ask.lock().await;
                    let existing = min_map.get(&price_key).copied();
                    let effective_lowest = match existing {
                        None => {
                            min_map.insert(price_key.clone(), opposite_ask);
                            opposite_ask
                        }
                        Some(low) if opposite_ask < low => {
                            min_map.insert(price_key.clone(), opposite_ask);
                            opposite_ask
                        }
                        Some(low) => low,
                    };
                    drop(min_map);
                    if opposite_ask < effective_lowest + hedge_trailing_stop {
                        crate::log_println!(
                            "   Trailing-buy [5m BTC] second ({}): ask={:.4} lowest_ask={:.4} trigger_at={:.4} (waiting for bounce)",
                            opposite_type.display_name(), opposite_ask, effective_lowest, effective_lowest + hedge_trailing_stop
                        );
                        return;
                    }
                    if !trader.is_simulation() {
                        if let Some(bal) = trader.get_token_balance_shares(&opposite_token.token_id).await {
                            if bal >= hedge_shares - 0.01 {
                                hedge_executed_for_market.lock().await.insert(key.clone());
                                two_min_trailing_min_ask.lock().await.remove(&price_key);
                                *trailing_status_line.lock().await = String::new();
                                return;
                            }
                        }
                    }
                    hedge_executed_for_market.lock().await.insert(key.clone());
                    two_min_trailing_min_ask.lock().await.remove(&price_key);
                    *trailing_status_line.lock().await = String::new();
                    let investment = hedge_shares * opposite_ask;
                    let opp = BuyOpportunity {
                        condition_id: snapshot.btc_market.condition_id.clone(),
                        token_id: opposite_token.token_id.clone(),
                        token_type: opposite_type,
                        bid_price: opposite_ask,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: true,
                        investment_amount_override: Some(investment),
                        is_individual_hedge: true,
                        is_standard_hedge: false,
                        dual_limit_shares: Some(hedge_shares),
                    };
                    if let Err(e) = trader.execute_buy(&opp).await {
                        warn!("Trailing-buy second token failed: {}", e);
                        hedge_executed_for_market.lock().await.remove(&key);
                    }
                    return;
                }

                // First-token phase: monitor token with ask > 0.55, track highest, buy when ask <= highest - trailing_stop_point.
                let up_ask = btc_up.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or_else(|| btc_up.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0));
                let down_ask = btc_down.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or_else(|| btc_down.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0));
                let (monitor_up, first_ask) = if up_ask > TRAILING_BUY_FIRST_TOKEN_THRESHOLD && (down_ask <= TRAILING_BUY_FIRST_TOKEN_THRESHOLD || up_ask >= down_ask) {
                    (true, up_ask)
                } else if down_ask > TRAILING_BUY_FIRST_TOKEN_THRESHOLD {
                    (false, down_ask)
                } else {
                    return;
                };
                {
                    let mut map = trailing_buy_first_highest.lock().await;
                    let entry = map.entry(key.clone()).or_insert((monitor_up, first_ask));
                    if entry.0 == monitor_up {
                        entry.1 = entry.1.max(first_ask);
                    } else {
                        *entry = (monitor_up, first_ask);
                    }
                }
                let highest = trailing_buy_first_highest.lock().await.get(&key).map(|(_, h)| *h).unwrap_or(first_ask);
                if first_ask > highest - trailing_stop_point {
                    let mut s = trailing_status_line.lock().await;
                    *s = format!("trail-buy 1st: {} ask={:.2} high={:.2} trig={:.2}", if monitor_up { "Up" } else { "Down" }, first_ask, highest, highest - trailing_stop_point);
                    return;
                }
                let (first_token, first_type) = if monitor_up {
                    (btc_up, polymarket_trading_bot::detector::TokenType::BtcUp)
                } else {
                    (btc_down, polymarket_trading_bot::detector::TokenType::BtcDown)
                };
                let first_shares = limit_shares.unwrap_or_else(|| config.trading.fixed_trade_amount / first_ask);
                if !trader.is_simulation() {
                    if let Some(bal) = trader.get_token_balance_shares(&first_token.token_id).await {
                        if bal >= first_shares - 0.01 {
                            trailing_buy_first_bought.lock().await.insert(key.clone(), (first_ask, monitor_up));
                            return;
                        }
                    }
                }
                crate::log_println!(
                    "   Trailing-buy [5m BTC] first: {} ask={:.4} <= high-{:.3} ({:.4}) → buying at market",
                    first_type.display_name(), first_ask, trailing_stop_point, highest - trailing_stop_point
                );
                let investment = first_shares * first_ask;
                let opp = BuyOpportunity {
                    condition_id: snapshot.btc_market.condition_id.clone(),
                    token_id: first_token.token_id.clone(),
                    token_type: first_type.clone(),
                    bid_price: first_ask,
                    period_timestamp: snapshot.period_timestamp,
                    time_remaining_seconds: snapshot.time_remaining_seconds,
                    time_elapsed_seconds,
                    use_market_order: true,
                    investment_amount_override: Some(investment),
                    is_individual_hedge: true,
                    is_standard_hedge: false,
                    dual_limit_shares: Some(first_shares),
                };
                let buy_ok = trader.execute_buy(&opp).await.is_ok();
                if buy_ok {
                    trailing_buy_first_bought.lock().await.insert(key.clone(), (first_ask, monitor_up));
                }
                return;
            }

            // Place limit orders only when a NEW market is discovered (within first NEW_MARKET_PLACE_WINDOW_SECONDS of period). Don't place mid-period if bot started late.
            let mut opportunities: Vec<BuyOpportunity> = Vec::new();
            {
                let mut last = last_placed_period.lock().await;
                let already_placed = last.map(|p| p == snapshot.period_timestamp).unwrap_or(false);
                let in_new_market_window = snapshot.time_remaining_seconds >= PERIOD_DURATION_5M.saturating_sub(NEW_MARKET_PLACE_WINDOW_SECONDS);
                if !already_placed && in_new_market_window {
                    *last = Some(snapshot.period_timestamp);
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
            }

            if !opportunities.is_empty() {
                crate::log_println!("🎯 5m new market detected - placing BTC limit buys at ${:.2} (ASAP)", limit_price);
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
                let mut checked_opportunities = Vec::new();
                for handle in position_check_handles {
                    if let Ok((opp, should_place)) = handle.await {
                        if should_place {
                            checked_opportunities.push(opp);
                        }
                    }
                }
                if !checked_opportunities.is_empty() {
                    crate::log_println!("📤 Placing {} BTC limit buy orders...", checked_opportunities.len());
                    let order_handles: Vec<_> = checked_opportunities.into_iter()
                        .map(|opp| {
                            let trader_clone = trader.clone();
                            let limit_shares_clone = limit_shares;
                            tokio::spawn(async move {
                                let mut last_err = None;
                                for attempt in 1..=3 {
                                    match trader_clone.execute_limit_buy(&opp, false, limit_shares_clone, false /* is_reentry: 5m BTC never does reentry */).await {
                                        Ok(r) => return Ok(r),
                                        Err(e) => {
                                            last_err = Some(e);
                                            if attempt < 3 {
                                                crate::log_println!("   ⚠️ Limit buy failed (attempt {}/3), retrying in 2s...", attempt);
                                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                            }
                                        }
                                    }
                                }
                                Err(last_err.unwrap())
                            })
                        })
                        .collect();
                    let mut error_count = 0;
                    for handle in order_handles {
                        match handle.await {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => {
                                warn!("Error executing limit buy: {}", e);
                                error_count += 1;
                            }
                            Err(e) => {
                                warn!("Error awaiting limit buy task: {}", e);
                                error_count += 1;
                            }
                        }
                    }
                    if error_count == 0 {
                        crate::log_println!("✅ Successfully placed all BTC limit buy orders");
                    } else {
                        crate::log_println!("⚠️  Placed orders with {} errors", error_count);
                    }
                }
            }

            // As soon as one side is filled: cancel the other side's limit order, then trailing stop runs (2-min/3-min) to buy unfilled at ask when trigger hits.
            if let (Some(btc_up), Some(btc_down)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) {
                let key = (snapshot.period_timestamp, snapshot.btc_market.condition_id.clone());
                if !opposite_limit_cancelled_for_market.lock().await.contains(&key)
                    && !hedge_executed_for_market.lock().await.contains(&key)
                    && !two_min_hedge_markets.lock().await.contains(&key)
                {
                    let up_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &btc_up.token_id).await;
                    let down_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &btc_down.token_id).await;
                    if let (Some(up_t), Some(down_t)) = (up_trade.as_ref(), down_trade.as_ref()) {
                        let (up_filled, down_filled) = (up_t.buy_order_confirmed, down_t.buy_order_confirmed);
                        if up_filled != down_filled {
                            let (unfilled_token, unfilled_type) = if !up_filled && down_filled {
                                (btc_up, polymarket_trading_bot::detector::TokenType::BtcUp)
                            } else {
                                (btc_down, polymarket_trading_bot::detector::TokenType::BtcDown)
                            };
                            for attempt in 1..=3 {
                                match trader.cancel_pending_limit_buy(snapshot.period_timestamp, &unfilled_token.token_id).await {
                                    Ok(()) => {
                                        crate::log_println!("   🗑️ One side filled: cancelled unfilled $0.45 limit for BTC {} — trailing stop active for {}", unfilled_type.display_name(), unfilled_type.display_name());
                                        opposite_limit_cancelled_for_market.lock().await.insert(key.clone());
                                        break;
                                    }
                                    Err(e) => {
                                        warn!("Cancel unfilled limit (5m BTC) failed (attempt {}/3): {}", attempt, e);
                                        if attempt < 3 {
                                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Trailing starts right after one side is filled (no time gate). Track lowest_ask; band before 3 min: 0.45, from 3 min: 0.5; trigger when ask >= lowest_ask + trailing_stop.
            let (Some(btc_up), Some(btc_down)) = (snapshot.btc_market.up_token.as_ref(), snapshot.btc_market.down_token.as_ref()) else { return };
            let key = (snapshot.period_timestamp, snapshot.btc_market.condition_id.clone());
            let price_key = (snapshot.period_timestamp, snapshot.btc_market.condition_id.clone());
            let hedge_trailing_stop = config.trading.dual_limit_hedge_trailing_stop.unwrap_or(0.03);

            let run_3min = time_elapsed_seconds >= THREE_MIN_AFTER_SECONDS;

            {
                let h = hedge_executed_for_market.lock().await;
                if h.contains(&key) {
                    // Trailing/hedge already done for this market: clear any trailing state and stop.
                    drop(h);
                    two_min_trailing_min_ask.lock().await.remove(&price_key);
                    *trailing_status_line.lock().await = String::new();
                    return;
                }
            }
            if run_3min {
                let t = two_min_hedge_markets.lock().await;
                if t.contains(&key) { return; }
            }
            // One side filled: we need the filled side's (units, price) and the unfilled side's token/ask.
            // After we cancel the unfilled limit, that trade is REMOVED from pending_trades, so we only have
            // the filled side's trade. Support both (Some, Some) with one filled and (Some, None)/(None, Some) when the other was cancelled.
            let up_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &btc_up.token_id).await;
            let down_trade = trader.get_pending_limit_trade(snapshot.period_timestamp, &btc_down.token_id).await;
            let (unfilled_token, unfilled_type, current_ask, hedge_shares, filled_side_price) = match (up_trade.as_ref(), down_trade.as_ref()) {
                (Some(up_t), Some(down_t)) if up_t.buy_order_confirmed != down_t.buy_order_confirmed => {
                    if !up_t.buy_order_confirmed && down_t.buy_order_confirmed {
                        let ask = btc_up.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or_else(|| btc_up.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0));
                        (btc_up, polymarket_trading_bot::detector::TokenType::BtcUp, ask, down_t.units, down_t.purchase_price)
                    } else {
                        let ask = btc_down.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or_else(|| btc_down.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0));
                        (btc_down, polymarket_trading_bot::detector::TokenType::BtcDown, ask, up_t.units, up_t.purchase_price)
                    }
                }
                // Unfilled side was cancelled (removed from pending); only the filled side remains.
                (Some(up_t), None) if up_t.buy_order_confirmed => {
                    let ask = btc_down.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or_else(|| btc_down.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0));
                    (btc_down, polymarket_trading_bot::detector::TokenType::BtcDown, ask, up_t.units, up_t.purchase_price)
                }
                (None, Some(down_t)) if down_t.buy_order_confirmed => {
                    let ask = btc_up.ask.map(|a| f64::try_from(a).unwrap_or(0.0)).unwrap_or_else(|| btc_up.bid.map(|b| f64::try_from(b).unwrap_or(0.0)).unwrap_or(0.0));
                    (btc_up, polymarket_trading_bot::detector::TokenType::BtcUp, ask, down_t.units, down_t.purchase_price)
                }
                _ => return,
            };
            if hedge_shares < 0.001 {
                return;
            }
            let run_4min = time_elapsed_seconds >= FOUR_MIN_AFTER_SECONDS;
            // From 4 min: if ask >= 0.85 buy at market now. If ask < 0.85 keep trailing (fall through) and buy when ask >= lowest_ask + trailing_stop.
            if run_4min && current_ask >= hedge_price {
                // Before buying: in live mode check real balance; skip if already have >= dual_limit_shares.
                if !trader.is_simulation() {
                    if let Some(bal) = trader.get_token_balance_shares(&unfilled_token.token_id).await {
                        if bal >= hedge_shares - 0.01 {
                            crate::log_println!("   ⏭️ Skipping 4-min hedge buy: {} already has {:.2} shares (need {:.2})", unfilled_type.display_name(), bal, hedge_shares);
                            hedge_executed_for_market.lock().await.insert(key);
                            two_min_trailing_min_ask.lock().await.remove(&price_key);
                            *trailing_status_line.lock().await = String::new();
                            return;
                        }
                    }
                }
                // ask already high: buy at market now. Mark executed immediately so no other tick can re-enter.
                hedge_executed_for_market.lock().await.insert(key.clone());
                two_min_trailing_min_ask.lock().await.remove(&price_key);
                *trailing_status_line.lock().await = String::new();
                let investment = hedge_shares * current_ask;
                crate::log_println!("🕐 4-MIN HEDGE (5m BTC): {} unfilled; ask={:.4} >= {:.2}; buying at market ${:.4}, {:.6} shares. Limit-filled side bought at ${:.4}",
                    unfilled_type.display_name(), current_ask, hedge_price, current_ask, hedge_shares, filled_side_price);
                let opp = BuyOpportunity {
                    condition_id: snapshot.btc_market.condition_id.clone(),
                    token_id: unfilled_token.token_id.clone(),
                    token_type: unfilled_type,
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
                        Ok(()) => { buy_ok = true; break; }
                        Err(e) => {
                            warn!("4-min hedge (5m): market buy failed (attempt {}/3): {}", attempt, e);
                            if attempt < 3 {
                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            }
                        }
                    }
                }
                if !buy_ok {
                    warn!("4-min hedge (5m): market buy failed after 3 attempts");
                    hedge_executed_for_market.lock().await.remove(&key);
                    return;
                }
                trader.mark_limit_trade_filled_by_hedge(snapshot.period_timestamp, &unfilled_token.token_id).await;
                for attempt in 1..=3 {
                    if let Ok(()) = trader.cancel_pending_limit_buy(snapshot.period_timestamp, &unfilled_token.token_id).await {
                        crate::log_println!("   🗑️ Cancelled unfilled $0.45 limit order (4-min hedge)");
                        break;
                    }
                    if attempt < 3 {
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    }
                }
                return;
            }
            // 3-min only, before 4 min: skip when ask >= hedge_price (too expensive). From 4 min we already handled ask >= 0.85 above; here we run trailing when ask < 0.85.
            if run_3min && !run_4min {
                if current_ask >= hedge_price {
                    crate::log_println!(
                        "   📊 Trailing [5m BTC] 3-min: unfilled {} ask={:.4} >= {:.2} — skipping this tick (too expensive), will retry next tick",
                        unfilled_type.display_name(), current_ask, hedge_price
                    );
                    return;
                }
            }

            // Band: 2-min = (1 - dual_limit_price - 0.1), 3-min = (1 - dual_limit_price). is_2min_window = before 3 min only.
            let band_2min = 1.0 - limit_price - BAND_2MIN_OFFSET;
            let band_3min = 1.0 - limit_price;
            let (band_threshold, band_label, is_2min_window) = if run_4min {
                (band_3min, "4-min trailing", false)
            } else if run_3min {
                (band_3min, "3-min", false)
            } else {
                (band_2min, "2-min", true)
            };
            // Show trailing status on price line: lowest, trigger (lowest+0.03), band.
            {
                let trailing_lowest = two_min_trailing_min_ask.lock().await.get(&price_key).copied().unwrap_or(current_ask);
                let trigger = trailing_lowest + hedge_trailing_stop;
                let mut s = trailing_status_line.lock().await;
                *s = format!("trail: {} ask={:.2} low={:.2} trig={:.2} band={:.2}", unfilled_type.display_name(), current_ask, trailing_lowest, trigger, band_threshold);
            }

                // When entering 3-min window, reset lowest_ask once (new baseline) unless we're allowing buy above band.
                let mut allow_buy_above_band = false;
                if current_ask >= band_threshold {
                    let lowest_before = two_min_trailing_min_ask.lock().await.get(&price_key).copied().unwrap_or(current_ask);
                    let bounce_threshold = band_threshold - hedge_trailing_stop;
                    if lowest_before <= bounce_threshold {
                        allow_buy_above_band = true;
                        crate::log_println!(
                            "   Trailing [5m BTC] unfilled {}: ask={:.4} >= {:.2} ({}) but lowest_ask={:.4} <= {:.4} → allow buy (valid bounce)",
                            unfilled_type.display_name(), current_ask, band_threshold, band_label, lowest_before, bounce_threshold
                        );
                    } else {
                        // Only update lowest when current ask is below previous lowest; never raise lowest.
                        if current_ask < lowest_before {
                            two_min_trailing_min_ask.lock().await.insert(price_key.clone(), current_ask);
                            crate::log_println!(
                                "   Trailing [5m BTC] unfilled {}: ask={:.4} >= {:.2} ({}) → new low, lowest_ask to {:.4}",
                                unfilled_type.display_name(), current_ask, band_threshold, band_label, current_ask
                            );
                        }
                        return;
                    }
                }
                // Do not reset lowest_ask when entering 3-min: keep previous lowest and only update when current_ask < previous lowest (so "waiting for bounce" uses true minimum).

                // Trailing: trigger when current_ask >= lowest_ask + trailing_stop.
                // Only update lowest when current ask is BELOW previous lowest; if current_ask >= previous lowest, keep previous lowest_ask.
                // When key is missing (first tick in trailing), insert current_ask to establish baseline so we don't show current=low every tick.
                {
                    let mut min_map = two_min_trailing_min_ask.lock().await;
                    let existing = min_map.get(&price_key).copied();
                    let effective_lowest = match existing {
                        None => {
                            min_map.insert(price_key.clone(), current_ask);
                            current_ask
                        }
                        Some(low) if current_ask < low => {
                            min_map.insert(price_key.clone(), current_ask);
                            current_ask
                        }
                        Some(low) => low,
                    };
                    if current_ask < effective_lowest + hedge_trailing_stop {
                        crate::log_println!(
                            "   Trailing [5m BTC] unfilled {} ({}): ask={:.4} lowest_ask={:.4} trigger_at={:.4} (+{:.3}) (waiting for bounce)",
                            unfilled_type.display_name(), if is_2min_window { "2-min" } else if run_4min { "4-min" } else { "3-min" }, current_ask, effective_lowest, effective_lowest + hedge_trailing_stop, hedge_trailing_stop
                        );
                        return;
                    }
                }

                let lowest_ask = two_min_trailing_min_ask.lock().await.get(&price_key).copied().unwrap_or(current_ask);
                // Before buying: in live mode check real balance; skip if already have >= dual_limit_shares.
                if !trader.is_simulation() {
                    if let Some(bal) = trader.get_token_balance_shares(&unfilled_token.token_id).await {
                        if bal >= hedge_shares - 0.01 {
                            crate::log_println!("   ⏭️ Skipping hedge buy: {} already has {:.2} shares (need {:.2})", unfilled_type.display_name(), bal, hedge_shares);
                            hedge_executed_for_market.lock().await.insert(key);
                            two_min_trailing_min_ask.lock().await.remove(&price_key);
                            *trailing_status_line.lock().await = String::new();
                            return;
                        }
                    }
                }
                crate::log_println!(
                    "   Trailing [5m BTC] unfilled {} ({}): TRIGGER ask={:.4} >= lowest_ask+{:.3} (lowest_ask={:.4}) → executing market buy",
                    unfilled_type.display_name(),
                    if is_2min_window { "2-min" } else if run_4min { "4-min" } else { "3-min" },
                    current_ask, hedge_trailing_stop, lowest_ask
                );
                let investment = hedge_shares * current_ask;
                crate::log_println!("{} (5m BTC): {} unfilled; ask >= lowest_ask+{:.3}; buying at ask ${:.4}, {:.6} shares. Limit-filled side bought at ${:.4}",
                    if is_2min_window { "⏱️ 2-MIN HEDGE" } else if run_4min { "🕐 4-MIN HEDGE (trailing)" } else { "🕐 3-MIN HEDGE" },
                    unfilled_type.display_name(), hedge_trailing_stop, current_ask, hedge_shares, filled_side_price);
                // Mark hedge as executed immediately so no other tick can re-enter trailing/hedge for this market.
                hedge_executed_for_market.lock().await.insert(key.clone());
                two_min_trailing_min_ask.lock().await.remove(&price_key);
                *trailing_status_line.lock().await = String::new();
                if is_2min_window {
                    two_min_hedge_markets.lock().await.insert(key.clone());
                }
                let opp = BuyOpportunity {
                    condition_id: snapshot.btc_market.condition_id.clone(),
                    token_id: unfilled_token.token_id.clone(),
                    token_type: unfilled_type,
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
                        Ok(()) => { buy_ok = true; break; }
                        Err(e) => {
                            warn!("{} (5m): market buy failed (attempt {}/3): {}", if is_2min_window { "2-min hedge" } else if run_4min { "4-min hedge" } else { "3-min hedge" }, attempt, e);
                            if attempt < 3 {
                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            }
                        }
                    }
                }
                if !buy_ok {
                    warn!("{} (5m): market buy failed after 3 attempts - leaving limit in place", if is_2min_window { "2-min hedge" } else if run_4min { "4-min hedge" } else { "3-min hedge" });
                    // Remove key so a later tick can retry (we already inserted above to block re-entry during attempts).
                    hedge_executed_for_market.lock().await.remove(&key);
                    if is_2min_window {
                        two_min_hedge_markets.lock().await.remove(&key);
                    }
                    return;
                }
                trader.mark_limit_trade_filled_by_hedge(snapshot.period_timestamp, &unfilled_token.token_id).await;
                let mut cancel_ok = false;
                for attempt in 1..=3 {
                    match trader.cancel_pending_limit_buy(snapshot.period_timestamp, &unfilled_token.token_id).await {
                        Ok(()) => {
                            crate::log_println!("   🗑️ Cancelled unfilled $0.45 limit order ({} hedge)", if is_2min_window { "2-min" } else if run_4min { "4-min" } else { "3-min" });
                            cancel_ok = true;
                            break;
                        }
                        Err(e) => {
                            warn!("{} (5m): cancel failed (attempt {}/3): {}", if is_2min_window { "2-min hedge" } else if run_4min { "4-min hedge" } else { "3-min hedge" }, attempt, e);
                            if attempt < 3 {
                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            }
                        }
                    }
                }
                if !cancel_ok {
                    warn!("{} (5m): could not cancel limit after 3 attempts - you may have double position", if is_2min_window { "2-min hedge" } else if run_4min { "4-min hedge" } else { "3-min hedge" });
                }
                // hedge_executed_for_market and trailing state already set before execute_buy to stop re-entry.
        }
    }).await;

    Ok(())
}

async fn get_or_discover_markets_5m_btc(
    api: &PolymarketApi,
) -> Result<(polymarket_trading_bot::models::Market, polymarket_trading_bot::models::Market, polymarket_trading_bot::models::Market, polymarket_trading_bot::models::Market)> {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut seen_ids = std::collections::HashSet::new();
    let btc_market = discover_btc_5m_market(api, current_time, &mut seen_ids).await?;
    let eth_market = disabled_eth_market();
    let solana_market = disabled_solana_market();
    let xrp_market = disabled_xrp_market();
    Ok((eth_market, btc_market, solana_market, xrp_market))
}

async fn discover_btc_5m_market(
    api: &PolymarketApi,
    current_time: u64,
    seen_ids: &mut std::collections::HashSet<String>,
) -> Result<polymarket_trading_bot::models::Market> {
    let rounded_time = (current_time / PERIOD_DURATION_5M) * PERIOD_DURATION_5M;
    let slug = format!("btc-updown-5m-{}", rounded_time);
    if let Ok(market) = api.get_market_by_slug(&slug).await {
        if !seen_ids.contains(&market.condition_id) && market.active && !market.closed {
            eprintln!("Found BTC 5m market by slug: {} | Condition ID: {}", market.slug, market.condition_id);
            return Ok(market);
        }
    }
    for offset in 1..=3 {
        let try_time = rounded_time.saturating_sub(offset * PERIOD_DURATION_5M);
        let try_slug = format!("btc-updown-5m-{}", try_time);
        eprintln!("Trying previous BTC 5m market: {}", try_slug);
        if let Ok(market) = api.get_market_by_slug(&try_slug).await {
            if !seen_ids.contains(&market.condition_id) && market.active && !market.closed {
                eprintln!("Found BTC 5m market by slug: {} | Condition ID: {}", market.slug, market.condition_id);
                return Ok(market);
            }
        }
    }
    anyhow::bail!(
        "Could not find active BTC 5-minute up/down market (tried btc-updown-5m-{} and 3 previous periods).",
        rounded_time
    )
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
