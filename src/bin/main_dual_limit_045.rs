// Limit order version: place Up/Down limit buys at market start with fixed price

use polymarket_arbitrage_bot::*;
use anyhow::{Context, Result};
use clap::Parser;
use polymarket_arbitrage_bot::config::{Args, Config};
use log::warn;
use std::sync::Arc;
use std::io::{self, Write};
use std::fs::{File, OpenOptions};
use std::sync::{Mutex, OnceLock};
use chrono::Utc;

use polymarket_arbitrage_bot::api::PolymarketApi;
use polymarket_arbitrage_bot::monitor::MarketMonitor;
use polymarket_arbitrage_bot::detector::BuyOpportunity;
use polymarket_arbitrage_bot::trader::Trader;

const LIMIT_PRICE: f64 = 0.45;
const PERIOD_DURATION: u64 = 900;

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
    polymarket_arbitrage_bot::init_history_file(log_file.try_clone().context("Failed to clone history file for lib.rs")?);

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

    eprintln!("🚀 Starting Polymarket Dual Limit-Start Bot");
    eprintln!("📝 Logs are being saved to: history.toml");
    let is_simulation = args.is_simulation();
    eprintln!("Mode: {}", if is_simulation { "SIMULATION" } else { "PRODUCTION" });
    let limit_price = config.trading.dual_limit_price.unwrap_or(LIMIT_PRICE);
    let limit_shares = config.trading.dual_limit_shares;
    eprintln!(
        "Strategy: At market start, place limit buys for BTC, ETH, SOL, and XRP Up/Down at ${:.2}",
        limit_price
    );
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

    api.authenticate().await.context(
        "Authentication failed. Set private_key (and api_key, api_secret, api_passphrase if using API credentials) in config.json."
    )?;
    eprintln!("✅ Authentication successful!");
    eprintln!("═══════════════════════════════════════════════════════════");

    eprintln!("🔍 Discovering BTC, ETH, Solana, and XRP markets...");
    let (eth_market_data, btc_market_data, solana_market_data, xrp_market_data) =
        get_or_discover_markets(
            &api,
            config.trading.enable_eth_trading,
            config.trading.enable_solana_trading,
            config.trading.enable_xrp_trading,
        ).await?;

    let monitor = MarketMonitor::new(
        api.clone(),
        eth_market_data,
        btc_market_data,
        solana_market_data,
        xrp_market_data,
        config.trading.check_interval_ms,
        is_simulation,
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
                    trader_check.print_trade_summary().await;
                }
            }
        }
    });

    // Background task to check market closure
    let trader_closure = trader_clone.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
            config.trading.market_closure_check_interval_seconds
        ));
        loop {
            interval.tick().await;
            if let Err(e) = trader_closure.check_market_closure().await {
                warn!("Error checking market closure: {}", e);
            }
        }
    });

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
    tokio::spawn(async move {
        loop {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let current_period = (current_time / 900) * 900;
            let current_market_timestamp = monitor_for_period_check.get_current_market_timestamp().await;

            if current_market_timestamp != current_period && current_market_timestamp != 0 {
                eprintln!("🔄 Market period mismatch detected! Current market: {}, Current period: {}",
                    current_market_timestamp, current_period);
            } else {
                let next_period_timestamp = current_period + 900;
                let sleep_duration = if next_period_timestamp > current_time {
                    next_period_timestamp - current_time
                } else {
                    0
                };

                eprintln!("⏰ Current market period: {}, next period starts in {} seconds",
                    current_market_timestamp, sleep_duration);

                if sleep_duration > 0 && sleep_duration < 1800 {
                    tokio::time::sleep(tokio::time::Duration::from_secs(sleep_duration)).await;
                } else if sleep_duration == 0 {
                    eprintln!("🔄 Next period already started, discovering new market...");
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
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
                        // Log market start in simulation mode
                        if let Some(tracker) = &simulation_tracker_for_market_start {
                            let period = (current_time / 900) * 900;
                            tracker.log_market_start(
                                period,
                                &eth_market.condition_id,
                                &btc_market.condition_id,
                                &solana_market.condition_id,
                                &xrp_market.condition_id
                            ).await;
                        }
                        trader_for_period_reset.reset_period(current_market_timestamp).await;
                    }
                }
                (Err(e), _) => warn!("Failed to discover new ETH market: {}", e),
                (_, Err(e)) => warn!("Failed to discover new BTC market: {}", e),
            }
        }
    });

    let last_placed_period = Arc::new(tokio::sync::Mutex::new(None::<u64>));
    let last_seen_period = Arc::new(tokio::sync::Mutex::new(None::<u64>));
    let enable_eth = config.trading.enable_eth_trading;
    let enable_solana = config.trading.enable_solana_trading;
    let enable_xrp = config.trading.enable_xrp_trading;

    monitor_arc.start_monitoring(move |snapshot| {
        let trader = trader_clone.clone();
        let last_placed_period = last_placed_period.clone();
        let last_seen_period = last_seen_period.clone();
        let enable_eth = enable_eth;
        let enable_solana = enable_solana;
        let enable_xrp = enable_xrp;

        async move {
            if snapshot.time_remaining_seconds == 0 {
                return;
            }

            // Skip the current market if the bot starts after it has already begun.
            {
                let mut seen = last_seen_period.lock().await;
                if seen.is_none() {
                    *seen = Some(snapshot.period_timestamp);
                    return;
                }
                if *seen != Some(snapshot.period_timestamp) {
                    *seen = Some(snapshot.period_timestamp);
                }
            }

            let time_elapsed_seconds = PERIOD_DURATION - snapshot.time_remaining_seconds;
            if time_elapsed_seconds > 2 {
                return;
            }

            {
                let mut last = last_placed_period.lock().await;
                if last.map(|p| p == snapshot.period_timestamp).unwrap_or(false) {
                    return;
                }
                *last = Some(snapshot.period_timestamp);
            }

            let mut opportunities: Vec<BuyOpportunity> = Vec::new();

            let time_elapsed_seconds = PERIOD_DURATION - snapshot.time_remaining_seconds;

            if let Some(btc_up) = snapshot.btc_market.up_token.as_ref() {
                opportunities.push(BuyOpportunity {
                    condition_id: snapshot.btc_market.condition_id.clone(),
                    token_id: btc_up.token_id.clone(),
                    token_type: crate::detector::TokenType::BtcUp,
                    bid_price: limit_price,
                    period_timestamp: snapshot.period_timestamp,
                    time_remaining_seconds: snapshot.time_remaining_seconds,
                    time_elapsed_seconds,
                    use_market_order: false,
                });
            }
            if let Some(btc_down) = snapshot.btc_market.down_token.as_ref() {
                opportunities.push(BuyOpportunity {
                    condition_id: snapshot.btc_market.condition_id.clone(),
                    token_id: btc_down.token_id.clone(),
                    token_type: crate::detector::TokenType::BtcDown,
                    bid_price: limit_price,
                    period_timestamp: snapshot.period_timestamp,
                    time_remaining_seconds: snapshot.time_remaining_seconds,
                    time_elapsed_seconds,
                    use_market_order: false,
                });
            }

            if enable_eth {
                if let Some(eth_up) = snapshot.eth_market.up_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.eth_market.condition_id.clone(),
                        token_id: eth_up.token_id.clone(),
                        token_type: crate::detector::TokenType::EthUp,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                    });
                }
                if let Some(eth_down) = snapshot.eth_market.down_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.eth_market.condition_id.clone(),
                        token_id: eth_down.token_id.clone(),
                        token_type: crate::detector::TokenType::EthDown,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                    });
                }
            }
            if enable_solana {
                if let Some(solana_up) = snapshot.solana_market.up_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.solana_market.condition_id.clone(),
                        token_id: solana_up.token_id.clone(),
                        token_type: crate::detector::TokenType::SolanaUp,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                    });
                }
                if let Some(solana_down) = snapshot.solana_market.down_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.solana_market.condition_id.clone(),
                        token_id: solana_down.token_id.clone(),
                        token_type: crate::detector::TokenType::SolanaDown,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                    });
                }
            }

            if enable_xrp {
                if let Some(xrp_up) = snapshot.xrp_market.up_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.xrp_market.condition_id.clone(),
                        token_id: xrp_up.token_id.clone(),
                        token_type: crate::detector::TokenType::XrpUp,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                    });
                }
                if let Some(xrp_down) = snapshot.xrp_market.down_token.as_ref() {
                    opportunities.push(BuyOpportunity {
                        condition_id: snapshot.xrp_market.condition_id.clone(),
                        token_id: xrp_down.token_id.clone(),
                        token_type: crate::detector::TokenType::XrpDown,
                        bid_price: limit_price,
                        period_timestamp: snapshot.period_timestamp,
                        time_remaining_seconds: snapshot.time_remaining_seconds,
                        time_elapsed_seconds,
                        use_market_order: false,
                    });
                }
            }

            if opportunities.is_empty() {
                return;
            }

            crate::log_println!("🎯 Market start detected - placing limit buys at ${:.2}", limit_price);
            for opportunity in opportunities {
                if trader.has_active_position(opportunity.period_timestamp, opportunity.token_type.clone()).await {
                    continue;
                }
                if let Err(e) = trader.execute_limit_buy(&opportunity, false, limit_shares).await {
                    warn!("Error executing limit buy: {}", e);
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
) -> Result<(crate::models::Market, crate::models::Market, crate::models::Market, crate::models::Market)> {
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
            crate::models::Market {
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

fn disabled_eth_market() -> crate::models::Market {
    crate::models::Market {
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

fn disabled_solana_market() -> crate::models::Market {
    crate::models::Market {
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

fn disabled_xrp_market() -> crate::models::Market {
    crate::models::Market {
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
) -> crate::models::Market {
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
) -> crate::models::Market {
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
) -> Result<crate::models::Market> {
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

