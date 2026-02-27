//! Test binary: place multiple limit orders on Polymarket (same or configurable params).
//!
//! Examples:
//!   # Buy current BTC 15m Up + Down with $1 each (market orders)
//!   cargo run --bin test_multiple_orders -- --btc-1usd
//!
//!   cargo run --bin test_multiple_orders -- --count 3 --price-cents 45 --shares 1
//!   cargo run --bin test_multiple_orders -- --token-id <ID> --count 5 --delay-ms 1000

use anyhow::Result;
use clap::Parser;
use chrono::Utc;
use polymarket_trading_bot::models::OrderRequest;
use polymarket_trading_bot::{Config, PolymarketApi};
use rust_decimal::Decimal;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "test_multiple_orders")]
#[command(about = "Place multiple limit orders on Polymarket (sequential)")]
struct Args {
    /// Buy current BTC 15min market Up and Down tokens with $1 USD each (2 market orders)
    #[arg(long)]
    btc_1usd: bool,

    /// Token ID (optional; if not set, discovers current BTC Up token; ignored if --btc-1usd)
    #[arg(long)]
    token_id: Option<String>,

    /// Number of orders to place (ignored if --btc-1usd)
    #[arg(short('n'), long, default_value = "2")]
    count: u32,

    /// Price in cents (e.g. 45 = $0.45) (ignored if --btc-1usd)
    #[arg(long, default_value = "45")]
    price_cents: u64,

    /// Shares per order (ignored if --btc-1usd)
    #[arg(long, default_value = "1")]
    shares: u64,

    /// Delay in ms between placing each order
    #[arg(long, default_value = "500")]
    delay_ms: u64,

    /// Side: BUY or SELL (ignored if --btc-1usd)
    #[arg(long, default_value = "BUY")]
    side: String,

    /// Config file path
    #[arg(short, long, default_value = "config.json")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();
    let config_path = std::path::PathBuf::from(&args.config);
    let config = Config::load(&config_path)?;

    let api = PolymarketApi::new(
        config.polymarket.gamma_api_url.clone(),
        config.polymarket.clob_api_url.clone(),
        config.polymarket.api_key.clone(),
        config.polymarket.api_secret.clone(),
        config.polymarket.api_passphrase.clone(),
        config.polymarket.private_key.clone(),
        config.polymarket.proxy_wallet_address.clone(),
        config.polymarket.signature_type,
    );

    println!("🔐 Authenticating with Polymarket CLOB API...");
    api.authenticate().await?;

    if args.btc_1usd {
        // Buy current BTC 15min market Up and Down with $1 each (market orders)
        println!("🔍 Discovering current BTC 15min market...");
        let condition_id = api
            .discover_current_market("BTC")
            .await?
            .ok_or_else(|| anyhow::anyhow!("Could not find current BTC 15min market"))?;
        let market = api.get_market(&condition_id).await?;
        let up_token = market
            .tokens
            .iter()
            .find(|t| t.outcome == "Up")
            .ok_or_else(|| anyhow::anyhow!("Could not find 'Up' token in BTC market"))?;
        let down_token = market
            .tokens
            .iter()
            .find(|t| t.outcome == "Down")
            .ok_or_else(|| anyhow::anyhow!("Could not find 'Down' token in BTC market"))?;
        println!("   ✅ BTC Up token:   {}...", &up_token.token_id[..up_token.token_id.len().min(24)]);
        println!("   ✅ BTC Down token: {}...", &down_token.token_id[..down_token.token_id.len().min(24)]);

        const USD_EACH: f64 = 1.0;
        let orders_batch: &[(&str, f64, &str, Option<&str>)] = &[
            (up_token.token_id.as_str(), USD_EACH, "BUY", Some("FAK")),
            (down_token.token_id.as_str(), USD_EACH, "BUY", Some("FAK")),
        ];

        println!("\n📝 Placing 2 market BUY orders (${} each) in one batch request:\n", USD_EACH);
        let send_ts = Utc::now();
        let start = Instant::now();
        println!("   send_ts={}", send_ts.format("%Y-%m-%dT%H:%M:%S%.3fZ"));
        let results = api.place_market_orders(orders_batch).await;
        let resp_ts = Utc::now();
        let elapsed_ms = start.elapsed().as_millis();
        println!("   response_ts={}  elapsed_ms={} (one round-trip for both orders)\n", resp_ts.format("%Y-%m-%dT%H:%M:%S%.3fZ"), elapsed_ms);

        let mut success = 0u32;
        let mut failed = 0u32;
        match results {
            Ok(responses) => {
                for (i, resp) in responses.into_iter().enumerate() {
                    let label = if i == 0 { "BTC Up" } else { "BTC Down" };
                    let ok = resp.message.as_deref().map(|m| m.starts_with("Order ID:")).unwrap_or(false);
                    if ok {
                        success += 1;
                        println!("   [{}] {}  ✅ Order ID: {}", i + 1, label, resp.order_id.as_deref().unwrap_or("(none)"));
                    } else {
                        failed += 1;
                        println!("   [{}] {}  ❌ {}", i + 1, label, resp.message.as_deref().unwrap_or("rejected"));
                    }
                }
            }
            Err(e) => {
                failed = 2;
                println!("   ❌ Batch request failed: {}", e);
            }
        }

        println!("\n📊 Done: {} succeeded, {} failed (total 2)", success, failed);
        if failed > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Limit-order mode: one or more limit orders on a single token
    let token_id = if let Some(id) = args.token_id {
        println!("📋 Using provided token ID: {}...", &id[..id.len().min(24)]);
        id
    } else {
        println!("🔍 Discovering current BTC market...");
        let condition_id = api
            .discover_current_market("BTC")
            .await?
            .ok_or_else(|| anyhow::anyhow!("Could not find current BTC market"))?;
        let market = api.get_market(&condition_id).await?;
        let up_token = market
            .tokens
            .iter()
            .find(|t| t.outcome == "Up")
            .ok_or_else(|| anyhow::anyhow!("Could not find 'Up' token in BTC market"))?;
        println!("   ✅ BTC Up token: {}...", &up_token.token_id[..up_token.token_id.len().min(24)]);
        up_token.token_id.clone()
    };

    let price = Decimal::from(args.price_cents) / Decimal::from(100);
    let size = Decimal::from(args.shares);

    println!("\n📝 Placing {} order(s):", args.count);
    println!("   Token: {}...", &token_id[..token_id.len().min(32)]);
    println!("   Side: {}  Price: {}  Size: {}", args.side, price, args.shares);
    println!("   Delay between orders: {} ms\n", args.delay_ms);

    let mut success = 0u32;
    let mut failed = 0u32;

    for i in 1..=args.count {
        let order = OrderRequest {
            token_id: token_id.clone(),
            side: args.side.clone(),
            size: size.to_string(),
            price: price.to_string(),
            order_type: "LIMIT".to_string(),
        };

        let send_ts = Utc::now();
        let start = Instant::now();
        print!("   [{}/{}] Limit order  send_ts={} ... ", i, args.count, send_ts.format("%Y-%m-%dT%H:%M:%S%.3fZ"));
        match api.place_order(&order).await {
            Ok(resp) => {
                let resp_ts = Utc::now();
                let elapsed_ms = start.elapsed().as_millis();
                success += 1;
                println!("response_ts={}  elapsed_ms={}  ✅ Order ID: {}", resp_ts.format("%Y-%m-%dT%H:%M:%S%.3fZ"), elapsed_ms, resp.order_id.as_deref().unwrap_or("(none)"));
            }
            Err(e) => {
                let resp_ts = Utc::now();
                let elapsed_ms = start.elapsed().as_millis();
                failed += 1;
                println!("response_ts={}  elapsed_ms={}  ❌ {}", resp_ts.format("%Y-%m-%dT%H:%M:%S%.3fZ"), elapsed_ms, e);
            }
        }

        if i < args.count && args.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(args.delay_ms)).await;
        }
    }

    println!("\n📊 Done: {} succeeded, {} failed (total {})", success, failed, args.count);
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}
