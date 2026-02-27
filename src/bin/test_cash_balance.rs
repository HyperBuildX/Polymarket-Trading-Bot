use anyhow::Result;
use clap::Parser;
use polymarket_trading_bot::{Config, PolymarketApi};
use rust_decimal::Decimal;

#[derive(Parser, Debug)]
#[command(name = "test_cash_balance")]
#[command(about = "Check USDC (cash) balance of your Polymarket account")]
struct Args {
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

    println!("🔍 Fetching USDC balance and allowance...\n");

    let (balance, allowance) = api.check_usdc_balance_allowance().await?;

    let one_million = Decimal::from(1_000_000u64);
    let balance_dollars = balance / one_million;
    let allowance_dollars = allowance / one_million;

    println!("   Cash (USDC) balance:  ${:.2}", balance_dollars);
    println!("   USDC allowance (to Exchange): ${:.2}", allowance_dollars);
    println!();

    Ok(())
}
