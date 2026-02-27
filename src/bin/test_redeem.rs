use anyhow::Result;
use clap::Parser;
use polymarket_trading_bot::{PolymarketApi, Config};

#[derive(Parser, Debug)]
#[command(name = "test_redeem")]
#[command(about = "Redeem winning tokens from your portfolio after market resolution")]
struct Args {
    /// Token ID to redeem (optional - if not provided, will scan portfolio and redeem all winning tokens)
    #[arg(short, long)]
    token_id: Option<String>,
    
    /// Config file path
    #[arg(short, long, default_value = "config.json")]
    config: String,
    
    /// Just check portfolio without redeeming
    #[arg(long)]
    check_only: bool,
    
    /// Scan portfolio and list all tokens with balance
    #[arg(long)]
    list: bool,
    
    /// Redeem all winning tokens in portfolio automatically
    #[arg(long)]
    redeem_all: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();
    let config_path = std::path::PathBuf::from(&args.config);
    let config = Config::load(&config_path)?;

    // Create API client
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

    // If --list, --redeem-all flag, or no token_id provided, scan portfolio
    if args.list || args.redeem_all || args.token_id.is_none() {
        println!("🔍 Scanning your portfolio for redeemable positions...\n");

        let wallet = api.get_wallet_address()?;
        println!("   Wallet: {}...\n", &wallet[..20.min(wallet.len())]);

        // Prefer Data API redeemable positions (user=wallet, redeemable=true)
        let redeemable_ids = api.get_redeemable_positions(&wallet).await.unwrap_or_default();
        let mut winning_tokens: Vec<(String, f64, String, String, String)> = Vec::new();
        let mut losing_tokens: Vec<(String, f64, String)> = Vec::new();
        let mut unresolved_tokens: Vec<(String, f64, String)> = Vec::new();

        if !redeemable_ids.is_empty() {
            println!("📋 Data API: {} redeemable condition(s)\n", redeemable_ids.len());
            for (idx, condition_id) in redeemable_ids.iter().enumerate() {
                println!("   {}. Condition ID: {}...", idx + 1, &condition_id[..16.min(condition_id.len())]);
                match api.get_market(condition_id).await {
                    Ok(market) => {
                        let winner = market.tokens.iter().find(|t| t.winner);
                        let outcome = winner
                            .map(|t| if t.outcome == "Yes" || t.outcome == "Up" { "Up" } else { "Down" })
                            .unwrap_or("Unknown");
                        let description = if market.question.is_empty() { format!("Condition {}", condition_id) } else { market.question.clone() };
                        println!("      Market: {}...", &description[..40.min(description.len())]);
                        println!("      Outcome: {}", outcome);
                        println!("      Status: ✅ WINNING (redeemable)");
                        winning_tokens.push((
                            winner.map(|t| t.token_id.clone()).unwrap_or_default(),
                            0.0,
                            description,
                            condition_id.clone(),
                            outcome.to_string(),
                        ));
                    }
                    Err(e) => {
                        println!("      ⚠️  Error fetching market: {}", e);
                        unresolved_tokens.push((String::new(), 0.0, condition_id.clone()));
                    }
                }
                println!();
            }
        }

        // If no redeemable from Data API, fall back to portfolio tokens (requires CLOB API credentials)
        if winning_tokens.is_empty() && redeemable_ids.is_empty() {
            if !api.has_api_credentials() {
                anyhow::bail!(
                    "No redeemable positions from Data API and portfolio scan requires API credentials. \
                    Set api_key, api_secret, and api_passphrase in config.json (and ensure the API key is enabled on Polymarket)."
                );
            }
            let tokens_result: Result<Vec<(String, f64, String, String)>, _> = api.get_portfolio_tokens_all(None, None).await;
            match tokens_result {
                Ok(tokens) => {
                    if tokens.is_empty() {
                        println!("   ⚠️  No tokens found with balance > 0 and no redeemable positions from Data API.");
                        println!("\n💡 Tips:");
                        println!("   - Make sure you've bought tokens and the market has resolved");
                        println!("   - Data API: https://data-api.polymarket.com/positions?user=<wallet>&redeemable=true");
                        return Ok(());
                    }
                    println!("📋 Found {} token(s) with balance (portfolio):\n", tokens.len());
                    for (idx, (token_id, balance, description, condition_id)) in tokens.iter().enumerate() {
                        println!("   {}. {} - Balance: {:.6} shares", idx + 1, description, balance);
                        println!("      Token ID: {}...", &token_id[..16.min(token_id.len())]);
                        let outcome = if description.contains("Up") || description.contains("Yes") {
                            "Up"
                        } else if description.contains("Down") || description.contains("No") {
                            "Down"
                        } else {
                            "Unknown"
                        };
                        match api.get_market(condition_id).await {
                            Ok(market) => {
                                let is_winner = market.tokens.iter().any(|t| t.token_id == *token_id && t.winner);
                                if !market.closed {
                                    println!("      Status: ⏳ Market not yet resolved");
                                    unresolved_tokens.push((token_id.clone(), *balance, description.clone()));
                                } else if is_winner {
                                    println!("      Status: ✅ WINNING TOKEN (worth $1.00)");
                                    winning_tokens.push((token_id.clone(), *balance, description.clone(), condition_id.clone(), outcome.to_string()));
                                } else {
                                    println!("      Status: ❌ LOSING TOKEN (worth $0.00)");
                                    losing_tokens.push((token_id.clone(), *balance, description.clone()));
                                }
                            }
                            Err(e) => {
                                println!("      ⚠️  Error checking market: {}", e);
                                unresolved_tokens.push((token_id.clone(), *balance, description.clone()));
                            }
                        }
                        println!();
                    }
                }
                Err(e) => {
                    let err_str = e.to_string();
                    eprintln!("❌ Failed to scan portfolio: {}", e);
                    if err_str.to_lowercase().contains("disabled") || err_str.to_lowercase().contains("api key") {
                        eprintln!("\n💡 If Polymarket says 'api key disabled': enable the key in your Polymarket account or create a new API key.");
                    }
                    eprintln!("\n💡 You can still specify a token ID manually:");
                    eprintln!("   cargo run --bin test_redeem -- --token-id <TOKEN_ID>");
                    return Err(e);
                }
            }
        }

        // Summary
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("📊 Portfolio Summary:");
        println!("   ✅ Winning / redeemable: {} position(s)", winning_tokens.len());
        println!("   ❌ Losing tokens (worth $0.00): {} token(s)", losing_tokens.len());
        println!("   ⏳ Unresolved: {} token(s)", unresolved_tokens.len());
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        if args.check_only || (args.list && !args.redeem_all) {
            if !winning_tokens.is_empty() {
                println!("💡 To redeem all winning tokens, run:");
                println!("   cargo run --bin test_redeem -- --redeem-all");
            }
            return Ok(());
        }

        if args.redeem_all {
            if winning_tokens.is_empty() {
                println!("⚠️  No winning tokens found to redeem.");
                if !unresolved_tokens.is_empty() {
                    println!("   You have {} token(s) in unresolved markets - wait for market resolution.", unresolved_tokens.len());
                }
                return Ok(());
            }
            println!("💰 Redeeming all {} winning position(s)...\n", winning_tokens.len());
            const DELAY_BETWEEN_REDEEMS_MS: u64 = 3000;
            let mut success_count = 0;
            let mut fail_count = 0;
            for (idx, (token_id, balance, description, condition_id, outcome)) in winning_tokens.iter().enumerate() {
                if idx > 0 {
                    println!("   ⏳ Waiting {}s before next redeem...", DELAY_BETWEEN_REDEEMS_MS / 1000);
                    tokio::time::sleep(tokio::time::Duration::from_millis(DELAY_BETWEEN_REDEEMS_MS)).await;
                }
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("Redeeming: {} (condition: {}...)", description, &condition_id[..16.min(condition_id.len())]);
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                match redeem_token(&api, token_id, condition_id, outcome, *balance).await {
                    Ok(_) => {
                        success_count += 1;
                        println!("✅ Successfully redeemed {}\n", description);
                    }
                    Err(e) => {
                        fail_count += 1;
                        eprintln!("❌ Failed to redeem {}: {}\n", description, e);
                    }
                }
            }
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("📊 Summary: ✅ {} succeeded, ❌ {} failed (total {})", success_count, fail_count, winning_tokens.len());
            return Ok(());
        }

        if args.token_id.is_none() && !winning_tokens.is_empty() {
            println!("💰 No token ID specified. Using first winning position: {}\n", winning_tokens[0].2);
            let (token_id, balance, _, condition_id, outcome) = &winning_tokens[0];
            return redeem_token(&api, token_id, condition_id, outcome, *balance).await;
        }
    }
    
    // If token_id is provided, we need condition_id and outcome too
    // For manual token_id, try to find it in recent markets
    let token_id = args.token_id.as_ref().ok_or_else(|| anyhow::anyhow!("Token ID is required. Use --list to scan portfolio first."))?;
    
    println!("🔍 Finding market for token {}...\n", &token_id[..16.min(token_id.len())]);
    
    // Scan recent markets to find this token
    let all_tokens = api.get_portfolio_tokens_all(None, None).await?;
    match all_tokens.iter().find(|(tid, _, _, _)| tid == token_id) {
        Some((_, balance, _, condition_id)) => {
            // Determine outcome from description or check market
            let outcome = if let Ok(market) = api.get_market(condition_id).await {
                market.tokens.iter()
                    .find(|t| t.token_id == *token_id)
                    .map(|t| if t.outcome == "Yes" || t.outcome == "Up" { "Up" } else { "Down" })
                    .unwrap_or("Unknown")
            } else {
                "Unknown"
            };
            
            println!("📊 Token Balance: {:.6} shares\n", balance);
            
            if args.check_only {
                println!("✅ Check complete - token has balance");
                return Ok(());
            }
            
            return redeem_token(&api, token_id, condition_id, outcome, *balance).await;
        }
        None => {
            anyhow::bail!("Token not found in portfolio. Make sure you own this token and it's from a BTC, ETH, or Solana 15-minute market.");
        }
    }
}

/// Find which market a token belongs to and determine outcome
async fn find_token_market(
    api: &PolymarketApi,
    _token_id: &str,
    description: &str,
) -> Result<Option<(String, String)>> {
    // Determine if BTC or ETH based on description
    let asset = if description.contains("BTC") {
        "BTC"
    } else if description.contains("ETH") {
        "ETH"
    } else {
        return Ok(None);
    };
    
    // Discover current market
    if let Some(condition_id) = api.discover_current_market(asset).await? {
        // Determine outcome based on description
        let outcome = if description.contains("Up") {
            "Up"
        } else if description.contains("Down") {
            "Down"
        } else {
            return Ok(None);
        };
        
        return Ok(Some((condition_id, outcome.to_string())));
    }
    
    Ok(None)
}

/// Find market for a token manually by checking BTC and ETH markets
async fn find_token_market_manual(
    api: &PolymarketApi,
    token_id: &str,
    btc_condition_id: Option<&str>,
    eth_condition_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    // Check BTC market
    if let Some(condition_id) = btc_condition_id {
        if let Ok(market) = api.get_market(condition_id).await {
            for token in &market.tokens {
                if token.token_id == *token_id {
                    let outcome = if token.outcome == "Yes" || token.outcome == "Up" {
                        "Up"
                    } else {
                        "Down"
                    };
                    return Ok(Some((condition_id.to_string(), outcome.to_string())));
                }
            }
        }
    }
    
    // Check ETH market
    if let Some(condition_id) = eth_condition_id {
        if let Ok(market) = api.get_market(condition_id).await {
            for token in &market.tokens {
                if token.token_id == *token_id {
                    let outcome = if token.outcome == "Yes" || token.outcome == "Up" {
                        "Up"
                    } else {
                        "Down"
                    };
                    return Ok(Some((condition_id.to_string(), outcome.to_string())));
                }
            }
        }
    }
    
    Ok(None)
}

/// Redeem a winning token
async fn redeem_token(
    api: &PolymarketApi,
    token_id: &str,
    condition_id: &str,
    outcome: &str,
    balance: f64,
) -> Result<()> {
    println!("🔄 Attempting to redeem token...");
    println!("   Token ID: {}...", &token_id[..16.min(token_id.len())]);
    println!("   Condition ID: {}...", &condition_id[..16.min(condition_id.len())]);
    println!("   Outcome: {}", outcome);
    println!("   Balance: {:.6} shares", balance);
    println!();
    
    // Check if market is resolved and token is winner
    match api.get_market(condition_id).await {
        Ok(market) => {
            if !market.closed {
                anyhow::bail!("Market is not yet resolved. Cannot redeem tokens until market closes.");
            }
            
            let is_winner = market.tokens.iter()
                .any(|t| t.token_id == *token_id && t.winner);
            
            if !is_winner {
                anyhow::bail!("Token is not a winner (worth $0.00). Only winning tokens can be redeemed.");
            }
            
            println!("   ✅ Market is resolved - token is a winner (worth $1.00)");
            println!("   💰 Expected redemption value: ${:.6}\n", balance);
        }
        Err(e) => {
            anyhow::bail!("Failed to check market status: {}", e);
        }
    }
    
    // Redeem the token
    match api.redeem_tokens(condition_id, token_id, outcome).await {
        Ok(response) => {
            println!("✅ REDEMPTION SUCCESSFUL!");
            if let Some(msg) = &response.message {
                println!("   Message: {}", msg);
            }
            if let Some(amount) = &response.amount_redeemed {
                println!("   Amount redeemed: {}", amount);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ REDEMPTION FAILED: {}", e);
            Err(e)
        }
    }
}
