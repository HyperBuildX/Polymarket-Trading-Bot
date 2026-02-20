use anyhow::Result;
use clap::Parser;
use rust_decimal::Decimal;
use polymarket_arbitrage_bot::{PolymarketApi, Config};

#[derive(Parser, Debug)]
#[command(name = "test_redeem")]
#[command(about = "Redeem winning tokens from your portfolio after market resolution (like Python redeem.py)")]
struct Args {
    /// Condition ID to redeem (hex, e.g. 0x37638d6e...). Same as Python: python redeem.py <condition_id>
    #[arg(long)]
    condition_id: Option<String>,
    
    /// Token ID to redeem (optional - if not provided, will scan portfolio or use --condition-id)
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
    
    /// Only redeem YES positions (index set 1). Same as Python --yes-only
    #[arg(long)]
    yes_only: bool,
    
    /// Only redeem NO positions (index set 2). Same as Python --no-only
    #[arg(long)]
    no_only: bool,
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

    // Redeem by condition ID (same as Python: python redeem.py <condition_id> [--yes-only] [--no-only])
    if let Some(condition_id) = &args.condition_id {
        let redeem_yes = !args.no_only;
        let redeem_no = !args.yes_only;
        if !redeem_yes && !redeem_no {
            anyhow::bail!("Must redeem at least one position. Use --yes-only, --no-only, or neither for both.");
        }
        println!("\n{}", "=".repeat(70));
        println!("Redeeming positions for condition ID: {}", condition_id);
        println!("Redeem YES: {}, Redeem NO: {}", redeem_yes, redeem_no);
        println!("{}\n", "=".repeat(70));
        let outcome = if redeem_yes && redeem_no {
            "YES and NO (contract pays winning only)"
        } else if redeem_yes {
            "YES only"
        } else {
            "NO only"
        };
        match api.redeem_tokens(condition_id, "", outcome, redeem_yes, redeem_no).await {
            Ok(res) => {
                println!("✓ Redeem successful!");
                if let Some(tx) = &res.transaction_hash {
                    println!("Transaction hash: {}", tx);
                }
                if let Some(id) = res.message.as_ref() {
                    println!("Details: {}", id);
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }

    // If --list, --redeem-all flag, or no token_id provided, scan portfolio
    if args.list || args.redeem_all || args.token_id.is_none() {
        println!("🔍 Scanning your portfolio for tokens with balance (BTC markets only)...\n");
        
        let tokens_result: Result<Vec<(String, f64, String, String)>, _> = api.get_portfolio_tokens_btc_only().await;
        match tokens_result {
            Ok(tokens) => {
                if tokens.is_empty() {
                    println!("   ⚠️  No tokens found with balance > 0");
                    println!("\n💡 Tips:");
                    println!("   - Make sure you've bought tokens from your portfolio");
                    println!("   - The script checks the last 10 market periods (2.5 hours)");
                    println!("   - Only BTC markets are checked (ETH/Solana/XRP disabled)");
                    println!("   - Try buying a BTC token and run this again");
                    return Ok(());
                }
                
                println!("📋 Found {} token(s) with balance:\n", tokens.len());
                
                // Check each token's market status
                let mut winning_tokens = Vec::new();
                let mut losing_tokens = Vec::new();
                let mut unresolved_tokens = Vec::new();
                
                for (idx, (token_id, balance, description, condition_id)) in tokens.iter().enumerate() {
                    println!("   {}. {} - Balance: {:.6} shares", idx + 1, description, balance);
                    println!("      Token ID: {}", token_id);
                    println!("      Condition ID: {}...", &condition_id[..16.min(condition_id.len())]);
                    
                    // Determine outcome from description
                    let outcome = if description.contains("Up") || description.contains("Yes") {
                        "Up"
                    } else if description.contains("Down") || description.contains("No") {
                        "Down"
                    } else {
                        "Unknown"
                    };
                    
                    // Determine asset type (BTC, ETH, or Solana)
                    let asset_type = if description.contains("BTC") {
                        "BTC"
                    } else if description.contains("ETH") {
                        "ETH"
                    } else if description.contains("Solana") || description.contains("SOL") {
                        "Solana"
                    } else {
                        "Unknown"
                    };
                    
                    println!("      Asset: {}", asset_type);
                    println!("      Outcome: {}", outcome);
                    
                    // Check market resolution
                    match api.get_market(condition_id).await {
                        Ok(market) => {
                            let is_closed = market.closed;
                            let is_winner = market.tokens.iter()
                                .any(|t| t.token_id == *token_id && t.winner);
                            
                            if !is_closed {
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
                
                // Summary
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("📊 Portfolio Summary:");
                println!("   ✅ Winning tokens (redeemable): {} token(s)", winning_tokens.len());
                println!("   ❌ Losing tokens (worth $0.00): {} token(s)", losing_tokens.len());
                println!("   ⏳ Unresolved markets: {} token(s)", unresolved_tokens.len());
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                
                if args.check_only || (args.list && !args.redeem_all) {
                    if !winning_tokens.is_empty() {
                        println!("💡 To redeem all winning tokens, run:");
                        println!("   cargo run --bin test_redeem -- --redeem-all");
                    }
                    return Ok(());
                }
                
                // If --redeem-all, redeem all winning tokens
                if args.redeem_all {
                    if winning_tokens.is_empty() {
                        println!("⚠️  No winning tokens found to redeem.");
                        if !losing_tokens.is_empty() {
                            println!("   You have {} losing token(s) (worth $0.00) - these cannot be redeemed.", losing_tokens.len());
                        }
                        if !unresolved_tokens.is_empty() {
                            println!("   You have {} token(s) in unresolved markets - wait for market resolution.", unresolved_tokens.len());
                        }
                        return Ok(());
                    }
                    
                    println!("💰 Redeeming all {} winning token(s)...\n", winning_tokens.len());
                    let mut success_count = 0;
                    let mut fail_count = 0;
                    
                    for (token_id, balance, description, condition_id, outcome) in &winning_tokens {
                        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        println!("Redeeming: {} (Balance: {:.6} shares)", description, balance);
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
                    println!("📊 Summary:");
                    println!("   ✅ Successfully redeemed: {} token(s)", success_count);
                    println!("   ❌ Failed: {} token(s)", fail_count);
                    println!("   📦 Total winning tokens: {} token(s)", winning_tokens.len());
                    return Ok(());
                }
                
                // If no token_id specified but we have winning tokens, use the first one
                if args.token_id.is_none() && !winning_tokens.is_empty() {
                    println!("💰 No token ID specified. Using first winning token: {}\n", winning_tokens[0].2);
                    let (token_id, balance, _, condition_id, outcome) = &winning_tokens[0];
                    return redeem_token(&api, token_id, condition_id, outcome, *balance).await;
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to scan portfolio: {}", e);
                eprintln!("\n💡 You can still specify a token ID manually:");
                eprintln!("   cargo run --bin test_redeem -- --token-id <TOKEN_ID>");
                return Err(e);
            }
        }
    }
    
    // If token_id is provided, we need condition_id and outcome too
    // For manual token_id, try to find it in recent markets
    let token_id = args.token_id.as_ref().ok_or_else(|| anyhow::anyhow!("Token ID is required. Use --list to scan portfolio first."))?;
    
    println!("🔍 Finding market for token {} (BTC markets only)...\n", &token_id[..16.min(token_id.len())]);
    
    let all_tokens = api.get_portfolio_tokens_btc_only().await?;
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
            anyhow::bail!("Token not found in BTC portfolio. This script checks BTC markets only. Make sure you own this token and it's from a BTC 15-minute market.");
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
    match api.redeem_tokens(condition_id, token_id, outcome, true, true).await {
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
}
    }
}
