/**
 * Polymarket Dual Limit-Start Bot (TypeScript)
 * At each 15-minute market start, place limit buys for BTC/ETH/SOL/XRP Up and Down at a fixed price (e.g. $0.45).
 * Port of Polymarket-Trading-Bot-Rust main_dual_limit_045.
 */
import { loadConfig, parseArgs } from "./config.js";
import { PolymarketApi } from "./api.js";
import { createClobClient, type ClobClient } from "./clob.js";
import { Trader } from "./trader.js";
import { fetchSnapshot, formatPrices, currentPeriodTimestamp } from "./monitor.js";
import type { Market, MarketSnapshot, BuyOpportunity, TokenType } from "./types.js";
import { tokenTypeDisplayName } from "./types.js";

const LIMIT_PRICE = 0.45;
const PERIOD_DURATION = 900;
const DEFAULT_SELL_TRIGGER_BID = 0.8;
const DEFAULT_SELL_AT_PRICE = 0.85;
const LIMIT_SELL_MAX_RETRIES = 5;
const LIMIT_SELL_RETRY_DELAY_MS = 3000;
/** Skip limit sell if filled position is below this (avoids CLOB min size rejections). */
const MIN_LIMIT_SELL_SHARES = 0.01;

function log(msg: string): void {
  process.stderr.write(msg + "\n");
}

function disabledMarket(conditionId: string, slug: string, question: string): Market {
  return {
    conditionId,
    slug,
    question,
    active: false,
    closed: true,
  };
}

async function discoverMarket(
  api: PolymarketApi,
  name: string,
  slugPrefixes: string[],
  currentTime: number,
  seenIds: Set<string>,
  includePrevious: boolean
): Promise<Market> {
  const roundedTime = Math.floor(currentTime / 900) * 900;
  for (let i = 0; i < slugPrefixes.length; i++) {
    const prefix = slugPrefixes[i];
    if (i > 0) log(`🔍 Trying ${name} market with slug prefix '${prefix}'...`);
    let slug = `${prefix}-updown-15m-${roundedTime}`;
    try {
      const market = await api.getMarketBySlug(slug);
      if (!seenIds.has(market.conditionId) && market.active && !market.closed) {
        log(`Found ${name} market by slug: ${market.slug} | Condition ID: ${market.conditionId}`);
        return market;
      }
    } catch {
      // try previous periods
    }
    if (includePrevious) {
      for (let offset = 1; offset <= 3; offset++) {
        const tryTime = roundedTime - offset * 900;
        slug = `${prefix}-updown-15m-${tryTime}`;
        try {
          const market = await api.getMarketBySlug(slug);
          if (!seenIds.has(market.conditionId) && market.active && !market.closed) {
            log(`Found ${name} market by slug: ${market.slug} | Condition ID: ${market.conditionId}`);
            return market;
          }
        } catch {
          /* skip */
        }
      }
    }
  }
  throw new Error(`Could not find active ${name} 15-minute up/down market (tried: ${slugPrefixes.join(", ")})`);
}

async function getOrDiscoverMarkets(
  api: PolymarketApi,
  enableEth: boolean,
  enableSolana: boolean,
  enableXrp: boolean
): Promise<{ eth: Market; btc: Market; solana: Market; xrp: Market }> {
  const now = Math.floor(Date.now() / 1000);
  const seenIds = new Set<string>();

  const eth = enableEth
    ? await discoverMarket(api, "ETH", ["eth"], now, seenIds, true).catch(() => {
        log("⚠️ Could not discover ETH market - using fallback");
        return disabledMarket("dummy_eth_fallback", "eth-updown-15m-fallback", "ETH Trading Disabled");
      })
    : disabledMarket("dummy_eth_fallback", "eth-updown-15m-fallback", "ETH Trading Disabled");
  seenIds.add(eth.conditionId);

  log("🔍 Discovering BTC market...");
  const btc = await discoverMarket(api, "BTC", ["btc"], now, seenIds, true).catch(() => {
    log("⚠️ Could not discover BTC market - using fallback");
    return disabledMarket("dummy_btc_fallback", "btc-updown-15m-fallback", "BTC Trading Disabled");
  });
  seenIds.add(btc.conditionId);

  const solana = enableSolana
    ? await discoverMarket(api, "Solana", ["solana", "sol"], now, seenIds, false).catch(() => {
        log("⚠️ Could not discover Solana market - using fallback");
        return disabledMarket("dummy_solana_fallback", "solana-updown-15m-fallback", "Solana Trading Disabled");
      })
    : disabledMarket("dummy_solana_fallback", "solana-updown-15m-fallback", "Solana Trading Disabled");

  const xrp = enableXrp
    ? await discoverMarket(api, "XRP", ["xrp"], now, seenIds, false).catch(() => {
        log("⚠️ Could not discover XRP market - using fallback");
        return disabledMarket("dummy_xrp_fallback", "xrp-updown-15m-fallback", "XRP Trading Disabled");
      })
    : disabledMarket("dummy_xrp_fallback", "xrp-updown-15m-fallback", "XRP Trading Disabled");

  return { eth, btc, solana, xrp };
}

function buildOpportunities(
  snapshot: MarketSnapshot,
  limitPrice: number,
  enableEth: boolean,
  enableSolana: boolean,
  enableXrp: boolean
): BuyOpportunity[] {
  const opps: BuyOpportunity[] = [];
  const period = snapshot.period_timestamp;
  const timeRem = snapshot.time_remaining_seconds;
  const timeElapsed = PERIOD_DURATION - timeRem;

  const add = (conditionId: string, tokenId: string, tokenType: TokenType) => {
    opps.push({
      condition_id: conditionId,
      token_id: tokenId,
      token_type: tokenType,
      bid_price: limitPrice,
      period_timestamp: period,
      time_remaining_seconds: timeRem,
      time_elapsed_seconds: timeElapsed,
      use_market_order: false,
    });
  };

  if (snapshot.btc_market.up_token) add(snapshot.btc_market.condition_id, snapshot.btc_market.up_token.token_id, "BtcUp");
  if (snapshot.btc_market.down_token) add(snapshot.btc_market.condition_id, snapshot.btc_market.down_token.token_id, "BtcDown");
  if (enableEth) {
    if (snapshot.eth_market.up_token) add(snapshot.eth_market.condition_id, snapshot.eth_market.up_token.token_id, "EthUp");
    if (snapshot.eth_market.down_token) add(snapshot.eth_market.condition_id, snapshot.eth_market.down_token.token_id, "EthDown");
  }
  if (enableSolana) {
    if (snapshot.solana_market.up_token) add(snapshot.solana_market.condition_id, snapshot.solana_market.up_token.token_id, "SolanaUp");
    if (snapshot.solana_market.down_token) add(snapshot.solana_market.condition_id, snapshot.solana_market.down_token.token_id, "SolanaDown");
  }
  if (enableXrp) {
    if (snapshot.xrp_market.up_token) add(snapshot.xrp_market.condition_id, snapshot.xrp_market.up_token.token_id, "XrpUp");
    if (snapshot.xrp_market.down_token) add(snapshot.xrp_market.condition_id, snapshot.xrp_market.down_token.token_id, "XrpDown");
  }
  return opps;
}

/** Get current ask price for a token from snapshot. */
function getAskForToken(snapshot: MarketSnapshot, tokenId: string): number | null {
  const markets = [
    snapshot.btc_market,
    snapshot.eth_market,
    snapshot.solana_market,
    snapshot.xrp_market,
  ];
  for (const m of markets) {
    if (m.up_token?.token_id === tokenId) return m.up_token.ask;
    if (m.down_token?.token_id === tokenId) return m.down_token.ask;
  }
  return null;
}

/** Get current bid price for a token from snapshot. */
function getBidForToken(snapshot: MarketSnapshot, tokenId: string): number | null {
  const markets = [
    snapshot.btc_market,
    snapshot.eth_market,
    snapshot.solana_market,
    snapshot.xrp_market,
  ];
  for (const m of markets) {
    if (m.up_token?.token_id === tokenId) return m.up_token.bid;
    if (m.down_token?.token_id === tokenId) return m.down_token.bid;
  }
  return null;
}

async function main(): Promise<void> {
  const { simulation, config: configPath } = parseArgs();
  const config = loadConfig(configPath);

  log("🚀 Starting Polymarket Dual Limit-Start Bot (TypeScript)");
  log("Mode: " + (simulation ? "SIMULATION" : "PRODUCTION"));
  const limitPrice = config.trading.dual_limit_price ?? LIMIT_PRICE;
  const limitShares = config.trading.dual_limit_shares ?? 1;
  log(`Strategy: At market start, place limit buys for BTC, ETH, SOL, XRP Up/Down at $${limitPrice.toFixed(2)}`);
  log(`Shares per order: ${limitShares}`);
  const extras: string[] = [];
  if (config.trading.enable_eth_trading) extras.push("ETH");
  if (config.trading.enable_solana_trading) extras.push("Solana");
  if (config.trading.enable_xrp_trading) extras.push("XRP");
  log("✅ Trading enabled for BTC and " + (extras.length ? extras.join(", ") : "no additional") + " 15-minute markets");
  const sellTrigger = config.trading.dual_limit_SL_sell_trigger_bid ?? DEFAULT_SELL_TRIGGER_BID;
  const sellPrice = config.trading.dual_limit_SL_sell_at_price ?? DEFAULT_SELL_AT_PRICE;
  const slThreshold = 1 - sellTrigger;
  const slEnabledStartup = config.trading.dual_limit_SL_enabled !== false;
  log(`Limit sell (hedge): ${slEnabledStartup ? "enabled" : "disabled"}. When enabled: one side filled and unfilled ask/bid >= $${slThreshold.toFixed(2)} → cancel unfilled limit buy, place limit sell at $${sellPrice.toFixed(2)}`);

  const api = new PolymarketApi(config.polymarket);
  log("\n═══════════════════════════════════════════════════════════");
  log("🔐 Authenticating with Polymarket CLOB API...");
  log("═══════════════════════════════════════════════════════════");

  const pk = config.polymarket.private_key?.trim();
  if (!pk) {
    log("❌ No private_key in config. Set polymarket.private_key in config.json to run.");
    log("   Authentication failed — bot will not start (no market discovery or trading).");
    log("═══════════════════════════════════════════════════════════");
    process.exit(1);
  }

  let clobClient: ClobClient | null = null;
  try {
    const client = await createClobClient(config.polymarket);
    await client.getOk();
    clobClient = client;
    log("✅ Successfully authenticated with Polymarket CLOB API");
    log("   ✓ Private key: Valid");
    log("   ✓ API credentials: Valid");
    log("   ✓ Trading account: EOA (private key account)");
    log("✅ Authentication successful!");
  } catch (e) {
    log("❌ Authentication failed: " + String(e));
    if (!simulation) {
      log("═══════════════════════════════════════════════════════════");
      process.exit(1);
    }
    log("   (Continuing in simulation mode with read-only market data.)");
  }
  log("═══════════════════════════════════════════════════════════");

  log("🔍 Discovering BTC, ETH, Solana, XRP markets...");
  const { eth, btc, solana, xrp } = await getOrDiscoverMarkets(
    api,
    config.trading.enable_eth_trading,
    config.trading.enable_solana_trading,
    config.trading.enable_xrp_trading
  );

  const trader = new Trader(api, config.trading, simulation, clobClient);
  let ethMarket = eth;
  let btcMarket = btc;
  let solanaMarket = solana;
  let xrpMarket = xrp;

  let lastPlacedPeriod: number | null = null;
  let lastSeenPeriod: number | null = null;
  const checkIntervalMs = config.trading.check_interval_ms ?? 1000;
  const sellTriggerBid = config.trading.dual_limit_SL_sell_trigger_bid ?? DEFAULT_SELL_TRIGGER_BID;
  const sellAtPrice = config.trading.dual_limit_SL_sell_at_price ?? DEFAULT_SELL_AT_PRICE;
  const limitSellPlacedForPeriod = new Set<string>(); // key: `${period}_${conditionId}`

  log("Starting market monitoring...");
  const now = Math.floor(Date.now() / 1000);
  const period = currentPeriodTimestamp();
  const nextPeriodStart = period + PERIOD_DURATION;
  const secondsUntilNext = nextPeriodStart - now;
  log(`⏰ Current market period: ${period}, next period starts in ${secondsUntilNext} seconds`);

  if (btcMarket.tokens?.length) {
    const up = btcMarket.tokens.find((t) => /up|1/i.test(t.outcome ?? ""));
    const down = btcMarket.tokens.find((t) => /down|0/i.test(t.outcome ?? ""));
    const upId = up?.tokenId ?? up?.token_id;
    const downId = down?.tokenId ?? down?.token_id;
    if (upId) log(`BTC Up token_id: ${upId}`);
    if (downId) log(`BTC Down token_id: ${downId}`);
  }

  for (;;) {
    let snapshot = await fetchSnapshot(api, ethMarket, btcMarket, solanaMarket, xrpMarket);
    log("📊 " + formatPrices(snapshot));

    if (snapshot.time_remaining_seconds === 0) {
      await new Promise((r) => setTimeout(r, checkIntervalMs));
      continue;
    }

    if (lastSeenPeriod === null) {
      lastSeenPeriod = snapshot.period_timestamp;
      await new Promise((r) => setTimeout(r, checkIntervalMs));
      continue;
    }
    if (lastSeenPeriod !== snapshot.period_timestamp) {
      lastSeenPeriod = snapshot.period_timestamp;
      limitSellPlacedForPeriod.clear();
      log("🔄 Period changed - refreshing markets for new period...");
      try {
        const markets = await getOrDiscoverMarkets(
          api,
          config.trading.enable_eth_trading,
          config.trading.enable_solana_trading,
          config.trading.enable_xrp_trading
        );
        ethMarket = markets.eth;
        btcMarket = markets.btc;
        solanaMarket = markets.solana;
        xrpMarket = markets.xrp;
        log("✅ Markets refreshed");
      } catch (e) {
        log("⚠️ Failed to refresh markets: " + String(e) + " - using previous markets");
      }
      // Re-fetch snapshot with new markets so we have correct token IDs for the new period
      snapshot = await fetchSnapshot(api, ethMarket, btcMarket, solanaMarket, xrpMarket);
      log("📊 " + formatPrices(snapshot));
      // Place batch ASAP after detecting new market (one request for all limit orders)
      if (lastPlacedPeriod !== snapshot.period_timestamp) {
        lastPlacedPeriod = snapshot.period_timestamp;
        const opportunities = buildOpportunities(
          snapshot,
          limitPrice,
          config.trading.enable_eth_trading,
          config.trading.enable_solana_trading,
          config.trading.enable_xrp_trading
        );
        if (opportunities.length > 0) {
          log(`🎯 New market detected - placing ${opportunities.length} limit buy(s) at $${limitPrice.toFixed(2)} (batch ASAP)`);
          try {
            await trader.executeLimitBuyBatch(opportunities, limitPrice, limitShares);
          } catch (e) {
            log("Error executing limit buy batch: " + String(e));
          }
        }
      }
      await new Promise((r) => setTimeout(r, checkIntervalMs));
      continue;
    }

    const timeElapsed = PERIOD_DURATION - snapshot.time_remaining_seconds;

    // Fallback: place in first 2 seconds if we haven't yet (e.g. bot started mid-period)
    if (timeElapsed <= 2 && lastPlacedPeriod !== snapshot.period_timestamp) {
      lastPlacedPeriod = snapshot.period_timestamp;
      const opportunities = buildOpportunities(
        snapshot,
        limitPrice,
        config.trading.enable_eth_trading,
        config.trading.enable_solana_trading,
        config.trading.enable_xrp_trading
      );
      if (opportunities.length > 0) {
        log(`🎯 Market start - placing ${opportunities.length} limit buy(s) at $${limitPrice.toFixed(2)} (batch)`);
        try {
          await trader.executeLimitBuyBatch(opportunities, limitPrice, limitShares);
        } catch (e) {
          log("Error executing limit buy batch: " + String(e));
        }
      }
    }

    // Hedge / stop-loss: one side filled, one unfilled. When unfilled ask >= (1 - trigger) → limit sell BOUGHT token, cancel unfilled limit buy.
    const slEnabled = config.trading.dual_limit_SL_enabled !== false;
    if (slEnabled && !simulation && clobClient && timeElapsed > 2) {
      const markets: Array<{
        name: string;
        conditionId: string;
        upTokenId: string | null;
        downTokenId: string | null;
        upType: TokenType;
        downType: TokenType;
      }> = [];
      if (snapshot.btc_market.up_token && snapshot.btc_market.down_token) {
        markets.push({
          name: "BTC",
          conditionId: snapshot.btc_market.condition_id,
          upTokenId: snapshot.btc_market.up_token.token_id,
          downTokenId: snapshot.btc_market.down_token.token_id,
          upType: "BtcUp",
          downType: "BtcDown",
        });
      }
      if (config.trading.enable_eth_trading && snapshot.eth_market.up_token && snapshot.eth_market.down_token) {
        markets.push({
          name: "ETH",
          conditionId: snapshot.eth_market.condition_id,
          upTokenId: snapshot.eth_market.up_token.token_id,
          downTokenId: snapshot.eth_market.down_token.token_id,
          upType: "EthUp",
          downType: "EthDown",
        });
      }
      if (config.trading.enable_solana_trading && snapshot.solana_market.up_token && snapshot.solana_market.down_token) {
        markets.push({
          name: "SOL",
          conditionId: snapshot.solana_market.condition_id,
          upTokenId: snapshot.solana_market.up_token.token_id,
          downTokenId: snapshot.solana_market.down_token.token_id,
          upType: "SolanaUp",
          downType: "SolanaDown",
        });
      }
      if (config.trading.enable_xrp_trading && snapshot.xrp_market.up_token && snapshot.xrp_market.down_token) {
        markets.push({
          name: "XRP",
          conditionId: snapshot.xrp_market.condition_id,
          upTokenId: snapshot.xrp_market.up_token.token_id,
          downTokenId: snapshot.xrp_market.down_token.token_id,
          upType: "XrpUp",
          downType: "XrpDown",
        });
      }
      for (const m of markets) {
        if (!m.upTokenId || !m.downTokenId) continue;
        const key = `${snapshot.period_timestamp}_${m.conditionId}`;
        if (limitSellPlacedForPeriod.has(key)) continue;

        const upBal = await trader.getBalance(m.upTokenId);
        const downBal = await trader.getBalance(m.downTokenId);
        const upFilled = upBal > 0.001;
        const downFilled = downBal > 0.001;
        if (upFilled === downFilled) continue;

        const unfilledTokenId = upFilled ? m.downTokenId : m.upTokenId;
        const unfilledAsk = getAskForToken(snapshot, unfilledTokenId);
        const unfilledBid = getBidForToken(snapshot, unfilledTokenId);
        const slTriggerThreshold = 1 - sellTriggerBid;
        const unfilledPriceForTrigger = unfilledAsk ?? unfilledBid ?? 0;
        if (unfilledPriceForTrigger < slTriggerThreshold) continue;

        // Sell the BOUGHT (filled) token only — limit sell at sellAtPrice when unfilled ask >= (1 - trigger)
        const filledTokenId = upFilled ? m.upTokenId : m.downTokenId;
        const filledType = upFilled ? m.upType : m.downType;
        const filledUnitsRaw = upFilled ? upBal : downBal;
        const filledUnits = Math.round(filledUnitsRaw * 1e6) / 1e6;
        if (filledUnits < MIN_LIMIT_SELL_SHARES) {
          log(`   ${m.name}: filled size ${filledUnits.toFixed(6)} < min ${MIN_LIMIT_SELL_SHARES}, skip limit sell\n`);
          continue;
        }
        log(`📤 SL trigger (${m.name}): unfilled price $${unfilledPriceForTrigger.toFixed(2)} >= $${slTriggerThreshold.toFixed(2)} (ask=${unfilledAsk != null ? unfilledAsk.toFixed(2) : "N/A"} bid=${unfilledBid != null ? unfilledBid.toFixed(2) : "N/A"}) → close unfilled limit buy, then sell BOUGHT ${tokenTypeDisplayName(filledType)} ${filledUnits.toFixed(6)} @ $${sellAtPrice.toFixed(2)}\n`);
        try {
          await trader.cancelPendingLimitBuy(snapshot.period_timestamp, unfilledTokenId);
        } catch (cancelErr) {
          log(`   ⚠️ Could not cancel unfilled limit buy: ${String(cancelErr)}\n`);
        }
        let limitSellOk = false;
        for (let attempt = 1; attempt <= LIMIT_SELL_MAX_RETRIES; attempt++) {
          try {
            await trader.executeLimitSell(filledTokenId, filledType, sellAtPrice, filledUnits);
            limitSellPlacedForPeriod.add(key);
            limitSellOk = true;
            break;
          } catch (e) {
            log(`   Limit sell attempt ${attempt}/${LIMIT_SELL_MAX_RETRIES} failed: ${String(e)}\n`);
            if (attempt < LIMIT_SELL_MAX_RETRIES) {
              log(`   Retrying in ${LIMIT_SELL_RETRY_DELAY_MS / 1000}s...\n`);
              await new Promise((r) => setTimeout(r, LIMIT_SELL_RETRY_DELAY_MS));
            }
          }
        }
        if (!limitSellOk) {
          log(`   ⚠️ Limit sell failed after ${LIMIT_SELL_MAX_RETRIES} attempts; will retry next poll\n`);
        }
      }
    }

    await new Promise((r) => setTimeout(r, checkIntervalMs));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
