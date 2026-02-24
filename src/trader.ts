import {
  createClobClient,
  placeLimitOrder,
  placeLimitOrdersBatch,
  placeMarketOrder,
  cancelOrder,
  getBalance as clobGetBalance,
  getOpenOrders,
  type ClobClient,
} from "./clob.js";
import type { PolymarketApi } from "./api.js";
import type { Config } from "./config.js";
import type { BuyOpportunity, TokenType } from "./types.js";
import { tokenTypeDisplayName } from "./types.js";

export interface PendingTrade {
  token_id: string;
  condition_id: string;
  token_type: TokenType;
  market_timestamp: number;
  sold: boolean;
  /** Order ID when we placed a limit order (for cancel). */
  order_id?: string;
  /** Filled units (set when we detect balance). */
  units?: number;
}

export class Trader {
  private api: PolymarketApi;
  private config: Config["trading"];
  private simulation: boolean;
  private clobClient: ClobClient | null;
  private pendingTrades: Map<string, PendingTrade> = new Map();

  constructor(
    api: PolymarketApi,
    config: Config["trading"],
    simulation: boolean,
    clobClient: ClobClient | null = null
  ) {
    this.api = api;
    this.config = config;
    this.simulation = simulation;
    this.clobClient = clobClient;
  }

  /** Check if we already have an active (unsold) position for this period + token type */
  hasActivePosition(periodTimestamp: number, tokenType: TokenType): boolean {
    for (const trade of this.pendingTrades.values()) {
      if (
        trade.market_timestamp === periodTimestamp &&
        trade.token_type === tokenType &&
        !trade.sold
      ) {
        return true;
      }
    }
    return false;
  }

  /** Execute limit buy: place order on CLOB or simulate */
  async executeLimitBuy(
    opportunity: BuyOpportunity,
    limitPrice: number,
    sharesOverride: number
  ): Promise<void> {
    const units = sharesOverride;
    const investmentAmount = units * opportunity.bid_price;

    log(
      `\n═══════════════════════════════════════════════════════════\n📋 PLACING LIMIT BUY ORDER\n═══════════════════════════════════════════════════════════\n` +
        `   Token: ${tokenTypeDisplayName(opportunity.token_type)}\n` +
        `   Token ID: ${opportunity.token_id}\n` +
        `   Limit Price: $${limitPrice.toFixed(2)}\n` +
        `   Size: ${units.toFixed(2)} shares\n` +
        `   Investment: $${investmentAmount.toFixed(2)}\n`
    );

    if (this.simulation) {
      log("🎮 SIMULATION MODE - Limit order NOT placed\n");
      const key = `${opportunity.period_timestamp}_${opportunity.token_id}_limit`;
      this.pendingTrades.set(key, {
        token_id: opportunity.token_id,
        condition_id: opportunity.condition_id,
        token_type: opportunity.token_type,
        market_timestamp: opportunity.period_timestamp,
        sold: false,
      });
      return;
    }

    let client = this.clobClient;
    if (!client) {
      const pk = this.api.getPrivateKey();
      if (!pk) throw new Error("private_key required for live trading");
      const cfg = {
        gamma_api_url: "https://gamma-api.polymarket.com",
        clob_api_url: this.api.getClobUrl(),
        api_key: this.api.getApiKey(),
        api_secret: this.api.getApiSecret(),
        api_passphrase: this.api.getApiPassphrase(),
        private_key: pk,
        proxy_wallet_address: this.api.getProxyWalletAddress(),
        signature_type: this.api.getSignatureType(),
      } as Config["polymarket"];
      client = await createClobClient(cfg);
    }
    const size = Math.round(units * 100) / 100;
    const price = Math.round(limitPrice * 100) / 100;
    const result = await placeLimitOrder(client, {
      tokenId: opportunity.token_id,
      side: "BUY",
      price,
      size,
      tickSize: "0.01",
      negRisk: false,
    });
    log(`✅ LIMIT BUY PLACED - Order ID: ${result.orderID} Status: ${result.status}\n`);
    const key = `${opportunity.period_timestamp}_${opportunity.token_id}_limit`;
    this.pendingTrades.set(key, {
      token_id: opportunity.token_id,
      condition_id: opportunity.condition_id,
      token_type: opportunity.token_type,
      market_timestamp: opportunity.period_timestamp,
      sold: false,
      order_id: result.orderID,
    });
  }

  /** Place multiple limit buys in one batch (single POST /orders). Skips opportunities where hasActivePosition. */
  async executeLimitBuyBatch(
    opportunities: BuyOpportunity[],
    limitPrice: number,
    sharesPerOrder: number
  ): Promise<void> {
    const toPlace = opportunities.filter(
      (opp) => !this.hasActivePosition(opp.period_timestamp, opp.token_type)
    );
    if (toPlace.length === 0) return;
    log(
      `\n═══════════════════════════════════════════════════════════\n📋 PLACING ${toPlace.length} LIMIT BUY ORDERS (BATCH)\n═══════════════════════════════════════════════════════════\n`
    );
    for (const opp of toPlace) {
      const price = Math.round(limitPrice * 100) / 100;
      log(`   ${tokenTypeDisplayName(opp.token_type)}: $${price} x ${sharesPerOrder} shares\n`);
    }

    if (this.simulation) {
      log("🎮 SIMULATION MODE - Batch limit orders NOT placed\n");
      for (const opp of toPlace) {
        const key = `${opp.period_timestamp}_${opp.token_id}_limit`;
        this.pendingTrades.set(key, {
          token_id: opp.token_id,
          condition_id: opp.condition_id,
          token_type: opp.token_type,
          market_timestamp: opp.period_timestamp,
          sold: false,
        });
      }
      return;
    }

    let client = this.clobClient;
    if (!client) {
      const pk = this.api.getPrivateKey();
      if (!pk) throw new Error("private_key required for live trading");
      const cfg = {
        gamma_api_url: "https://gamma-api.polymarket.com",
        clob_api_url: this.api.getClobUrl(),
        api_key: this.api.getApiKey(),
        api_secret: this.api.getApiSecret(),
        api_passphrase: this.api.getApiPassphrase(),
        private_key: pk,
        proxy_wallet_address: this.api.getProxyWalletAddress(),
        signature_type: this.api.getSignatureType(),
      } as Config["polymarket"];
      client = await createClobClient(cfg);
    }

    const paramsList = toPlace.map((opp) => {
      const size = Math.round(sharesPerOrder * 100) / 100;
      const price = Math.round(limitPrice * 100) / 100;
      return {
        tokenId: opp.token_id,
        side: "BUY" as const,
        price,
        size,
        tickSize: "0.01" as const,
        negRisk: false,
      };
    });

    let results = await placeLimitOrdersBatch(client, paramsList);
    const allEmpty = results.every((r) => !r?.orderID || r?.orderID === "");
    if (allEmpty && results.length > 0) {
      log(`⚠️ Batch returned no order IDs - retrying each order individually\n`);
      results = [];
      for (const opp of toPlace) {
        const size = Math.round(sharesPerOrder * 100) / 100;
        const price = Math.round(limitPrice * 100) / 100;
        try {
          const one = await placeLimitOrder(client, {
            tokenId: opp.token_id,
            side: "BUY",
            price,
            size,
            tickSize: "0.01",
            negRisk: false,
          });
          results.push(one);
        } catch (e) {
          log(`   ❌ ${tokenTypeDisplayName(opp.token_type)}: ${String(e)}\n`);
          results.push({ orderID: "", status: "failed" });
        }
      }
    } else {
      log(`✅ BATCH: ${results.length} order(s) sent in one request\n`);
    }
    let confirmed = 0;
    let notConfirmed = 0;
    for (let i = 0; i < toPlace.length; i++) {
      const opp = toPlace[i];
      const r = results[i];
      const key = `${opp.period_timestamp}_${opp.token_id}_limit`;
      this.pendingTrades.set(key, {
        token_id: opp.token_id,
        condition_id: opp.condition_id,
        token_type: opp.token_type,
        market_timestamp: opp.period_timestamp,
        sold: false,
        order_id: r?.orderID,
      });
      const name = tokenTypeDisplayName(opp.token_type);
      const orderId = r?.orderID ?? "";
      const status = r?.status ?? "unknown";
      const errorMsg = r?.errorMsg ?? "";
      const isConfirmed =
        (status === "live" || status === "matched") && orderId.length > 0 && r?.success !== false;
      if (isConfirmed) {
        confirmed++;
        log(`   ✅ ${name} confirmed — Order ID: ${orderId} (${status})\n`);
      } else {
        notConfirmed++;
        if (errorMsg) {
          log(`   ❌ ${name} not confirmed — ${errorMsg}${orderId ? ` | Order ID: ${orderId}` : ""}\n`);
        } else {
          log(`   ❌ ${name} not confirmed — status: ${status}${orderId ? ` | Order ID: ${orderId}` : " (no ID)"}\n`);
        }
      }
    }
    if (notConfirmed > 0) {
      log(`   📋 Batch result: ${confirmed} confirmed, ${notConfirmed} not confirmed\n`);
    }
  }

  /** Get balance for a token (shares). Uses CLOB client; returns 0 if no client or error. */
  async getBalance(tokenId: string): Promise<number> {
    const client = this.clobClient;
    if (!client) return 0;
    return clobGetBalance(client, tokenId);
  }

  /** Get pending limit trade for (period, tokenId). */
  getPendingLimitTrade(periodTimestamp: number, tokenId: string): PendingTrade | undefined {
    return this.pendingTrades.get(`${periodTimestamp}_${tokenId}_limit`);
  }

  /** True if we have at least one pending limit order for this period (up or down token). */
  hasPendingLimitOrdersForPeriod(
    periodTimestamp: number,
    upTokenId: string,
    downTokenId: string
  ): boolean {
    return (
      this.getPendingLimitTrade(periodTimestamp, upTokenId) !== undefined ||
      this.getPendingLimitTrade(periodTimestamp, downTokenId) !== undefined
    );
  }

  /** Open orders on CLOB for this token (BUY). Returns [] if no client or on error. */
  async getOpenOrdersForToken(tokenId: string): Promise<Array<{ id: string; asset_id: string; side: string; original_size: string; price: string }>> {
    if (!this.clobClient) return [];
    try {
      return await getOpenOrders(this.clobClient, tokenId);
    } catch {
      return [];
    }
  }

  /** Cancel the limit order for (period, tokenId). Uses stored order_id or fetches open orders. */
  async cancelPendingLimitBuy(periodTimestamp: number, tokenId: string): Promise<void> {
    const key = `${periodTimestamp}_${tokenId}_limit`;
    const trade = this.pendingTrades.get(key);
    const orderId = trade?.order_id;
    if (!this.clobClient) throw new Error("No CLOB client for cancel");
    if (orderId) {
      await cancelOrder(this.clobClient, orderId);
      if (trade) trade.order_id = undefined;
      log(`   🗑️ Cancelled limit order ${orderId}\n`);
      return;
    }
    const openOrders = await this.clobClient.getOpenOrders({ asset_id: tokenId }, true);
    const orders = Array.isArray(openOrders) ? openOrders : [];
    for (const o of orders) {
      if (o.side === "BUY" && (o.asset_id === tokenId || (o as { asset_id?: string }).asset_id === tokenId)) {
        await cancelOrder(this.clobClient, o.id);
        log(`   🗑️ Cancelled limit order ${o.id}\n`);
        return;
      }
    }
    log(`   ⚠️ No open limit order found for token ${tokenId.slice(0, 16)}...\n`);
  }

  /** Place limit sell order (e.g. sell filled side at 0.85 when unfilled bid crosses trigger). */
  async executeLimitSell(tokenId: string, tokenType: TokenType, price: number, size: number): Promise<void> {
    if (this.simulation) {
      log(`🎮 SIMULATION: Limit sell would place ${tokenTypeDisplayName(tokenType)} ${size} @ $${price.toFixed(2)}\n`);
      return;
    }
    const client = this.clobClient;
    if (!client) throw new Error("No CLOB client for limit sell");
    const result = await placeLimitOrder(client, {
      tokenId,
      side: "SELL",
      price,
      size,
      tickSize: "0.01",
      negRisk: false,
    });
    if (!result.orderID || result.orderID.trim() === "") {
      throw new Error("Limit sell failed: no order ID returned");
    }
    log(`✅ LIMIT SELL PLACED - ${tokenTypeDisplayName(tokenType)} ${size} @ $${price.toFixed(2)} Order ID: ${result.orderID}\n`);
  }

  /** Execute market buy (for hedge). amountUsd = USD to spend (same-size: filled_units * unfilled_ask). */
  async executeMarketBuy(opportunity: BuyOpportunity, amountUsd: number): Promise<void> {
    if (this.simulation) {
      log(`🎮 SIMULATION: Market buy would place for ${tokenTypeDisplayName(opportunity.token_type)} $${amountUsd.toFixed(2)}\n`);
      const key = `${opportunity.period_timestamp}_${opportunity.token_id}_hedge`;
      this.pendingTrades.set(key, {
        token_id: opportunity.token_id,
        condition_id: opportunity.condition_id,
        token_type: opportunity.token_type,
        market_timestamp: opportunity.period_timestamp,
        sold: false,
      });
      return;
    }
    const client = this.clobClient;
    if (!client) throw new Error("No CLOB client for market buy");
    const result = await placeMarketOrder(client, {
      tokenId: opportunity.token_id,
      side: "BUY",
      amount: amountUsd,
      orderType: "FAK",
    });
    log(`✅ MARKET BUY (hedge) PLACED - Order ID: ${result.orderID}\n`);
    const key = `${opportunity.period_timestamp}_${opportunity.token_id}_hedge`;
    this.pendingTrades.set(key, {
      token_id: opportunity.token_id,
      condition_id: opportunity.condition_id,
      token_type: opportunity.token_type,
      market_timestamp: opportunity.period_timestamp,
      sold: false,
    });
  }

  /** Execute FAK sell (for stop-loss). size = shares to sell. */
  async executeSell(tokenId: string, size: number, tokenType: TokenType, periodTimestamp: number): Promise<void> {
    if (this.simulation) {
      log(`🎮 SIMULATION: Stop-loss sell would place for ${tokenTypeDisplayName(tokenType)} ${size} shares\n`);
      this.markTradeSold(periodTimestamp, tokenId);
      return;
    }
    const client = this.clobClient;
    if (!client) throw new Error("No CLOB client for sell");
    await placeMarketOrder(client, {
      tokenId,
      side: "SELL",
      amount: size,
      orderType: "FAK",
    });
    log(`✅ STOP-LOSS SELL PLACED - ${size} shares\n`);
    this.markTradeSold(periodTimestamp, tokenId);
  }

  /** Mark any pending trade for this (period, tokenId) as sold. */
  markTradeSold(periodTimestamp: number, tokenId: string): void {
    for (const [key, trade] of this.pendingTrades.entries()) {
      if (trade.market_timestamp === periodTimestamp && trade.token_id === tokenId) {
        trade.sold = true;
        break;
      }
    }
  }

  /** All pending trades (for stop-loss iteration). */
  getPendingTrades(): Map<string, PendingTrade> {
    return this.pendingTrades;
  }
}

function log(msg: string): void {
  process.stderr.write(msg);
}
