import axios, { AxiosInstance } from "axios";
import { Market, Token } from "./types.js";
import type { Config } from "./config.js";

const POLYGON_CHAIN_ID = 137;

export class PolymarketApi {
  private gammaUrl: string;
  private clobUrl: string;
  private config: Config["polymarket"];
  private gammaClient: AxiosInstance;

  constructor(cfg: Config["polymarket"]) {
    this.gammaUrl = cfg.gamma_api_url.replace(/\/$/, "");
    this.clobUrl = cfg.clob_api_url.replace(/\/$/, "");
    this.config = cfg;
    this.gammaClient = axios.create({
      baseURL: this.gammaUrl,
      timeout: 15_000,
      headers: { "Content-Type": "application/json" },
    });
  }

  getClobUrl(): string {
    return this.clobUrl;
  }

  getPrivateKey(): string | null {
    return this.config.private_key;
  }

  getProxyWalletAddress(): string | null {
    return this.config.proxy_wallet_address;
  }

  getApiKey(): string | null {
    return this.config.api_key ?? null;
  }

  getApiSecret(): string | null {
    return this.config.api_secret ?? null;
  }

  getApiPassphrase(): string | null {
    return this.config.api_passphrase ?? null;
  }

  getSignatureType(): number | null {
    return this.config.signature_type ?? null;
  }

  /** Gamma: get event by slug; returns first market from event.markets (tokens may be empty; use getMarketByConditionId for tokens) */
  async getMarketBySlug(slug: string): Promise<Market> {
    const { data } = await this.gammaClient.get<{ markets?: unknown[] }>(
      `/events/slug/${encodeURIComponent(slug)}`
    );
    const markets = data?.markets;
    if (!Array.isArray(markets) || markets.length === 0) {
      throw new Error(`Invalid market response: no markets for slug ${slug}`);
    }
    const raw = markets[0] as Record<string, unknown>;
    const conditionId = String(raw.conditionId ?? raw.condition_id ?? "");
    const base: Market = {
      conditionId,
      question: String(raw.question ?? ""),
      slug: String(raw.slug ?? ""),
      active: Boolean(raw.active),
      closed: Boolean(raw.closed),
      id: raw.id != null ? String(raw.id) : undefined,
      resolutionSource: raw.resolutionSource != null ? String(raw.resolutionSource) : undefined,
      endDateISO: raw.endDateISO != null ? String(raw.endDateISO) : undefined,
      endDateIso: raw.endDateIso != null ? String(raw.endDateIso) : undefined,
      tokens: Array.isArray(raw.tokens) ? (raw.tokens as Market["tokens"]) : undefined,
      clobTokenIds: raw.clobTokenIds != null ? String(raw.clobTokenIds) : undefined,
      outcomes: raw.outcomes != null ? String(raw.outcomes) : undefined,
    };
    if (Array.isArray(base.tokens) && base.tokens.length > 0) {
      return base;
    }
    const clobMarket = await this.getMarketByConditionId(conditionId);
    return { ...base, tokens: clobMarket.tokens as Market["tokens"] };
  }

  /** CLOB: get market by condition ID (includes tokens with token_id and outcome) */
  async getMarketByConditionId(conditionId: string): Promise<{ tokens: Token[] }> {
    const { data } = await axios.get<{ tokens?: Array<{ token_id?: string; outcome?: string }> }>(
      `${this.clobUrl}/markets/${conditionId}`,
      { timeout: 10_000 }
    );
    const tokens: Token[] = (data?.tokens ?? []).map((t) => ({
      token_id: String(t.token_id ?? ""),
      outcome: String(t.outcome ?? ""),
    }));
    return { tokens };
  }

  /** CLOB: get order book for a token. Returns bids/asks (price as string). Best bid = highest, best ask = lowest. */
  async getOrderBook(tokenId: string): Promise<{ bids: Array<{ price: string; size: string }>; asks: Array<{ price: string; size: string }> }> {
    const { data } = await axios.get<{
      bids?: Array<{ price: string; size: string }>;
      asks?: Array<{ price: string; size: string }>;
      error?: string;
    }>(`${this.clobUrl}/book`, {
      params: { token_id: tokenId },
      timeout: 10_000,
    });
    if (data?.error) {
      return { bids: [], asks: [] };
    }
    const bids = Array.isArray(data?.bids) ? data.bids : [];
    const asks = Array.isArray(data?.asks) ? data.asks : [];
    return { bids, asks };
  }
}

// Re-export for clob client usage
export { POLYGON_CHAIN_ID };
