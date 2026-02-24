// Gamma API / CLOB types aligned with Rust models

export interface Market {
  conditionId: string;
  id?: string;
  question: string;
  slug: string;
  resolutionSource?: string;
  endDateISO?: string;
  endDateIso?: string;
  active: boolean;
  closed: boolean;
  tokens?: Token[];
  clobTokenIds?: string;
  outcomes?: string;
}

export interface Token {
  tokenId?: string;
  token_id?: string;
  outcome: string;
  price?: string;
}

export interface MarketDetails {
  condition_id: string;
  tokens: Array<{ token_id: string; outcome: string }>;
}

export interface OrderBookEntry {
  price: string;
  size: string;
}

export interface OrderBook {
  bids: OrderBookEntry[];
  asks: OrderBookEntry[];
}

export interface TokenPrice {
  token_id: string;
  bid: number | null;
  ask: number | null;
}

export type TokenType =
  | "BtcUp"
  | "BtcDown"
  | "EthUp"
  | "EthDown"
  | "SolanaUp"
  | "SolanaDown"
  | "XrpUp"
  | "XrpDown";

export function tokenTypeDisplayName(t: TokenType): string {
  const map: Record<TokenType, string> = {
    BtcUp: "BTC Up",
    BtcDown: "BTC Down",
    EthUp: "ETH Up",
    EthDown: "ETH Down",
    SolanaUp: "SOL Up",
    SolanaDown: "SOL Down",
    XrpUp: "XRP Up",
    XrpDown: "XRP Down",
  };
  return map[t];
}

export function getOppositeTokenType(t: TokenType): TokenType {
  const map: Record<TokenType, TokenType> = {
    BtcUp: "BtcDown",
    BtcDown: "BtcUp",
    EthUp: "EthDown",
    EthDown: "EthUp",
    SolanaUp: "SolanaDown",
    SolanaDown: "SolanaUp",
    XrpUp: "XrpDown",
    XrpDown: "XrpUp",
  };
  return map[t];
}

export interface BuyOpportunity {
  condition_id: string;
  token_id: string;
  token_type: TokenType;
  bid_price: number;
  period_timestamp: number;
  time_remaining_seconds: number;
  time_elapsed_seconds: number;
  use_market_order: boolean;
}

export interface MarketData {
  condition_id: string;
  up_token: TokenPrice | null;
  down_token: TokenPrice | null;
}

export interface MarketSnapshot {
  eth_market: MarketData;
  btc_market: MarketData;
  solana_market: MarketData;
  xrp_market: MarketData;
  time_remaining_seconds: number;
  period_timestamp: number;
}
