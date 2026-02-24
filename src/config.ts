import { readFileSync, existsSync, writeFileSync } from "fs";
import { join } from "path";

export interface PolymarketConfig {
  gamma_api_url: string;
  clob_api_url: string;
  api_key: string | null;
  api_secret: string | null;
  api_passphrase: string | null;
  private_key: string | null;
  proxy_wallet_address: string | null;
  signature_type: number | null;
}

export interface TradingConfig {
  /** Poll interval in ms. */
  check_interval_ms: number;
  enable_eth_trading: boolean;
  enable_solana_trading: boolean;
  enable_xrp_trading: boolean;
  /** Limit price for Up/Down orders (e.g. 0.45). */
  dual_limit_price: number | null;
  /** Shares per limit order (both Up and Down). Default 1. */
  dual_limit_shares: number | null;
  /** If false, do not place limit sell or cancel unfilled buy when one side is filled. */
  dual_limit_SL_enabled?: boolean | null;
  /** When one side filled and unfilled ask >= (1 - this), place limit sell on filled token. E.g. 0.2 means trigger when unfilled ask >= 0.8. */
  dual_limit_SL_sell_trigger_bid?: number | null;
  /** Limit sell price for the filled token when trigger is hit (e.g. 0.85). */
  dual_limit_SL_sell_at_price?: number | null;
}

export interface Config {
  polymarket: PolymarketConfig;
  trading: TradingConfig;
}

const DEFAULT_CONFIG: Config = {
  polymarket: {
    gamma_api_url: "https://gamma-api.polymarket.com",
    clob_api_url: "https://clob.polymarket.com",
    api_key: null,
    api_secret: null,
    api_passphrase: null,
    private_key: null,
    proxy_wallet_address: null,
    signature_type: null,
  },
  trading: {
    check_interval_ms: 1000,
    enable_eth_trading: false,
    enable_solana_trading: false,
    enable_xrp_trading: false,
    dual_limit_price: 0.45,
    dual_limit_shares: 1,
    dual_limit_SL_enabled: true,
    dual_limit_SL_sell_trigger_bid: 0.8,
    dual_limit_SL_sell_at_price: 0.85,
  },
};

export function loadConfig(configPath: string = "config.json"): Config {
  const path = join(process.cwd(), configPath);
  if (existsSync(path)) {
    const content = readFileSync(path, "utf-8");
    return JSON.parse(content) as Config;
  }
  writeFileSync(path, JSON.stringify(DEFAULT_CONFIG, null, 2));
  return DEFAULT_CONFIG;
}

export function parseArgs(): { simulation: boolean; config: string } {
  const args = process.argv.slice(2);
  let simulation = true;
  let config = "config.json";
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--no-simulation") simulation = false;
    else if (args[i] === "--simulation") simulation = true;
    else if (args[i] === "-c" || args[i] === "--config") config = args[++i] ?? config;
  }
  return { simulation, config };
}
