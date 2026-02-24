import { ethers } from "ethers";
import { ClobClient, Side, OrderType, Chain, AssetType } from "clob-client-sdk";
import type { Config } from "./config.js";

export type { ClobClient };

/** Create ethers Wallet from private key hex (with or without 0x) */
export function createWallet(privateKey: string): ethers.Wallet {
  const key = privateKey.startsWith("0x") ? privateKey : `0x${privateKey}`;
  return new ethers.Wallet(key);
}

/** Build authenticated CLOB client for order placement */
export async function createClobClient(cfg: Config["polymarket"]): Promise<ClobClient> {
  const pk = cfg.private_key;
  if (!pk) throw new Error("private_key is required in config");
  const wallet = createWallet(pk);
  const host = cfg.clob_api_url.replace(/\/$/, "");

  let apiCreds: { key: string; secret: string; passphrase: string } | undefined;
  if (cfg.api_key && cfg.api_secret && cfg.api_passphrase) {
    apiCreds = {
      key: cfg.api_key,
      secret: cfg.api_secret,
      passphrase: cfg.api_passphrase,
    };
  }

  // Match Rust/other projects: pass signature type and proxy so L2 auth matches API key.
  // 0 = EOA, 1 = POLY_PROXY, 2 = POLY_GNOSIS_SAFE (per @polymarket/order-utils).
  const signatureType = cfg.signature_type ?? 0;
  const funderAddress =
    (signatureType === 1 || signatureType === 2) && cfg.proxy_wallet_address
      ? cfg.proxy_wallet_address
      : undefined;

  const client = new ClobClient(host, Chain.POLYGON, wallet, apiCreds, signatureType, funderAddress);
  if (!apiCreds) {
    // Try derive first (restores existing key). createApiKey() often returns 400 "Could not create api key" if the account already has a key.
    let creds: { key: string; secret: string; passphrase: string } | null = null;
    try {
      const derived = await client.deriveApiKey();
      if (derived?.key && derived?.secret && derived?.passphrase) {
        creds = derived;
      }
    } catch {
      // derive failed (e.g. no existing key), fall through to create
    }
    if (!creds) {
      try {
        const created = await client.createApiKey();
        if (created?.key && created?.secret && created?.passphrase) {
          creds = created;
        }
      } catch (e) {
        throw new Error(
          "CLOB API key failed: create and derive both failed. If you already have a key, add api_key, api_secret, api_passphrase to config.json (from polymarket.com/settings?tab=builder). Error: " +
            String(e instanceof Error ? e.message : e)
        );
      }
    }
    if (!creds) {
      throw new Error("CLOB API key derivation/creation returned no credentials. Add api_key, api_secret, api_passphrase to config.json.");
    }
    return new ClobClient(host, Chain.POLYGON, wallet, creds, signatureType, funderAddress);
  }
  return client;
}

export interface PlaceLimitOrderParams {
  tokenId: string;
  side: "BUY" | "SELL";
  price: number;
  size: number;
  tickSize?: "0.1" | "0.01" | "0.001" | "0.0001";
  negRisk?: boolean;
}

/** Place a limit order using createAndPostOrder */
export async function placeLimitOrder(
  client: ClobClient,
  params: PlaceLimitOrderParams
): Promise<{ orderID: string; status: string }> {
  const side = params.side === "BUY" ? Side.BUY : Side.SELL;
  const tickSize = params.tickSize ?? "0.01";
  const negRisk = params.negRisk ?? false;
  const result = await client.createAndPostOrder(
    {
      tokenID: params.tokenId,
      price: params.price,
      size: params.size,
      side,
    },
    { tickSize, negRisk },
    OrderType.GTC
  );
  return {
    orderID: (result as { orderID?: string }).orderID ?? (result as { id?: string }).id ?? "",
    status: (result as { status?: string }).status ?? "unknown",
  };
}

export interface PlaceLimitOrderBatchResult {
  orderID: string;
  status: string;
  success?: boolean;
  errorMsg?: string;
}

/** Place multiple limit orders in one batch (single POST /orders). */
export async function placeLimitOrdersBatch(
  client: ClobClient,
  paramsList: PlaceLimitOrderParams[]
): Promise<PlaceLimitOrderBatchResult[]> {
  if (paramsList.length === 0) return [];
  const tickSize = "0.01";
  const negRisk = false;
  const signedOrders = [];
  for (const params of paramsList) {
    const side = params.side === "BUY" ? Side.BUY : Side.SELL;
    const order = await client.createOrder(
      {
        tokenID: params.tokenId,
        price: params.price,
        size: params.size,
        side,
      },
      { tickSize: params.tickSize ?? tickSize, negRisk: params.negRisk ?? negRisk }
    );
    signedOrders.push({ order, orderType: OrderType.GTC });
  }
  const raw = await client.postOrders(signedOrders);
  const results: PlaceLimitOrderBatchResult[] = [];
  const arr = Array.isArray(raw)
    ? raw
    : raw && typeof raw === "object" && Array.isArray((raw as { data?: unknown }).data)
      ? (raw as { data: unknown[] }).data
      : [raw];
  for (let i = 0; i < paramsList.length; i++) {
    const r = arr[i];
    if (r && typeof r === "object") {
      const orderID =
        (r as { orderID?: string }).orderID ??
        (r as { order_id?: string }).order_id ??
        (r as { id?: string }).id ??
        "";
      const status = (r as { status?: string }).status ?? "unknown";
      const success = (r as { success?: boolean }).success;
      const errorMsg =
        (r as { errorMsg?: string }).errorMsg ??
        (r as { error?: string }).error ??
        (r as { message?: string }).message ??
        "";
      results.push({
        orderID: String(orderID ?? ""),
        status,
        ...(success !== undefined && { success }),
        ...(errorMsg !== undefined && errorMsg !== "" && { errorMsg }),
      });
    } else {
      results.push({ orderID: "", status: "unknown" });
    }
  }
  return results;
}

/** Get balance for a conditional token (shares). Returns 0 if token_id missing or on error. */
export async function getBalance(client: ClobClient, tokenId: string): Promise<number> {
  try {
    const res = await client.getBalanceAllowance({
      asset_type: AssetType.CONDITIONAL,
      token_id: tokenId,
    });
    const raw = parseFloat(res?.balance ?? "0");
    if (!Number.isFinite(raw)) return 0;
    return raw / 1e6;
  } catch {
    return 0;
  }
}

export interface PlaceMarketOrderParams {
  tokenId: string;
  side: "BUY" | "SELL";
  /** BUY: USD amount to spend. SELL: shares to sell. */
  amount: number;
  orderType?: "FOK" | "FAK";
}

/** Place a market order (FOK or FAK). */
export async function placeMarketOrder(
  client: ClobClient,
  params: PlaceMarketOrderParams
): Promise<{ orderID: string; status: string }> {
  const side = params.side === "BUY" ? Side.BUY : Side.SELL;
  const orderType = params.orderType === "FAK" ? OrderType.FAK : OrderType.FOK;
  const result = await client.createAndPostMarketOrder(
    {
      tokenID: params.tokenId,
      side,
      amount: params.amount,
    },
    { tickSize: "0.01", negRisk: false },
    orderType
  );
  return {
    orderID: (result as { orderID?: string }).orderID ?? (result as { id?: string }).id ?? "",
    status: (result as { status?: string }).status ?? "unknown",
  };
}

/** Cancel one order by ID. */
export async function cancelOrder(client: ClobClient, orderId: string): Promise<void> {
  await client.cancelOrder({ orderID: orderId });
}

/** Get open orders, optionally filtered by asset_id (token_id). */
export async function getOpenOrders(
  client: ClobClient,
  assetId?: string
): Promise<Array<{ id: string; asset_id: string; side: string; original_size: string; price: string }>> {
  const params = assetId ? { asset_id: assetId } : undefined;
  const orders = await client.getOpenOrders(params, true);
  return Array.isArray(orders) ? orders : [];
}
