//! Polymarket Real-Time Data Socket (RTDS) client for Chainlink crypto prices.
//! Connects to wss://ws-live-data.polymarket.com and subscribes to btc/usd.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use log::{debug, warn};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, tungstenite::Message};

const RTDS_URL: &str = "wss://ws-live-data.polymarket.com";
const RECONNECT_DELAY_SECS: u64 = 5;

/// Spawn a background task that keeps the latest Chainlink BTC/USD price in `out`.
/// On each RTDS update, sets *out = Some(value). Reconnects on disconnect.
pub fn spawn_chainlink_btc_task(out: Arc<Mutex<Option<f64>>>) {
    tokio::spawn(async move {
        loop {
            match run_chainlink_btc_loop(out.clone()).await {
                Ok(()) => {}
                Err(e) => {
                    warn!("RTDS chainlink btc loop error: {} - reconnecting in {}s", e, RECONNECT_DELAY_SECS);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(RECONNECT_DELAY_SECS)).await;
        }
    });
}

async fn run_chainlink_btc_loop(out: Arc<Mutex<Option<f64>>>) -> Result<()> {
    let (ws_stream, _) = connect_async(RTDS_URL).await?;
    let (mut write, mut read) = ws_stream.split();

    // Subscribe to crypto_prices_chainlink for btc/usd
    let subscribe = serde_json::json!({
        "action": "subscribe",
        "subscriptions": [{
            "topic": "crypto_prices_chainlink",
            "type": "*",
            "filters": r#"{"symbol":"btc/usd"}"#
        }]
    });
    write.send(Message::Text(subscribe.to_string())).await?;

    while let Some(msg) = read.next().await {
        let msg = msg?;
        let text = match msg {
            Message::Text(t) => t,
            _ => continue,
        };
        if let Ok(value) = parse_chainlink_btc_value(&text) {
            let mut g = out.lock().await;
            *g = Some(value);
            debug!("RTDS BTC/USD: {}", value);
        }
    }
    Ok(())
}

fn parse_chainlink_btc_value(text: &str) -> Result<f64> {
    let v: serde_json::Value = serde_json::from_str(text)?;
    let payload = v.get("payload").ok_or_else(|| anyhow::anyhow!("no payload"))?;
    let value = payload.get("value").ok_or_else(|| anyhow::anyhow!("no value"))?;
    let f = value.as_f64().ok_or_else(|| anyhow::anyhow!("value not f64"))?;
    Ok(f)
}
