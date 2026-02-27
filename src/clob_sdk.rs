//! Load the private CLOB SDK from a shared library (.so / .dylib / .dll).
//! Set `LIBCOB_SDK_SO` to the path of the .so, or place it in `./lib/` or current dir.
//! Build the SDK with: `cd polymarket-clob-sdk && cargo build --release --features clob`
//! → `target/release/libclob_sdk.so` (Linux), `libclob_sdk.dylib` (macOS), `clob_sdk.dll` (Windows).

use std::ffi::{c_char, c_int, CString};
use std::os::raw::c_ulonglong;
use std::str::FromStr;
use std::sync::OnceLock;

use alloy::primitives::Address;

use anyhow::{Context, Result};
use libloading::Library;

/// Contract addresses from the .so (same shape as SDK ContractConfig).
/// Uses alloy::Address so this module does not depend on polymarket-client-sdk.
pub struct ContractConfig {
    pub exchange: Address,
    pub collateral: Address,
    pub conditional_tokens: Address,
    pub neg_risk_adapter: Option<Address>,
}

static LIB: OnceLock<Result<Library, libloading::Error>> = OnceLock::new();

fn load_lib() -> Result<&'static Library> {
    let path = std::env::var("LIBCOB_SDK_SO")
        .ok()
        .filter(|p| std::path::Path::new(p).exists())
        .or_else(|| {
            #[cfg(not(target_os = "windows"))]
            let candidates = [
                "lib/libclob_sdk.so",
                "src/lib/libclob_sdk.so",
            ];
            candidates
                .into_iter()
                .find(|p| std::path::Path::new(p).exists())
                .map(String::from)
        })
        .context(
            "CLOB SDK .so not found. Set LIBCOB_SDK_SO to the path of libclob_sdk.so (or .dylib/.dll), \
             or place it in ./lib/ or current directory, or run from the bot dir when the SDK is at \
             ../polymarket-clob-sdk. Build: cd polymarket-clob-sdk && cargo build --release --features clob",
        )?;
    let lib = LIB
        .get_or_init(|| unsafe { Library::new(&path) })
        .as_ref()
        .map_err(|e| anyhow::anyhow!("Failed to load CLOB SDK library {}: {}", path, e))?;
    Ok(lib)
}

/// Polygon mainnet chain ID (137). From the loaded .so.
pub fn polygon_chain_id() -> u64 {
    let lib = match load_lib() {
        Ok(l) => l,
        Err(_) => return 137, // fallback if .so not loaded yet and we're in a path that can't fail
    };
    let f: libloading::Symbol<unsafe extern "C" fn() -> c_ulonglong> =
        unsafe { lib.get(b"clob_sdk_polygon_chain_id") }.unwrap();
    unsafe { f() as u64 }
}

fn read_string_from_ffi(
    lib: &Library,
    fn_name: &[u8],
    chain_id: u64,
    neg_risk: bool,
) -> Result<Option<String>> {
    let mut buf = [0u8; 64];
    let f: libloading::Symbol<
        unsafe extern "C" fn(c_ulonglong, c_int, *mut c_char, usize) -> c_int,
    > = unsafe { lib.get(fn_name) }.context("FFI symbol not found")?;
    let ret = unsafe { f(chain_id as c_ulonglong, neg_risk as c_int, buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if ret != 0 {
        return Ok(None); // chain not supported
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = std::str::from_utf8(&buf[..len]).context("FFI returned invalid UTF-8")?;
    Ok(Some(s.to_string()))
}

/// Get contract config from the loaded SDK .so. Same as SDK's contract_config(chain_id, is_neg_risk).
pub fn contract_config(chain_id: u64, is_neg_risk: bool) -> Result<Option<ContractConfig>> {
    let lib = load_lib()?;
    let exchange = match read_string_from_ffi(
        lib,
        b"clob_sdk_contract_exchange_address",
        chain_id,
        is_neg_risk,
    )? {
        Some(s) => s,
        None => return Ok(None),
    };
    let collateral = match read_string_from_ffi(
        lib,
        b"clob_sdk_contract_collateral_address",
        chain_id,
        is_neg_risk,
    )? {
        Some(s) => s,
        None => return Ok(None),
    };
    let conditional_tokens = match read_string_from_ffi(
        lib,
        b"clob_sdk_contract_ctf_address",
        chain_id,
        is_neg_risk,
    )? {
        Some(s) => s,
        None => return Ok(None),
    };
    let neg_risk_adapter = read_string_from_ffi(
        lib,
        b"clob_sdk_contract_neg_risk_adapter_address",
        chain_id,
        is_neg_risk,
    )?
    .and_then(|s| if s.trim().is_empty() { None } else { Some(s) });

    let exchange = Address::from_str(exchange.trim()).context("Invalid exchange address from SDK")?;
    let collateral = Address::from_str(collateral.trim()).context("Invalid collateral address from SDK")?;
    let conditional_tokens =
        Address::from_str(conditional_tokens.trim()).context("Invalid CTF address from SDK")?;
    let neg_risk_adapter = neg_risk_adapter
        .as_ref()
        .and_then(|s| Address::from_str(s.trim()).ok());

    Ok(Some(ContractConfig {
        exchange,
        collateral,
        conditional_tokens,
        neg_risk_adapter,
    }))
}

/// Ensure the SDK .so is loaded and return POLYGON chain id. Use this where the bot currently uses POLYGON.
pub fn polygon() -> u64 {
    polygon_chain_id()
}

// ---------- Client FFI (create, orders, balance) ----------

const ERR_BUF_LEN: usize = 512;

fn copy_rust_to_c(s: &str) -> Result<CString> {
    CString::new(s).context("CString from Rust string")
}

/// Create authenticated CLOB client. Returns handle (non-zero) on success.
/// funder: None for EOA; Some(proxy_wallet_address) for proxy/safe.
/// signature_type: 0 = Eoa, 1 = Proxy, 2 = GnosisSafe.
pub fn client_create(
    clob_url: &str,
    private_key_hex: &str,
    chain_id: u64,
    funder: Option<&str>,
    signature_type: u8,
    api_key: &str,
    api_secret: &str,
    api_passphrase: &str,
) -> Result<u64> {
    let lib = load_lib()?;
    let create: libloading::Symbol<
        unsafe extern "C" fn(
            *const c_char,
            *const c_char,
            c_ulonglong,
            *const c_char,
            c_int,
            *const c_char,
            *const c_char,
            *const c_char,
            *mut c_char,
            usize,
        ) -> c_ulonglong,
    > = unsafe { lib.get(b"clob_sdk_client_create") }.with_context(|| {
            format!(
                "symbol clob_sdk_client_create not found in CLOB SDK library. \
                 Your .so only exports contract/chain symbols (polygon_chain_id, contract_*). \
                 Authentication and orders need a full build that also exports: client_create, client_destroy, \
                 post_limit_order, post_market_order, balance_allowance, update_balance_allowance, tick_size, neg_risk. \
                 Rebuild the CLOB SDK with the client/order FFI included, or set LIBCOB_SDK_SO to that .so."
            )
        })?;

    let c_url = copy_rust_to_c(clob_url)?;
    let c_pk = copy_rust_to_c(private_key_hex.trim_start_matches("0x"))?;
    let c_funder = funder
        .map(|s| copy_rust_to_c(s.trim()))
        .transpose()?;
    let c_key = copy_rust_to_c(api_key)?;
    let c_secret = copy_rust_to_c(api_secret)?;
    let c_pass = copy_rust_to_c(api_passphrase)?;

    let mut err_buf = vec![0i8; ERR_BUF_LEN];
    let handle = unsafe {
        create(
            c_url.as_ptr(),
            c_pk.as_ptr(),
            chain_id as c_ulonglong,
            c_funder.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null()),
            signature_type as c_int,
            c_key.as_ptr(),
            c_secret.as_ptr(),
            c_pass.as_ptr(),
            err_buf.as_mut_ptr(),
            err_buf.len(),
        )
    };
    if handle == 0 {
        let len = err_buf.iter().position(|&b| b == 0).unwrap_or(ERR_BUF_LEN);
        let msg = std::str::from_utf8(unsafe { std::slice::from_raw_parts(err_buf.as_ptr() as *const u8, len) })
            .unwrap_or("unknown error");
        anyhow::bail!("CLOB client create failed: {}", msg);
    }
    Ok(handle)
}

/// Destroy client. Call when done with the handle.
pub fn client_destroy(handle: u64) -> Result<()> {
    let lib = load_lib()?;
    let destroy: libloading::Symbol<unsafe extern "C" fn(c_ulonglong) -> c_int> =
        unsafe { lib.get(b"clob_sdk_client_destroy") }.context("clob_sdk_client_destroy not found")?;
    let ret = unsafe { destroy(handle) };
    if ret != 0 {
        anyhow::bail!("client_destroy failed for handle {}", handle);
    }
    Ok(())
}

/// Post limit order. Returns order_id on success.
pub fn post_limit_order(
    handle: u64,
    token_id: &str,
    side: &str,
    price: &str,
    size: &str,
) -> Result<String> {
    let lib = load_lib()?;
    let f: libloading::Symbol<
        unsafe extern "C" fn(
            c_ulonglong,
            *const c_char,
            *const c_char,
            *const c_char,
            *const c_char,
            *mut c_char,
            usize,
            *mut c_char,
            usize,
        ) -> c_int,
    > = unsafe { lib.get(b"clob_sdk_post_limit_order") }.context("clob_sdk_post_limit_order not found")?;

    let c_token = copy_rust_to_c(token_id)?;
    let c_side = copy_rust_to_c(side)?;
    let c_price = copy_rust_to_c(price)?;
    let c_size = copy_rust_to_c(size)?;
    let mut order_id_buf = vec![0i8; 128];
    let mut err_buf = vec![0i8; ERR_BUF_LEN];

    let ret = unsafe {
        f(
            handle,
            c_token.as_ptr(),
            c_side.as_ptr(),
            c_price.as_ptr(),
            c_size.as_ptr(),
            order_id_buf.as_mut_ptr(),
            order_id_buf.len(),
            err_buf.as_mut_ptr(),
            err_buf.len(),
        )
    };
    if ret != 0 {
        let len = err_buf.iter().position(|&b| b == 0).unwrap_or(ERR_BUF_LEN);
        anyhow::bail!(
            "{}",
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(err_buf.as_ptr() as *const u8, len) })
                .unwrap_or("unknown")
        );
    }
    let len = order_id_buf.iter().position(|&b| b == 0).unwrap_or(order_id_buf.len());
    Ok(String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(order_id_buf.as_ptr() as *const u8, len) }).into_owned())
}

/// Post market order. amount_is_usdc: true = amount in USDC, false = amount in shares. order_type: "FOK" or "FAK".
pub fn post_market_order(
    handle: u64,
    token_id: &str,
    side: &str,
    amount: &str,
    amount_is_usdc: bool,
    order_type: &str,
) -> Result<String> {
    let lib = load_lib()?;
    let f: libloading::Symbol<
        unsafe extern "C" fn(
            c_ulonglong,
            *const c_char,
            *const c_char,
            *const c_char,
            c_int,
            *const c_char,
            *mut c_char,
            usize,
            *mut c_char,
            usize,
        ) -> c_int,
    > = unsafe { lib.get(b"clob_sdk_post_market_order") }.context("clob_sdk_post_market_order not found")?;

    let c_token = copy_rust_to_c(token_id)?;
    let c_side = copy_rust_to_c(side)?;
    let c_amount = copy_rust_to_c(amount)?;
    let c_ot = copy_rust_to_c(order_type)?;
    let mut order_id_buf = vec![0i8; 128];
    let mut err_buf = vec![0i8; ERR_BUF_LEN];

    let ret = unsafe {
        f(
            handle,
            c_token.as_ptr(),
            c_side.as_ptr(),
            c_amount.as_ptr(),
            if amount_is_usdc { 1 } else { 0 },
            c_ot.as_ptr(),
            order_id_buf.as_mut_ptr(),
            order_id_buf.len(),
            err_buf.as_mut_ptr(),
            err_buf.len(),
        )
    };
    if ret != 0 {
        let len = err_buf.iter().position(|&b| b == 0).unwrap_or(ERR_BUF_LEN);
        anyhow::bail!(
            "{}",
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(err_buf.as_ptr() as *const u8, len) })
                .unwrap_or("unknown")
        );
    }
    let len = order_id_buf.iter().position(|&b| b == 0).unwrap_or(order_id_buf.len());
    Ok(String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(order_id_buf.as_ptr() as *const u8, len) }).into_owned())
}

/// Fetch balance and allowance for token. asset_type: "Collateral" (USDC) or "Conditional".
pub fn balance_allowance(
    handle: u64,
    token_id: &str,
    asset_type: &str,
) -> Result<(String, String)> {
    let lib = load_lib()?;
    let f: libloading::Symbol<
        unsafe extern "C" fn(
            c_ulonglong,
            *const c_char,
            *const c_char,
            *mut c_char,
            usize,
            *mut c_char,
            usize,
            *mut c_char,
            usize,
        ) -> c_int,
    > = unsafe { lib.get(b"clob_sdk_balance_allowance") }.context("clob_sdk_balance_allowance not found")?;

    let c_token = copy_rust_to_c(token_id)?;
    let c_at = copy_rust_to_c(asset_type)?;
    let mut balance_buf = vec![0i8; 64];
    let mut allowance_buf = vec![0i8; 64];
    let mut err_buf = vec![0i8; ERR_BUF_LEN];

    let ret = unsafe {
        f(
            handle,
            c_token.as_ptr(),
            c_at.as_ptr(),
            balance_buf.as_mut_ptr(),
            balance_buf.len(),
            allowance_buf.as_mut_ptr(),
            allowance_buf.len(),
            err_buf.as_mut_ptr(),
            err_buf.len(),
        )
    };
    if ret != 0 {
        let len = err_buf.iter().position(|&b| b == 0).unwrap_or(ERR_BUF_LEN);
        anyhow::bail!(
            "{}",
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(err_buf.as_ptr() as *const u8, len) })
                .unwrap_or("unknown")
        );
    }
    let blen = balance_buf.iter().position(|&b| b == 0).unwrap_or(balance_buf.len());
    let alen = allowance_buf.iter().position(|&b| b == 0).unwrap_or(allowance_buf.len());
    let balance = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(balance_buf.as_ptr() as *const u8, blen) }).into_owned();
    let allowance = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(allowance_buf.as_ptr() as *const u8, alen) }).into_owned();
    Ok((balance, allowance))
}

/// Update balance/allowance cache. asset_type: "Collateral" or "Conditional".
pub fn update_balance_allowance(handle: u64, token_id: &str, asset_type: &str) -> Result<()> {
    let lib = load_lib()?;
    let f: libloading::Symbol<
        unsafe extern "C" fn(c_ulonglong, *const c_char, *const c_char, *mut c_char, usize) -> c_int,
    > = unsafe { lib.get(b"clob_sdk_update_balance_allowance") }.context("clob_sdk_update_balance_allowance not found")?;

    let c_token = copy_rust_to_c(token_id)?;
    let c_at = copy_rust_to_c(asset_type)?;
    let mut err_buf = vec![0i8; ERR_BUF_LEN];
    let ret = unsafe { f(handle, c_token.as_ptr(), c_at.as_ptr(), err_buf.as_mut_ptr(), err_buf.len()) };
    if ret != 0 {
        let len = err_buf.iter().position(|&b| b == 0).unwrap_or(ERR_BUF_LEN);
        anyhow::bail!(
            "{}",
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(err_buf.as_ptr() as *const u8, len) })
                .unwrap_or("unknown")
        );
    }
    Ok(())
}

/// Get tick size for token (e.g. "0.01").
pub fn tick_size(handle: u64, token_id: &str) -> Result<String> {
    let lib = load_lib()?;
    let f: libloading::Symbol<
        unsafe extern "C" fn(c_ulonglong, *const c_char, *mut c_char, usize, *mut c_char, usize) -> c_int,
    > = unsafe { lib.get(b"clob_sdk_tick_size") }.context("clob_sdk_tick_size not found")?;

    let c_token = copy_rust_to_c(token_id)?;
    let mut out_buf = vec![0i8; 32];
    let mut err_buf = vec![0i8; ERR_BUF_LEN];
    let ret = unsafe {
        f(
            handle,
            c_token.as_ptr(),
            out_buf.as_mut_ptr(),
            out_buf.len(),
            err_buf.as_mut_ptr(),
            err_buf.len(),
        )
    };
    if ret != 0 {
        let len = err_buf.iter().position(|&b| b == 0).unwrap_or(ERR_BUF_LEN);
        anyhow::bail!(
            "{}",
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(err_buf.as_ptr() as *const u8, len) })
                .unwrap_or("unknown")
        );
    }
    let len = out_buf.iter().position(|&b| b == 0).unwrap_or(out_buf.len());
    Ok(String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(out_buf.as_ptr() as *const u8, len) }).into_owned())
}

/// Get neg_risk for token. Returns true/false.
pub fn neg_risk(handle: u64, token_id: &str) -> Result<bool> {
    let lib = load_lib()?;
    let f: libloading::Symbol<
        unsafe extern "C" fn(c_ulonglong, *const c_char, *mut c_char, usize) -> c_int,
    > = unsafe { lib.get(b"clob_sdk_neg_risk") }.context("clob_sdk_neg_risk not found")?;

    let c_token = copy_rust_to_c(token_id)?;
    let mut err_buf = vec![0i8; ERR_BUF_LEN];
    let ret = unsafe { f(handle, c_token.as_ptr(), err_buf.as_mut_ptr(), err_buf.len()) };
    if ret == -1 {
        let len = err_buf.iter().position(|&b| b == 0).unwrap_or(ERR_BUF_LEN);
        anyhow::bail!(
            "{}",
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(err_buf.as_ptr() as *const u8, len) })
                .unwrap_or("unknown")
        );
    }
    Ok(ret == 1)
}
