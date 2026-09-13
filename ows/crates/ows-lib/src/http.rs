//! Shared HTTP timeout policy for the curl-based broadcast/RPC helpers.
//!
//! Every outbound `curl` in ows-lib goes through [`curl_timeout_args`] so that a
//! slow or hostile RPC/broadcast endpoint cannot hang a signing call forever. The
//! overall deadline defaults to 60s and can be overridden with the
//! `OWS_HTTP_TIMEOUT_SECS` environment variable (used by the tests to keep them fast).

/// Overall request timeout in seconds (connect + transfer). Defaults to 60.
/// `OWS_HTTP_TIMEOUT_SECS`, when set to a positive integer, overrides it.
pub(crate) fn timeout_secs() -> u64 {
    std::env::var("OWS_HTTP_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(60)
}

/// curl flags enforcing a connect timeout and an overall deadline. Prepended to
/// every curl invocation so no broadcast or RPC call can block indefinitely.
pub(crate) fn curl_timeout_args() -> Vec<String> {
    let overall = timeout_secs();
    // Connect timeout is the smaller of 10s and the overall deadline.
    let connect = overall.min(10);
    vec![
        "--connect-timeout".to_string(),
        connect.to_string(),
        "--max-time".to_string(),
        overall.to_string(),
    ]
}
