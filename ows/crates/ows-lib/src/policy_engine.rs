use ows_core::{
    NearTransactionLimits, Policy, PolicyContext, PolicyRequestType, PolicyResult, PolicyRule,
};
use serde_json::Value;
use std::io::Write as _;
use std::process::Command;
use std::time::Duration;

/// Evaluate all policies against a context. AND semantics: short-circuits on
/// first denial. Returns `PolicyResult::allowed()` if every policy passes.
pub fn evaluate_policies(policies: &[Policy], context: &PolicyContext) -> PolicyResult {
    for policy in policies {
        let result = evaluate_one(policy, context);
        if !result.allow {
            return result;
        }
    }
    PolicyResult::allowed()
}

/// Evaluate a single policy: declarative rules first, then executable (if any).
fn evaluate_one(policy: &Policy, context: &PolicyContext) -> PolicyResult {
    // Declarative rules — fast, in-process
    for rule in &policy.rules {
        let result = evaluate_rule(rule, &policy.id, context);
        if !result.allow {
            return result;
        }
    }

    // Executable — only if declarative rules passed
    if let Some(ref exe) = policy.executable {
        return evaluate_executable(exe, policy.config.as_ref(), &policy.id, context);
    }

    PolicyResult::allowed()
}

// ---------------------------------------------------------------------------
// Declarative rule evaluation
// ---------------------------------------------------------------------------

fn evaluate_rule(rule: &PolicyRule, policy_id: &str, ctx: &PolicyContext) -> PolicyResult {
    match rule {
        PolicyRule::AllowedChains { chain_ids } => eval_allowed_chains(policy_id, chain_ids, ctx),
        PolicyRule::ExpiresAt { timestamp } => eval_expires_at(policy_id, timestamp, ctx),
        PolicyRule::AllowedTypedDataContracts { contracts } => {
            eval_allowed_typed_data_contracts(policy_id, contracts, ctx)
        }
        PolicyRule::NearTransactionLimits(limits) => {
            eval_near_transaction_limits(policy_id, limits, ctx)
        }
    }
}

fn eval_allowed_chains(policy_id: &str, chain_ids: &[String], ctx: &PolicyContext) -> PolicyResult {
    if chain_ids.iter().any(|c| c == &ctx.chain_id) {
        PolicyResult::allowed()
    } else {
        PolicyResult::denied(
            policy_id,
            format!("chain {} not in allowlist", ctx.chain_id),
        )
    }
}

fn eval_expires_at(policy_id: &str, timestamp: &str, ctx: &PolicyContext) -> PolicyResult {
    let now = chrono::DateTime::parse_from_rfc3339(&ctx.timestamp);
    let exp = chrono::DateTime::parse_from_rfc3339(timestamp);
    match (now, exp) {
        (Ok(now), Ok(exp)) if now > exp => {
            PolicyResult::denied(policy_id, format!("policy expired at {timestamp}"))
        }
        (Ok(_), Ok(_)) => PolicyResult::allowed(),
        _ => PolicyResult::denied(
            policy_id,
            format!(
                "invalid timestamp in expiry check: ctx={}, rule={}",
                ctx.timestamp, timestamp
            ),
        ),
    }
}

fn eval_allowed_typed_data_contracts(
    policy_id: &str,
    contracts: &[String],
    ctx: &PolicyContext,
) -> PolicyResult {
    let td = match &ctx.typed_data {
        None => return PolicyResult::allowed(),
        Some(td) => td,
    };

    let contract = match &td.verifying_contract {
        None => {
            return PolicyResult::denied(
                policy_id,
                "typed data has no verifyingContract but policy requires one",
            );
        }
        Some(c) => c,
    };

    let contract_lower = contract.to_lowercase();
    if contracts.iter().any(|c| c.to_lowercase() == contract_lower) {
        PolicyResult::allowed()
    } else {
        PolicyResult::denied(
            policy_id,
            format!("verifyingContract {contract} not in allowed list"),
        )
    }
}

/// CAIP-2 namespaces, other than `near`, whose OWS signer produces a plain
/// Ed25519 signature over the caller's bytes as given (message signing, and
/// transaction signing over the signable part). A wallet imported from a raw
/// Ed25519 private key signs these chains with the same key as NEAR, so a
/// 32-byte payload signed there is a valid NEAR transaction signature. Sui
/// (intent-prefixed BLAKE2b digest) and Nano (Ed25519-BLAKE2b) sign something
/// else and are not listed; `raw_ed25519_chain_list_is_complete` pins this list.
pub(crate) const RAW_ED25519_NAMESPACES: &[&str] = &["solana", "ton"];

/// `near_transaction_limits`. NEAR transactions (and NEP-366 delegate actions,
/// and NEP-413 messages) are Ed25519 signatures over a 32-byte SHA-256 digest,
/// so any raw Ed25519 signature over 32 caller-chosen bytes could authorize one.
///
/// On a `near:` chain:
/// - `sign_transaction` is checked against the decoded transaction (or NEP-366
///   delegate action) the NEAR signer puts in `chain_extra` (deny if missing);
/// - `sign_message` is denied when the message is exactly 32 bytes;
/// - `sign_hash` is denied (defense in depth: OWS only signs raw hashes on
///   secp256k1 chains today).
///
/// On a chain in [`RAW_ED25519_NAMESPACES`], requests whose signed bytes are
/// exactly 32 long are denied the same way, since an imported key is shared.
///
/// Everything else passes through.
fn eval_near_transaction_limits(
    policy_id: &str,
    limits: &NearTransactionLimits,
    ctx: &PolicyContext,
) -> PolicyResult {
    let namespace = ctx.chain_id.split(':').next().unwrap_or_default();
    let result = if namespace == "near" {
        match ctx.request_type {
            PolicyRequestType::SignTransaction => check_near_transaction(limits, ctx),
            PolicyRequestType::SignMessage => check_not_32_bytes(ctx, false),
            PolicyRequestType::SignHash => {
                Err("raw hash signing on NEAR could authorize any transaction".to_string())
            }
            PolicyRequestType::SignTypedData | PolicyRequestType::ReadBalance => Ok(()),
        }
    } else if RAW_ED25519_NAMESPACES.contains(&namespace) {
        match ctx.request_type {
            PolicyRequestType::SignMessage => check_not_32_bytes(ctx, false),
            PolicyRequestType::SignTransaction => check_not_32_bytes(ctx, true),
            PolicyRequestType::SignHash => Err(format!(
                "raw hash signing on {namespace} could produce a NEAR transaction signature"
            )),
            PolicyRequestType::SignTypedData | PolicyRequestType::ReadBalance => Ok(()),
        }
    } else {
        Ok(())
    };
    match result {
        Ok(()) => PolicyResult::allowed(),
        Err(reason) => PolicyResult::denied(policy_id, reason),
    }
}

/// Deny when the bytes the chain will sign are exactly 32 long. For a
/// transaction, those are the chain's signable part (Solana drops its
/// signature-slot header); for a message, the message itself.
fn check_not_32_bytes(ctx: &PolicyContext, transaction: bool) -> Result<(), String> {
    let payload = ctx
        .transaction
        .as_ref()
        .and_then(|tx| hex::decode(&tx.raw_hex).ok())
        .ok_or_else(|| format!("{} payload is missing", ctx.chain_id))?;
    let signed_len = if transaction {
        let chain = ows_core::parse_chain(&ctx.chain_id)?;
        let signer = ows_signer::signer_for_chain(&chain).map_err(|e| e.to_string())?;
        signer
            .extract_signable_bytes(&payload)
            .map_err(|e| e.to_string())?
            .len()
    } else {
        payload.len()
    };
    if signed_len == 32 {
        return Err(format!(
            "signing 32 raw bytes on {} could produce a NEAR transaction signature",
            ctx.chain_id
        ));
    }
    Ok(())
}

fn check_near_transaction(
    limits: &NearTransactionLimits,
    ctx: &PolicyContext,
) -> Result<(), String> {
    let tx = ctx
        .transaction
        .as_ref()
        .and_then(|tx| tx.chain_extra.as_ref())
        .filter(|extra| {
            matches!(
                extra.get("kind").and_then(Value::as_str),
                Some("transaction" | "delegate_action")
            )
        })
        .ok_or("NEAR transaction was not decoded, so its limits cannot be checked")?;
    check_near_actions(limits, tx)
}

/// Check a decoded NEAR transaction or delegate action (`receiver_id`,
/// `actions`, `total_deposit`) against the limits.
fn check_near_actions(limits: &NearTransactionLimits, tx: &Value) -> Result<(), String> {
    let receiver = tx
        .get("receiver_id")
        .and_then(Value::as_str)
        .ok_or("decoded NEAR transaction has no receiver_id")?;
    if let Some(receivers) = &limits.receivers {
        if !receivers.iter().any(|r| r == receiver) {
            return Err(format!(
                "receiver {receiver} is not in the allowed receivers"
            ));
        }
    }

    let allowed_actions: Vec<&str> = match &limits.actions {
        Some(actions) => actions.iter().map(String::as_str).collect(),
        None => NearTransactionLimits::DEFAULT_ACTIONS.to_vec(),
    };
    if let Some(unknown) = allowed_actions
        .iter()
        .find(|a| !ows_signer::chains::near::decode::ACTION_TYPES.contains(a))
    {
        return Err(format!("policy lists unknown NEAR action type '{unknown}'"));
    }

    let actions = tx
        .get("actions")
        .and_then(Value::as_array)
        .ok_or("decoded NEAR transaction has no actions")?;
    for action in actions {
        let action_type = action
            .get("type")
            .and_then(Value::as_str)
            .ok_or("decoded NEAR action has no type")?;
        if !allowed_actions.contains(&action_type) {
            return Err(format!("NEAR action {action_type} is not allowed"));
        }
        if action_type == "function_call" {
            if let Some(methods) = &limits.methods {
                let method = action
                    .get("method_name")
                    .and_then(Value::as_str)
                    .ok_or("decoded NEAR function call has no method_name")?;
                if !methods.iter().any(|m| m == method) {
                    return Err(format!("method {method} is not in the allowed methods"));
                }
            }
        }
    }

    if let Some(max) = &limits.max_deposit {
        let max: u128 = max
            .parse()
            .map_err(|_| format!("invalid max_deposit '{max}' in policy"))?;
        let total: u128 = tx
            .get("total_deposit")
            .and_then(Value::as_str)
            .and_then(|t| t.parse().ok())
            .ok_or("decoded NEAR transaction has no total_deposit")?;
        if total > max {
            return Err(format!(
                "deposit of {total} yoctoNEAR exceeds max_deposit {max}"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Executable policy evaluation
// ---------------------------------------------------------------------------

fn evaluate_executable(
    exe: &str,
    config: Option<&serde_json::Value>,
    policy_id: &str,
    ctx: &PolicyContext,
) -> PolicyResult {
    // Build stdin payload: context + policy_config
    let mut payload = serde_json::to_value(ctx).unwrap_or_default();
    if let Some(cfg) = config {
        payload
            .as_object_mut()
            .map(|m| m.insert("policy_config".to_string(), cfg.clone()));
    }

    let stdin_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            return PolicyResult::denied(policy_id, format!("failed to serialize context: {e}"))
        }
    };

    let mut child = match Command::new(exe)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return PolicyResult::denied(policy_id, format!("failed to start executable: {e}"))
        }
    };

    // Write stdin
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&stdin_bytes);
    }

    // Wait with timeout (5 seconds)
    let output = match wait_with_timeout(&mut child, Duration::from_secs(5)) {
        Ok(output) => output,
        Err(reason) => return PolicyResult::denied(policy_id, reason),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return PolicyResult::denied(
            policy_id,
            format!(
                "executable exited with {}: {}",
                output.status,
                stderr.trim()
            ),
        );
    }

    // Parse stdout as PolicyResult
    match serde_json::from_slice::<PolicyResult>(&output.stdout) {
        Ok(result) => {
            if !result.allow {
                // Ensure the policy_id is set even if the executable omitted it
                PolicyResult::denied(
                    policy_id,
                    result
                        .reason
                        .unwrap_or_else(|| "denied by executable".into()),
                )
            } else {
                PolicyResult::allowed()
            }
        }
        Err(e) => PolicyResult::denied(policy_id, format!("invalid JSON from executable: {e}")),
    }
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process has exited — collect output.
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    let _ = out.read_to_end(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let _ = err.read_to_end(&mut stderr);
                }
                let status = child.wait().map_err(|e| e.to_string())?;
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("executable timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("failed to wait on executable: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ows_core::policy::{
        SpendingContext, TransactionContext, TransactionEffect, TypedDataContext,
    };
    use ows_core::PolicyAction;

    fn base_context() -> PolicyContext {
        PolicyContext {
            chain_id: "eip155:8453".to_string(),
            wallet_id: "wallet-1".to_string(),
            api_key_id: "key-1".to_string(),
            request_type: PolicyRequestType::SignTransaction,
            transaction: Some(TransactionContext {
                effects: vec![TransactionEffect {
                    address: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C".into(),
                    diff: vec![("ETH".into(), "100000000000000000".into())], // 0.1 ETH
                }],
                raw_hex: "0x02f8...".to_string(),
                data: None,
                chain_extra: None,
            }),
            spending: SpendingContext {
                daily_total: "50000000000000000".to_string(), // 0.05 ETH already spent
                date: "2026-03-22".to_string(),
            },
            timestamp: "2026-03-22T10:35:22Z".to_string(),
            typed_data: None,
        }
    }

    fn policy_with_rules(id: &str, rules: Vec<PolicyRule>) -> Policy {
        Policy {
            id: id.to_string(),
            name: id.to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules,
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        }
    }

    // --- AllowedChains ---

    #[test]
    fn allowed_chains_passes_matching_chain() {
        let ctx = base_context(); // chain_id = eip155:8453
        let policy = policy_with_rules(
            "chains",
            vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:8453".to_string(), "eip155:84532".to_string()],
            }],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_chains_denies_non_matching() {
        let ctx = base_context();
        let policy = policy_with_rules(
            "chains",
            vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:1".to_string()], // mainnet only
            }],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("not in allowlist"));
    }

    // --- ExpiresAt ---

    #[test]
    fn expires_at_allows_before_expiry() {
        let ctx = base_context(); // timestamp = 2026-03-22T10:35:22Z
        let policy = policy_with_rules(
            "exp",
            vec![PolicyRule::ExpiresAt {
                timestamp: "2026-04-01T00:00:00Z".to_string(),
            }],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn expires_at_denies_after_expiry() {
        let ctx = base_context(); // timestamp = 2026-03-22T10:35:22Z
        let policy = policy_with_rules(
            "exp",
            vec![PolicyRule::ExpiresAt {
                timestamp: "2026-03-01T00:00:00Z".to_string(), // already expired
            }],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("expired"));
    }

    // --- Multi-rule / multi-policy AND semantics ---

    #[test]
    fn multiple_rules_all_must_pass() {
        let ctx = base_context();
        let policy = policy_with_rules(
            "multi",
            vec![
                PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:8453".to_string()],
                },
                PolicyRule::ExpiresAt {
                    timestamp: "2026-04-01T00:00:00Z".to_string(),
                },
            ],
        );

        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn short_circuits_on_first_denial() {
        let ctx = base_context();
        let policies = vec![
            policy_with_rules(
                "pass",
                vec![PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:8453".to_string()],
                }],
            ),
            policy_with_rules(
                "fail",
                vec![PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:1".to_string()], // wrong chain
                }],
            ),
            policy_with_rules(
                "never-reached",
                vec![PolicyRule::ExpiresAt {
                    timestamp: "2020-01-01T00:00:00Z".to_string(),
                }],
            ),
        ];

        let result = evaluate_policies(&policies, &ctx);
        assert!(!result.allow);
        assert_eq!(result.policy_id.unwrap(), "fail");
    }

    #[test]
    fn empty_policies_allows() {
        let ctx = base_context();
        let result = evaluate_policies(&[], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn policy_with_no_rules_and_no_executable_allows() {
        let ctx = base_context();
        let policy = policy_with_rules("empty", vec![]);
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    // --- Executable policy ---

    #[test]
    fn executable_invalid_json_denies() {
        let ctx = base_context();
        // sh without args just reads stdin, won't produce valid JSON → denied
        let result = evaluate_executable("sh", None, "exe-invalid", &ctx);
        assert!(!result.allow);
    }

    #[test]
    fn executable_nonexistent_binary_denies() {
        let ctx = base_context();
        let result = evaluate_executable("/nonexistent/binary", None, "bad-exe", &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("failed to start"));
    }

    #[test]
    fn executable_with_script() {
        // Create a temp script that outputs {"allow": true}
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("allow.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\ncat > /dev/null\necho '{\"allow\": true}'\n",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let ctx = base_context();
        let result = evaluate_executable(script.to_str().unwrap(), None, "script-allow", &ctx);
        assert!(result.allow);
    }

    #[test]
    fn executable_deny_script() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("deny.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\ncat > /dev/null\necho '{\"allow\": false, \"reason\": \"nope\"}'\n",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let ctx = base_context();
        let result = evaluate_executable(script.to_str().unwrap(), None, "script-deny", &ctx);
        assert!(!result.allow);
        assert_eq!(result.reason.as_deref(), Some("nope"));
        assert_eq!(result.policy_id.as_deref(), Some("script-deny"));
    }

    #[test]
    fn executable_nonzero_exit_denies() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fail.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 1\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let ctx = base_context();
        let result = evaluate_executable(script.to_str().unwrap(), None, "exit-fail", &ctx);
        assert!(!result.allow);
    }

    #[test]
    fn rules_prefilter_before_executable() {
        // If declarative rules deny, executable should not run
        let dir = tempfile::tempdir().unwrap();
        // Create a marker file approach: if exe runs, it creates a file
        let marker = dir.path().join("ran");
        let script = dir.path().join("marker.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ntouch {}\necho '{{\"allow\": true}}'\n",
                marker.display()
            ),
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let ctx = base_context();
        let policy = Policy {
            id: "prefilter".to_string(),
            name: "prefilter".to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:1".to_string()], // wrong chain → deny
            }],
            executable: Some(script.to_str().unwrap().to_string()),
            config: None,
            action: PolicyAction::Deny,
        };

        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(!marker.exists(), "executable should not have run");
    }

    // --- AllowedTypedDataContracts ---

    fn typed_data_context(verifying_contract: Option<&str>) -> TypedDataContext {
        TypedDataContext {
            verifying_contract: verifying_contract.map(String::from),
            domain_chain_id: Some(8453),
            primary_type: "PermitSingle".into(),
            domain_name: Some("Permit2".into()),
            domain_version: Some("1".into()),
            raw_json: "{}".into(),
        }
    }

    #[test]
    fn allowed_typed_data_contracts_matching_allows() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some(
            "0x000000000022D473030F116dDEE9F6B43aC78BA3",
        )));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_typed_data_contracts_non_matching_denies() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some("0xDEAD")));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("not in allowed list"));
    }

    #[test]
    fn allowed_typed_data_contracts_case_insensitive() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some(
            "0x000000000022d473030f116ddee9f6b43ac78ba3",
        )));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_typed_data_contracts_no_typed_data_passes() {
        let ctx = base_context();
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_typed_data_contracts_no_verifying_contract_denies() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(None));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("no verifyingContract"));
    }

    #[test]
    fn allowed_typed_data_contracts_empty_list_denies_everything() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some(
            "0x000000000022D473030F116dDEE9F6B43aC78BA3",
        )));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts { contracts: vec![] }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("not in allowed list"));
    }

    #[test]
    fn combined_rules_with_typed_data_contracts() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some(
            "0x000000000022D473030F116dDEE9F6B43aC78BA3",
        )));
        let policy = policy_with_rules(
            "combined",
            vec![
                PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:8453".into()],
                },
                PolicyRule::AllowedTypedDataContracts {
                    contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
                },
                PolicyRule::ExpiresAt {
                    timestamp: "2027-01-01T00:00:00Z".into(),
                },
            ],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    // --- NearTransactionLimits ---

    /// A `sign_transaction` context as the NEAR signer builds it.
    fn near_tx_context(chain_extra: Value) -> PolicyContext {
        PolicyContext {
            chain_id: "near:mainnet".to_string(),
            transaction: Some(TransactionContext {
                effects: vec![],
                raw_hex: "00".to_string(),
                data: None,
                chain_extra: Some(chain_extra),
            }),
            ..base_context()
        }
    }

    fn near_tx(receiver: &str, actions: Value, total_deposit: &str) -> Value {
        serde_json::json!({
            "kind": "transaction",
            "signer_id": "agent.near",
            "receiver_id": receiver,
            "actions": actions,
            "total_deposit": total_deposit,
        })
    }

    fn ft_transfer_tx() -> Value {
        near_tx(
            "ft.example.near",
            serde_json::json!([
                { "type": "function_call", "method_name": "ft_transfer", "deposit": "1" },
                { "type": "transfer", "deposit": "9" },
            ]),
            "10",
        )
    }

    fn near_limits(limits: NearTransactionLimits) -> Policy {
        policy_with_rules("near", vec![PolicyRule::NearTransactionLimits(limits)])
    }

    fn eval_near(limits: NearTransactionLimits, ctx: &PolicyContext) -> PolicyResult {
        evaluate_policies(&[near_limits(limits)], ctx)
    }

    fn strings(items: &[&str]) -> Option<Vec<String>> {
        Some(items.iter().map(|s| s.to_string()).collect())
    }

    fn denied_reason(result: PolicyResult) -> String {
        assert!(!result.allow, "expected a denial");
        assert_eq!(result.policy_id.as_deref(), Some("near"));
        result.reason.unwrap()
    }

    #[test]
    fn near_limits_allow_a_transaction_within_every_limit() {
        let limits = NearTransactionLimits {
            receivers: strings(&["ft.example.near"]),
            methods: strings(&["ft_transfer"]),
            max_deposit: Some("10".into()),
            actions: None,
        };
        assert!(eval_near(limits, &near_tx_context(ft_transfer_tx())).allow);
    }

    #[test]
    fn near_limits_with_no_fields_still_apply_default_actions() {
        let ctx = near_tx_context(ft_transfer_tx());
        assert!(eval_near(NearTransactionLimits::default(), &ctx).allow);

        let add_key = near_tx(
            "agent.near",
            serde_json::json!([{ "type": "add_key", "public_key": "ed25519:x" }]),
            "0",
        );
        let reason = denied_reason(eval_near(
            NearTransactionLimits::default(),
            &near_tx_context(add_key.clone()),
        ));
        assert!(reason.contains("add_key is not allowed"), "{reason}");

        let explicit = NearTransactionLimits {
            actions: strings(&["add_key"]),
            ..Default::default()
        };
        assert!(eval_near(explicit, &near_tx_context(add_key)).allow);
    }

    #[test]
    fn near_limits_explicit_actions_replace_the_defaults() {
        let only_calls = NearTransactionLimits {
            actions: strings(&["function_call"]),
            ..Default::default()
        };
        let reason = denied_reason(eval_near(only_calls, &near_tx_context(ft_transfer_tx())));
        assert!(reason.contains("transfer is not allowed"), "{reason}");
    }

    #[test]
    fn near_limits_deny_receiver_not_listed() {
        let limits = NearTransactionLimits {
            receivers: strings(&["other.near"]),
            ..Default::default()
        };
        let reason = denied_reason(eval_near(limits, &near_tx_context(ft_transfer_tx())));
        assert!(reason.contains("receiver ft.example.near"), "{reason}");

        let empty = NearTransactionLimits {
            receivers: Some(vec![]),
            ..Default::default()
        };
        assert!(!eval_near(empty, &near_tx_context(ft_transfer_tx())).allow);
    }

    #[test]
    fn near_limits_match_receivers_and_methods_exactly() {
        for receiver in ["FT.example.near", "ft.example.near ", "example.near"] {
            let limits = NearTransactionLimits {
                receivers: strings(&[receiver]),
                ..Default::default()
            };
            assert!(!eval_near(limits, &near_tx_context(ft_transfer_tx())).allow);
        }
        let limits = NearTransactionLimits {
            methods: strings(&["FT_TRANSFER", "ft_transfer_call"]),
            ..Default::default()
        };
        assert!(!eval_near(limits, &near_tx_context(ft_transfer_tx())).allow);
    }

    #[test]
    fn near_limits_deny_method_not_listed() {
        let limits = NearTransactionLimits {
            methods: strings(&["storage_deposit"]),
            ..Default::default()
        };
        let reason = denied_reason(eval_near(limits, &near_tx_context(ft_transfer_tx())));
        assert!(reason.contains("method ft_transfer"), "{reason}");

        // An empty method list blocks function calls but not plain transfers.
        let none = NearTransactionLimits {
            methods: Some(vec![]),
            ..Default::default()
        };
        assert!(!eval_near(none.clone(), &near_tx_context(ft_transfer_tx())).allow);
        let transfer_only = near_tx(
            "bob.near",
            serde_json::json!([{ "type": "transfer", "deposit": "1" }]),
            "1",
        );
        assert!(eval_near(none, &near_tx_context(transfer_only)).allow);
    }

    #[test]
    fn near_limits_max_deposit_is_inclusive() {
        let at = |max: &str| NearTransactionLimits {
            max_deposit: Some(max.into()),
            ..Default::default()
        };
        assert!(eval_near(at("10"), &near_tx_context(ft_transfer_tx())).allow);
        let reason = denied_reason(eval_near(at("9"), &near_tx_context(ft_transfer_tx())));
        assert!(reason.contains("exceeds max_deposit 9"), "{reason}");
        // u128 range: 340282366920938463463374607431768211455 yoctoNEAR.
        let max_tx = near_tx(
            "bob.near",
            serde_json::json!([{ "type": "transfer", "deposit": u128::MAX.to_string() }]),
            &u128::MAX.to_string(),
        );
        assert!(eval_near(at(&u128::MAX.to_string()), &near_tx_context(max_tx.clone())).allow);
        assert!(!eval_near(at(&(u128::MAX - 1).to_string()), &near_tx_context(max_tx)).allow);
    }

    #[test]
    fn near_limits_deny_invalid_policy_values() {
        for bad in ["", "-1", "1e24", "0x10", "1.5", " 10"] {
            let limits = NearTransactionLimits {
                max_deposit: Some(bad.into()),
                ..Default::default()
            };
            let reason = denied_reason(eval_near(limits, &near_tx_context(ft_transfer_tx())));
            assert!(reason.contains("invalid max_deposit"), "{bad:?}: {reason}");
        }
        let limits = NearTransactionLimits {
            actions: strings(&["transfer", "Function_Call"]),
            ..Default::default()
        };
        let reason = denied_reason(eval_near(limits, &near_tx_context(ft_transfer_tx())));
        assert!(
            reason.contains("unknown NEAR action type 'Function_Call'"),
            "{reason}"
        );
    }

    #[test]
    fn near_limits_deny_undecoded_transactions() {
        let mut ctx = near_tx_context(ft_transfer_tx());
        ctx.transaction.as_mut().unwrap().chain_extra = None;
        let reason = denied_reason(eval_near(NearTransactionLimits::default(), &ctx));
        assert!(reason.contains("not decoded"), "{reason}");

        // A context that would pass every limit but is not a decoded transaction.
        let mut other = ft_transfer_tx();
        other["kind"] = serde_json::json!("nep413_message");
        assert!(!eval_near(NearTransactionLimits::default(), &near_tx_context(other)).allow);

        let mut no_tx = near_tx_context(ft_transfer_tx());
        no_tx.transaction = None;
        assert!(!eval_near(NearTransactionLimits::default(), &no_tx).allow);
    }

    #[test]
    fn near_limits_apply_to_delegate_actions_being_signed() {
        // NEP-366: the delegate's own receiver, actions and deposits are checked.
        let mut delegate = ft_transfer_tx();
        delegate["kind"] = serde_json::json!("delegate_action");
        let ok = NearTransactionLimits {
            receivers: strings(&["ft.example.near"]),
            methods: strings(&["ft_transfer"]),
            max_deposit: Some("10".into()),
            actions: None,
        };
        assert!(eval_near(ok.clone(), &near_tx_context(delegate.clone())).allow);
        let low = NearTransactionLimits {
            max_deposit: Some("9".into()),
            ..ok
        };
        assert!(!eval_near(low, &near_tx_context(delegate)).allow);
    }

    #[test]
    fn near_limits_do_not_look_inside_delegate_actions() {
        // A relayed delegate action's inner actions are authorized by its own
        // signature, so only the outer action type is checked. (Its inner deposits
        // are prepaid by the relayer and already counted in `total_deposit` by
        // the decoder.)
        let relay = near_tx(
            "user.near",
            serde_json::json!([{
                "type": "delegate",
                "delegate_action": { "receiver_id": "anything.near", "actions": [{ "type": "add_key" }] },
            }]),
            "0",
        );
        assert!(
            !eval_near(
                NearTransactionLimits::default(),
                &near_tx_context(relay.clone())
            )
            .allow
        );
        let allow_relay = NearTransactionLimits {
            actions: strings(&["delegate"]),
            ..Default::default()
        };
        assert!(eval_near(allow_relay, &near_tx_context(relay)).allow);
    }

    fn near_message_context(len: usize) -> PolicyContext {
        PolicyContext {
            chain_id: "near:testnet".to_string(),
            request_type: PolicyRequestType::SignMessage,
            transaction: Some(TransactionContext {
                effects: vec![],
                raw_hex: "ab".repeat(len),
                data: None,
                chain_extra: None,
            }),
            ..base_context()
        }
    }

    #[test]
    fn near_limits_deny_raw_32_byte_messages_only() {
        let reason = denied_reason(eval_near(
            NearTransactionLimits::default(),
            &near_message_context(32),
        ));
        assert!(reason.contains("32 raw bytes"), "{reason}");
        for len in [0, 31, 33, 64] {
            assert!(
                eval_near(NearTransactionLimits::default(), &near_message_context(len)).allow,
                "a {len}-byte message cannot be a transaction signature"
            );
        }
        let mut missing = near_message_context(10);
        missing.transaction = None;
        assert!(!eval_near(NearTransactionLimits::default(), &missing).allow);
    }

    #[test]
    fn near_limits_deny_raw_hash_and_allow_unsigned_operations() {
        let mut ctx = near_message_context(32);
        ctx.request_type = PolicyRequestType::SignHash;
        assert!(!eval_near(NearTransactionLimits::default(), &ctx).allow);
        for request_type in [
            PolicyRequestType::ReadBalance,
            PolicyRequestType::SignTypedData,
        ] {
            ctx.request_type = request_type;
            assert!(eval_near(NearTransactionLimits::default(), &ctx).allow);
        }
    }

    #[test]
    fn near_limits_pass_through_other_chains() {
        let strict = NearTransactionLimits {
            receivers: Some(vec![]),
            ..Default::default()
        };
        // base_context is an EVM transaction with no NEAR context at all.
        assert!(eval_near(strict.clone(), &base_context()).allow);
        // Chains that do not sign raw Ed25519 with a key NEAR could share.
        for chain_id in [
            "nearx:mainnet",
            "eip155:1",
            "sui:mainnet",
            "nano:mainnet",
            "cip34:1-764824073",
        ] {
            let mut ctx = near_message_context(32);
            ctx.chain_id = chain_id.to_string();
            assert!(eval_near(strict.clone(), &ctx).allow, "{chain_id}");
        }
    }

    fn chain_context(
        chain_id: &str,
        request_type: PolicyRequestType,
        payload: &[u8],
    ) -> PolicyContext {
        PolicyContext {
            chain_id: chain_id.to_string(),
            request_type,
            transaction: Some(TransactionContext {
                effects: vec![],
                raw_hex: hex::encode(payload),
                data: None,
                chain_extra: None,
            }),
            ..base_context()
        }
    }

    #[test]
    fn near_limits_deny_32_byte_raw_signing_on_shared_key_chains() {
        // On a wallet imported from a raw Ed25519 key, Solana and TON sign with
        // the NEAR key, over the caller's bytes as given.
        let limits = NearTransactionLimits::default;
        let solana = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
        for (chain_id, request_type) in [
            (solana, PolicyRequestType::SignMessage),
            ("ton:mainnet", PolicyRequestType::SignMessage),
            ("ton:mainnet", PolicyRequestType::SignTransaction),
        ] {
            let reason = denied_reason(eval_near(
                limits(),
                &chain_context(chain_id, request_type, &[0x11; 32]),
            ));
            assert!(reason.contains("32 raw bytes"), "{chain_id}: {reason}");
            for len in [31, 33] {
                assert!(
                    eval_near(
                        limits(),
                        &chain_context(chain_id, request_type, &vec![0x11; len])
                    )
                    .allow
                );
            }
        }
        // Solana signs the message after the signature slots: [n][n * 64 bytes][message].
        let envelope = |message_len: usize| {
            let mut tx = vec![0x01];
            tx.extend_from_slice(&[0u8; 64]);
            tx.extend_from_slice(&vec![0x22; message_len]);
            tx
        };
        assert!(
            !eval_near(
                limits(),
                &chain_context(solana, PolicyRequestType::SignTransaction, &envelope(32))
            )
            .allow
        );
        assert!(
            eval_near(
                limits(),
                &chain_context(solana, PolicyRequestType::SignTransaction, &envelope(33))
            )
            .allow
        );
        // A malformed envelope cannot be measured, so it is denied.
        assert!(
            !eval_near(
                limits(),
                &chain_context(solana, PolicyRequestType::SignTransaction, &[0x05; 10])
            )
            .allow
        );
        let mut hash = chain_context(solana, PolicyRequestType::SignHash, &[0x11; 32]);
        assert!(!eval_near(limits(), &hash).allow);
        hash.request_type = PolicyRequestType::ReadBalance;
        assert!(eval_near(limits(), &hash).allow);
    }

    #[test]
    fn raw_ed25519_chain_list_is_complete() {
        // Every chain whose signer uses the plain Ed25519 key and signs a 32-byte
        // payload as-is (an Ed25519 signature over exactly those bytes) must be
        // listed, or near_transaction_limits could be bypassed through it.
        use ed25519_dalek::{Signature, Verifier};
        let seed = [0x42u8; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let digest = [0x5au8; 32];
        let verifies = |sig: &Result<ows_signer::SignOutput, ows_signer::SignerError>,
                        message: &[u8]| {
            sig.as_ref()
                .ok()
                .and_then(|out| <[u8; 64]>::try_from(out.signature.as_slice()).ok())
                .is_some_and(|sig| public.verify(message, &Signature::from_bytes(&sig)).is_ok())
        };
        let raw_signs =
            |sig: Result<ows_signer::SignOutput, ows_signer::SignerError>| verifies(&sig, &digest);
        // No Ed25519 chain other than NEAR may sign `sha256(payload)` itself — NEAR's
        // own scheme — or it could sign a whole NEAR transaction the decoder never sees.
        let payload = b"\x0a\x00\x00\x00alice.near-not-really-a-transaction";
        let near_digest = <sha2::Sha256 as sha2::Digest>::digest(payload);
        let mut found = Vec::new();
        for chain_type in ows_core::ALL_CHAIN_TYPES {
            let signer = ows_signer::signer_for_chain_type(chain_type).unwrap();
            if signer.curve() != ows_signer::Curve::Ed25519
                || chain_type == ows_core::ChainType::Near
            {
                continue;
            }
            for sig in [
                signer.sign_message(&seed, payload, None),
                signer.sign_transaction(&seed, payload),
            ] {
                assert!(
                    !verifies(&sig, &near_digest),
                    "{chain_type} signs sha256(payload) like NEAR"
                );
            }
            if raw_signs(signer.sign_message(&seed, &digest, None))
                || raw_signs(signer.sign_transaction(&seed, &digest))
            {
                found.push(chain_type.namespace());
            }
        }
        found.sort_unstable();
        let mut listed = RAW_ED25519_NAMESPACES.to_vec();
        listed.sort_unstable();
        assert_eq!(found, listed);
    }

    #[test]
    fn near_limits_read_the_near_signer_context() {
        use ows_signer::ChainSigner;
        // near-api-js 7.3.1 transaction: alice.near -> ft.example.near with
        // storage_deposit (0.00125 NEAR), ft_transfer (1 yocto) and transfer(10).
        let tx = hex::decode(
            "0a000000616c6963652e6e65617200d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a07\
             000000000000000f00000066742e6578616d706c652e6e656172a0a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5\
             a6a7a8a9aaabacadaeaf03000000020f00000073746f726167655f6465706f7369741b0000007b226163636f756e745f\
             6964223a22616c6963652e6e656172227d00e057eb481b00000000485637193cc34300000000000000020b0000006674\
             5f7472616e73666572280000007b2272656365697665725f6964223a22626f622e6e656172222c22616d6f756e74223a\
             223432227d00e057eb481b000001000000000000000000000000000000030a000000000000000000000000000000",
        )
        .unwrap();
        let transaction = ows_signer::chains::NearSigner
            .make_transaction_context(&tx, None)
            .unwrap();
        let ctx = PolicyContext {
            chain_id: "near:mainnet".to_string(),
            transaction: Some(transaction),
            ..base_context()
        };
        let limits = |max: &str| NearTransactionLimits {
            receivers: strings(&["ft.example.near"]),
            methods: strings(&["storage_deposit", "ft_transfer"]),
            max_deposit: Some(max.into()),
            actions: None,
        };
        assert!(eval_near(limits("1250000000000000000011"), &ctx).allow);
        assert!(!eval_near(limits("1250000000000000000010"), &ctx).allow);
    }

    #[test]
    fn near_default_actions_are_known_action_types() {
        for action in NearTransactionLimits::DEFAULT_ACTIONS {
            assert!(ows_signer::chains::near::decode::ACTION_TYPES.contains(action));
        }
    }
}
