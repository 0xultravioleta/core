//! Borsh decoding of NEAR transactions, so a policy can see what a transaction
//! does (receiver, actions, method names, attached deposits) instead of opaque
//! bytes.
//!
//! The layout follows nearcore and `near-api-js` 7.x: `Transaction` (V0) and the
//! action set `CreateAccount` (0) through `UseGlobalContract` (10). Decoding is
//! strict: an unknown enum discriminant, invalid UTF-8, an invalid account ID, a
//! truncated field or trailing bytes is an error, because Borsh cannot skip what
//! it does not know and a policy must not be shown a partial transaction. Actions
//! nearcore added after that set (state init, gas keys, `DelegateV2`) are not
//! decoded, so they cannot be signed with an API token.
//!
//! Account IDs are validated with nearcore's rules. Besides keeping garbage out
//! of policy context, this keeps the decoder in step with nearcore, which reads a
//! `TransactionV1` when the second byte is non-zero: a valid signer ID is at most
//! 64 bytes, so its length's second byte is always zero.

use crate::traits::SignerError;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Length of an ML-DSA-65 public key (key type 2: nearcore `KeyType::MLDSA65`,
/// `ML_DSA_65_PUBLIC_KEY_LENGTH`; near-api-js `KeyType.MLDSA65`).
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// Length of an ML-DSA-65 signature (nearcore `ML_DSA_65_SIGNATURE_LENGTH`).
const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// nearcore account ID length bounds.
const ACCOUNT_ID_MIN_LEN: usize = 2;
const ACCOUNT_ID_MAX_LEN: usize = 64;

/// A NEAR public key (`PublicKey` enum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    Secp256k1([u8; 64]),
    MlDsa65(Vec<u8>),
}

impl std::fmt::Display for PublicKey {
    /// The `<type>:<base58>` form NEAR tooling prints (`ed25519:...`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (prefix, data): (&str, &[u8]) = match self {
            PublicKey::Ed25519(k) => ("ed25519", k),
            PublicKey::Secp256k1(k) => ("secp256k1", k),
            PublicKey::MlDsa65(k) => ("ml-dsa-65", k),
        };
        write!(f, "{prefix}:{}", bs58::encode(data).into_string())
    }
}

/// A NEAR signature (`Signature` enum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    Ed25519([u8; 64]),
    Secp256k1([u8; 65]),
    MlDsa65(Vec<u8>),
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (prefix, data): (&str, &[u8]) = match self {
            Signature::Ed25519(s) => ("ed25519", s),
            Signature::Secp256k1(s) => ("secp256k1", s),
            Signature::MlDsa65(s) => ("ml-dsa-65", s),
        };
        write!(f, "{prefix}:{}", bs58::encode(data).into_string())
    }
}

/// Access key permission (`AccessKeyPermission` enum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessKeyPermission {
    FunctionCall {
        allowance: Option<u128>,
        receiver_id: String,
        method_names: Vec<String>,
    },
    FullAccess,
}

/// How a global contract is addressed once deployed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalContractDeployMode {
    CodeHash,
    AccountId,
}

/// Which global contract an account uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalContractIdentifier {
    CodeHash([u8; 32]),
    AccountId(String),
}

/// A NEAR action. `Delegate` only appears at the top level of a transaction:
/// nearcore rejects a delegate action nested in another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    CreateAccount,
    DeployContract {
        code: Vec<u8>,
    },
    FunctionCall {
        method_name: String,
        args: Vec<u8>,
        gas: u64,
        deposit: u128,
    },
    Transfer {
        deposit: u128,
    },
    Stake {
        stake: u128,
        public_key: PublicKey,
    },
    AddKey {
        public_key: PublicKey,
        nonce: u64,
        permission: AccessKeyPermission,
    },
    DeleteKey {
        public_key: PublicKey,
    },
    DeleteAccount {
        beneficiary_id: String,
    },
    Delegate(Box<SignedDelegateAction>),
    DeployGlobalContract {
        code: Vec<u8>,
        deploy_mode: GlobalContractDeployMode,
    },
    UseGlobalContract {
        contract_identifier: GlobalContractIdentifier,
    },
}

impl Action {
    /// The snake_case action type used in policy context and policy rules.
    pub fn type_name(&self) -> &'static str {
        match self {
            Action::CreateAccount => "create_account",
            Action::DeployContract { .. } => "deploy_contract",
            Action::FunctionCall { .. } => "function_call",
            Action::Transfer { .. } => "transfer",
            Action::Stake { .. } => "stake",
            Action::AddKey { .. } => "add_key",
            Action::DeleteKey { .. } => "delete_key",
            Action::DeleteAccount { .. } => "delete_account",
            Action::Delegate(_) => "delegate",
            Action::DeployGlobalContract { .. } => "deploy_global_contract",
            Action::UseGlobalContract { .. } => "use_global_contract",
        }
    }

    /// yoctoNEAR the signer of the enclosing transaction pays for this action as
    /// a deposit, as nearcore's `total_deposit` counts it: the `transfer` and
    /// `function_call` deposits, and for a `delegate` action the deposits of its
    /// inner actions, which the relayer prepays. Zero for every other action.
    pub fn attached_deposit(&self) -> Result<u128, SignerError> {
        match self {
            Action::Transfer { deposit } | Action::FunctionCall { deposit, .. } => Ok(*deposit),
            Action::Delegate(signed) => total_deposit(&signed.delegate_action.actions),
            _ => Ok(0),
        }
    }
}

/// Every action type name [`Action::type_name`] can return.
pub const ACTION_TYPES: &[&str] = &[
    "create_account",
    "deploy_contract",
    "function_call",
    "transfer",
    "stake",
    "add_key",
    "delete_key",
    "delete_account",
    "delegate",
    "deploy_global_contract",
    "use_global_contract",
];

/// NEP-366 `DelegateAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateAction {
    pub sender_id: String,
    pub receiver_id: String,
    pub actions: Vec<Action>,
    pub nonce: u64,
    pub max_block_height: u64,
    pub public_key: PublicKey,
}

/// NEP-366 `SignedDelegateAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDelegateAction {
    pub delegate_action: DelegateAction,
    pub signature: Signature,
}

/// An unsigned NEAR `Transaction` (V0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub signer_id: String,
    pub public_key: PublicKey,
    pub nonce: u64,
    pub receiver_id: String,
    pub block_hash: [u8; 32],
    pub actions: Vec<Action>,
}

impl Transaction {
    /// Decode `borsh(Transaction)`. The whole input must be consumed.
    pub fn from_borsh(bytes: &[u8]) -> Result<Self, SignerError> {
        let mut r = Reader::new(bytes);
        let tx = Transaction {
            signer_id: r.account_id("signer_id")?,
            public_key: r.public_key()?,
            nonce: r.u64()?,
            receiver_id: r.account_id("receiver_id")?,
            block_hash: r.array::<32>()?,
            actions: r.actions(true)?,
        };
        r.finish()?;
        Ok(tx)
    }

    /// Sum of the deposits the signer pays, in yoctoNEAR, as nearcore's
    /// `total_deposit` computes it (see [`Action::attached_deposit`]): deposits
    /// inside a relayed `delegate` action count, because the relayer prepays them.
    /// An overflow is an error, as it is in nearcore.
    pub fn total_deposit(&self) -> Result<u128, SignerError> {
        total_deposit(&self.actions)
    }

    /// The policy-facing JSON (`TransactionContext::chain_extra`).
    pub fn to_json(&self) -> Result<Value, SignerError> {
        Ok(json!({
            "kind": "transaction",
            "signer_id": self.signer_id,
            "public_key": self.public_key.to_string(),
            "nonce": self.nonce.to_string(),
            "receiver_id": self.receiver_id,
            "block_hash": bs58::encode(self.block_hash).into_string(),
            "actions": actions_json(&self.actions),
            "total_deposit": self.total_deposit()?.to_string(),
        }))
    }
}

impl DelegateAction {
    /// Decode `borsh(DelegateAction)`, without the NEP-366 prefix. The whole
    /// input must be consumed, and a nested delegate action is rejected.
    pub fn from_borsh(bytes: &[u8]) -> Result<Self, SignerError> {
        let mut r = Reader::new(bytes);
        let delegate_action = r.delegate_action()?;
        r.finish()?;
        Ok(delegate_action)
    }

    /// Sum of the deposits the delegate's actions attach, in yoctoNEAR. nearcore
    /// has the relayer that submits the delegate prepay them (refunded to
    /// `sender_id` if the actions fail).
    pub fn total_deposit(&self) -> Result<u128, SignerError> {
        total_deposit(&self.actions)
    }

    /// The policy-facing JSON (`TransactionContext::chain_extra`) for a
    /// delegate action being signed: its fields plus `kind: "delegate_action"`
    /// and `total_deposit`.
    pub fn to_json(&self) -> Result<Value, SignerError> {
        let mut json = self.fields_json();
        json["kind"] = json!("delegate_action");
        json["total_deposit"] = json!(self.total_deposit()?.to_string());
        Ok(json)
    }

    /// The delegate's fields as JSON, without a `kind` tag.
    fn fields_json(&self) -> Value {
        json!({
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "actions": actions_json(&self.actions),
            "nonce": self.nonce.to_string(),
            "max_block_height": self.max_block_height.to_string(),
            "public_key": self.public_key.to_string(),
        })
    }
}

fn total_deposit(actions: &[Action]) -> Result<u128, SignerError> {
    actions.iter().try_fold(0u128, |sum, action| {
        sum.checked_add(action.attached_deposit()?)
            .ok_or_else(|| SignerError::InvalidTransaction("total deposit overflows u128".into()))
    })
}

fn actions_json(actions: &[Action]) -> Vec<Value> {
    actions.iter().map(action_json).collect()
}

fn code_hash(code: &[u8]) -> String {
    bs58::encode(Sha256::digest(code)).into_string()
}

fn action_json(action: &Action) -> Value {
    let ty = action.type_name();
    match action {
        Action::CreateAccount => json!({ "type": ty }),
        Action::DeployContract { code } => json!({
            "type": ty,
            "code_hash": code_hash(code),
            "code_len": code.len(),
        }),
        Action::FunctionCall {
            method_name,
            args,
            gas,
            deposit,
        } => json!({
            "type": ty,
            "method_name": method_name,
            "args": base64::engine::general_purpose::STANDARD.encode(args),
            "gas": gas.to_string(),
            "deposit": deposit.to_string(),
        }),
        Action::Transfer { deposit } => json!({ "type": ty, "deposit": deposit.to_string() }),
        Action::Stake { stake, public_key } => json!({
            "type": ty,
            "stake": stake.to_string(),
            "public_key": public_key.to_string(),
        }),
        Action::AddKey {
            public_key,
            nonce,
            permission,
        } => {
            let permission = match permission {
                AccessKeyPermission::FullAccess => json!({ "type": "full_access" }),
                AccessKeyPermission::FunctionCall {
                    allowance,
                    receiver_id,
                    method_names,
                } => json!({
                    "type": "function_call",
                    "allowance": allowance.map(|a| a.to_string()),
                    "receiver_id": receiver_id,
                    "method_names": method_names,
                }),
            };
            json!({
                "type": ty,
                "public_key": public_key.to_string(),
                "access_key": { "nonce": nonce.to_string(), "permission": permission },
            })
        }
        Action::DeleteKey { public_key } => {
            json!({ "type": ty, "public_key": public_key.to_string() })
        }
        Action::DeleteAccount { beneficiary_id } => {
            json!({ "type": ty, "beneficiary_id": beneficiary_id })
        }
        Action::Delegate(signed) => json!({
            "type": ty,
            "delegate_action": signed.delegate_action.fields_json(),
            "signature": signed.signature.to_string(),
        }),
        Action::DeployGlobalContract { code, deploy_mode } => json!({
            "type": ty,
            "code_hash": code_hash(code),
            "code_len": code.len(),
            "deploy_mode": match deploy_mode {
                GlobalContractDeployMode::CodeHash => "code_hash",
                GlobalContractDeployMode::AccountId => "account_id",
            },
        }),
        Action::UseGlobalContract {
            contract_identifier,
        } => json!({
            "type": ty,
            "contract_identifier": match contract_identifier {
                GlobalContractIdentifier::CodeHash(hash) => {
                    json!({ "code_hash": bs58::encode(hash).into_string() })
                }
                GlobalContractIdentifier::AccountId(account_id) => {
                    json!({ "account_id": account_id })
                }
            },
        }),
    }
}

/// nearcore's account ID rules: 2 to 64 bytes of `a-z`, `0-9` and the separators
/// `-`, `_` and `.`, with no separator first, last or next to another.
fn validate_account_id(id: &str) -> Result<(), &'static str> {
    if !(ACCOUNT_ID_MIN_LEN..=ACCOUNT_ID_MAX_LEN).contains(&id.len()) {
        return Err("length must be 2 to 64");
    }
    let mut previous_was_separator = true; // rejects a leading separator
    for c in id.bytes() {
        match c {
            b'a'..=b'z' | b'0'..=b'9' => previous_was_separator = false,
            b'-' | b'_' | b'.' if !previous_was_separator => previous_was_separator = true,
            b'-' | b'_' | b'.' => return Err("separator at the start or next to another"),
            _ => return Err("only a-z, 0-9, '-', '_' and '.' are allowed"),
        }
    }
    if previous_was_separator {
        return Err("separator at the end");
    }
    Ok(())
}

/// A bounds-checked Borsh reader. Every length is checked against the bytes
/// that remain before anything is allocated, so a hostile length prefix cannot
/// trigger a large allocation.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

fn malformed(msg: impl Into<String>) -> SignerError {
    SignerError::InvalidTransaction(format!("malformed NEAR borsh: {}", msg.into()))
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SignerError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| malformed(format!("unexpected end of input at byte {}", self.pos)))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SignerError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, SignerError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, SignerError> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, SignerError> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }

    fn u128(&mut self) -> Result<u128, SignerError> {
        Ok(u128::from_le_bytes(self.array::<16>()?))
    }

    fn len_prefix(&mut self) -> Result<usize, SignerError> {
        usize::try_from(self.u32()?).map_err(|_| malformed("length does not fit in usize"))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, SignerError> {
        let len = self.len_prefix()?;
        Ok(self.take(len)?.to_vec())
    }

    fn string(&mut self, field: &str) -> Result<String, SignerError> {
        let len = self.len_prefix()?;
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec()).map_err(|_| malformed(format!("{field} is not UTF-8")))
    }

    /// A Borsh string that must be a valid NEAR account ID.
    fn account_id(&mut self, field: &str) -> Result<String, SignerError> {
        let id = self.string(field)?;
        validate_account_id(&id)
            .map_err(|why| malformed(format!("{field} is not a valid NEAR account ID: {why}")))?;
        Ok(id)
    }

    fn option_u128(&mut self) -> Result<Option<u128>, SignerError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u128()?)),
            tag => Err(malformed(format!("invalid Option tag {tag}"))),
        }
    }

    fn public_key(&mut self) -> Result<PublicKey, SignerError> {
        match self.u8()? {
            0 => Ok(PublicKey::Ed25519(self.array()?)),
            1 => Ok(PublicKey::Secp256k1(self.array()?)),
            2 => Ok(PublicKey::MlDsa65(
                self.take(ML_DSA_65_PUBLIC_KEY_LEN)?.to_vec(),
            )),
            tag => Err(malformed(format!("unknown public key type {tag}"))),
        }
    }

    fn signature(&mut self) -> Result<Signature, SignerError> {
        match self.u8()? {
            0 => Ok(Signature::Ed25519(self.array()?)),
            1 => Ok(Signature::Secp256k1(self.array()?)),
            2 => Ok(Signature::MlDsa65(
                self.take(ML_DSA_65_SIGNATURE_LEN)?.to_vec(),
            )),
            tag => Err(malformed(format!("unknown signature type {tag}"))),
        }
    }

    /// `Vec<Action>`. Every action is at least one byte, so the loop is bounded
    /// by the input length whatever the count prefix says.
    fn actions(&mut self, allow_delegate: bool) -> Result<Vec<Action>, SignerError> {
        let count = self.u32()?;
        let mut actions = Vec::new();
        for _ in 0..count {
            actions.push(self.action(allow_delegate)?);
        }
        Ok(actions)
    }

    fn action(&mut self, allow_delegate: bool) -> Result<Action, SignerError> {
        Ok(match self.u8()? {
            0 => Action::CreateAccount,
            1 => Action::DeployContract {
                code: self.bytes()?,
            },
            2 => Action::FunctionCall {
                method_name: self.string("method_name")?,
                args: self.bytes()?,
                gas: self.u64()?,
                deposit: self.u128()?,
            },
            3 => Action::Transfer {
                deposit: self.u128()?,
            },
            4 => Action::Stake {
                stake: self.u128()?,
                public_key: self.public_key()?,
            },
            5 => {
                let public_key = self.public_key()?;
                let nonce = self.u64()?;
                let permission = match self.u8()? {
                    0 => AccessKeyPermission::FunctionCall {
                        allowance: self.option_u128()?,
                        receiver_id: self.string("receiver_id")?,
                        method_names: {
                            let count = self.u32()?;
                            let mut names = Vec::new();
                            for _ in 0..count {
                                names.push(self.string("method_names")?);
                            }
                            names
                        },
                    },
                    1 => AccessKeyPermission::FullAccess,
                    tag => return Err(malformed(format!("unknown access key permission {tag}"))),
                };
                Action::AddKey {
                    public_key,
                    nonce,
                    permission,
                }
            }
            6 => Action::DeleteKey {
                public_key: self.public_key()?,
            },
            7 => Action::DeleteAccount {
                beneficiary_id: self.account_id("beneficiary_id")?,
            },
            8 if allow_delegate => Action::Delegate(Box::new(SignedDelegateAction {
                delegate_action: self.delegate_action()?,
                signature: self.signature()?,
            })),
            8 => {
                return Err(malformed(
                    "a delegate action cannot contain another delegate action",
                ))
            }
            9 => Action::DeployGlobalContract {
                code: self.bytes()?,
                deploy_mode: match self.u8()? {
                    0 => GlobalContractDeployMode::CodeHash,
                    1 => GlobalContractDeployMode::AccountId,
                    tag => {
                        return Err(malformed(format!(
                            "unknown global contract deploy mode {tag}"
                        )))
                    }
                },
            },
            10 => Action::UseGlobalContract {
                contract_identifier: match self.u8()? {
                    0 => GlobalContractIdentifier::CodeHash(self.array()?),
                    1 => {
                        GlobalContractIdentifier::AccountId(self.account_id("contract_identifier")?)
                    }
                    tag => {
                        return Err(malformed(format!(
                            "unknown global contract identifier {tag}"
                        )))
                    }
                },
            },
            tag => return Err(malformed(format!("unknown action type {tag}"))),
        })
    }

    fn delegate_action(&mut self) -> Result<DelegateAction, SignerError> {
        Ok(DelegateAction {
            sender_id: self.account_id("sender_id")?,
            receiver_id: self.account_id("receiver_id")?,
            actions: self.actions(false)?,
            nonce: self.u64()?,
            max_block_height: self.u64()?,
            public_key: self.public_key()?,
        })
    }

    fn finish(&self) -> Result<(), SignerError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(malformed(format!(
                "{} trailing bytes after the value",
                self.buf.len() - self.pos
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors built with near-api-js 7.3.1 (`createTransaction` + `encodeTransaction`).
    // `EXPECTED_*` is the policy JSON derived from near-api-js's own
    // `deserialize(SCHEMA.Transaction, ...)`, not from this decoder.

    /// `alice.near` -> `ft.example.near`: storage_deposit, ft_transfer, transfer(10).
    const TX_TRANSFER_AND_CALL: &str = "0a000000616c6963652e6e65617200d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a07\
         000000000000000f00000066742e6578616d706c652e6e656172a0a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5\
         a6a7a8a9aaabacadaeaf03000000020f00000073746f726167655f6465706f7369741b0000007b226163636f756e745f\
         6964223a22616c6963652e6e656172227d00e057eb481b00000000485637193cc34300000000000000020b0000006674\
         5f7472616e73666572280000007b2272656365697665725f6964223a22626f622e6e656172222c22616d6f756e74223a\
         223432227d00e057eb481b000001000000000000000000000000000000030a000000000000000000000000000000";
    const EXPECTED_TRANSFER_AND_CALL: &str = r#"{"kind":"transaction","signer_id":"alice.near","public_key":"ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z","nonce":"7","receiver_id":"ft.example.near","block_hash":"Bp3BbhbyBNoTt3LgewDgCezdiUAWKxiWq18vdj3PVUiS","actions":[{"type":"function_call","method_name":"storage_deposit","args":"eyJhY2NvdW50X2lkIjoiYWxpY2UubmVhciJ9","gas":"30000000000000","deposit":"1250000000000000000000"},{"type":"function_call","method_name":"ft_transfer","args":"eyJyZWNlaXZlcl9pZCI6ImJvYi5uZWFyIiwiYW1vdW50IjoiNDIifQ==","gas":"30000000000000","deposit":"1"},{"type":"transfer","deposit":"10"}],"total_deposit":"1250000000000000000011"}"#;

    /// Every action type near-api-js 7.3.1 can encode (create_account through
    /// use_global_contract, including a signed delegate action and a secp256k1
    /// key). A `u128::MAX - 1` transfer plus the delegate's 1-yocto deposit make
    /// the total exactly `u128::MAX`.
    const TX_ALL_ACTIONS: &str = "400000006437356139383031383262313061623764353462666564336339363430373361306565313732663364616136\
         323332356166303231613638663730373531316100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a\
         68f707511a79df0d86487000000e0000007375622e616c6963652e6e656172a0a1a2a3a4a5a6a7a8a9aaabacadaeafa0\
         a1a2a3a4a5a6a7a8a9aaabacadaeaf0e0000000001080000000061736d0100000002030000006e657704000000deadbe\
         ef01000000000000000000000000000000000000000000000003feffffffffffffffffffffffffffffff04e803000000\
         000000000000000000000000d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a05010102\
         030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132\
         333435363738393a3b3c3d3e3f4000000000000000000105000707070707070707070707070707070707070707070707\
         07070707070707070700000000000000000000080000006170702e6e6561720000000006000707070707070707070707\
         070707070707070707070707070707070707070707071000000062656e65666963696172792e6e656172084000000064\
         373561393830313832623130616237643534626665643363393634303733613065653137326633646161363233323561\
         6630323161363866373037353131610f00000066742e6578616d706c652e6e65617201000000020b00000066745f7472\
         616e736665723a0000007b2272656365697665725f6964223a226d65726368616e742e6578616d706c652e6e65617222\
         2c22616d6f756e74223a2231303030303030227d00e057eb481b0000010000000000000000000000000000002a000000\
         0000000000e1f5050000000000d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a00b01b\
         4df30474223b0892e3bc1fe7b8fb9362b8783e89017be2e9a4bbc88d9c9054e6f33067c97fc2de71602b54844990cc72\
         c382a23b1a5e0a1390b9b72c4200090300000001020300090100000004010a0011111111111111111111111111111111\
         111111111111111111111111111111110a010b000000676c6f62616c2e6e656172";
    const EXPECTED_ALL_ACTIONS: &str = r#"{"kind":"transaction","signer_id":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","public_key":"ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z","nonce":"123456789012345","receiver_id":"sub.alice.near","block_hash":"Bp3BbhbyBNoTt3LgewDgCezdiUAWKxiWq18vdj3PVUiS","actions":[{"type":"create_account"},{"type":"deploy_contract","code_hash":"AwLEfgaHQguPVVLGUV9Sf5QKGrMMMr2N6MVSjBj9dJAh","code_len":8},{"type":"function_call","method_name":"new","args":"3q2+7w==","gas":"1","deposit":"0"},{"type":"transfer","deposit":"340282366920938463463374607431768211454"},{"type":"stake","stake":"1000","public_key":"ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"},{"type":"add_key","public_key":"secp256k1:2Ana1pUpv2ZbMVkwF5FXapYeBEjdxDatLn7nvJkhgTSXbs59SyZSx866bXirPgj8QQVB57uxHJBG1YFvkRbFj4T","access_key":{"nonce":"0","permission":{"type":"full_access"}}},{"type":"add_key","public_key":"ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx","access_key":{"nonce":"0","permission":{"type":"function_call","allowance":null,"receiver_id":"app.near","method_names":[]}}},{"type":"delete_key","public_key":"ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx"},{"type":"delete_account","beneficiary_id":"beneficiary.near"},{"type":"delegate","delegate_action":{"sender_id":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","receiver_id":"ft.example.near","actions":[{"type":"function_call","method_name":"ft_transfer","args":"eyJyZWNlaXZlcl9pZCI6Im1lcmNoYW50LmV4YW1wbGUubmVhciIsImFtb3VudCI6IjEwMDAwMDAifQ==","gas":"30000000000000","deposit":"1"}],"nonce":"42","max_block_height":"100000000","public_key":"ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"},"signature":"ed25519:4XDRtxVr4CbfZBC5CmD3xY8B4LyK8BpJ2bGRqzcghpxtC5gtT1zBNU1kvL1u5ko9PxHVjVKyjHtBBGFtsH4VQiEK"},{"type":"deploy_global_contract","code_hash":"EutHBsdT1YCzHxjCfQHnLPL1vFrkSyLSio4vkphfnEk","code_len":3,"deploy_mode":"code_hash"},{"type":"deploy_global_contract","code_hash":"GRchfHguxbWYGGLHZfpSFo3SnPVbxmyh6FnR1ThKqfqS","code_len":1,"deploy_mode":"account_id"},{"type":"use_global_contract","contract_identifier":{"code_hash":"29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2"}},{"type":"use_global_contract","contract_identifier":{"account_id":"global.near"}}],"total_deposit":"340282366920938463463374607431768211455"}"#;

    fn decode_hex(hex_str: &str) -> Result<Transaction, SignerError> {
        Transaction::from_borsh(&hex::decode(hex_str).unwrap())
    }

    #[test]
    fn decodes_near_api_js_transactions() {
        for (tx_hex, expected) in [
            (TX_TRANSFER_AND_CALL, EXPECTED_TRANSFER_AND_CALL),
            (TX_ALL_ACTIONS, EXPECTED_ALL_ACTIONS),
        ] {
            let tx = decode_hex(tx_hex).unwrap();
            let expected: Value = serde_json::from_str(expected).unwrap();
            assert_eq!(tx.to_json().unwrap(), expected);
        }
    }

    #[test]
    fn decoded_fields_are_typed() {
        let tx = decode_hex(TX_TRANSFER_AND_CALL).unwrap();
        assert_eq!(tx.signer_id, "alice.near");
        assert_eq!(tx.receiver_id, "ft.example.near");
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.actions.len(), 3);
        assert_eq!(
            tx.actions[1],
            Action::FunctionCall {
                method_name: "ft_transfer".into(),
                args: br#"{"receiver_id":"bob.near","amount":"42"}"#.to_vec(),
                gas: 30_000_000_000_000,
                deposit: 1,
            }
        );
        assert_eq!(tx.total_deposit().unwrap(), 1_250_000_000_000_000_000_011);

        let all = decode_hex(TX_ALL_ACTIONS).unwrap();
        let types: Vec<&str> = all.actions.iter().map(Action::type_name).collect();
        assert_eq!(
            types,
            [
                "create_account",
                "deploy_contract",
                "function_call",
                "transfer",
                "stake",
                "add_key",
                "add_key",
                "delete_key",
                "delete_account",
                "delegate",
                "deploy_global_contract",
                "deploy_global_contract",
                "use_global_contract",
                "use_global_contract",
            ]
        );
        // Every type the decoder can produce is listed in ACTION_TYPES.
        for ty in &types {
            assert!(ACTION_TYPES.contains(ty));
        }
        assert_eq!(ACTION_TYPES.len(), 11);
    }

    /// near-api-js 7.3.1 `KeyPairSigner.signTransaction` of `TX_TRANSFER_AND_CALL`
    /// with the RFC 8032 vector 1 key.
    const TX_TRANSFER_AND_CALL_SIGNATURE: &str = "c0b4334753921bab761842bea9f215a02926612c5e8b67f81488f3f9e2f9f2b74d91502cbf98cba7095aa682e8a8059f1e5a3170c11798ce71caf50329dc570b";

    #[test]
    fn near_signer_matches_near_api_js_and_builds_policy_context() {
        use crate::traits::ChainSigner;
        let signer = crate::chains::NearSigner;
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let tx = hex::decode(TX_TRANSFER_AND_CALL).unwrap();

        let out = signer.sign_transaction(&seed, &tx).unwrap();
        assert_eq!(hex::encode(&out.signature), TX_TRANSFER_AND_CALL_SIGNATURE);
        let signed = signer.encode_signed_transaction(&tx, &out).unwrap();
        assert_eq!(
            hex::encode(signed),
            format!("{TX_TRANSFER_AND_CALL}00{TX_TRANSFER_AND_CALL_SIGNATURE}")
        );

        let ctx = signer.make_transaction_context(&tx, None).unwrap();
        assert!(ctx.effects.is_empty());
        assert_eq!(ctx.raw_hex, TX_TRANSFER_AND_CALL);
        assert!(ctx.data.is_none());
        let expected: Value = serde_json::from_str(EXPECTED_TRANSFER_AND_CALL).unwrap();
        assert_eq!(ctx.chain_extra, Some(expected));
        assert!(!signer.transaction_context_needs_rpc());

        // Bytes that are not a NEAR transaction get no context, so an API token cannot sign them.
        assert!(signer.make_transaction_context(&[0x42; 80], None).is_err());
    }

    // ----- synthetic edge cases -----

    fn put_str(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u32).to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    }

    fn ed25519_key(out: &mut Vec<u8>) {
        out.push(0);
        out.extend_from_slice(&[0xd7; 32]);
    }

    /// `borsh(Transaction)` from `alice.near` to `bob.near` with raw action bytes.
    fn tx_bytes(actions: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        put_str(&mut out, "alice.near");
        ed25519_key(&mut out);
        out.extend_from_slice(&1u64.to_le_bytes());
        put_str(&mut out, "bob.near");
        out.extend_from_slice(&[0xaa; 32]);
        out.extend_from_slice(&(actions.len() as u32).to_le_bytes());
        for action in actions {
            out.extend_from_slice(action);
        }
        out
    }

    fn transfer(deposit: u128) -> Vec<u8> {
        let mut out = vec![3];
        out.extend_from_slice(&deposit.to_le_bytes());
        out
    }

    /// A signed delegate action whose own actions are `inner`.
    fn delegate(inner: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![8];
        put_str(&mut out, "alice.near");
        put_str(&mut out, "bob.near");
        out.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        for action in inner {
            out.extend_from_slice(action);
        }
        out.extend_from_slice(&5u64.to_le_bytes());
        out.extend_from_slice(&9u64.to_le_bytes());
        ed25519_key(&mut out);
        out.push(0);
        out.extend_from_slice(&[0x11; 64]);
        out
    }

    fn err_text(bytes: &[u8]) -> String {
        match Transaction::from_borsh(bytes) {
            Err(SignerError::InvalidTransaction(msg)) => msg,
            other => panic!("expected InvalidTransaction, got {other:?}"),
        }
    }

    #[test]
    fn empty_action_list_decodes() {
        let tx = Transaction::from_borsh(&tx_bytes(&[])).unwrap();
        assert!(tx.actions.is_empty());
        assert_eq!(tx.to_json().unwrap()["total_deposit"], "0");
    }

    #[test]
    fn rejects_empty_and_truncated_input() {
        assert!(err_text(&[]).contains("unexpected end of input"));
        let full = tx_bytes(&[transfer(5)]);
        for len in 0..full.len() {
            assert!(
                Transaction::from_borsh(&full[..len]).is_err(),
                "a {len}-byte prefix must not decode"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = tx_bytes(&[transfer(5)]);
        bytes.push(0);
        assert!(err_text(&bytes).contains("1 trailing bytes"));
    }

    #[test]
    fn rejects_unknown_action_type() {
        assert!(err_text(&tx_bytes(&[vec![11]])).contains("unknown action type 11"));
    }

    #[test]
    fn rejects_unknown_key_signature_and_enum_tags() {
        // Public key type 3 in a delete_key action.
        assert!(err_text(&tx_bytes(&[vec![6, 3]])).contains("unknown public key type 3"));
        // Access key permission 2.
        let mut add_key = vec![5];
        ed25519_key(&mut add_key);
        add_key.extend_from_slice(&0u64.to_le_bytes());
        add_key.push(2);
        assert!(err_text(&tx_bytes(&[add_key])).contains("unknown access key permission 2"));
        // Option tag 2 for a function-call allowance.
        let mut fc_key = vec![5];
        ed25519_key(&mut fc_key);
        fc_key.extend_from_slice(&0u64.to_le_bytes());
        fc_key.extend_from_slice(&[0, 2]);
        assert!(err_text(&tx_bytes(&[fc_key])).contains("invalid Option tag 2"));
        // Global contract deploy mode 2 and identifier 2.
        let mut deploy = vec![9];
        deploy.extend_from_slice(&0u32.to_le_bytes());
        deploy.push(2);
        assert!(err_text(&tx_bytes(&[deploy])).contains("deploy mode 2"));
        assert!(err_text(&tx_bytes(&[vec![10, 2]])).contains("contract identifier 2"));
        // Signature type 3 on a delegate action.
        let mut bad_sig = delegate(&[transfer(1)]);
        let n = bad_sig.len();
        bad_sig.truncate(n - 65);
        bad_sig.push(3);
        assert!(err_text(&tx_bytes(&[bad_sig])).contains("unknown signature type 3"));
    }

    #[test]
    fn rejects_invalid_utf8_account_id() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&[0xff, 0xfe]);
        assert!(err_text(&bytes).contains("signer_id is not UTF-8"));
    }

    /// `borsh(Transaction)` with the given signer and receiver and no actions.
    fn tx_between(signer: &str, receiver: &str) -> Vec<u8> {
        let mut out = Vec::new();
        put_str(&mut out, signer);
        ed25519_key(&mut out);
        out.extend_from_slice(&1u64.to_le_bytes());
        put_str(&mut out, receiver);
        out.extend_from_slice(&[0xaa; 32]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    #[test]
    fn validates_account_ids() {
        let implicit = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        for ok in [
            "ab",
            "alice.near",
            "a-b_c.d1",
            "0x1234567890abcdef1234567890abcdef12345678",
            implicit,
        ] {
            assert!(
                Transaction::from_borsh(&tx_between(ok, "bob.near")).is_ok(),
                "{ok}"
            );
        }
        let too_long = "a".repeat(65);
        for bad in [
            "a",
            "",
            too_long.as_str(),
            "Alice.near",
            "alice..near",
            ".alice",
            "alice.",
            "alice-.near",
            "al ice",
            "alice@near",
            "ali\u{e7}e",
        ] {
            let msg = err_text(&tx_between("alice.near", bad));
            assert!(
                msg.contains("receiver_id is not a valid NEAR account ID"),
                "{bad:?}: {msg}"
            );
        }
        assert!(err_text(&tx_between("A.near", "bob.near")).contains("signer_id"));
        // DeleteAccount beneficiary and UseGlobalContract account are account IDs too.
        let mut delete = vec![7];
        put_str(&mut delete, "Bad");
        assert!(err_text(&tx_bytes(&[delete])).contains("beneficiary_id"));
        let mut use_global = vec![10, 1];
        put_str(&mut use_global, "x");
        assert!(err_text(&tx_bytes(&[use_global])).contains("contract_identifier"));
    }

    #[test]
    fn a_v1_shaped_prefix_is_not_decoded_as_v0() {
        // nearcore reads bytes whose second byte is non-zero as a TransactionV1.
        // A V0 signer ID that long (>= 256 bytes) is not a valid account ID, so the
        // two readers cannot disagree on which transaction the bytes are.
        let long_signer = "a".repeat(257);
        let bytes = tx_between(&long_signer, "bob.near");
        assert_ne!(bytes[1], 0);
        assert!(err_text(&bytes).contains("signer_id is not a valid NEAR account ID"));
    }

    #[test]
    fn rejects_nested_delegate_action() {
        // nearcore forbids a delegate action inside a delegate action.
        let nested = delegate(&[delegate(&[transfer(1)])]);
        assert!(err_text(&tx_bytes(&[nested])).contains("cannot contain another delegate"));
    }

    #[test]
    fn relayed_delegate_deposits_count_toward_the_total() {
        // nearcore `total_deposit`: the relayer prepays a delegate's inner deposits.
        let tx = Transaction::from_borsh(&tx_bytes(&[transfer(7), delegate(&[transfer(1_000)])]))
            .unwrap();
        assert_eq!(tx.total_deposit().unwrap(), 1_007);
        let json = tx.to_json().unwrap();
        assert_eq!(json["total_deposit"], "1007");
        assert_eq!(
            json["actions"][1]["delegate_action"]["actions"][0]["deposit"],
            "1000"
        );
        // ...including when the sum only overflows through the delegate.
        let overflow =
            Transaction::from_borsh(&tx_bytes(&[transfer(u128::MAX), delegate(&[transfer(1)])]))
                .unwrap();
        assert!(overflow.total_deposit().is_err());
    }

    #[test]
    fn total_deposit_overflow_is_an_error() {
        let tx = Transaction::from_borsh(&tx_bytes(&[transfer(u128::MAX), transfer(1)])).unwrap();
        assert!(tx.total_deposit().is_err());
        assert!(tx.to_json().is_err());
    }

    #[test]
    fn huge_length_prefix_does_not_allocate() {
        // A u32::MAX string length must fail on bounds, not try to allocate 4 GiB.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(err_text(&bytes).contains("unexpected end of input"));
        // A u32::MAX action count with no actions behind it.
        let mut many = tx_bytes(&[]);
        let n = many.len();
        many[n - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(err_text(&many).contains("unexpected end of input"));
    }

    #[test]
    fn decodes_ml_dsa_65_signatures() {
        // A relayed delegate action signed with a 3309-byte ML-DSA-65 signature.
        let mut relayed = delegate(&[transfer(1)]);
        let n = relayed.len();
        relayed.truncate(n - 65);
        relayed.push(2);
        relayed.extend_from_slice(&[0x6b; 3309]);
        let tx = Transaction::from_borsh(&tx_bytes(&[relayed])).unwrap();
        let signature = tx.to_json().unwrap()["actions"][0]["signature"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(signature.starts_with("ml-dsa-65:"));
        assert_eq!(
            bs58::decode(&signature["ml-dsa-65:".len()..])
                .into_vec()
                .unwrap()
                .len(),
            3309
        );
    }

    #[test]
    fn decodes_ml_dsa_65_keys() {
        // near-api-js 7.x key type 2: 1952-byte ML-DSA-65 public key (literal, not
        // the constant, so a wrong constant fails here).
        let mut delete_key = vec![6, 2];
        delete_key.extend_from_slice(&[0x5a; 1952]);
        let tx = Transaction::from_borsh(&tx_bytes(&[delete_key])).unwrap();
        let key = tx.to_json().unwrap()["actions"][0]["public_key"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(key.starts_with("ml-dsa-65:"));
        assert_eq!(
            bs58::decode(&key["ml-dsa-65:".len()..]).into_vec().unwrap(),
            vec![0x5a; 1952]
        );
    }

    // ----- NEP-366 delegate actions -----

    /// near-api-js 7.3.1 `buildDelegateAction` + `KeyPairSigner.signDelegateAction`
    /// with the RFC 8032 vector 1 key. `expected` is derived from near-api-js's own
    /// `deserialize(SCHEMA.DelegateAction, ...)`.
    struct DelegateVector {
        delegate_action_hex: &'static str,
        hash_hex: &'static str,
        signature_hex: &'static str,
        expected: &'static str,
    }

    const DELEGATE_VECTORS: &[DelegateVector] = &[
        // implicit account -> ft.example.near: ft_transfer with 1 yoctoNEAR.
        DelegateVector {
            delegate_action_hex: "400000006437356139383031383262313061623764353462666564336339363430373361306565313732663364616136\
         32333235616630323161363866373037353131610f00000066742e6578616d706c652e6e65617201000000020b000000\
         66745f7472616e736665723a0000007b2272656365697665725f6964223a226d65726368616e742e6578616d706c652e\
         6e656172222c22616d6f756e74223a2231303030303030227d00e057eb481b0000010000000000000000000000000000\
         002a0000000000000000e1f5050000000000d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707\
         511a",
            hash_hex: "cb7d799ec8512d99f74a285153a8e5041ed7bb36975d144359ba9fb88c6d2345",
            signature_hex: "b01b4df30474223b0892e3bc1fe7b8fb9362b8783e89017be2e9a4bbc88d9c9054e6f33067c97fc2de71602b54844990cc72c382a23b1a5e0a1390b9b72c4200",
            expected: r#"{"sender_id":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","receiver_id":"ft.example.near","actions":[{"type":"function_call","method_name":"ft_transfer","args":"eyJyZWNlaXZlcl9pZCI6Im1lcmNoYW50LmV4YW1wbGUubmVhciIsImFtb3VudCI6IjEwMDAwMDAifQ==","gas":"30000000000000","deposit":"1"}],"nonce":"42","max_block_height":"100000000","public_key":"ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z","kind":"delegate_action","total_deposit":"1"}"#,
        },
        // agent.example.near -> escrow.example.near: transfer(1 NEAR),
        // ft_transfer_call and a function-call access key; u64::MAX nonce.
        DelegateVector {
            delegate_action_hex: "120000006167656e742e6578616d706c652e6e65617213000000657363726f772e6578616d706c652e6e656172030000\
         0003000000a1edccce1bc2d3000000000000021000000066745f7472616e736665725f63616c6c3b0000007b22726563\
         65697665725f6964223a22657363726f772e6578616d706c652e6e656172222c22616d6f756e74223a2235222c226d73\
         67223a22227d00203d88792d000001000000000000000000000000000000050007070707070707070707070707070707\
         0707070707070707070707070707070700000000000000000001000040683bb3f386f034000000000000130000006573\
         63726f772e6578616d706c652e6e6561720200000005000000636c61696d06000000726566756e64ffffffffffffffff\
         010000000000000000d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            hash_hex: "dff5ebbff1264f9ad4b20656e2cbb1053c0bcc6b0736cc54fa4ccf72e21a9df2",
            signature_hex: "aa2272bbd8b8169ddeccf62735c11f69e87c66d14ad30702c9cf4692c793a2cb29fe8e9d8557847ccc2296eb1ce5827e67162b0eba997ceefb62fd53c0025f0b",
            expected: r#"{"sender_id":"agent.example.near","receiver_id":"escrow.example.near","actions":[{"type":"transfer","deposit":"1000000000000000000000000"},{"type":"function_call","method_name":"ft_transfer_call","args":"eyJyZWNlaXZlcl9pZCI6ImVzY3Jvdy5leGFtcGxlLm5lYXIiLCJhbW91bnQiOiI1IiwibXNnIjoiIn0=","gas":"50000000000000","deposit":"1"},{"type":"add_key","public_key":"ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx","access_key":{"nonce":"0","permission":{"type":"function_call","allowance":"250000000000000000000000","receiver_id":"escrow.example.near","method_names":["claim","refund"]}}}],"nonce":"18446744073709551615","max_block_height":"1","public_key":"ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z","kind":"delegate_action","total_deposit":"1000000000000000000000001"}"#,
        },
    ];

    fn rfc_seed() -> Vec<u8> {
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap()
    }

    #[test]
    fn nep366_prefix_value() {
        assert_eq!(crate::chains::near::NEP366_PREFIX, 1_073_742_190);
        assert_eq!(
            crate::chains::near::NEP366_PREFIX.to_le_bytes(),
            [0x6e, 0x01, 0x00, 0x40]
        );
    }

    #[test]
    fn delegate_actions_match_near_api_js() {
        use crate::chains::near::{delegate_action_hash, NearSigner};
        for v in DELEGATE_VECTORS {
            let bytes = hex::decode(v.delegate_action_hex).unwrap();
            let decoded = DelegateAction::from_borsh(&bytes).unwrap();
            let expected: Value = serde_json::from_str(v.expected).unwrap();
            assert_eq!(decoded.to_json().unwrap(), expected);

            assert_eq!(hex::encode(delegate_action_hash(&bytes)), v.hash_hex);
            let out = NearSigner
                .sign_delegate_action(&rfc_seed(), &bytes)
                .unwrap();
            assert_eq!(hex::encode(&out.signature), v.signature_hex);
        }
    }

    #[test]
    fn sign_delegate_action_requires_the_signing_key() {
        use crate::chains::near::NearSigner;
        let bytes = hex::decode(DELEGATE_VECTORS[0].delegate_action_hex).unwrap();
        // Any other key: the delegate names the RFC 8032 key, so it could never be relayed.
        let err = NearSigner
            .sign_delegate_action(&[0x01; 32], &bytes)
            .unwrap_err();
        assert!(
            matches!(&err, SignerError::InvalidTransaction(m) if m.contains("is not the signing key")),
            "{err}"
        );
        // A secp256k1 public_key in the delegate never matches an Ed25519 key.
        let mut secp = bytes[..bytes.len() - 33].to_vec();
        secp.push(1);
        secp.extend_from_slice(&[0x02; 64]);
        assert!(DelegateAction::from_borsh(&secp).is_ok());
        assert!(NearSigner.sign_delegate_action(&rfc_seed(), &secp).is_err());
        // Invalid key length.
        assert!(NearSigner
            .sign_delegate_action(&[0x01; 31], &bytes)
            .is_err());
    }

    #[test]
    fn sign_delegate_action_rejects_malformed_input() {
        use crate::chains::near::NearSigner;
        let bytes = hex::decode(DELEGATE_VECTORS[0].delegate_action_hex).unwrap();
        // Already prefixed: the prefix is added by the signer, not the caller.
        let mut prefixed = crate::chains::near::NEP366_PREFIX.to_le_bytes().to_vec();
        prefixed.extend_from_slice(&bytes);
        assert!(NearSigner
            .sign_delegate_action(&rfc_seed(), &prefixed)
            .is_err());
        // Trailing bytes and truncation.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DelegateAction::from_borsh(&trailing).is_err());
        assert!(DelegateAction::from_borsh(&bytes[..bytes.len() - 1]).is_err());
        assert!(DelegateAction::from_borsh(&[]).is_err());
        // A transaction is not a delegate action.
        let tx = hex::decode(TX_TRANSFER_AND_CALL).unwrap();
        assert!(NearSigner.sign_delegate_action(&rfc_seed(), &tx).is_err());
    }

    #[test]
    fn delegate_action_rejects_nested_delegate() {
        // `delegate(..)` minus its action tag is a SignedDelegateAction; strip the
        // signature to get a DelegateAction whose single action is a delegate.
        let mut inner = delegate(&[delegate(&[transfer(1)])]);
        inner.remove(0);
        inner.truncate(inner.len() - 65);
        let err = DelegateAction::from_borsh(&inner).unwrap_err();
        assert!(
            err.to_string().contains("cannot contain another delegate"),
            "{err}"
        );
    }

    #[test]
    fn delegate_action_json_counts_its_own_deposits() {
        let mut da = delegate(&[transfer(7), transfer(5)]);
        da.remove(0);
        da.truncate(da.len() - 65);
        let decoded = DelegateAction::from_borsh(&da).unwrap();
        assert_eq!(decoded.total_deposit().unwrap(), 12);
        let json = decoded.to_json().unwrap();
        assert_eq!(json["kind"], "delegate_action");
        assert_eq!(json["total_deposit"], "12");
        assert_eq!(json["sender_id"], "alice.near");
        assert_eq!(json["receiver_id"], "bob.near");
    }
}
