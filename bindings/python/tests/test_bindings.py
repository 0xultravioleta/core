"""Tests for ows Python bindings."""

import copy
import json
import tempfile
import pytest
import ows


@pytest.fixture
def vault_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_generate_mnemonic_12():
    phrase = ows.generate_mnemonic(12)
    assert len(phrase.split()) == 12


def test_generate_mnemonic_24():
    phrase = ows.generate_mnemonic(24)
    assert len(phrase.split()) == 24


def test_derive_address_evm():
    phrase = ows.generate_mnemonic(12)
    # "evm" still works via backward compat
    address = ows.derive_address(phrase, "evm")
    assert address.startswith("0x")
    assert len(address) == 42


def test_derive_address_ethereum():
    phrase = ows.generate_mnemonic(12)
    address = ows.derive_address(phrase, "ethereum")
    assert address.startswith("0x")
    assert len(address) == 42


def test_derive_address_all_supported_chains():
    phrase = ows.generate_mnemonic(12)
    for chain in ["evm", "solana", "sui", "bitcoin", "cosmos", "tron", "ton", "filecoin", "xrpl", "nano", "near", "cardano"]:
        address = ows.derive_address(phrase, chain)
        assert len(address) > 0


def test_create_and_list_wallets(vault_dir):
    wallet = ows.create_wallet("test-wallet", vault_path_opt=vault_dir)
    assert wallet["name"] == "test-wallet"
    assert isinstance(wallet["accounts"], list)
    assert len(wallet["accounts"]) == 16

    # Verify each chain family is present
    chain_ids = [a["chain_id"] for a in wallet["accounts"]]
    assert any(c.startswith("eip155:") for c in chain_ids)
    assert any(c.startswith("solana:") for c in chain_ids)
    assert any(c.startswith("sui:") for c in chain_ids)
    assert any(c.startswith("bip122:") for c in chain_ids)
    assert any(c.startswith("cosmos:") for c in chain_ids)
    assert any(c.startswith("tron:") for c in chain_ids)
    assert any(c.startswith("ton:") for c in chain_ids)
    assert any(c.startswith("spark:") for c in chain_ids)
    assert any(c.startswith("fil:") for c in chain_ids)
    assert any(c.startswith("xrpl:") for c in chain_ids)
    assert any(c.startswith("nano:") for c in chain_ids)
    assert any(c.startswith("near:") for c in chain_ids)
    assert any(c.startswith("cip34:") for c in chain_ids)

    wallets = ows.list_wallets(vault_path_opt=vault_dir)
    assert len(wallets) == 1
    assert wallets[0]["id"] == wallet["id"]


def test_get_wallet(vault_dir):
    wallet = ows.create_wallet("lookup", vault_path_opt=vault_dir)

    found = ows.get_wallet("lookup", vault_path_opt=vault_dir)
    assert found["id"] == wallet["id"]

    found = ows.get_wallet(wallet["id"], vault_path_opt=vault_dir)
    assert found["name"] == "lookup"


def test_rename_wallet(vault_dir):
    ows.create_wallet("old-name", vault_path_opt=vault_dir)
    ows.rename_wallet("old-name", "new-name", vault_path_opt=vault_dir)

    found = ows.get_wallet("new-name", vault_path_opt=vault_dir)
    assert found["name"] == "new-name"


def test_export_wallet(vault_dir):
    ows.create_wallet("exportable", vault_path_opt=vault_dir)
    secret = ows.export_wallet("exportable", vault_path_opt=vault_dir)
    assert len(secret.split()) == 12


def test_delete_wallet(vault_dir):
    wallet = ows.create_wallet("deletable", vault_path_opt=vault_dir)
    ows.delete_wallet("deletable", vault_path_opt=vault_dir)

    wallets = ows.list_wallets(vault_path_opt=vault_dir)
    assert len(wallets) == 0


def test_import_wallet_mnemonic(vault_dir):
    phrase = ows.generate_mnemonic(12)
    expected_addr = ows.derive_address(phrase, "ethereum")

    wallet = ows.import_wallet_mnemonic(
        "imported", phrase, vault_path_opt=vault_dir
    )
    assert wallet["name"] == "imported"
    assert len(wallet["accounts"]) == 16

    # EVM account should match derived address
    evm_account = next(a for a in wallet["accounts"] if a["chain_id"].startswith("eip155:"))
    assert evm_account["address"] == expected_addr


def test_sign_transaction(vault_dir):
    ows.create_wallet("signer", vault_path_opt=vault_dir)

    tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    result = ows.sign_transaction(
        "signer", "evm", tx_hex, vault_path_opt=vault_dir
    )
    assert len(result["signature"]) > 0
    assert result["recovery_id"] is not None


def test_sign_message(vault_dir):
    ows.create_wallet("msg-signer", vault_path_opt=vault_dir)

    result = ows.sign_message(
        "msg-signer", "evm", "hello world", vault_path_opt=vault_dir
    )
    assert len(result["signature"]) > 0


def test_sign_hash_and_authorization_owner_mode(vault_dir):
    wallet = ows.create_wallet("hash-owner", vault_path_opt=vault_dir)

    hash_result = ows.sign_hash(
        wallet["id"], "base", "11" * 32, vault_path_opt=vault_dir
    )
    assert len(hash_result["signature"]) > 0
    assert hash_result["recovery_id"] in (0, 1)

    auth_result = ows.sign_authorization(
        wallet["id"],
        "base",
        "0x1111111111111111111111111111111111111111",
        "7",
        vault_path_opt=vault_dir,
    )
    assert len(auth_result["signature"]) > 0
    assert auth_result["recovery_id"] in (0, 1)


def test_sign_hash_and_authorization_api_key_mode(vault_dir):
    wallet = ows.create_wallet("hash-agent", vault_path_opt=vault_dir)

    ows.create_policy(
        """{
          "id": "base-only-hash",
          "name": "Base Only Hash",
          "version": 1,
          "created_at": "2026-03-22T00:00:00Z",
          "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453"]}
          ],
          "action": "deny"
        }""",
        vault_path_opt=vault_dir,
    )

    key = ows.create_api_key(
        "hash-agent-key",
        [wallet["id"]],
        ["base-only-hash"],
        "",
        vault_path_opt=vault_dir,
    )

    hash_result = ows.sign_hash(
        wallet["id"], "base", "22" * 32, key["token"], vault_path_opt=vault_dir
    )
    assert len(hash_result["signature"]) > 0

    auth_result = ows.sign_authorization(
        wallet["id"],
        "base",
        "0x1111111111111111111111111111111111111111",
        "7",
        key["token"],
        vault_path_opt=vault_dir,
    )
    assert len(auth_result["signature"]) > 0

    with pytest.raises(RuntimeError, match="not in allowlist"):
        ows.sign_authorization(
            wallet["id"],
            "ethereum",
            "0x1111111111111111111111111111111111111111",
            "7",
            key["token"],
            vault_path_opt=vault_dir,
        )


def test_sign_typed_data_with_api_key(vault_dir):
    wallet = ows.create_wallet("td-api-test", vault_path_opt=vault_dir)

    # Register a policy allowing Base chains
    ows.create_policy(json.dumps({
        "id": "td-base-only",
        "name": "Base Only",
        "version": 1,
        "created_at": "2026-03-22T00:00:00Z",
        "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"]},
        ],
        "action": "deny",
    }), vault_path_opt=vault_dir)

    # Create API key bound to the wallet and policy
    key = ows.create_api_key(
        "td-agent", [wallet["id"]], ["td-base-only"], "",
        vault_path_opt=vault_dir,
    )
    assert key["token"].startswith("ows_key_")

    # EIP-712 typed data (the standard "Mail" example)
    typed_data_json = json.dumps({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"},
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"},
            ],
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 8453,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!",
        },
    })

    # Sign on allowed chain -- should succeed
    result = ows.sign_typed_data(
        wallet["id"], "base", typed_data_json,
        passphrase=key["token"], vault_path_opt=vault_dir,
    )
    assert len(result["signature"]) > 0
    assert result["recovery_id"] is not None

    # Sign on denied chain -- should fail
    # Build typed data with chainId=1 matching ethereum so the domain check passes
    # and AllowedChains (base-only) correctly denies
    eth_td = copy.deepcopy(json.loads(typed_data_json))
    eth_td["domain"]["chainId"] = 1
    eth_typed_data_json = json.dumps(eth_td)
    with pytest.raises(Exception, match="not in allowlist"):
        ows.sign_typed_data(
            wallet["id"], "ethereum", eth_typed_data_json,
            passphrase=key["token"], vault_path_opt=vault_dir,
        )

    # Cleanup
    ows.revoke_api_key(key["id"], vault_path_opt=vault_dir)
    ows.delete_policy("td-base-only", vault_path_opt=vault_dir)
    ows.delete_wallet(wallet["id"], vault_path_opt=vault_dir)


def test_sign_typed_data_respects_allowed_typed_data_contracts(vault_dir):
    wallet = ows.create_wallet("td-contract-test", vault_path_opt=vault_dir)

    ows.create_policy(json.dumps({
        "id": "td-contract-only",
        "name": "Typed Data Contract Only",
        "version": 1,
        "created_at": "2026-03-22T00:00:00Z",
        "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453"]},
            {
                "type": "allowed_typed_data_contracts",
                "contracts": ["0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"],
            },
        ],
        "action": "deny",
    }), vault_path_opt=vault_dir)

    key = ows.create_api_key(
        "td-contract-agent",
        [wallet["id"]],
        ["td-contract-only"],
        "",
        vault_path_opt=vault_dir,
    )

    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Mail": [{"name": "contents", "type": "string"}],
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 8453,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        },
        "message": {
            "contents": "Hello, Bob!",
        },
    }

    allowed = ows.sign_typed_data(
        wallet["id"],
        "base",
        json.dumps(typed_data),
        passphrase=key["token"],
        vault_path_opt=vault_dir,
    )
    assert len(allowed["signature"]) > 0

    denied_typed_data = copy.deepcopy(typed_data)
    denied_typed_data["domain"]["verifyingContract"] = "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC"

    with pytest.raises(Exception, match="not in allowed list"):
        ows.sign_typed_data(
            wallet["id"],
            "base",
            json.dumps(denied_typed_data),
            passphrase=key["token"],
            vault_path_opt=vault_dir,
        )

    ows.revoke_api_key(key["id"], vault_path_opt=vault_dir)
    ows.delete_policy("td-contract-only", vault_path_opt=vault_dir)
    ows.delete_wallet(wallet["id"], vault_path_opt=vault_dir)


# near-api-js 7.3.1 transaction (alice.near -> ft.example.near: storage_deposit,
# ft_transfer, transfer(10)) and its signature with the RFC 8032 vector 1 key.
NEAR_LIMITS_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
NEAR_LIMITS_TX = "0a000000616c6963652e6e65617200d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a07000000000000000f00000066742e6578616d706c652e6e656172a0a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5a6a7a8a9aaabacadaeaf03000000020f00000073746f726167655f6465706f7369741b0000007b226163636f756e745f6964223a22616c6963652e6e656172227d00e057eb481b00000000485637193cc34300000000000000020b00000066745f7472616e73666572280000007b2272656365697665725f6964223a22626f622e6e656172222c22616d6f756e74223a223432227d00e057eb481b000001000000000000000000000000000000030a000000000000000000000000000000"
NEAR_LIMITS_c0b4334753921bab761842bea9f215a02926612c5e8b67f81488f3f9e2f9f2b74d91502cbf98cba7095aa682e8a8059f1e5a3170c11798ce71caf50329dc570b = "c0b4334753921bab761842bea9f215a02926612c5e8b67f81488f3f9e2f9f2b74d91502cbf98cba7095aa682e8a8059f1e5a3170c11798ce71caf50329dc570b"


def test_near_transaction_limits_policy(vault_dir):
    wallet = ows.import_wallet_private_key(
        "near-limits", NEAR_LIMITS_SEED, chain="near", vault_path_opt=vault_dir
    )
    for policy_id, max_deposit in [
        ("near-limits-ok", "1250000000000000000011"),
        ("near-limits-low", "1250000000000000000010"),
    ]:
        ows.create_policy(json.dumps({
            "id": policy_id,
            "name": policy_id,
            "version": 1,
            "created_at": "2026-03-22T00:00:00Z",
            "rules": [{
                "type": "near_transaction_limits",
                "receivers": ["ft.example.near"],
                "methods": ["storage_deposit", "ft_transfer"],
                "max_deposit": max_deposit,
            }],
            "action": "deny",
        }), vault_path_opt=vault_dir)

    ok = ows.create_api_key(
        "near-ok", [wallet["id"]], ["near-limits-ok"], "", vault_path_opt=vault_dir
    )
    result = ows.sign_transaction(
        wallet["id"], "near", NEAR_LIMITS_TX, ok["token"], vault_path_opt=vault_dir
    )
    assert result["signature"] == NEAR_LIMITS_c0b4334753921bab761842bea9f215a02926612c5e8b67f81488f3f9e2f9f2b74d91502cbf98cba7095aa682e8a8059f1e5a3170c11798ce71caf50329dc570b

    low = ows.create_api_key(
        "near-low", [wallet["id"]], ["near-limits-low"], "", vault_path_opt=vault_dir
    )
    with pytest.raises(RuntimeError, match="exceeds max_deposit"):
        ows.sign_transaction(
            wallet["id"], "near", NEAR_LIMITS_TX, low["token"], vault_path_opt=vault_dir
        )

    # A misspelled limit is rejected when the policy is created.
    with pytest.raises(ValueError, match="unknown field"):
        ows.create_policy(json.dumps({
            "id": "near-typo",
            "name": "typo",
            "version": 1,
            "created_at": "2026-03-22T00:00:00Z",
            "rules": [{"type": "near_transaction_limits", "receiver": ["x.near"]}],
            "action": "deny",
        }), vault_path_opt=vault_dir)


# near-api-js 7.3.1 buildDelegateAction (ft_transfer, 1 yoctoNEAR) signed with the
# RFC 8032 vector 1 key by KeyPairSigner.signDelegateAction.
NEAR_DELEGATE = "40000000643735613938303138326231306162376435346266656433633936343037336130656531373266336461613632333235616630323161363866373037353131610f00000066742e6578616d706c652e6e65617201000000020b00000066745f7472616e736665723a0000007b2272656365697665725f6964223a226d65726368616e742e6578616d706c652e6e656172222c22616d6f756e74223a2231303030303030227d00e057eb481b0000010000000000000000000000000000002a0000000000000000e1f5050000000000d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
NEAR_DELEGATE_SIG = "b01b4df30474223b0892e3bc1fe7b8fb9362b8783e89017be2e9a4bbc88d9c9054e6f33067c97fc2de71602b54844990cc72c382a23b1a5e0a1390b9b72c4200"


def test_sign_delegate_action(vault_dir):
    wallet = ows.import_wallet_private_key(
        "nep366", NEAR_LIMITS_SEED, chain="near", vault_path_opt=vault_dir
    )
    result = ows.sign_delegate_action(
        wallet["id"], "near", NEAR_DELEGATE, vault_path_opt=vault_dir
    )
    assert result["signature"] == NEAR_DELEGATE_SIG
    assert result["recovery_id"] is None

    ows.create_policy(json.dumps({
        "id": "near-delegate-limits",
        "name": "NEAR delegate limits",
        "version": 1,
        "created_at": "2026-03-22T00:00:00Z",
        "rules": [{"type": "near_transaction_limits", "receivers": ["other.near"]}],
        "action": "deny",
    }), vault_path_opt=vault_dir)
    key = ows.create_api_key(
        "nep366-agent", [wallet["id"]], ["near-delegate-limits"], "",
        vault_path_opt=vault_dir,
    )
    with pytest.raises(RuntimeError, match="not in the allowed receivers"):
        ows.sign_delegate_action(
            wallet["id"], "near", NEAR_DELEGATE, key["token"], vault_path_opt=vault_dir
        )
    with pytest.raises(RuntimeError, match="only supported for NEAR chains"):
        ows.sign_delegate_action(
            wallet["id"], "solana", NEAR_DELEGATE, vault_path_opt=vault_dir
        )

