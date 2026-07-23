//! Least-privilege integration proof for near-payment-agent.
//!
//! The headline: a scoped **function-call key** can drive `pay` within policy but
//! CANNOT drain, redeploy, delete, add keys, move the token directly, attach a
//! deposit, or exceed the caps. Failed transfers refund the reservation; the owner
//! can pause and revoke.
//!
//! Wasms are pre-built (they are NOT compiled inside this test — building the
//! contract inside `cargo test` deadlocks on the target lock). Before running:
//!   cargo build --target wasm32-unknown-unknown --release
//! then: cargo test --test least_privilege

use near_sdk::json_types::U128;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{KeyType, NearToken, SecretKey};
use near_workspaces::{Account, Contract, Worker};
use serde_json::json;

// Wasm paths come from env vars (this project uses a shared, relocated cargo
// target dir, so a hardcoded ./target path would not resolve). Build first, then:
//   AGENT_WASM=<path> FT_WASM=<path> cargo test --test least_privilege
fn wasm(env_key: &str) -> anyhow::Result<Vec<u8>> {
    let path = std::env::var(env_key).map_err(|_| {
        anyhow::anyhow!("set {env_key} to the built .wasm path (see the module docs)")
    })?;
    std::fs::read(&path).map_err(|e| anyhow::anyhow!("{path}: {e}"))
}

const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);
const PER_TX_CAP: u128 = 100_000;
const WINDOW_CAP: u128 = 200_000;

type WsResult = Result<ExecutionFinalResult, near_workspaces::error::Error>;

/// Assert a call was rejected — either the tx was not admitted (Err, e.g. an
/// access-key permission failure) or it executed and failed.
fn assert_rejected(res: WsResult, what: &str) {
    match res {
        Err(_) => {}
        Ok(r) => assert!(r.is_failure(), "expected `{what}` to be rejected, but it succeeded: {r:#?}"),
    }
}

async fn ft_balance(ft: &Contract, who: &near_workspaces::AccountId) -> anyhow::Result<u128> {
    let b: U128 = ft
        .view("ft_balance_of")
        .args_json(json!({ "account_id": who }))
        .await?
        .json()?;
    Ok(b.0)
}

async fn window_spent(agent: &Contract) -> anyhow::Result<u128> {
    let v: serde_json::Value = agent.view("get_spend").args_json(json!({})).await?.json()?;
    Ok(v["window_spent"].as_str().unwrap().parse()?)
}

// IGNORED pending the Step 4 rework: near-workspaces' bundled sandbox mismatches the
// MSRV-pinned client (`missing field is_slashed`), so the access-key CANNOTs will be
// proven on **testnet** instead (real runtime, no sandbox). That rework also updates
// the `pay` calls below to pass the new `payment_id` argument. Contract *logic* is
// covered by the fast near-sdk unit tests in `src/lib.rs`.
#[ignore = "sandbox version mismatch; access-key proofs pivot to testnet (Step 4)"]
#[tokio::test]
async fn least_privilege() -> anyhow::Result<()> {
    let worker: Worker<_> = near_workspaces::sandbox().await?;
    let agent_wasm = wasm("AGENT_WASM")?;
    let ft_wasm = wasm("FT_WASM")?;

    let ft = worker.dev_deploy(&ft_wasm).await?;
    let agent = worker.dev_deploy(&agent_wasm).await?;
    let owner = worker.dev_create_account().await?;
    let merchant = worker.dev_create_account().await?;
    let stranger = worker.dev_create_account().await?; // never registered on the token

    // ---- token setup: owner holds supply; register agent + merchant; fund agent ----
    ft.call("new")
        .args_json(json!({ "owner_id": owner.id(), "total_supply": "1000000" }))
        .transact().await?.into_result()?;
    for a in [agent.id(), merchant.id()] {
        owner.call(ft.id(), "storage_deposit")
            .args_json(json!({ "account_id": a }))
            .deposit(NearToken::from_millinear(10))
            .transact().await?.into_result()?;
    }
    owner.call(ft.id(), "ft_transfer")
        .args_json(json!({ "receiver_id": agent.id(), "amount": "500000" }))
        .deposit(ONE_YOCTO)
        .transact().await?.into_result()?;

    // ---- agent init: owner-controlled, no allowlist, no window expiry ----
    agent.call("new")
        .args_json(json!({
            "owner_id": owner.id(),
            "token_id": ft.id(),
            "policy": {
                "per_tx_cap": PER_TX_CAP.to_string(),
                "window_cap": WINDOW_CAP.to_string(),
                "window_duration_ns": "0",
                "total_cap": null,
                "allowlist_enabled": false
            }
        }))
        .transact().await?.into_result()?;

    // ---- owner adds a `pay`-scoped function-call key ----
    let scoped_sk = SecretKey::from_random(KeyType::ED25519);
    let scoped_pk = scoped_sk.public_key();
    owner.call(agent.id(), "add_agent_key")
        .args_json(json!({ "public_key": scoped_pk, "allowance": null }))
        .deposit(ONE_YOCTO)
        .transact().await?.into_result()?;
    // An Account that IS the agent account but signs with the scoped key.
    let scoped = Account::from_secret_key(agent.id().clone(), scoped_sk, &worker);

    // ================= CAN: pay within policy, signed by the fc-key =================
    scoped.call(agent.id(), "pay")
        .args_json(json!({ "recipient": merchant.id(), "amount": "50000" }))
        .max_gas()
        .transact().await?.into_result()?;
    assert_eq!(ft_balance(&ft, merchant.id()).await?, 50_000, "merchant should receive the payment");
    assert_eq!(ft_balance(&ft, agent.id()).await?, 450_000, "agent balance should drop by the payment");
    assert_eq!(window_spent(&agent).await?, 50_000, "window_spent should reflect the payment");

    // ================= CANNOT (scoped fc-key) =================
    assert_rejected(
        scoped.call(agent.id(), "withdraw").args_json(json!({ "to": merchant.id(), "amount": "1" })).max_gas().transact().await,
        "scoped withdraw",
    );
    assert_rejected(
        scoped.call(agent.id(), "add_agent_key").args_json(json!({ "public_key": scoped.secret_key().public_key(), "allowance": null })).max_gas().transact().await,
        "scoped add_agent_key",
    );
    assert_rejected(
        scoped.call(agent.id(), "set_paused").args_json(json!({ "paused": true })).max_gas().transact().await,
        "scoped set_paused",
    );
    // direct token transfer with the scoped key: its receiver is the agent, not the token
    assert_rejected(
        scoped.call(ft.id(), "ft_transfer").args_json(json!({ "receiver_id": merchant.id(), "amount": "1" })).deposit(ONE_YOCTO).max_gas().transact().await,
        "scoped direct ft_transfer",
    );
    // pay with an attached deposit: function-call keys cannot attach one
    assert_rejected(
        scoped.call(agent.id(), "pay").args_json(json!({ "recipient": merchant.id(), "amount": "1" })).deposit(ONE_YOCTO).max_gas().transact().await,
        "scoped pay with deposit",
    );
    // over the per-tx cap
    assert_rejected(
        scoped.call(agent.id(), "pay").args_json(json!({ "recipient": merchant.id(), "amount": (PER_TX_CAP + 1).to_string() })).max_gas().transact().await,
        "pay over per_tx_cap",
    );
    assert_eq!(window_spent(&agent).await?, 50_000, "rejected pays must not move the counter");

    // ================= refund: pay to an unregistered recipient =================
    let before = window_spent(&agent).await?;
    // Outer `pay` reserves, the inner ft_transfer fails (stranger unregistered),
    // ft_resolve refunds. Assert the reservation was returned and no tokens moved.
    let _ = scoped.call(agent.id(), "pay")
        .args_json(json!({ "recipient": stranger.id(), "amount": "10000" }))
        .max_gas()
        .transact().await?;
    assert_eq!(window_spent(&agent).await?, before, "failed transfer must refund the reservation");
    assert_eq!(ft_balance(&ft, agent.id()).await?, 450_000, "no tokens should move on a failed transfer");

    // ================= revocation: pause, then delete the key =================
    owner.call(agent.id(), "set_paused").args_json(json!({ "paused": true })).deposit(ONE_YOCTO).transact().await?.into_result()?;
    assert_rejected(
        scoped.call(agent.id(), "pay").args_json(json!({ "recipient": merchant.id(), "amount": "1000" })).max_gas().transact().await,
        "pay while paused",
    );
    owner.call(agent.id(), "set_paused").args_json(json!({ "paused": false })).deposit(ONE_YOCTO).transact().await?.into_result()?;

    owner.call(agent.id(), "revoke_agent_key").args_json(json!({ "public_key": scoped.secret_key().public_key() })).deposit(ONE_YOCTO).transact().await?.into_result()?;
    assert_rejected(
        scoped.call(agent.id(), "pay").args_json(json!({ "recipient": merchant.id(), "amount": "1000" })).max_gas().transact().await,
        "pay after key revocation",
    );

    // ================= owner retains control: withdraw =================
    // The owner is registered on the token (it minted the supply), so withdraw
    // moves tokens out of the agent back to the owner.
    owner.call(agent.id(), "withdraw").args_json(json!({ "to": owner.id(), "amount": "100000" })).deposit(ONE_YOCTO).max_gas().transact().await?.into_result()?;
    assert_eq!(ft_balance(&ft, agent.id()).await?, 350_000, "owner withdraw should move tokens out of the agent");
    assert_eq!(ft_balance(&ft, owner.id()).await?, 600_000, "owner should receive the withdrawn tokens");

    Ok(())
}
