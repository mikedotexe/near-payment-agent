//! Least-privilege NEP-141 payment-agent contract.
//!
//! Holds a single NEP-141 token for one owner and exposes exactly one payment
//! method, [`PaymentAgent::pay`], that a custodian or agent can drive with a
//! *function-call* access key scoped to `pay` — never a full-access key.
//!
//! The unlock: NEP-141 `ft_transfer` requires exactly 1 yoctoNEAR attached, and
//! function-call keys cannot attach any deposit. So instead of the key attaching
//! it, **this contract** attaches the 1 yoctoNEAR to its own `ft_transfer`
//! promise, from the agent account's balance. The calling key therefore needs no
//! deposit authority — and must not have any. Every owner-only method is guarded
//! by [`near_sdk::assert_one_yocto`], which a function-call key structurally
//! cannot satisfy, so a scoped key can reach `pay` and nothing else.
//!
//! See `docs/design.md` and `docs/threat-model.md`.

use near_sdk::json_types::{U128, U64};
use near_sdk::store::{LookupSet};
use near_sdk::{
    assert_one_yocto, env, ext_contract, near, require, AccountId, Allowance, Gas, NearToken,
    PanicOnDefault, Promise, PromiseError, PublicKey,
};

const GAS_FT_TRANSFER: Gas = Gas::from_tgas(15);
const GAS_FT_RESOLVE: Gas = Gas::from_tgas(10);
const EVENT_STANDARD: &str = "payment_agent";
const EVENT_VERSION: &str = "1.0.0";

#[allow(dead_code)]
#[ext_contract(ext_ft)]
trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[allow(dead_code)]
#[ext_contract(ext_self)]
trait ExtSelf {
    fn ft_resolve(&mut self, recipient: AccountId, amount: U128, payment_id: String) -> bool;
}

/// Policy supplied at deploy time.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct PolicyInit {
    pub per_tx_cap: U128,
    pub window_cap: U128,
    /// Rolling-window length in nanoseconds. **0 disables rolling** — the window
    /// counter never resets, so `window_cap` acts as a lifetime cap.
    pub window_duration_ns: U64,
    pub total_cap: Option<U128>,
    pub allowlist_enabled: bool,
    /// Optional unix-seconds expiry for the whole agent's `pay` authority.
    pub expires_at_seconds: Option<u64>,
}

#[near(serializers = [json])]
pub struct PolicyView {
    pub token_id: AccountId,
    pub per_tx_cap: U128,
    pub window_cap: U128,
    pub window_duration_ns: U64,
    pub total_cap: Option<U128>,
    pub allowlist_enabled: bool,
    pub expires_at_seconds: Option<u64>,
    pub paused: bool,
}

/// Minimal, attestable metadata a facilitator reads during preflight. Trust it
/// only after the account's code hash matches an allowlisted build.
#[near(serializers = [json])]
pub struct AgentMetadata {
    pub version: u16,
    pub token_id: AccountId,
    pub owner_id: AccountId,
}

#[near(serializers = [json])]
pub struct SpendView {
    pub window_start_ns: U64,
    pub window_spent: U128,
    pub total_spent: U128,
}

/// Result of the gasless `simulate_pay` policy preflight.
#[near(serializers = [json])]
pub struct SimResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub remaining_window: U128,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct PaymentAgent {
    owner_id: AccountId,
    token_id: AccountId,
    paused: bool,
    config_version: u16,

    // ---- policy ----
    per_tx_cap: u128,
    window_cap: u128,
    window_duration_ns: u64,
    total_cap: Option<u128>,
    allowlist_enabled: bool,
    /// Whole-agent expiry (unix seconds). Per-*key* expiry is not enforceable here:
    /// in the meta-tx (relayed) flow the contract cannot identify which scoped key
    /// signed, so expiry is per-agent. Use a separate agent per delegate for
    /// independent expiries (cheap under the per-payer global-contract model).
    policy_expires_at: Option<u64>,
    recipients: LookupSet<AccountId>,
    /// Idempotency: payment_ids that have been committed (or are in-flight). A
    /// failed transfer frees its id so the payment can be retried.
    seen_payments: LookupSet<String>,

    // ---- accounting (reserve-then-commit; counters include in-flight reservations) ----
    window_start_ns: u64,
    window_spent: u128,
    total_spent: u128,
}

#[near]
impl PaymentAgent {
    #[init]
    pub fn new(owner_id: AccountId, token_id: AccountId, policy: PolicyInit) -> Self {
        Self {
            owner_id,
            token_id,
            paused: false,
            config_version: 1,
            per_tx_cap: policy.per_tx_cap.0,
            window_cap: policy.window_cap.0,
            window_duration_ns: policy.window_duration_ns.0,
            total_cap: policy.total_cap.map(|c| c.0),
            allowlist_enabled: policy.allowlist_enabled,
            policy_expires_at: policy.expires_at_seconds,
            recipients: LookupSet::new(b"r".to_vec()),
            seen_payments: LookupSet::new(b"p".to_vec()),
            window_start_ns: env::block_timestamp(),
            window_spent: 0,
            total_spent: 0,
        }
    }

    // ---------------------------------------------------------------------
    // Payment — the scoped-key path
    // ---------------------------------------------------------------------

    /// Move `amount` of the pinned token to `recipient`, subject to policy.
    /// `payment_id` is a caller-supplied idempotency key (deduplicated).
    ///
    /// Deliberately NOT `#[payable]`: near-sdk then asserts `attached_deposit == 0`,
    /// which is exactly what a function-call key attaches. The 1 yoctoNEAR NEP-141
    /// requires is attached by this contract to its own `ft_transfer` promise,
    /// funded from the agent account's balance — never from the calling key.
    pub fn pay(&mut self, recipient: AccountId, amount: U128, payment_id: String) -> Promise {
        require!(!self.paused, "paused");
        if let Some(expires_at) = self.policy_expires_at {
            require!(now_seconds() < expires_at, "authority expired");
        }
        require!(
            !self.seen_payments.contains(&payment_id),
            "payment_id already used"
        );

        let amt = amount.0;
        self.roll_window();
        require!(amt <= self.per_tx_cap, "amount exceeds per_tx_cap");
        if self.allowlist_enabled {
            require!(
                self.recipients.contains(&recipient),
                "recipient not allowlisted"
            );
        }
        let next_window = self
            .window_spent
            .checked_add(amt)
            .expect("window counter overflow");
        require!(next_window <= self.window_cap, "window_cap exceeded");
        let next_total = self
            .total_spent
            .checked_add(amt)
            .expect("total counter overflow");
        if let Some(cap) = self.total_cap {
            require!(next_total <= cap, "total_cap exceeded");
        }

        // RESERVE before transferring (NEAR interleaves receipts, so concurrent
        // `pay`s must each observe the decremented budget). `ft_resolve` refunds
        // on a failed transfer.
        self.window_spent = next_window;
        self.total_spent = next_total;
        self.seen_payments.insert(payment_id.clone());

        ext_ft::ext(self.token_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FT_TRANSFER)
            .ft_transfer(recipient.clone(), amount, Some(payment_id.clone()))
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(GAS_FT_RESOLVE)
                    .ft_resolve(recipient, amount, payment_id),
            )
    }

    /// Private callback: commit on success, refund the reservation and free the
    /// `payment_id` on failure. MUST stay `#[private]` — a forged external call
    /// has no promise result and would read as a failure, corrupting counters.
    #[private]
    pub fn ft_resolve(
        &mut self,
        recipient: AccountId,
        amount: U128,
        payment_id: String,
        #[callback_result] transfer: Result<(), PromiseError>,
    ) -> bool {
        if transfer.is_ok() {
            self.emit("pay_succeeded", &recipient, amount, &payment_id);
            true
        } else {
            self.window_spent = self.window_spent.saturating_sub(amount.0);
            self.total_spent = self.total_spent.saturating_sub(amount.0);
            self.seen_payments.remove(&payment_id); // failed -> retryable with the same id
            self.emit("pay_refunded", &recipient, amount, &payment_id);
            false
        }
    }

    // ---------------------------------------------------------------------
    // Owner: scoped-key management (assert_one_yocto ⇒ full-access key only)
    // ---------------------------------------------------------------------

    /// Add a function-call access key scoped to `pay` on this account. `allowance`
    /// is the gas budget in yoctoNEAR (NOT a token cap — token limits are policy).
    #[payable]
    pub fn add_agent_key(&mut self, public_key: PublicKey, allowance: Option<U128>) -> Promise {
        self.assert_owner();
        let allowance = match allowance {
            Some(a) => {
                Allowance::limited(NearToken::from_yoctonear(a.0)).expect("allowance must be > 0")
            }
            None => Allowance::unlimited(),
        };
        Promise::new(env::current_account_id()).add_access_key_allowance(
            public_key,
            allowance,
            env::current_account_id(),
            "pay".to_string(),
        )
    }

    #[payable]
    pub fn revoke_agent_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();
        Promise::new(env::current_account_id()).delete_key(public_key)
    }

    // ---------------------------------------------------------------------
    // Owner: policy
    // ---------------------------------------------------------------------

    #[payable]
    pub fn set_limits(
        &mut self,
        per_tx_cap: U128,
        window_cap: U128,
        window_duration_ns: U64,
        total_cap: Option<U128>,
    ) {
        self.assert_owner();
        self.per_tx_cap = per_tx_cap.0;
        self.window_cap = window_cap.0;
        self.window_duration_ns = window_duration_ns.0;
        self.total_cap = total_cap.map(|c| c.0);
        self.config_version += 1;
    }

    #[payable]
    pub fn set_expiry(&mut self, expires_at_seconds: Option<u64>) {
        self.assert_owner();
        self.policy_expires_at = expires_at_seconds;
        self.config_version += 1;
    }

    #[payable]
    pub fn set_allowlist_enabled(&mut self, enabled: bool) {
        self.assert_owner();
        self.allowlist_enabled = enabled;
        self.config_version += 1;
    }

    #[payable]
    pub fn add_recipient(&mut self, recipient: AccountId) {
        self.assert_owner();
        self.recipients.insert(recipient);
    }

    #[payable]
    pub fn remove_recipient(&mut self, recipient: AccountId) {
        self.assert_owner();
        self.recipients.remove(&recipient);
    }

    /// Immediate stop. Checked inside `pay`, so it halts even already-signed,
    /// in-flight delegate actions — the true kill switch (stronger than DeleteKey,
    /// which does not cancel delegates until their max_block_height).
    #[payable]
    pub fn set_paused(&mut self, paused: bool) {
        self.assert_owner();
        self.paused = paused;
    }

    #[payable]
    pub fn set_owner(&mut self, new_owner: AccountId) {
        self.assert_owner();
        self.owner_id = new_owner;
    }

    // ---------------------------------------------------------------------
    // Owner: funds (storage registration + simulate_pay land in Phase 2)
    // ---------------------------------------------------------------------

    #[payable]
    pub fn withdraw(&mut self, to: AccountId, amount: U128) -> Promise {
        self.assert_owner();
        ext_ft::ext(self.token_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FT_TRANSFER)
            .ft_transfer(to, amount, None)
    }

    #[payable]
    pub fn withdraw_near(&mut self, to: AccountId, amount: U128) -> Promise {
        self.assert_owner();
        Promise::new(to).transfer(NearToken::from_yoctonear(amount.0))
    }

    #[payable]
    pub fn close_account(&mut self, beneficiary: AccountId) -> Promise {
        self.assert_owner();
        Promise::new(env::current_account_id()).delete_account(beneficiary)
    }

    #[payable]
    pub fn storage_register_self(&mut self, deposit: U128) -> Promise {
        self.assert_owner();
        let _ = deposit;
        todo!("Phase 2: storage_deposit on the token contract for this account")
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    pub fn get_policy(&self) -> PolicyView {
        PolicyView {
            token_id: self.token_id.clone(),
            per_tx_cap: U128(self.per_tx_cap),
            window_cap: U128(self.window_cap),
            window_duration_ns: U64(self.window_duration_ns),
            total_cap: self.total_cap.map(U128),
            allowlist_enabled: self.allowlist_enabled,
            expires_at_seconds: self.policy_expires_at,
            paused: self.paused,
        }
    }

    pub fn x402_agent_metadata(&self) -> AgentMetadata {
        AgentMetadata {
            version: self.config_version,
            token_id: self.token_id.clone(),
            owner_id: self.owner_id.clone(),
        }
    }

    pub fn simulate_pay(&self, recipient: AccountId, amount: U128) -> SimResult {
        let _ = (recipient, amount);
        todo!("Phase 2")
    }

    pub fn get_spend(&self) -> SpendView {
        SpendView {
            window_start_ns: U64(self.window_start_ns),
            window_spent: U128(self.window_spent),
            total_spent: U128(self.total_spent),
        }
    }

    pub fn is_payment_seen(&self, payment_id: String) -> bool {
        self.seen_payments.contains(&payment_id)
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    /// Full-access-only guard: `assert_one_yocto` requires a 1-yocto deposit,
    /// which a function-call key cannot attach, so scoped keys can never pass.
    fn assert_owner(&self) {
        assert_one_yocto();
        require!(
            env::predecessor_account_id() == self.owner_id,
            "owner only"
        );
    }

    /// Reset the rolling window if it has elapsed. `window_duration_ns == 0`
    /// disables rolling entirely (window_cap becomes a lifetime cap).
    fn roll_window(&mut self) {
        if self.window_duration_ns == 0 {
            return;
        }
        let now = env::block_timestamp();
        if now.saturating_sub(self.window_start_ns) >= self.window_duration_ns {
            self.window_start_ns = now;
            self.window_spent = 0;
        }
    }

    fn emit(&self, event: &str, recipient: &AccountId, amount: U128, payment_id: &str) {
        let json = near_sdk::serde_json::json!({
            "standard": EVENT_STANDARD,
            "version": EVENT_VERSION,
            "event": event,
            "data": [{
                "token_id": self.token_id,
                "recipient": recipient,
                "amount": amount,
                "payment_id": payment_id,
            }],
        });
        env::log_str(&format!("EVENT_JSON:{}", json));
    }
}

fn now_seconds() -> u64 {
    env::block_timestamp_ms() / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn acc(s: &str) -> AccountId {
        s.parse().unwrap()
    }

    /// Context builder. `deposit_yocto` lets owner-method tests attach the 1 yocto
    /// `assert_one_yocto` requires; `pay` tests use predecessor == the agent itself
    /// (the self-call a delegate action produces) with deposit 0.
    fn ctx(predecessor: &str, deposit_yocto: u128, ts_seconds: u64) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.current_account_id(acc("agent.mike.testnet"))
            .predecessor_account_id(acc(predecessor))
            .signer_account_id(acc(predecessor))
            .attached_deposit(NearToken::from_yoctonear(deposit_yocto))
            .block_timestamp(ts_seconds * 1_000_000_000);
        b
    }

    fn policy() -> PolicyInit {
        PolicyInit {
            per_tx_cap: U128(100),
            window_cap: U128(200),
            window_duration_ns: U64(0), // lifetime cap
            total_cap: None,
            allowlist_enabled: false,
            expires_at_seconds: None,
        }
    }

    fn new_contract() -> PaymentAgent {
        testing_env!(ctx("owner.testnet", 0, 100).build());
        PaymentAgent::new(acc("owner.testnet"), acc("usdc.testnet"), policy())
    }

    // predecessor == the agent account == a self-call, deposit 0 (what a scoped
    // function-call key produces).
    fn as_agent(ts: u64) {
        testing_env!(ctx("agent.mike.testnet", 0, ts).build());
    }
    fn as_owner(ts: u64) {
        testing_env!(ctx("owner.testnet", 1, ts).build());
    }

    #[test]
    fn pay_reserves_and_records() {
        let mut c = new_contract();
        as_agent(101);
        let _ = c.pay(acc("merchant.testnet"), U128(50), "pay-1".to_string());
        assert_eq!(c.get_spend().window_spent.0, 50);
        assert_eq!(c.get_spend().total_spent.0, 50);
        assert!(c.is_payment_seen("pay-1".to_string()));
    }

    #[test]
    #[should_panic(expected = "payment_id already used")]
    fn pay_rejects_replay() {
        let mut c = new_contract();
        as_agent(101);
        let _ = c.pay(acc("merchant.testnet"), U128(50), "dup".to_string());
        let _ = c.pay(acc("merchant.testnet"), U128(10), "dup".to_string());
    }

    #[test]
    #[should_panic(expected = "amount exceeds per_tx_cap")]
    fn pay_rejects_over_per_tx_cap() {
        let mut c = new_contract();
        as_agent(101);
        let _ = c.pay(acc("merchant.testnet"), U128(101), "x".to_string());
    }

    #[test]
    #[should_panic(expected = "window_cap exceeded")]
    fn pay_rejects_over_window_cap() {
        let mut c = new_contract();
        as_agent(101);
        let _ = c.pay(acc("m.testnet"), U128(100), "a".to_string()); // 100
        let _ = c.pay(acc("m.testnet"), U128(100), "b".to_string()); // 200 == cap, ok
        let _ = c.pay(acc("m.testnet"), U128(1), "c".to_string()); // 201 > cap
    }

    #[test]
    #[should_panic(expected = "total_cap exceeded")]
    fn pay_rejects_over_total_cap() {
        testing_env!(ctx("owner.testnet", 0, 100).build());
        let mut p = policy();
        p.total_cap = Some(U128(120));
        p.window_duration_ns = U64(1_000_000_000); // rolling, so window won't bind first
        let mut c = PaymentAgent::new(acc("owner.testnet"), acc("usdc.testnet"), p);
        as_agent(101);
        let _ = c.pay(acc("m.testnet"), U128(100), "a".to_string()); // total 100
        as_agent(103); // new window
        let _ = c.pay(acc("m.testnet"), U128(100), "b".to_string()); // total 200 > 120
    }

    #[test]
    #[should_panic(expected = "paused")]
    fn pay_rejects_when_paused() {
        let mut c = new_contract();
        as_owner(101);
        c.set_paused(true);
        as_agent(102);
        let _ = c.pay(acc("m.testnet"), U128(1), "p".to_string());
    }

    #[test]
    #[should_panic(expected = "authority expired")]
    fn pay_rejects_after_expiry() {
        let mut c = new_contract();
        as_owner(101);
        c.set_expiry(Some(200));
        as_agent(201);
        let _ = c.pay(acc("m.testnet"), U128(1), "e".to_string());
    }

    #[test]
    #[should_panic(expected = "recipient not allowlisted")]
    fn pay_rejects_non_allowlisted() {
        let mut c = new_contract();
        as_owner(101);
        c.set_allowlist_enabled(true);
        as_agent(102);
        let _ = c.pay(acc("stranger.testnet"), U128(1), "n".to_string());
    }

    #[test]
    fn pay_allows_allowlisted_recipient() {
        let mut c = new_contract();
        as_owner(101);
        c.set_allowlist_enabled(true);
        as_owner(101);
        c.add_recipient(acc("merchant.testnet"));
        as_agent(102);
        let _ = c.pay(acc("merchant.testnet"), U128(10), "ok".to_string());
        assert_eq!(c.get_spend().window_spent.0, 10);
    }

    #[test]
    fn resolve_success_commits() {
        let mut c = new_contract();
        as_agent(101);
        let _ = c.pay(acc("m.testnet"), U128(50), "s".to_string());
        as_agent(102);
        let kept = c.ft_resolve(acc("m.testnet"), U128(50), "s".to_string(), Ok(()));
        assert!(kept);
        assert_eq!(c.get_spend().window_spent.0, 50);
        assert!(c.is_payment_seen("s".to_string()));
    }

    #[test]
    fn resolve_failure_refunds_and_frees_payment_id() {
        let mut c = new_contract();
        as_agent(101);
        let _ = c.pay(acc("m.testnet"), U128(50), "f".to_string());
        assert_eq!(c.get_spend().window_spent.0, 50);
        as_agent(102);
        let kept = c.ft_resolve(
            acc("m.testnet"),
            U128(50),
            "f".to_string(),
            Err(PromiseError::Failed),
        );
        assert!(!kept);
        assert_eq!(c.get_spend().window_spent.0, 0);
        assert_eq!(c.get_spend().total_spent.0, 0);
        assert!(!c.is_payment_seen("f".to_string()));
        // retryable with the same id
        as_agent(103);
        let _ = c.pay(acc("m.testnet"), U128(50), "f".to_string());
        assert_eq!(c.get_spend().window_spent.0, 50);
    }

    #[test]
    fn window_rolls_after_duration() {
        testing_env!(ctx("owner.testnet", 0, 100).build());
        let mut p = policy();
        p.window_duration_ns = U64(1_000_000_000); // 1s
        let mut c = PaymentAgent::new(acc("owner.testnet"), acc("usdc.testnet"), p);
        as_agent(100);
        let _ = c.pay(acc("m.testnet"), U128(100), "w1".to_string());
        assert_eq!(c.get_spend().window_spent.0, 100);
        as_agent(102); // > 1s later -> window resets, then +100
        let _ = c.pay(acc("m.testnet"), U128(100), "w2".to_string());
        assert_eq!(c.get_spend().window_spent.0, 100);
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn non_owner_cannot_set_limits() {
        let mut c = new_contract();
        testing_env!(ctx("attacker.testnet", 1, 101).build());
        c.set_limits(U128(1), U128(1), U64(0), None);
    }

    #[test]
    #[should_panic(expected = "1 yoctoNEAR")]
    fn owner_method_requires_one_yocto() {
        let mut c = new_contract();
        testing_env!(ctx("owner.testnet", 0, 101).build()); // no yocto
        c.set_paused(true);
    }

    #[test]
    fn owner_can_update_policy() {
        let mut c = new_contract();
        as_owner(101);
        c.set_limits(U128(5), U128(9), U64(0), Some(U128(50)));
        let p = c.get_policy();
        assert_eq!(p.per_tx_cap.0, 5);
        assert_eq!(p.window_cap.0, 9);
        assert_eq!(p.total_cap.unwrap().0, 50);
    }
}
