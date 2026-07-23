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
use near_sdk::store::LookupSet;
use near_sdk::{
    assert_one_yocto, env, ext_contract, near, require, AccountId, Allowance, Gas, NearToken,
    PanicOnDefault, Promise, PromiseError, PublicKey,
};

/// Static gas for the spawned `ft_transfer` and the resolve callback.
const GAS_FT_TRANSFER: Gas = Gas::from_tgas(15);
const GAS_FT_RESOLVE: Gas = Gas::from_tgas(10);

const EVENT_STANDARD: &str = "payment_agent";
const EVENT_VERSION: &str = "1.0.0";

// The NEP-141 interface this contract calls, and the self-callback.
#[allow(dead_code)]
#[ext_contract(ext_ft)]
trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[allow(dead_code)]
#[ext_contract(ext_self)]
trait ExtSelf {
    fn ft_resolve(&mut self, recipient: AccountId, amount: U128, seq: u64) -> bool;
}

/// Policy supplied at deploy time.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct PolicyInit {
    pub per_tx_cap: U128,
    pub window_cap: U128,
    pub window_duration_ns: U64,
    pub total_cap: Option<U128>,
    pub allowlist_enabled: bool,
}

#[near(serializers = [json])]
pub struct PolicyView {
    pub token_id: AccountId,
    pub per_tx_cap: U128,
    pub window_cap: U128,
    pub window_duration_ns: U64,
    pub total_cap: Option<U128>,
    pub allowlist_enabled: bool,
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
    recipients: LookupSet<AccountId>,

    // ---- accounting (reserve-then-commit; counters include in-flight reservations) ----
    window_start_ns: u64,
    window_spent: u128,
    total_spent: u128,
    event_seq: u64,
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
            recipients: LookupSet::new(b"r".to_vec()),
            window_start_ns: env::block_timestamp(),
            window_spent: 0,
            total_spent: 0,
            event_seq: 0,
        }
    }

    // ---------------------------------------------------------------------
    // Payment — the scoped-key path
    // ---------------------------------------------------------------------

    /// Move `amount` of the pinned token to `recipient`, subject to policy.
    ///
    /// Deliberately NOT `#[payable]`: near-sdk then asserts `attached_deposit == 0`,
    /// which is exactly what a function-call key attaches. The 1 yoctoNEAR NEP-141
    /// requires is attached by this contract to its own `ft_transfer` promise,
    /// funded from the agent account's balance — never from the calling key.
    pub fn pay(&mut self, recipient: AccountId, amount: U128) -> Promise {
        require!(!self.paused, "paused");
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

        // RESERVE before transferring: NEAR interleaves receipts, so concurrent
        // `pay` calls must each observe the decremented budget or a burst blows
        // the cap. `ft_resolve` refunds on a failed transfer.
        self.window_spent = next_window;
        self.total_spent = next_total;
        let seq = self.event_seq;
        self.event_seq += 1;

        ext_ft::ext(self.token_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FT_TRANSFER)
            .ft_transfer(recipient.clone(), amount, None)
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(GAS_FT_RESOLVE)
                    .ft_resolve(recipient, amount, seq),
            )
    }

    /// Private callback: commit on success, refund the reservation on failure.
    /// MUST stay `#[private]` — a forged external call has no promise result and
    /// would read as a failure, refunding budget that was never spent.
    #[private]
    pub fn ft_resolve(
        &mut self,
        recipient: AccountId,
        amount: U128,
        seq: u64,
        #[callback_result] transfer: Result<(), PromiseError>,
    ) -> bool {
        if transfer.is_ok() {
            self.emit("pay_succeeded", &recipient, amount, seq);
            true
        } else {
            // Refund the reservation. saturating_sub is defensive; counters were
            // reserved in `pay` so they cannot legitimately underflow.
            self.window_spent = self.window_spent.saturating_sub(amount.0);
            self.total_spent = self.total_spent.saturating_sub(amount.0);
            self.emit("pay_refunded", &recipient, amount, seq);
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
            paused: self.paused,
        }
    }

    /// Facilitator preflight metadata. Only meaningful once the caller has
    /// confirmed this account's code hash is an allowlisted build.
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

    /// Reset the rolling window if the current one has elapsed.
    fn roll_window(&mut self) {
        let now = env::block_timestamp();
        if now.saturating_sub(self.window_start_ns) >= self.window_duration_ns {
            self.window_start_ns = now;
            self.window_spent = 0;
        }
    }

    fn emit(&self, event: &str, recipient: &AccountId, amount: U128, seq: u64) {
        let json = near_sdk::serde_json::json!({
            "standard": EVENT_STANDARD,
            "version": EVENT_VERSION,
            "event": event,
            "data": [{
                "token_id": self.token_id,
                "recipient": recipient,
                "amount": amount,
                "seq": seq,
            }],
        });
        env::log_str(&format!("EVENT_JSON:{}", json));
    }
}
