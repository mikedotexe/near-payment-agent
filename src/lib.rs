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
//! PHASE 0 — interface skeleton only. Method bodies are `todo!()`; the payment,
//! policy, reserve-then-commit accounting, and callback logic land in Phase 1+.
//! See `docs/design.md` and `docs/threat-model.md`.

use near_sdk::json_types::{U128, U64};
use near_sdk::store::LookupSet;
use near_sdk::{
    assert_one_yocto, env, near, require, AccountId, PanicOnDefault, Promise, PublicKey,
};

/// Policy supplied at deploy time.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct PolicyInit {
    /// Maximum per-`pay` amount, atomic token units.
    pub per_tx_cap: U128,
    /// Maximum cumulative spend within one rolling window.
    pub window_cap: U128,
    /// Rolling-window duration, nanoseconds.
    pub window_duration_ns: U64,
    /// Optional lifetime spend ceiling.
    pub total_cap: Option<U128>,
    /// When true, `pay` recipients must be on the on-chain allowlist.
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
    /// Full-access controller: the only principal that can change policy, manage
    /// keys, withdraw, or delete the account.
    owner_id: AccountId,
    /// The single NEP-141 token this agent may move.
    token_id: AccountId,
    /// Kill switch, checked at the top of `pay` (halts even in-flight delegates).
    paused: bool,
    /// Bumped on policy/config change; pairs with the code hash for attestation.
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
        let _ = (owner_id, token_id, policy);
        todo!("Phase 1: initialize state, recipients LookupSet, and the first window")
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
        let _ = (recipient, amount);
        todo!("Phase 1: policy checks -> reserve budget -> ft_transfer{{1yocto}}.then(ft_resolve)")
    }

    /// Private callback: commit on success, refund the reservation on failure.
    /// MUST stay `#[private]` — a forged external call has no promise result and
    /// would read as a failure, refunding budget that was never spent.
    #[private]
    pub fn ft_resolve(&mut self, recipient: AccountId, amount: U128, seq: u64) -> bool {
        let _ = (recipient, amount, seq);
        todo!("Phase 1: interpret promise result; refund window/total counters on failure")
    }

    // ---------------------------------------------------------------------
    // Owner: scoped-key management (assert_one_yocto ⇒ full-access key only)
    // ---------------------------------------------------------------------

    #[payable]
    pub fn add_agent_key(&mut self, public_key: PublicKey, allowance: Option<U128>) -> Promise {
        self.assert_owner();
        let _ = (public_key, allowance);
        todo!("Phase 2: AddKey with a FunctionCall permission scoped to method `pay` on self")
    }

    #[payable]
    pub fn revoke_agent_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();
        let _ = public_key;
        todo!("Phase 2: DeleteKey")
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
        let _ = (per_tx_cap, window_cap, window_duration_ns, total_cap);
        todo!("Phase 2")
    }

    #[payable]
    pub fn set_allowlist_enabled(&mut self, enabled: bool) {
        self.assert_owner();
        let _ = enabled;
        todo!("Phase 2")
    }

    #[payable]
    pub fn add_recipient(&mut self, recipient: AccountId) {
        self.assert_owner();
        let _ = recipient;
        todo!("Phase 2")
    }

    #[payable]
    pub fn remove_recipient(&mut self, recipient: AccountId) {
        self.assert_owner();
        let _ = recipient;
        todo!("Phase 2")
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
    // Owner: NEP-145 storage + funds
    // ---------------------------------------------------------------------

    #[payable]
    pub fn storage_register_self(&mut self, deposit: U128) -> Promise {
        self.assert_owner();
        let _ = deposit;
        todo!("Phase 2: storage_deposit on the token contract for this account")
    }

    #[payable]
    pub fn withdraw(&mut self, to: AccountId, amount: U128) -> Promise {
        self.assert_owner();
        let _ = (to, amount);
        todo!("Phase 2: owner-controlled ft_transfer out")
    }

    #[payable]
    pub fn withdraw_near(&mut self, to: AccountId, amount: U128) -> Promise {
        self.assert_owner();
        let _ = (to, amount);
        todo!("Phase 2: reclaim excess NEAR")
    }

    #[payable]
    pub fn close_account(&mut self, beneficiary: AccountId) -> Promise {
        self.assert_owner();
        let _ = beneficiary;
        todo!("Phase 2: DeleteAccount, remaining balance to beneficiary")
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    pub fn get_policy(&self) -> PolicyView {
        todo!("Phase 1")
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

    /// Gasless policy preflight — lets a facilitator reject a doomed `pay`
    /// without sponsoring gas on it.
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
}
