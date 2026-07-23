//! Minimal NEP-141 test fixture for `near-payment-agent`. Not for production.
//!
//! Faithful on the two properties the agent's mechanism depends on:
//! 1. `ft_transfer` asserts exactly 1 yoctoNEAR is attached (so the agent must
//!    attach it from its own balance — the whole point of the primitive).
//! 2. the receiver must be registered (`storage_deposit`) or `ft_transfer` panics,
//!    which drives the agent's failed-transfer refund path.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{assert_one_yocto, env, near, require, AccountId, PanicOnDefault};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MockFt {
    balances: LookupMap<AccountId, u128>,
    total_supply: u128,
}

#[near]
impl MockFt {
    #[init]
    pub fn new(owner_id: AccountId, total_supply: U128) -> Self {
        let mut balances = LookupMap::new(b"b".to_vec());
        balances.insert(owner_id, total_supply.0);
        Self {
            balances,
            total_supply: total_supply.0,
        }
    }

    /// NEP-145 (minimal): registration == presence in the balances map.
    #[payable]
    pub fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) {
        let _ = registration_only;
        let a = account_id.unwrap_or_else(env::predecessor_account_id);
        if !self.balances.contains_key(&a) {
            self.balances.insert(a, 0);
        }
    }

    pub fn storage_balance_of(&self, account_id: AccountId) -> Option<U128> {
        if self.balances.contains_key(&account_id) {
            Some(U128(0))
        } else {
            None
        }
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        assert_one_yocto();
        let _ = memo;
        let sender = env::predecessor_account_id();
        let amt = amount.0;
        require!(
            self.balances.contains_key(&receiver_id),
            "receiver not registered"
        );
        let sb = self.balances.get(&sender).copied().unwrap_or(0);
        require!(sb >= amt, "not enough balance");
        self.balances.insert(sender, sb - amt);
        let rb = self.balances.get(&receiver_id).copied().unwrap_or(0);
        self.balances.insert(receiver_id, rb + amt);
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }

    pub fn ft_total_supply(&self) -> U128 {
        U128(self.total_supply)
    }
}
