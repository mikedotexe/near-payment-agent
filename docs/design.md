# Design — near-payment-agent

## The unlock (why this is possible)

NEAR's `deposit > 0` prohibition is a check on the **action signed by a
function-call access key**, enforced when the transaction (or `DelegateAction`) is
admitted. A `Promise` created *inside* contract execution draws its attached
deposit from the **contract account's own balance**, under the account's own
authority — no key is involved at that layer. So `pay()`, invoked by a deposit-0,
method-scoped function-call key, may legally emit `token.ft_transfer{ deposit: 1 }`.
The custodian's key never needs deposit authority, and every owner-only method is
guarded by `assert_one_yocto()`, which a function-call key cannot satisfy. That is
the whole primitive.

## Contract model — per-payer instance, distributed as a global contract

**Recommended: one contract instance per payer account**, not a singleton
multi-tenant vault.

- A singleton vault pools every payer's USDC under one account and re-implements
  per-owner authorization in state — reintroducing the exact shared-ledger property
  we criticize in Intents, and making a single contract bug systemic across all
  tenants.
- A per-payer instance keeps funds in the payer's **own** account, lets the
  protocol do the key-scoping natively (`method_names=["pay"]`, `receiver=self`),
  and bounds any bug to one payer.

The per-payer model's only real cost is code storage staking (~1.5–2 NEAR per
account). **NEAR global contracts** (deploy the code once, reference it by hash
from each payer account) collapse that to state-only. `near-sdk` 5.27 ships
`near-global-contracts` support, so this is viable; **confirm testnet/mainnet
availability with an actual deploy in Phase 1.**

Distributing as a global contract *by code hash* also makes the facilitator's trust
story clean: every payer instance shares one attestable hash (see the scheme spec).

## State (`src/lib.rs`)

```
owner_id:            AccountId          // full-access controller (often = the account itself)
token_id:            AccountId          // the single pinned NEP-141 (e.g. USDC)
paused:              bool               // kill switch, checked at the top of pay()
config_version:      u16                // bumped on policy change; pairs with code hash

// policy
per_tx_cap:          u128
window_cap:          u128               // cap per rolling window
window_duration_ns:  u64
total_cap:           Option<u128>       // optional lifetime ceiling
allowlist_enabled:   bool
recipients:          LookupSet<AccountId>

// accounting (reserve-then-commit; counters include in-flight reservations)
window_start_ns:     u64
window_spent:        u128
total_spent:         u128
event_seq:           u64                // NEP-297 event ordering
```

Native access keys are the source of truth for *who* may call `pay`; the contract
enforces *what* (token, amount, recipient, caps).

## `pay()` — reserve-then-commit + the 1-yocto callback

`pay` is deliberately **not** `#[payable]`: near-sdk then asserts
`attached_deposit == 0`, which is exactly what a function-call key attaches.

```
pay(recipient, amount):
  assert !paused
  (attached_deposit == 0 is enforced by near-sdk, non-payable)
  roll_window_if_expired()
  assert amount <= per_tx_cap
  assert !allowlist_enabled || recipients.contains(recipient)
  assert window_spent + amount <= window_cap
  assert total_cap.map_or(true, |c| total_spent + amount <= c)
  // RESERVE before transferring:
  window_spent += amount ;  total_spent += amount
  seq = next_seq()
  return token.ft_transfer(recipient, amount, memo){ deposit: 1yocto, gas: G }
            .then( self.ft_resolve(recipient, amount, seq) )

ft_resolve(recipient, amount, seq):   // #[private]
  match promise_result(0):
    Success => emit ft_pay_succeeded ; true
    Failure => window_spent -= amount ; total_spent -= amount ; emit ft_pay_refunded ; false
```

**Why reserve-then-commit (not increment-on-success).** NEAR has no synchronous
reentrancy, but it *interleaves* receipts: N `pay()` calls can all execute before
any `ft_resolve` fires. If counters were bumped only in the callback, all N would
read the same pre-spend value and collectively blow the cap. Reserving up front
makes each concurrent `pay` observe the decremented budget. The refund path handles
the rarer failed transfer. (The token contract independently enforces the agent's
actual balance, so real USDC over-spend is impossible regardless; reserve-then-commit
keeps the *policy counters* honest under bursts.)

**Callback safety.**
- `ft_resolve` MUST stay `#[private]` (predecessor == current account). A forged
  external call has no promise result → reads as failure → refunds budget never
  spent. This is the single sharpest contract bug; do not omit it.
- Use `ft_transfer`, never `ft_transfer_call` — `ft_transfer` runs no recipient
  code, so a recipient cannot re-enter `pay` mid-flight. (`ft_transfer_call` is out
  of scope for v1.)
- Fail-safe direction: if the callback runs out of gas on a *failed* transfer, the
  refund is skipped and counters over-report spend (budget under-counts) — the safe
  direction. Budget generous callback gas anyway.

## Interface & access control

Legend: **[owner]** = `assert_one_yocto()` + `predecessor == owner_id` (the yocto
forces a full-access key). **[scoped]** = reachable by a `pay`-scoped function-call
key (and the owner).

| Method | Access | Notes |
|---|---|---|
| `new(owner_id, token_id, policy)` | init | deploy-time |
| `pay(recipient, amount) -> Promise` | **[scoped]** | non-payable ⇒ deposit 0; reserve then `ft_transfer` |
| `ft_resolve(recipient, amount, seq)` | `#[private]` | commit/refund callback |
| `add_agent_key(pk, allowance?)` / `revoke_agent_key(pk)` | **[owner]** | scoped-key lifecycle (owner can also use native AddKey/DeleteKey) |
| `set_limits`, `set_allowlist_enabled`, `add_recipient`, `remove_recipient` | **[owner]** | policy |
| `set_paused(bool)` | **[owner]** | immediate stop, checked inside `pay` |
| `set_owner(new)` | **[owner]** | transfer control |
| `storage_register_self`, `withdraw`, `withdraw_near`, `close_account` | **[owner]** | NEP-145 + funds |
| `get_policy`, `x402_agent_metadata`, `simulate_pay`, `get_spend` | view | `x402_agent_metadata`/`simulate_pay` are facilitator preflight |

## Phased build plan

- **Phase 0 (this) — design + compiling skeleton.** ✅ interface compiles for wasm;
  bodies `todo!()`.
- **Phase 1 — MVP + least-privilege proof.** `new`/`pay`/`ft_resolve`/`withdraw` +
  `per_tx_cap` + `paused`; reproducible `cargo near build` → publish code hash;
  near-workspaces suite proving the CANNOTs, the happy path signed by a
  **function-call key**, refund, revocation, and concurrency. Confirm global-contract
  deploy on testnet.
- **Phase 2 — full policy.** allowlist, rolling window, total cap, key-mgmt
  conveniences, storage registration, views; concurrency / allowance-semantics /
  storage-griefing tests.
- **Phase 3 — `@x402/near-agent` scheme** (in the x402 fork) + contribute the
  `scheme_exact_agent_near.md` spec.
- **Phase 4 — E2E**: sandbox → testnet headline (function-call-key settlement) →
  small-value mainnet proof; record evidence in the hub (Program 04).
- **Phase 5 — harden**: audit; global-contract-by-hash; deployment guide; the
  userland artifact backing the parked `near/NEPs` least-privilege ask.
