# Threat model — near-payment-agent

Scope: what the **scoped custodian/agent key** can and cannot do, the contract's
attack surface, and an honest comparison to NEAR Intents. Owner-key compromise is
explicitly out of scope — this primitive reduces the *custodian's* blast radius,
not the owner's.

## What the scoped function-call key CAN do
- Sign a NEP-366 delegate (or a direct call) to **`pay(recipient, amount)`**,
  deposit 0, on the agent account.
- Move the pinned token to a **policy-allowed** recipient: `amount ≤ per_tx_cap`,
  within `window_cap` and `total_cap`.
- Burn its own gas allowance (self-griefing; recoverable by re-adding the key).

## What it CANNOT do — and why
| Capability | Blocked by |
|---|---|
| Attach any NEAR deposit | Runtime rejects `deposit>0` for function-call keys (tx + delegate) → cannot reach any `[owner]` method (all `assert_one_yocto`) |
| Call anything but `pay` | Access-key `method_names = ["pay"]` |
| Target any account but the agent | Access-key `receiver_id = agent` → cannot call the token's `ft_transfer` directly, cannot touch other accounts |
| Add/remove keys, deploy, delete the account | Those are non-FunctionCall actions; function-call keys cannot carry them |
| Move a different token | Contract pins `token_id` |
| Exceed per-tx / window / total caps, or pay a non-allowlisted recipient | Contract policy (reserve-then-commit) |
| Drain via unlimited calls | Cumulative key-driven outflow ≤ min(window budget over elapsed windows, `total_cap`, agent's held balance); owner revokes instantly |

**Bound sketch.** The only state-mutating, key-reachable method is `pay`; it
reserves budget atomically before transferring. Token value leaves only via `pay`
(capped, allowlisted) or `withdraw` (`[owner]`). So key-driven outflow between owner
interventions ≤ `window_cap` per window and ≤ `total_cap` lifetime, never exceeding
the agent's balance. Standing risk between revocations ≈ the current window's
remaining budget.

**Revocation.** `set_paused(true)` is the true immediate stop — `pay` checks it at
execution, halting even already-signed in-flight delegates. `DeleteKey` (native or
`revoke_agent_key`) takes effect next block but does **not** cancel in-flight
delegates until their `max_block_height`. Recommend **pause, then revoke**.

## Comparison vs NEAR Intents (`intents.near`, defuse v0.4.2, per hub Program 04)
| Property | Payment-agent contract | NEAR Intents |
|---|---|---|
| Custody location | Payer's **own** account (no transfer) | **Shared `intents.near` ledger** (custody transferred) |
| Delegated-key blast radius | Method-scoped, capped, allowlisted → **≤ policy** | Entire **deposited balance** (key can withdraw all, or `AddPublicKey`) |
| Native method scoping | Yes | No |
| Recipient restriction | On-chain allowlist | None at key level |
| Per-tx / rate / total caps | On-chain policy | None (per-intent nonce only) |
| Systemic / shared-tenant risk | None (per-payer isolation) | Yes (pooled deposits) |
| Standing risk | ≈ window budget (JIT windows → ~1 payment) | ≈ deposited balance (JIT deposits → ~1 payment) |
| Onboarding | Needs a NEAR account + deployed agent + a little NEAR | **No NEAR account required at all** |

**The honest read:** with just-in-time deposits Intents already gets standing risk
down to ~one payment, so that is *not* the differentiator. The durable wins are
**no custody transfer**, **native method/recipient/cap scoping**, and **per-payer
isolation**. Intents wins on **onboarding** (an EVM wallet can pay with no NEAR
account). Lead the pitch accordingly.

## Attack enumeration
1. **Policy bypass via direct token call** — blocked: key `receiver_id` is the
   agent, and it cannot attach the 1 yocto anyway.
2. **Callback forgery** (`ft_resolve` called externally to force a refund and
   inflate budget) — blocked by `#[private]`. *The sharpest bug if omitted.*
3. **Concurrent over-spend** (burst of `pay` before callbacks) — blocked by
   reserve-then-commit.
4. **Allowance-exhaustion griefing** — the gas allowance drains per landed `pay`;
   exhausting it bricks the key until re-added. Liveness only, never fund-safety.
   Mitigate with generous/`None` allowance (still deposit-0 + method-scoped).
   *Open question: whether the allowance even decrements on the relayed meta-tx
   path — resolve in the Phase 2 sandbox test.*
5. **Recipient-allowlist gaps** — with `allowlist_enabled=false`, the key may pay
   any account up to caps (self-exfiltration up to window budget). Recommend the
   allowlist for high-value agents; the facilitator also pins `payTo`. Match exact
   account IDs (watch implicit vs named).
6. **Key-allowance vs token-cap confusion** — the native key `allowance` is **gas,
   not USDC**. The token cap is contract policy only. Document loudly.
7. **Storage-deposit griefing** — if `pay` auto-registered unregistered recipients
   (paying `storage_deposit` from agent NEAR), many tiny payments to fresh accounts
   would drain the agent's **NEAR**. Mitigation: `pay` does **not** auto-register;
   require recipients pre-registered; the facilitator preflights
   `storage_balance_of(payTo)`.
8. **Failed-transfer griefing** — paying an unregistered recipient fails the
   transfer, refunds budget, moves no token, costs relayer gas. Bounded by the
   facilitator gas cap + preflight rejecting unregistered recipients.
9. **Window tuning** — short window + large cap resets often (more cumulative spend
   over time); `total_cap` bounds lifetime. Timestamp from `block_timestamp` (not
   key-manipulable).
10. **Owner-key compromise** — out of scope by design.
11. **Relayer gas griefing** — inherit the exact-scheme defenses: sponsored-gas cap,
    relayer ≠ payer, nonce/expiry, plus the code-hash allowlist preflight.
12. **Counter overflow** — checked u128 math (`overflow-checks = true` in release).

## Must-not-get-wrong (audit focus)
- `#[private]` on `ft_resolve`.
- Reserve-*before*-transfer, refund-*on-failure* accounting.
- `ft_transfer` (not `ft_transfer_call`); no recipient reentrancy.
- No auto-registration of recipients in `pay`.
- Checked arithmetic on all counters.
