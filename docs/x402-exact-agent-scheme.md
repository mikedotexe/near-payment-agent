# Scheme: `exact-agent` on `NEAR` (draft)

> Draft kept with the contract during design. In Phase 3 it is contributed to the
> x402 fork as `specs/schemes/exact-agent/scheme_exact_agent_near.md`, mirroring
> the existing `scheme_exact_near.md`, and coordinated with the x402 Foundation.

## Summary

`exact-agent` lets a client pay an exact amount of a NEP-141 token **through a
least-privilege payment-agent contract**, while a facilitator-sponsored relayer
submits the transaction. Unlike `exact` — where the client signs a direct
`ft_transfer` and must therefore use a **full-access** key attaching 1 yoctoNEAR —
`exact-agent` has the client sign a call to the agent contract's `pay(recipient,
amount)` with a **function-call key** attaching **zero** deposit; the agent contract
attaches the NEP-141 yocto from its own balance.

This is the scheme's reason to exist: it settles a payment authorized by a
**method-scoped, capped, revocable** key that the `exact` scheme structurally
cannot accept (it rejects function-call keys and requires a 1-yocto deposit).

## Versions supported

x402 v2 only (`x402Version` MUST be `2`).

## Supported networks

`near:mainnet`, `near:testnet` (CAIP-style, MAY extend to other `near:*`).

## Protocol flow

Identical to `exact` except step 3/7:
1. Client requests a protected resource.
2. Server responds `402` with `PAYMENT-REQUIRED` (v2 `PaymentRequired`, `scheme = "exact-agent"`).
3. Client constructs a NEP-366 `SignedDelegateAction` whose single action is a
   `FunctionCall` to **`pay(recipient=payTo, amount)`** on the client's own agent
   contract, `deposit = 0`, signed by a **function-call key scoped to `pay`**.
4. Client retries with `PAYMENT-SIGNATURE`.
5. Server calls facilitator `verify`.
6. On success, server calls facilitator `settle`.
7. Relayer submits the delegate; the agent's `pay` spawns the real `ft_transfer` to
   `payTo`. The facilitator waits until that **inner token receipt** finishes and
   confirms it moved `amount` to `payTo` (§ Settlement).
8. Server returns the resource + `PAYMENT-RESPONSE`.

## `PaymentRequirements`

**Identical shape to `exact`** (`scheme`, `network`, `amount`, `asset`, `payTo`,
`maxTimeoutSeconds`). The agent contract is a **payer-side private detail** carried
in the payload's `sender_id`, not named by the merchant. `maxTimeoutSeconds →
max_block_height` mapping is unchanged (`estimatedBlockSeconds = 1`).

```json
{ "scheme": "exact-agent", "network": "near:testnet",
  "amount": "1000000", "asset": "usdc.testnet",
  "payTo": "merchant.testnet", "maxTimeoutSeconds": 60 }
```

## `PAYMENT-SIGNATURE` payload

```json
{ "signedDelegateAction": "base64-borsh-signed-delegate-action",
  "agentContractId": "agent.payer.testnet" }
```

`signedDelegateAction` is a base64 Borsh `SignedDelegateAction` whose delegate
action is exactly one `FunctionCall` to `pay`. `agentContractId` is OPTIONAL and, if
present, MUST equal the delegate `sender_id`/`receiver_id`. Both `ed25519` and
`secp256k1` keys are supported.

## Facilitator `verify` (deltas from `exact`)

A fork of the `exact` verify. Same envelope checks (network, expiry via
`max_block_height`, signature over the NEP-366 preimage, single action). Then:

- **Method**: `functionCall.methodName == "pay"` (not `ft_transfer`).
- **Target is the agent, self-called**: `delegate.receiverId == delegate.senderId`
  (the agent account). *(Inverse of exact, where `receiverId == asset`.)*
- **Args**: parse `pay` args → `recipient == payTo`, `amount == requirements.amount`.
- **Deposit is ZERO**: `functionCall.deposit == 0`. *(Inverse of exact's 1-yocto.)*
- **Key is a scoped function-call key**: read `view_access_key`; require a
  `FunctionCall` permission with `receiver_id == agentContractId` and `method_names`
  containing `"pay"`. For the headline proof, **require** function-call (reject
  full-access) so settlement provably used a least-privilege key.
- **Agent attestation (anti-DoS/trust)**:
  `view_account(agentContractId).code_hash ∈ trustedAgentCodeHashes` (facilitator
  config; ideally the shared global-contract hash). Only then trust its views:
  `x402_agent_metadata().token_id == requirements.asset` and
  `simulate_pay(payTo, amount).allowed` (gasless policy preflight).
- **Preflight**: agent account exists with allowlisted code; `ft_balance_of(agent)
  ≥ amount`; `storage_balance_of(payTo)` registered (NEP-145). Gas ≤
  `maxAgentSponsoredGas` (higher than exact — `pay` + `ft_transfer` + callback,
  ~100–150 TGas).

## Facilitator `settle` — trustless success interpretation

Submit via the reused NEP-366 relay path (relayer sponsors gas). Then determine
success from the **spawned token receipt**, not the agent's return value:

- Scan `receipts_outcome` for `executor_id == requirements.asset` with a
  `SuccessValue`, and parse its **NEP-297 `ft_transfer` event log**: require
  `old_owner_id == agentContractId`, `new_owner_id == payTo`, `amount ==
  requirements.amount`. Reject if the `pay`/callback chain has any `Failure`.
- This makes settlement **trustless with respect to the agent contract**: an unknown
  or even malicious contract cannot make `settle` report success without producing
  the exact on-chain `ft_transfer` to `payTo`. Code-hash attestation in `verify` is
  a preflight/DoS control only; correctness rests on the observed event.

**Reference-implementation note.** `@x402/near`'s `interpretSettlementOutcome`
derives `tokenContractId = delegateAction.receiverId` and reads only status — which
for `exact-agent` would be the agent account, not the token. The clean contribution
is to make the outcome interpreter an **injectable strategy** on
`submitSignedDelegateAction`, so `@x402/near-agent` supplies its event-based
interpreter without duplicating the relay body.

## Two trust layers (summary)
- **Settlement correctness = trustless** (observed `ft_transfer` event to `payTo`).
- **Preflight = code-hash attestation** (avoid sponsoring gas on contracts that
  won't pay / views that lie). Open governance question: facilitator-local allowlist
  vs. a shared on-chain registry of blessed agent code hashes.
