# Testnet evidence — least-privilege payment settled by a function-call key

**2026-07-23, NEAR testnet.** A scoped **function-call access key** settled a
NEP-141 payment through the payment-agent contract, and the *same key* was rejected
on-chain when it tried to do anything else. This is the thing the x402 `exact`
scheme structurally cannot accept — it requires a full-access key and a 1-yocto
deposit (see `docs/design.md`).

Reproduce with [`scripts/testnet-proof.sh`](../scripts/testnet-proof.sh).

## Cast

| Role | Account | Notes |
|---|---|---|
| Owner (full-access) | `mike.testnet` | deploys, funds, manages keys |
| Payment agent | `ag839619.mike.testnet` | this contract; holds the token |
| Token (NEP-141) | `ft839619.mike.testnet` | a **mock** FT, faithful on the two load-bearing properties: `ft_transfer` asserts 1 yocto, and the receiver must be registered |
| Merchant | `shop839619.mike.testnet` | payment recipient |
| Scoped key | `ed25519:7deeaRucLykMFZfW32qPsN1u4js3ZMfq8pjofTnecWZS` | the custodian/agent key |

The scoped key's on-chain permission (RPC `view_access_key`) is the crux:

```json
{ "FunctionCall": { "receiver_id": "ag839619.mike.testnet",
                    "method_names": ["pay"], "allowance": null } }
```

It can call **only `pay`, only on the agent**, and can attach **no deposit**. The
contract attaches the NEP-141 yocto itself.

## What was proven

**CAN — `pay()` signed by the scoped function-call key succeeded.** The agent's
`pay` emitted `EVENT_JSON: pay_succeeded {amount:1000, payment_id:"proof-1"}` and
1000 units moved agent → merchant. Final balances: merchant **1000**, agent
**499000**.

**CANNOT — the same key was rejected doing anything else, each for a distinct,
correct reason:**

| Attempt | Rejected by | Meaning |
|---|---|---|
| `withdraw` (drain) | `MethodNameMismatch` (`method_name: 'withdraw'`) | method not in the key's `[pay]` scope |
| call the token `ft_transfer` directly | receiver mismatch (`ak_receiver: agent` ≠ `tx_receiver: token`) | the key can only target the agent, not other accounts |
| attach a deposit to `pay` | `DepositWithFunctionCall` (on-chain) | function-call keys cannot attach a deposit — so they cannot satisfy any owner guard |

The withdraw/deposit rejection is *why* an owner-only method (guarded by
`assert_one_yocto`) is unreachable by a scoped key: it needs a 1-yocto deposit the
key cannot attach.

## Transactions (testnet.nearblocks.io/txns/…)

| Step | Tx |
|---|---|
| create agent account | `9DiJMVfLnMprChTmHgmVFUmutaHFraAAy2NsozLNn46C` |
| deploy mock-ft | `8FsPeiZGjqWXNzAHi1J4CUy57Ke9UXaoYmtG9yAJefNH` |
| deploy payment-agent | `Ho7HFZ2G17wcfvgZLxMseFBtiVRdeTLBgxUELVpTRXce` |
| fund agent (500000) | `HBLbWrSZxD3fpsZeLB1vty55hM7uBLc8Yo3Vadc11Rkd` |
| add scoped `pay` key (via `add_agent_key`) | `3Dm951hoLo7LLXAjXy5g12z5iBCqybsYoj46SDZfqqWA` |
| **CAN: `pay` by the scoped key** | **`A3C234V1yBV2hAYmDrcH9gkKqEtBN6wLeD1ukXLedejV`** |
| CANNOT: `pay` + deposit (`DepositWithFunctionCall`) | `9PqCUeqjvmiBvE9FmpVgr3w6Gk673jRSVQQyvWzQeVbT` |
| CANNOT: `withdraw` + deposit (`DepositWithFunctionCall`) | `8TqhDzvxgU7bfH8HFLPtJ8VJDfhDrtJbUfkPDCJoaLVT` |

(The method- and receiver-scope rejections are enforced from the on-chain key
permission above; near-cli refuses to broadcast them, so they carry no tx hash —
the `view_access_key` permission is their proof.)

## Honest scope

- The token is a **mock NEP-141**. The mechanism proven here — function-call-key
  scoping, the contract attaching the yocto, and the method/receiver/deposit
  rejections — is **token-agnostic**: it is identical against real USDC or
  `wrap.testnet`. A real-token run adds no new information about the authority model
  and is a straightforward follow-up.
- This proves the **direct** function-call-key path. The **relayed** path (a
  facilitator sponsoring gas via a NEP-366 meta-transaction under the `exact-agent`
  x402 scheme) is Phase 3.
- Contract logic (policy, reserve-then-commit, refund) is covered separately by the
  15 near-sdk unit tests in `src/lib.rs`.
