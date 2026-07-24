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

## Relayed settlement — the full x402 meta-tx path (2026-07-23)

The proof above has the function-call key pay its own gas. The **relayed** path is the
actual x402 shape: the scoped key only *authorizes*, and a **relayer sponsors the gas**
via a NEP-366 meta-transaction. Demonstrated on testnet
([`demo/relayed-agent-pay`](../demo/relayed-agent-pay)):

- the scoped key `ed25519:7deeaRuc…` signed a `pay()` SignedDelegate;
- a relayer, `relay839619.mike.testnet`, wrapped it in `Action::Delegate` and broadcast
  it — the **outer tx signer is the relayer**, whose balance dropped by the gas
  (~0.00068 Ⓝ); the custodian paid nothing;
- the agent's `pay` attached the 1 yocto itself and moved 500 to the merchant
  (1000 → 1500); the inner NEP-141 `ft_transfer` receipt (executor = token) succeeded.

Tx [`C5KaUwv8E7tuPegHZQFPLpQsU5WHnuJvhG27cyFgZadb`](https://testnet.nearblocks.io/txns/C5KaUwv8E7tuPegHZQFPLpQsU5WHnuJvhG27cyFgZadb).
This resolves the open "who pays gas" question: in the relayed delegate the **relayer**
pays and the function-call key's allowance is not charged — the full custodial flow (no
full-access key, no gas from the payer) settled through a standard meta-transaction,
which is exactly what the `exact` scheme cannot do.

## Real-token runs — Circle testnet USDC and wrap.testnet (2026-07-23)

The proofs above used a mock NEP-141. The same mechanism was then re-proven against
**two real, third-party tokens** — the token-agnostic claim is now evidence, not
assertion. Reproduce with
[`scripts/testnet-proof-real-token.sh`](../scripts/testnet-proof-real-token.sh),
which points a fresh agent at any existing NEP-141 instead of deploying a mock.

### Circle testnet USDC (`3e2210e1…cb8af`, 6 decimals)

Agent `ag854443.mike.testnet`, merchant `shop854443.mike.testnet`, scoped key
`ed25519:7fthtnLK8gQNrkqcDsR1EF3VF3QWvQwdXWqA686oXarn` — on-chain permission
`FunctionCall{receiver_id: ag854443…, method_names: ["pay"]}` — funded with 1000
atomic units of the Circle-issued test USDC.

| Step | Tx |
|---|---|
| deploy payment-agent (`token_id` = USDC) | `FbiNGjYoKFHzqBQe5w1Pqier41i4GyxQC1AwPqhpgSHM` |
| NEP-145 register agent + merchant | `4cr2bYEziyNvMkfYXEJxYKPCAad2KtJuNTgvX9PNz3bK`, `E9ChYJs87Z8HKLcdYy7ZPqYfgFFaRwYprVeBZRYFd4ez` |
| fund agent (1000 from `merchant.mike.testnet`) | `E6mHUD6wmVJaN4fBwbC9QJD3FywQq64PgEu7uTFsmDc2` |
| add scoped `pay` key | `EVvwsCCKZM73eMxDjMVvEFqCPvZgqCaLr8HDu2Rhimv1` |
| **CAN: direct `pay` of 300 by the scoped key** | **[`2BaCYpkzcmmTwc4jDL9yXveL9FrMnpuBQjF1A36JmBCC`](https://testnet.nearblocks.io/txns/2BaCYpkzcmmTwc4jDL9yXveL9FrMnpuBQjF1A36JmBCC)** |
| **CAN: relayed `pay` of 200 (NEP-366 meta-tx)** | **[`1E1QCSnxc7kW8dFVejUXZuyvCoeQ1oCr9riVL2kVD1p`](https://testnet.nearblocks.io/txns/1E1QCSnxc7kW8dFVejUXZuyvCoeQ1oCr9riVL2kVD1p)** |

Direct: the **real USDC contract** emitted `ft_transfer {amount:"300"}` and the agent
emitted `pay_succeeded`; merchant 0 → 300, agent 1000 → 700. Relayed: outer tx signer
`relay839619.mike.testnet` (the relayer paid the gas), merchant 300 → 500, and the
inner `ft_transfer` receipt was executed by the USDC contract with `SuccessValue` —
the full x402 meta-tx shape settling Circle-issued USDC. The same scoped key was
rejected on `withdraw` (`MethodNameMismatch`), on calling USDC directly
(`ak_receiver: ag854443…` ≠ `tx_receiver: 3e2210e1…`), and on attaching a deposit to
`pay` (`DepositWithFunctionCall`).

### wrap.testnet (wNEAR, 24 decimals)

Agent `ag854950.mike.testnet`, merchant `shop854950.mike.testnet`. Wrapped 0.02 Ⓝ
(`near_deposit`, tx `EXorUNqzYm8CEsQdSWGu5hnQM5Pk6FaKPDjW3H9VeTmt`), funded the agent
0.01 wNEAR (`3XrCmc5NxySJE4ZPUQd29zoUFEnapjn1smvcUSePzjpJ`), and the scoped key
settled a direct `pay` of 0.003 wNEAR —
[`9Wq5AEumEi2N4giYKxR13RriPBzTLt4Y9hq6Hd7x9MF6`](https://testnet.nearblocks.io/txns/9Wq5AEumEi2N4giYKxR13RriPBzTLt4Y9hq6Hd7x9MF6)
(merchant 3×10²¹, agent 7×10²¹ yocto-wNEAR). All three CANNOT rejections reproduced
identically (`MethodNameMismatch` / `ak_receiver` ≠ `tx_receiver: wrap.testnet` /
`DepositWithFunctionCall`).

As in the mock run, the method- and receiver-scope rejections are enforced from the
on-chain key permission (near-cli refuses to broadcast them); `DepositWithFunctionCall`
is the node's own rejection. Operational note: `rpc.testnet.near.org` is deprecated
and rate-limits (-429) — the script and demo now default to
`rpc.testnet.fastnear.com` (override via `NEAR_TESTNET_RPC` / `NODE_URL`).

## Honest scope

- The mechanism is proven against the **mock** NEP-141 (above) and against **two real
  tokens** — Circle-issued testnet USDC and `wrap.testnet` — with identical behavior:
  function-call-key scoping, the contract attaching the yocto, and the
  method/receiver/deposit rejections. Real-token evidence closes the mock-only
  caveat; mainnet remains unexercised for this contract.
- Both the **direct** and the **relayed** (relayer-sponsored, NEP-366 meta-tx)
  function-call-key paths are proven on testnet — relayed on both the mock and real
  USDC. What remains is packaging the client + reference relay as a first-class
  `@x402/near-agent` scheme for the x402 Foundation.
- Contract logic (policy, reserve-then-commit, refund) is covered separately by the
  15 near-sdk unit tests in `src/lib.rs`.
