# near-payment-agent

A **least-privilege NEP-141 payment authority** for NEAR. It lets a custodian or
autonomous agent make bounded, policy-checked stablecoin payments from an account
it does **not** fully control — driving one method with a *function-call* access
key, never a full-access key.

## Why this exists

NEP-141 `ft_transfer` requires exactly **1 yoctoNEAR** attached. Function-call
access keys **cannot attach any deposit**. So on NEAR today, any account-based key
that can move a stablecoin must be **full-access** — able to drain the balance,
redeploy the contract, remove other keys, or delete the account. Custodial and
agentic payment integrations are forced either to hand out that blast radius or to
route through a shared-custody ledger (NEAR Intents), which transfers custody and
whose key can still drain the whole deposit.

This contract closes that gap in userspace, with no protocol change:

> The **contract** holds the token and attaches the 1 yoctoNEAR to its own
> `ft_transfer`, from its balance. The custodian calls `pay(recipient, amount)`
> with a function-call key that carries **zero** deposit and is scoped to `pay`.
> The key makes policy-bounded payments and nothing else — it cannot drain,
> redeploy, delete, add keys, or move any other token.

- [`docs/design.md`](docs/design.md) — full design, contract model, and the
  reserve-then-commit + callback mechanics.
- [`docs/threat-model.md`](docs/threat-model.md) — what the scoped key can and
  cannot do, the attack surface, and an honest comparison to NEAR Intents.
- [`docs/x402-exact-agent-scheme.md`](docs/x402-exact-agent-scheme.md) — the x402
  `exact-agent` payment scheme this contract settles under (draft; contributed to
  the x402 fork's spec set in Phase 3).

## Status

**Phase 1 — MVP proven.** Contract logic is covered by 15 near-sdk unit tests, and
the least-privilege thesis is **demonstrated on NEAR testnet**: a `pay`-scoped
function-call key settled a payment and was rejected on-chain doing anything else
(method / receiver / deposit). See [`docs/testnet-evidence.md`](docs/testnet-evidence.md),
reproducible via [`scripts/testnet-proof.sh`](scripts/testnet-proof.sh). Next: the
`exact-agent` x402 scheme (relayer-sponsored settlement). Phased plan in
[`docs/design.md`](docs/design.md).

## Build & test

```sh
cargo check --target wasm32-unknown-unknown   # fast type-check (near-sdk requires the wasm cfg)
cargo near build                              # reproducible wasm artifact + attestable code hash
# Phase 1+: near-workspaces integration tests via `cargo test`
```

Toolchain: Rust + near-sdk 5 + cargo-near. `rust-version` is pinned in `Cargo.toml`
and the MSRV-aware resolver selects a compatible `near-sdk` (5.27 at time of
writing); `Cargo.lock` is committed for reproducibility.

## License

Apache-2.0
