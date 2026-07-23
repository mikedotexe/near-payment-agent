# relayed-agent-pay — Phase 3 demo

Proves the **relayed** `exact-agent` settlement on NEAR: a custodian's *function-call
key* authorizes `pay()` via a NEP-366 SignedDelegate, and a **relayer sponsors the
gas**. The custodian holds no full-access key and pays nothing for gas — the full x402
meta-transaction path, and the thing the plain `exact` scheme (full-access key + 1-yocto
deposit) structurally cannot do.

## Run (testnet)

Needs the JS `near` keychain entry for the relayer and the scoped-key JSON file (both
produced by [`../../scripts/testnet-proof.sh`](../../scripts/testnet-proof.sh)).

```sh
npm install
AGENT=<agent>.testnet SHOP=<merchant>.testnet FT=<token>.testnet \
  RELAYER=<relayer>.testnet SCOPED_KEY_FILE=~/.near-credentials/testnet/scoped.json \
  npx tsx relayed-pay.ts
```

It prints the settling tx (outer signer = the relayer), the merchant balance delta, the
relayer's gas cost, and the inner `ft_transfer` receipt status. A recorded run is in
[`../../docs/testnet-evidence.md`](../../docs/testnet-evidence.md).

Note: pins `near-api-js` and builds the delegate + relay with its flat `transactions`
API (`transactions.functionCall`, `new transactions.Action({ signedDelegate })`) — the
`@near-js/transactions` `actionCreators` subpath is ESM-broken in the bundled version.
