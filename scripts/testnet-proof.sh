#!/usr/bin/env bash
#
# End-to-end least-privilege proof on NEAR testnet.
#
# Deploys a mock NEP-141 + the payment-agent, adds a `pay`-scoped function-call
# key, then demonstrates:
#   CAN     — the scoped key settles a payment (agent -> merchant)
#   CANNOT  — the same key is rejected on withdraw / a direct token transfer /
#             attaching a deposit
#
# Usage:  MASTER=mike.testnet scripts/testnet-proof.sh
# Requires: the JS `near` CLI, a testnet keychain entry for $MASTER, Rust + wasm32.
#
set -uo pipefail
MASTER="${MASTER:-mike.testnet}"
NET=testnet
RUN=$(date +%s | tail -c 7 | head -c 6)
FT="ft${RUN}.${MASTER}"
AGENT="ag${RUN}.${MASTER}"
SHOP="shop${RUN}.${MASTER}"
CREDS="$HOME/.near-credentials/$NET"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

say "build wasms"
( cd "$here" && cargo build --target wasm32-unknown-unknown --release -p near-payment-agent -p mock-ft )
TGT="$(cd "$here" && cargo metadata --format-version 1 --no-deps | python3 -c 'import sys,json;print(json.load(sys.stdin)["target_directory"])')/wasm32-unknown-unknown/release"
AGENTWASM="$TGT/near_payment_agent.wasm"; FTWASM="$TGT/mock_ft.wasm"

say "create accounts ($FT, $AGENT, $SHOP)"
near create-account "$FT"    --masterAccount "$MASTER" --initialBalance 3 --networkId $NET
near create-account "$AGENT" --masterAccount "$MASTER" --initialBalance 6 --networkId $NET
near create-account "$SHOP"  --masterAccount "$MASTER" --initialBalance 1 --networkId $NET

say "deploy mock-ft + payment-agent"
near deploy "$FT" "$FTWASM" --initFunction new \
  --initArgs "{\"owner_id\":\"$MASTER\",\"total_supply\":\"1000000000\"}" --networkId $NET
near deploy "$AGENT" "$AGENTWASM" --initFunction new \
  --initArgs "{\"owner_id\":\"$MASTER\",\"token_id\":\"$FT\",\"policy\":{\"per_tx_cap\":\"100000\",\"window_cap\":\"500000\",\"window_duration_ns\":\"0\",\"total_cap\":null,\"allowlist_enabled\":false,\"expires_at_seconds\":null}}" --networkId $NET

say "register + fund the agent (500000)"
near call "$FT" storage_deposit "{\"account_id\":\"$AGENT\"}" --accountId "$MASTER" --deposit 0.01 --networkId $NET
near call "$FT" storage_deposit "{\"account_id\":\"$SHOP\"}"  --accountId "$MASTER" --deposit 0.01 --networkId $NET
near call "$FT" ft_transfer "{\"receiver_id\":\"$AGENT\",\"amount\":\"500000\"}" --accountId "$MASTER" --depositYocto 1 --networkId $NET

say "add a pay-scoped function-call key via add_agent_key (owner-only)"
near generate-key "scoped$RUN" --networkId $NET >/dev/null 2>&1
PK=$(python3 -c "import json;print(json.load(open('$CREDS/scoped$RUN.json'))['public_key'])")
SK=$(python3 -c "import json;print(json.load(open('$CREDS/scoped$RUN.json'))['private_key'])")
near call "$AGENT" add_agent_key "{\"public_key\":\"$PK\",\"allowance\":null}" \
  --accountId "$MASTER" --depositYocto 1 --gas 100000000000000 --networkId $NET
echo "scoped key permission:"
curl -s https://rpc.testnet.near.org -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_access_key\",\"finality\":\"final\",\"account_id\":\"$AGENT\",\"public_key\":\"$PK\"}}" \
  | python3 -c "import sys,json;print(' ',json.load(sys.stdin)['result']['permission'])"

# install the scoped key as the agent's signing key (back up full-access first)
cp "$CREDS/$AGENT.json" "$CREDS/$AGENT.fullaccess.$RUN.json"
printf '{"account_id":"%s","public_key":"%s","private_key":"%s"}' "$AGENT" "$PK" "$SK" > "$CREDS/$AGENT.json"

say "CAN: pay() signed by the scoped function-call key"
near call "$AGENT" pay "{\"recipient\":\"$SHOP\",\"amount\":\"1000\",\"payment_id\":\"proof-1\"}" \
  --accountId "$AGENT" --gas 300000000000000 --networkId $NET
echo -n "merchant balance (expect 1000): "; near view "$FT" ft_balance_of "{\"account_id\":\"$SHOP\"}" --networkId $NET

cannot() { local label="$1"; shift; say "CANNOT: $label"
  if "$@" >/tmp/pa_cannot.$$ 2>&1; then echo "  !!! UNEXPECTED SUCCESS"; else
    echo "  rejected:"; grep -oiE "MethodNameMismatch|method_name: '[^']+'|ak_receiver: '[^']+'|tx_receiver: '[^']+'|DepositWithFunctionCall|transactionHash: '[^']+'" /tmp/pa_cannot.$$ | sed 's/^/    /' | head -4; fi; }
cannot "withdraw (method not in [pay])" \
  near call "$AGENT" withdraw "{\"to\":\"$SHOP\",\"amount\":\"1\"}" --accountId "$AGENT" --gas 300000000000000 --networkId $NET
cannot "call the token directly (receiver is the agent)" \
  near call "$FT" ft_transfer "{\"receiver_id\":\"$SHOP\",\"amount\":\"1\"}" --accountId "$AGENT" --gas 300000000000000 --networkId $NET
cannot "attach a deposit to pay (fc-keys cannot)" \
  near call "$AGENT" pay "{\"recipient\":\"$SHOP\",\"amount\":\"1\",\"payment_id\":\"pd$RUN\"}" --accountId "$AGENT" --depositYocto 1 --gas 300000000000000 --networkId $NET

# restore the agent's full-access keystore entry
cp "$CREDS/$AGENT.fullaccess.$RUN.json" "$CREDS/$AGENT.json"
say "done — agent=$AGENT shop=$SHOP token=$FT"
