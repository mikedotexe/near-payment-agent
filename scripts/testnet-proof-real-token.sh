#!/usr/bin/env bash
#
# Least-privilege proof on NEAR testnet against a REAL, pre-existing NEP-141 —
# the token-agnostic twin of testnet-proof.sh (which deploys a mock).
#
# Deploys a fresh payment-agent pointed at $FT, registers + funds it from an
# account that already holds the token, adds a `pay`-scoped function-call key,
# then demonstrates:
#   CAN     — the scoped key settles a payment (agent -> merchant)
#   CANNOT  — the same key is rejected on withdraw / a direct token transfer /
#             attaching a deposit
#
# Usage (Circle testnet USDC, funded from an account holding it):
#   FT=3e2210e1184b45b64c8a434c0a7e7b23cc04ea7eb7a6c3c32520d03d4afcb8af \
#   FUND_FROM=merchant.mike.testnet FUND_AMOUNT=1000 PAY_AMOUNT=300 \
#     scripts/testnet-proof-real-token.sh
# Usage (wrap.testnet, wrapping fresh NEAR first):
#   FT=wrap.testnet WRAP_DEPOSIT=0.02 FUND_AMOUNT=10000000000000000000000 \
#   PAY_AMOUNT=3000000000000000000000 scripts/testnet-proof-real-token.sh
#
# Requires: the JS `near` CLI, testnet keychain entries for $MASTER and
# $FUND_FROM, Rust + wasm32.
#
set -uo pipefail
# rpc.testnet.near.org is deprecated and rate-limits (-429); default to FastNEAR.
export NEAR_TESTNET_RPC="${NEAR_TESTNET_RPC:-https://rpc.testnet.fastnear.com}"
MASTER="${MASTER:-mike.testnet}"
FT="${FT:?set FT to an existing NEP-141 contract id}"
FUND_FROM="${FUND_FROM:-$MASTER}"
FUND_AMOUNT="${FUND_AMOUNT:?atomic units to fund the agent with}"
PAY_AMOUNT="${PAY_AMOUNT:?atomic units for the CAN payment}"
PER_TX_CAP="${PER_TX_CAP:-$PAY_AMOUNT}"
WINDOW_CAP="${WINDOW_CAP:-$FUND_AMOUNT}"
WRAP_DEPOSIT="${WRAP_DEPOSIT:-}"   # if set: near_deposit this many NEAR on $FT first
NET=testnet
RUN=$(date +%s | tail -c 7 | head -c 6)
AGENT="ag${RUN}.${MASTER}"
SHOP="shop${RUN}.${MASTER}"
CREDS="$HOME/.near-credentials/$NET"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
bal() { near view "$FT" ft_balance_of "{\"account_id\":\"$1\"}" --networkId $NET 2>/dev/null | tail -1; }

say "build agent wasm"
( cd "$here" && cargo build --target wasm32-unknown-unknown --release -p near-payment-agent )
TGT="$(cd "$here" && cargo metadata --format-version 1 --no-deps | python3 -c 'import sys,json;print(json.load(sys.stdin)["target_directory"])')/wasm32-unknown-unknown/release"
AGENTWASM="$TGT/near_payment_agent.wasm"

say "token sanity ($FT)"
near view "$FT" ft_metadata '{}' --networkId $NET | grep -oE '"(symbol|decimals)":[^,}]+' || true

say "create accounts ($AGENT, $SHOP)"
near create-account "$AGENT" --masterAccount "$MASTER" --initialBalance 6 --networkId $NET
near create-account "$SHOP"  --masterAccount "$MASTER" --initialBalance 1 --networkId $NET

say "deploy payment-agent (token_id=$FT)"
near deploy "$AGENT" "$AGENTWASM" --initFunction new \
  --initArgs "{\"owner_id\":\"$MASTER\",\"token_id\":\"$FT\",\"policy\":{\"per_tx_cap\":\"$PER_TX_CAP\",\"window_cap\":\"$WINDOW_CAP\",\"window_duration_ns\":\"0\",\"total_cap\":null,\"allowlist_enabled\":false,\"expires_at_seconds\":null}}" --networkId $NET

say "register agent + merchant on the real token (NEP-145)"
near call "$FT" storage_deposit "{\"account_id\":\"$AGENT\",\"registration_only\":true}" --accountId "$MASTER" --deposit 0.00125 --networkId $NET
near call "$FT" storage_deposit "{\"account_id\":\"$SHOP\",\"registration_only\":true}"  --accountId "$MASTER" --deposit 0.00125 --networkId $NET

if [ -n "$WRAP_DEPOSIT" ]; then
  say "wrap $WRAP_DEPOSIT NEAR into $FT for $FUND_FROM"
  near call "$FT" storage_deposit "{\"account_id\":\"$FUND_FROM\",\"registration_only\":true}" --accountId "$MASTER" --deposit 0.00125 --networkId $NET || true
  near call "$FT" near_deposit '{}' --accountId "$FUND_FROM" --deposit "$WRAP_DEPOSIT" --networkId $NET
fi

say "fund the agent with $FUND_AMOUNT from $FUND_FROM"
HAVE=$(bal "$FUND_FROM")
echo "  $FUND_FROM holds: $HAVE"
near call "$FT" ft_transfer "{\"receiver_id\":\"$AGENT\",\"amount\":\"$FUND_AMOUNT\"}" --accountId "$FUND_FROM" --depositYocto 1 --networkId $NET

say "add a pay-scoped function-call key via add_agent_key (owner-only)"
near generate-key "scoped$RUN" --networkId $NET >/dev/null 2>&1
PK=$(python3 -c "import json;print(json.load(open('$CREDS/scoped$RUN.json'))['public_key'])")
SK=$(python3 -c "import json;print(json.load(open('$CREDS/scoped$RUN.json'))['private_key'])")
near call "$AGENT" add_agent_key "{\"public_key\":\"$PK\",\"allowance\":null}" \
  --accountId "$MASTER" --depositYocto 1 --gas 100000000000000 --networkId $NET
echo "scoped key permission:"
curl -s "$NEAR_TESTNET_RPC" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_access_key\",\"finality\":\"final\",\"account_id\":\"$AGENT\",\"public_key\":\"$PK\"}}" \
  | python3 -c "import sys,json;print(' ',json.load(sys.stdin)['result']['permission'])"

# install the scoped key as the agent's signing key (back up full-access first)
cp "$CREDS/$AGENT.json" "$CREDS/$AGENT.fullaccess.$RUN.json"
printf '{"account_id":"%s","public_key":"%s","private_key":"%s"}' "$AGENT" "$PK" "$SK" > "$CREDS/$AGENT.json"

say "CAN: pay() signed by the scoped function-call key"
near call "$AGENT" pay "{\"recipient\":\"$SHOP\",\"amount\":\"$PAY_AMOUNT\",\"payment_id\":\"real-$RUN-1\"}" \
  --accountId "$AGENT" --gas 300000000000000 --networkId $NET
echo -n "merchant balance (expect $PAY_AMOUNT): "; bal "$SHOP"
echo -n "agent balance: "; bal "$AGENT"

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
say "done — agent=$AGENT shop=$SHOP token=$FT scoped_key_file=$CREDS/scoped$RUN.json"
