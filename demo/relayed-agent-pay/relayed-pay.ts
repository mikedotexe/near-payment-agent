// Phase 3 — relayed `exact-agent` settlement.
//
// The custodian's **scoped function-call key** signs a NEP-366 SignedDelegate calling
// `pay(recipient, amount, payment_id)` with deposit 0. A **relayer** wraps it in an
// `Action::Delegate` and broadcasts it, sponsoring the gas. The agent contract attaches
// the NEP-141 yocto itself and moves the token to the merchant. This is the full x402
// meta-transaction path — the custodian pays no gas and holds no full-access key.
//
// Run:  AGENT=… SHOP=… FT=… RELAYER=… SCOPED_KEY_FILE=… npx tsx relayed-pay.ts
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { connect, keyStores, KeyPair, transactions } from "near-api-js";

const NET = "testnet";
const NODE = "https://rpc.testnet.near.org";
const CREDS = `${homedir()}/.near-credentials/${NET}`;

const AGENT = must("AGENT");
const SHOP = must("SHOP");
const FT = must("FT");
const RELAYER = must("RELAYER");
const SCOPED_KEY_FILE = must("SCOPED_KEY_FILE");
const AMOUNT = process.env.AMOUNT ?? "500";
const PAYMENT_ID = process.env.PAYMENT_ID ?? `relayed-${Math.floor(Date.now() / 1000)}`;

function must(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name}`);
  return v;
}
function readCreds(path: string) {
  return JSON.parse(readFileSync(path, "utf8")) as { private_key: string };
}

async function main() {
  const keyStore = new keyStores.InMemoryKeyStore();
  // The agent account signs with the SCOPED function-call key (not its full-access key).
  await keyStore.setKey(NET, AGENT, KeyPair.fromString(readCreds(SCOPED_KEY_FILE).private_key as any));
  await keyStore.setKey(NET, RELAYER, KeyPair.fromString(readCreds(`${CREDS}/${RELAYER}.json`).private_key as any));

  const near = await connect({ networkId: NET, keyStore, nodeUrl: NODE });
  const agent = await near.account(AGENT);
  const relayer = await near.account(RELAYER);

  const ftBalance = async (who: string): Promise<string> =>
    (await agent.viewFunction({ contractId: FT, methodName: "ft_balance_of", args: { account_id: who } })) as string;

  const shopBefore = await ftBalance(SHOP);
  const relayerBefore = (await relayer.getAccountBalance()).available;

  // 1) CLIENT — the scoped fc-key builds and signs a pay() SignedDelegate (deposit 0).
  const signedDelegate = await agent.signedDelegate({
    receiverId: AGENT,
    blockHeightTtl: 120,
    actions: [
      transactions.functionCall(
        "pay",
        { recipient: SHOP, amount: AMOUNT, payment_id: PAYMENT_ID },
        BigInt("100000000000000"), // 100 TGas for pay -> ft_transfer -> callback
        BigInt(0), // deposit 0: a function-call key cannot attach any
      ),
    ],
  });
  console.log("client: pay() SignedDelegate signed by", signedDelegate.delegateAction.publicKey.toString());

  // 2) RELAYER — wrap in Action::Delegate and broadcast, sponsoring the gas.
  const outcome = await relayer.signAndSendTransaction({
    receiverId: AGENT,
    actions: [new transactions.Action({ signedDelegate })],
  });
  const txHash = (outcome as any).transaction.hash;
  const outerSigner = (outcome as any).transaction.signer_id;

  // 3) VERIFY
  const shopAfter = await ftBalance(SHOP);
  const relayerAfter = (await relayer.getAccountBalance()).available;
  const ftReceipt = (outcome as any).receipts_outcome.find((r: any) => r.outcome.executor_id === FT);

  console.log("\n=== relayed exact-agent settlement ===");
  console.log("outer tx signer (gas sponsor):", outerSigner, outerSigner === RELAYER ? "✓ relayer" : "✗");
  console.log("merchant balance:", shopBefore, "->", shopAfter, `(+${Number(shopAfter) - Number(shopBefore)})`);
  console.log("relayer available Ⓝ:", relayerBefore, "->", relayerAfter, "(gas came from the relayer)");
  console.log("inner ft_transfer receipt:", ftReceipt?.outcome.executor_id, JSON.stringify(ftReceipt?.outcome.status));
  console.log("tx:", `https://testnet.nearblocks.io/txns/${txHash}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
