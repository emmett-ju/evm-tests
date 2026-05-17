import os, json, urllib.request, time
from adapter.env import load_dotenv
from adapter.profile import load_chain_profile
from adapter.signer import sign_type_2_transaction, private_key_to_address

load_dotenv()
profile = load_chain_profile("profiles/juchain.toml")
priv_key = int(os.environ["JUCHAIN_PRIVATE_KEY"], 16)

def rpc(method, params):
    req = urllib.request.Request("https://testnet-rpc.juchain.org", json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}).encode(), {"Content-Type": "application/json", "User-Agent": "evm-rpc-tests/0.1"})
    res = json.loads(urllib.request.urlopen(req).read().decode())
    if "error" in res: raise Exception(res["error"])
    return res["result"]

nonce = int(rpc("eth_getTransactionCount", [profile.admin_account, "pending"]), 16)
tx = {
    "nonce": hex(nonce),
    "maxPriorityFeePerGas": hex(profile.gas_policy.max_priority_fee_per_gas),
    "maxFeePerGas": hex(profile.gas_policy.max_fee_per_gas),
    "gas": hex(3000000),
    "to": "0x",
    "value": "0x0",
    "data": "0x6005600c60003960056000f3602a5f5500",
}
raw = sign_type_2_transaction(profile, priv_key, tx)
tx_hash = rpc("eth_sendRawTransaction", [raw])
print("deploy tx:", tx_hash)
while True:
    receipt = rpc("eth_getTransactionReceipt", [tx_hash])
    if receipt: break
    time.sleep(1)

addr = receipt["contractAddress"]
print("deployed at:", addr)
print("code:", rpc("eth_getCode", [addr, "latest"]))
