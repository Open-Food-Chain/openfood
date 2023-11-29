import requests
import json
from .openfood_env import BATCH_NODE
from .openfood_env import BATCH_RPC_USER
from .openfood_env import BATCH_RPC_PASSWORD
from .openfood_env import BATCH_RPC_PORT

def rpc_call(method, params, rpc_url, rpc_user, rpc_password):
    headers = {'content-type': 'application/json'}
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 0})
    response = requests.post(rpc_url, headers=headers, data=payload, auth=(rpc_user, rpc_password))
    return response.json()

def get_mining_node(rpc_url, rpc_user, rpc_password):
    getinfo_result = rpc_call('getinfo', [], rpc_url, rpc_user, rpc_password)
    return getinfo_result['result']['id']

def get_coinbase_transaction(rpc_url, rpc_user, rpc_password):
    block_hash = rpc_call('getblockhash', [1], rpc_url, rpc_user, rpc_password)['result']
    block = rpc_call('getblock', [block_hash], rpc_url, rpc_user, rpc_password)
    return block['result']['tx'][0]

def get_block_reward_winner_pubkey(coinbase_txid, rpc_url, rpc_user, rpc_password):
    coinbase_tx = rpc_call('getrawtransaction', [coinbase_txid, 1], rpc_url, rpc_user, rpc_password)['result']
    return coinbase_tx['vout'][1]['scriptPubKey']['addresses'][0]

def get_oracle_pubkey(block_reward_winner_pubkey, rpc_url, rpc_user, rpc_password):
    oracle_info = rpc_call('oraclesinfo', [], rpc_url, rpc_user, rpc_password)
    return next((o['address'] for o in oracle_info['result'] if o['pubkey'] == block_reward_winner_pubkey), None)

def get_oracles_list(rpc_url, rpc_user, rpc_password):
    return rpc_call('oracleslist', [], rpc_url, rpc_user, rpc_password)['result']

def find_foundation_publisher(oracles_list):
    return next((p for p in oracles_list if p['name'] == 'FOUNDATION'), None)

def get_address_book(oracle_pubkey, publisher, rpc_url, rpc_user, rpc_password):
    return rpc_call('oraclesaddress', [oracle_pubkey, publisher], rpc_url, rpc_user, rpc_password)

def get_address_book():
    rpc_user = BATCH_RPC_USER
    rpc_password = BATCH_RPC_PASSWORD
    rpc_host = BATCH_NODE
    rpc_port = BATCH_RPC_PORT
    rpc_url = f'http://{rpc_host}:{rpc_port}'

    try:
        mining_node = get_mining_node(rpc_url, rpc_user, rpc_password)
        coinbase_txid = get_coinbase_transaction(rpc_url, rpc_user, rpc_password)
        block_reward_winner_pubkey = get_block_reward_winner_pubkey(coinbase_txid, rpc_url, rpc_user, rpc_password)
        oracle_pubkey = get_oracle_pubkey(block_reward_winner_pubkey, rpc_url, rpc_user, rpc_password)
        oracles_list = get_oracles_list(rpc_url, rpc_user, rpc_password)
        foundation_publisher = find_foundation_publisher(oracles_list)

        if foundation_publisher:
            address_book = get_address_book(oracle_pubkey, foundation_publisher['publisher'], rpc_url, rpc_user, rpc_password)
            return address_book
        else:
            return "FOUNDATION publisher not found."
    except Exception as e:
        return f"Error: {e}"
