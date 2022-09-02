import requests
import json

from .openfood_env import EXPLORER_URL
from .openfood_komodo_node import decoderawtransaction_wrapper

def explorer_get_utxos(querywallet):
    print("Get UTXO for wallet " + querywallet)
    # INSIGHT_API_KOMODO_ADDRESS_UTXO = "insight-api-komodo/addrs/{querywallet}/utxo"
    INSIGHT_API_KOMODO_ADDRESS_UTXO = "insight-api-komodo/addrs/" + querywallet + "/utxo"
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_ADDRESS_UTXO)
        #res = requests.get(EXPLORER_URL + 'insight-api-komodo/addrs/RH5dNSsN3k4wfHZ2zbNBqtAQ9hJyVJWy4r/utxo')
    except Exception as e:
        raise Exception(e)
    # vouts = json.loads(res.text)
    # for vout in vouts:
        # print(vout['txid'] + " " + str(vout['vout']) + " " + str(vout['amount']) + " " + str(vout['satoshis']))
    return res.text


def explorer_get_balance(querywallet):
    print("Get balance for wallet: " + querywallet)
    INSIGHT_API_KOMODO_ADDRESS_BALANCE = "insight-api-komodo/addr/" + querywallet + "/balance"
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_ADDRESS_BALANCE)
    except Exception as e:
        raise Exception(e)
    return int(res.text)


def broadcast_via_explorer(explorer_url, signedtx):
    INSIGHT_API_BROADCAST_TX = "insight-api-komodo/tx/send"
    params = {'rawtx': signedtx}
    url = explorer_url + INSIGHT_API_BROADCAST_TX
    # print(params)
    print("Broadcast via " + url)

    try:
        broadcast_res = requests.post(url, data=params)
        print(broadcast_res.text)
        if len(broadcast_res.text) < 64: # TODO check if json, then if the json has a txid field and it is 64
            raise Exception(broadcast_res.text)
        else:
            return json.loads(broadcast_res.text)
    except Exception as e:
        # log2discord(f"---\nThere is an exception during the broadcast: **{params}**\n Error: **{e}**\n---")
        rawtx_text = json.dumps(decoderawtransaction_wrapper(params['rawtx']), sort_keys=False, indent=3)
        # log2discord(rawtx_text)
        raise(e)
        # mempool = getrawmempool_wrapper()
        # mempool_tx_count = 1
        # for tx in mempool:
        #     print(mempool_tx_count)
        #     mempool_tx_count = mempool_tx_count + 1
        #     print(tx)
        #     mempool_raw_tx = explorer_get_transaction(tx)
        #     print("MYLO MEMPOOL1")
        #     mempool_raw_tx_loads = json.loads(mempool_raw_tx)
        #     # print("MYLO MEMPOOL2")
        #     # print(mempool_raw_tx)
        #     # print("MYLO MEMPOOL3")
        #     # print(mempool_raw_tx_loads['vin'])
        #     log2discord(json.dumps(mempool_raw_tx_loads['vin']))
        #     # print("MYLO MEMPOOL4")
        # print(e)


def explorer_get_transaction(txid):
    print("Get transaction " + txid)
    INSIGHT_API_KOMODO_TXID = "insight-api-komodo/tx/" + txid
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_TXID)
    except Exception as e:
        raise Exception(e)
    return res.text