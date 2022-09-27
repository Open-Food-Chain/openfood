import logging
import os
import requests
import json
import sys

from .openfood_env import EXPLORER_URL
from .openfood_komodo_node import decoderawtransaction_wrapper
#from helpers.logging import setup_logger
#from .log_config import *

#setup_logger('explorer_libs', os.path.dirname(os.path.realpath(__file__)) + '/openfood.log')
#logger = logging.getLogger('explorer_libs.module')

def explorer_get_utxos(querywallet):
    print("Get UTXO for wallet " + querywallet)
    print("start explorer_get_utxos")
    # INSIGHT_API_KOMODO_ADDRESS_UTXO = "insight-api-komodo/addrs/{querywallet}/utxo"
    INSIGHT_API_KOMODO_ADDRESS_UTXO = "insight-api-komodo/addrs/" + querywallet + "/utxo"
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_ADDRESS_UTXO)

        print("end explorer_get_utxos")
    except Exception as e:
        print("explorer_get_utxos " + str(e))
        raise Exception(e)
    # vouts = json.loads(res.text)
    # for vout in vouts:
        # print(vout['txid'] + " " + str(vout['vout']) + " " + str(vout['amount']) + " " + str(vout['satoshis']))
    return res.text


def explorer_get_balance(querywallet):
    print("Get balance for wallet: " + querywallet)
    print("start explorer_get_balance")
    INSIGHT_API_KOMODO_ADDRESS_BALANCE = "insight-api-komodo/addr/" + querywallet + "/balance"
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_ADDRESS_BALANCE)
        print("end explorer_get_balance")
    except Exception as e:
        print("explorer_get_balance " + str(e))
        raise Exception(e)
    return int(res.text)


def broadcast_via_explorer(explorer_url, signedtx):
    INSIGHT_API_BROADCAST_TX = "insight-api-komodo/tx/send"
    params = {'rawtx': signedtx}
    url = explorer_url + INSIGHT_API_BROADCAST_TX
    # print(params)
    print("Broadcast via " + url)
    print("start broadcast_via_explorer")
    print(f"params {params}")

    try:
        broadcast_res = requests.post(url, data=params)
        print(broadcast_res.text)
        if len(broadcast_res.text) < 64: # TODO check if json, then if the json has a txid field and it is 64
            raise Exception(broadcast_res.text)
        else:
            return json.loads(broadcast_res.text)

        print("end broadcast_via_explorer")
    except Exception as e:
        # log2discord(f"---\nThere is an exception during the broadcast: **{params}**\n Error: **{e}**\n---")
        rawtx_text = json.dumps(decoderawtransaction_wrapper(params['rawtx']), sort_keys=False, indent=3)
        # log2discord(rawtx_text)
        print("broadcast_via_explorer " + str(e))
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
    print("start explorer_get_transaction")
    INSIGHT_API_KOMODO_TXID = "insight-api-komodo/tx/" + txid
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_TXID)
        print("end explorer_get_transaction")
    except Exception as e:
        print("explorer_get_transaction " + str(e))
        raise Exception(e)
    return res.text