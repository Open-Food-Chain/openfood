import requests
import json

from .openfood_env import EXPLORER_URL
from .openfood_komodo_node import decoderawtransaction_wrapper

def explorer_get_utxos(querywallet: str):
    print("Get UTXO for wallet " + querywallet)
    print("start explorer_get_utxos")

    if type(querywallet) is not str:
        print("Query wallet must be string")
        raise Exception("Query Wallet must be string")

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


def explorer_get_balance(querywallet: str):
    print("Get balance for wallet: " + querywallet)
    print("start explorer_get_balance")

    if type(querywallet) is not str:
        print("Query wallet must be string")
        raise Exception("Query wallet must be string")

    INSIGHT_API_KOMODO_ADDRESS_BALANCE = "insight-api-komodo/addr/" + querywallet + "/balance"
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_ADDRESS_BALANCE)
        print("end explorer_get_balance")
    except Exception as e:
        print("explorer_get_balance " + str(e))
        raise Exception(e)
    return int(res.text)


def broadcast_via_explorer(explorer_url: str, signedtx: str):
    print("start broadcast_via_explorer")

    if type(explorer_url) is not str:
        print("Explorer URL must be string")
        raise Exception("Explorer URL must be string")

    if type(signedtx) is not str:
        print("SignedTX must be string")
        raise Exception("SignedTX must be string")

    INSIGHT_API_BROADCAST_TX = "insight-api-komodo/tx/send"
    params = {'rawtx': signedtx}
    url = explorer_url + INSIGHT_API_BROADCAST_TX
    print("Broadcast via " + url)

    try:
        broadcast_res = requests.post(url, data=params)
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


def explorer_get_transaction(txid: str):
    print("Get transaction " + txid)
    print("start explorer_get_transaction")

    if type(txid) is not str:
        print("TXID must be string")
        raise Exception("TXID must be string")
    print("Get transaction " + txid)

    INSIGHT_API_KOMODO_TXID = "insight-api-komodo/tx/" + txid
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_TXID)
        print("end explorer_get_transaction")
    except Exception as e:
        print("explorer_get_transaction " + str(e))
        raise Exception(e)
    return res.text


def explorer_get_balance_final(querywallet):
    print("Get balance for wallet: " + querywallet)
    INSIGHT_API_KOMODO_ADDRESS_BALANCE = "insight-api-komodo/addr/" + querywallet + "/balance"
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_ADDRESS_BALANCE)
        result = int(res.text) / 100000000
    except Exception as e:
        print("explorer_get_balance " + str(e))
        raise Exception(e)
    return result


def explorer_get_network_status():
    print("Get network status")
    try:
        EXPLORER_JSON = str(os.environ['EXPLORER_LIST'])
        try:
            EXPLORER_LIST = json.loads(EXPLORER_JSON)
        except Exception as e:
            EXPLORER_LIST = json.loads("{}")
            
        EXPLORER_URL = ""
        for explorer_name, explorer_data in EXPLORER_LIST.items():
            if explorer_data["port"] == "443":
                http_protocol = "https://"
            else:
                http_protocol = "http://"

            url = http_protocol + EXPLORER_LIST[explorer_name]["host"] + ":" + EXPLORER_LIST[explorer_name]["port"] + "/"
            print("URL : " + url)
            try:
                res = requests.get(url + "insight-api-komodo/status/")
                print("Result network status : " + str(res.json()))
                return res.json()
            except:
                pass
    except Exception as e:
        raise Exception(e)