import json
import subprocess
import hashlib
from . import rpclib
from .openfood_env import BATCH_NODE
from .openfood_env import BATCH_RPC_USER
from .openfood_env import BATCH_RPC_PASSWORD
from .openfood_env import BATCH_RPC_PORT
from .openfood_env import THIS_NODE_RADDRESS
from .openfood_env import BLOCKNOTIFY_CHAINSYNC_LIMIT
from .openfood_env import THIS_NODE_WIF
from .openfood_env import HOUSEKEEPING_RADDRESS
from slickrpc import Proxy
from .openfood_log import *

BATCHRPC = ""
KV1RPC = ""


def connect_batch_node():
    global BATCHRPC
    print("Connecting to: " + BATCH_NODE + ":" + BATCH_RPC_PORT)
    try:
        BATCHRPC = Proxy("http://" + BATCH_RPC_USER + ":" + BATCH_RPC_PASSWORD + "@" + BATCH_NODE + ":" + BATCH_RPC_PORT)
        return True
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def connect_kv1_node():
    global KV1RPC
    print("Connecting KV to: " + KV1_NODE + ":" + KV1_RPC_PORT)
    try:
        KV1RPC = Proxy("http://" + KV1_RPC_USER + ":" + KV1_RPC_PASSWORD + "@" + KV1_NODE + ":" + KV1_RPC_PORT)
        return True
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def find_oracleid_with_pubkey(pubkey):
    try:
        or_responce = oracle_list()
        for oracle in or_responce:
            oracle = oracle_info(oracle)
            for registered in oracle['registered']:
                if registered['publisher'] == pubkey:
                    return oracle['txid']
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def housekeeping_tx(amount):
    try:
        return sendtoaddress_wrapper(HOUSEKEEPING_RADDRESS, amount)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def kvupdate_wrapper(kv_key, kv_value, kv_days, kv_passphrase):
    try:
        txid = rpclib.kvupdate(KV1RPC, kv_key, kv_value, kv_days, kv_passphrase)
        return txid
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def kvsearch_wrapper(kv_key):
    try:
        kv_response = rpclib.kvsearch(KV1RPC, kv_key)
        return kv_response
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def sendtoaddress_wrapper(to_address, amount):
    try:
        send_amount = round(amount, 10)
        txid = rpclib.sendtoaddress(BATCHRPC, to_address, send_amount)
        return txid
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def sendmany_wrapper(from_address, recipients_json):
    try:
        txid = rpclib.sendmany(BATCHRPC, from_address, recipients_json)
        return txid
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def signmessage_wrapper(data):
    try:
        signed_data = rpclib.signmessage(BATCHRPC, THIS_NODE_RADDRESS, data)
        return signed_data
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def createrawtx_wrapper(txids, vouts, to_address, amount):
    try:
        return rpclib.createrawtransaction(BATCHRPC, txids, vouts, to_address, amount)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')

def getutxos_wrapper(min, max, address):
    try:
        utxos = rpclib.listunspent(BATCHRPC, min, max, address)
        return utxos
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')
        return e 

def decoderawtx_wrapper(tx):
    try:
        return rpclib.decoderawtransaction(BATCHRPC, tx)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def gen_wallet(data, label='NoLabelOK', verbose=False):
    try:
        signed_data = rpclib.signmessage(BATCHRPC, THIS_NODE_RADDRESS, data)
        if verbose:
            print("Creating a %s address signing with %s and data %s" % (label, THIS_NODE_RADDRESS, data))
            print("Signed data is %s" % (signed_data))
        new_wallet_json = subprocess.getoutput("php genwallet.php " + signed_data)
        new_wallet = json.loads(new_wallet_json)
        if verbose:
            print("Created wallet %s" % (new_wallet["address"]))
            
        return new_wallet
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def gen_wallet_data_hash(data, label='NoLabelOK', verbose=False):
    try:
        hashed_data = hashlib.sha256(data)
        if verbose:
            print("Creating a %s address signing with %s and data %s" % (label, THIS_NODE_RADDRESS, data))
            print("Signed data is %s" % (hashed_data))
        new_wallet_json = subprocess.getoutput("php genwallet.php " + hashed_data)
        new_wallet = json.loads(new_wallet_json)
        if verbose:
            print("Created wallet %s" % (new_wallet["address"]))

        return new_wallet
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


# test skipped
def oracle_create(name, description, data_type):
    try:
        or_responce = rpclib.oracles_create(BATCHRPC, name, description, data_type)
        return or_responce
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


# test skipped
def oracle_fund(or_id):
    try:
        or_responce = rpclib.oracles_fund(BATCHRPC, or_id)
        return or_responce
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


# test skipped
def oracle_register(or_id, data_fee):
    try:
        or_responce = rpclib.oracles_register(BATCHRPC, or_id, data_fee)
        return or_responce
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


# test skipped
def oracle_subscribe(or_id, publisher_id, data_fee):
    try:
        or_responce = rpclib.oracles_subscribe(BATCHRPC, or_id, publisher_id, data_fee)
        return or_responce
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


# test skipped
def oracle_info(or_id):
    try:
        or_responce = rpclib.oracles_info(BATCHRPC, or_id)
        return or_responce
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


# test skipped
def oracle_data(or_id, hex_string):
    print(f"oracle data: {hex_string}")
    try:
        or_responce = rpclib.oracles_data(BATCHRPC, or_id, hex_string)
        return or_responce
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


# test skipped
def oracle_list():
    try:
        or_responce = rpclib.oracles_list(BATCHRPC)
        return or_responce
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


# test skipped
def oracle_samples(oracletxid, batonutxo, num):
    try:
        or_responce = rpclib.oracles_samples(BATCHRPC, oracletxid, batonutxo, num)
        return or_responce
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def getrawmempool_wrapper():
    try:
        return rpclib.get_rawmempool(BATCHRPC)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def decoderawtransaction_wrapper(rawtx):
    try:
        return rpclib.decoderawtransaction(BATCHRPC, rawtx)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def check_sync():
    try:
        general_info = rpclib.getinfo(BATCHRPC)
        #print(f" general_info {general_info}")
        sync = general_info['longestchain'] - general_info['blocks']

        print("Chain info.  Longest chain, blocks, sync diff")
        print(f"Longest chain {general_info['longestchain']}")

        print(f"General info {general_info['blocks']}")

        print(f"Sync {sync}")

        if sync >= BLOCKNOTIFY_CHAINSYNC_LIMIT:
            print('the chain is not synced, try again later')
            exit()

        # add if longest chain is zero exit logic

        print("Chain is synced")
        return True
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def check_node_wallet():
    # check wallet management
    try:
        print("Validating node wallet with " + THIS_NODE_RADDRESS)
        is_mine = rpclib.validateaddress(BATCHRPC, THIS_NODE_RADDRESS)['ismine']
        print(is_mine)
        if is_mine is False:
            rpclib.importprivkey(BATCHRPC, THIS_NODE_WIF)
        is_mine = rpclib.validateaddress(BATCHRPC, THIS_NODE_RADDRESS)['ismine']

        return is_mine
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')
        print(str(e))
        print("## CHECK NODE WALLET ERROR ##")
        print("# Things that could be wrong:")
        print("# Wallet is not imported on this node or wallet mismatch to env")
        print("# Node is not available. Check debug.log for details")
        print("# If node is rescanning, will take a short while")
        print("# If changing wallet & env, rescan will occur")
        print("# Exiting.")
        print("##")
        exit()


def check_kv1_wallet():
    # check wallet management
    try:
        print("Validating kv1 wallet with " + THIS_NODE_RADDRESS)
        is_mine = rpclib.validateaddress(KV1RPC, THIS_NODE_RADDRESS)['ismine']
        print(is_mine)
        if is_mine is False:
            rpclib.importprivkey(KV1RPC, THIS_NODE_WIF)
        is_mine = rpclib.validateaddress(KV1RPC, THIS_NODE_RADDRESS)['ismine']

        return is_mine
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')
        print(str(e))
        print("## CHECK KV1 WALLET ERROR ##")
        print("# Things that could be wrong:")
        print("# Wallet is not imported on this node or wallet mismatch to env")
        print("# Node is not available. Check debug.log for details")
        print("# If node is rescanning, will take a short while")
        print("# If changing wallet & env, rescan will occur")
        print("# Exiting.")
        print("##")
        exit()


def createrawtxwithchange(txids, vouts, to_address, amount, change_address, change_amount):
    # print(to_address)
    # print(amount)
    # print(change_address)
    # print(change_amount)
    try:
        return rpclib.createrawtransactionwithchange(BATCHRPC, txids, vouts, to_address, amount, change_address, change_amount)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def createrawtx_split_wallet(txids, vouts, to_address, amount, change_address, change_amount):
    # print(to_address)
    # print(amount)
    # print(change_address)
    # print(change_amount)
    try:
        return rpclib.createrawtransactionsplit(BATCHRPC, txids, vouts, to_address, amount, change_address, change_amount)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def createrawtx(txids, vouts, to_address, amount):
    print("Deprecated: use createrawtx_wrapper")
    try:
        return rpclib.createrawtransaction(BATCHRPC, txids, vouts, to_address, amount)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


"""START - New function for address_amount_dict"""
def createrawtx_wrapper_addr_amount_dict(txids_vouts, address_amount_dict):
    try:
        return rpclib.createrawtransaction_addr_amount_dict(BATCHRPC, txids_vouts, address_amount_dict)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')

def createrawtxwithchange_addr_amount_dict(txids_vouts, addr_amount_dict, change_address, change_amount):
    try:
        return rpclib.createrawtransactionwithchange_addr_amount_dict(BATCHRPC, txids_vouts, addr_amount_dict, change_address, change_amount)
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')
"""END - New function for address_amount_dict"""


def getbalance():
    try:
        KV1RPC = Proxy("http://" + KV1_RPC_USER + ":" + KV1_RPC_PASSWORD + "@" + KV1_NODE + ":" + KV1_RPC_PORT)
        get_balance = rpclib.getbalance(KV1RPC)
        print("Balance : " + str(get_balance))
        return get_balance
    except Exception as e:
        raise Exception(e)

def batch_getinfo():
    try:
        BATCHREQ = Proxy("http://" + BATCH_RPC_USER + ":" + BATCH_RPC_PASSWORD + "@" + BATCH_NODE + ":" + BATCH_RPC_PORT)
        get_info = rpclib.getinfo(BATCHREQ)
        #print("Info : " + str(get_info))
        return get_info
    except Exception as e:
        raise Exception(e)


def kv_getinfo():
    try:
        KV1RPC = Proxy("http://" + KV1_RPC_USER + ":" + KV1_RPC_PASSWORD + "@" + KV1_NODE + ":" + KV1_RPC_PORT)
        get_info = rpclib.getinfo(KV1RPC)
        #print("Info : " + str(get_info))
        return get_info
    except Exception as e:
        raise Exception(e)


def listunspent(minconf=1, maxconf=99999, addr=[]):
    try:
        txid = rpclib.listunspent(BATCHRPC, minconf, maxconf, addr)
        return txid
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')


def signrawtx_wrapper(rawtx):
    try:
        signed_data = rpclib.signrawtx(BATCHRPC, rawtx)
        return signed_data
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')
        return e

def sendrawtx_wrapper(rawtx):
    try:
        tx = rpclib.sendrawtransaction(BATCHRPC, rawtx)
        return tx
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')
        print("Warning: " + str(e))
        return e

def signrawtx_wrapper_with_privkey(rawtx, privkey):
    try:
        signed_data = rpclib.signrawtransaction(BATCHRPC, rawtx, privkey)
        return signed_data
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')
        return e

