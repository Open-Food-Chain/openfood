import json
import subprocess
from . import rpclib
from .openfood_env import BATCH_NODE
from .openfood_env import BATCH_RPC_USER
from .openfood_env import BATCH_RPC_PASSWORD
from .openfood_env import BATCH_RPC_PORT
from .openfood_env import KV1_NODE
from .openfood_env import KV1_RPC_USER
from .openfood_env import KV1_RPC_PASSWORD
from .openfood_env import KV1_RPC_PORT
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
    sentry_sdk.capture_message("Connecting to: " + BATCH_NODE + ":" + BATCH_RPC_PORT, 'info')
    BATCHRPC = Proxy("http://" + BATCH_RPC_USER + ":" + BATCH_RPC_PASSWORD + "@" + BATCH_NODE + ":" + BATCH_RPC_PORT)
    return True


def connect_kv1_node():
    global KV1RPC
    print("Connecting KV to: " + KV1_NODE + ":" + KV1_RPC_PORT)
    sentry_sdk.capture_message("Connecting KV to: " + KV1_NODE + ":" + KV1_RPC_PORT, 'info')
    KV1RPC = Proxy("http://" + KV1_RPC_USER + ":" + KV1_RPC_PASSWORD + "@" + KV1_NODE + ":" + KV1_RPC_PORT)
    return True


def find_oracleid_with_pubkey(pubkey):
    print("process === find oracle_id with pubkey")
    sentry_sdk.capture_message("process === find oracle_id with pubkey", 'info')
    or_responce = oracle_list()
    for oracle in or_responce:
        oracle = oracle_info(oracle)
        for registered in oracle['registered']:
            if registered['publisher'] == pubkey:
                return oracle['txid']


def housekeeping_tx(amount):
    print("process === housekeeping_tx")
    sentry_sdk.capture_message("process === housekeeping_tx", 'info')
    return sendtoaddress_wrapper(HOUSEKEEPING_RADDRESS, amount)


def kvupdate_wrapper(kv_key, kv_value, kv_days, kv_passphrase):
    print("start === kvupdate_wrapper")
    sentry_sdk.capture_message("start === kvupdate_wrapper", 'info')
    txid = rpclib.kvupdate(KV1RPC, kv_key, kv_value, kv_days, kv_passphrase)
    print("end ==== kvupdate_wrapper")
    sentry_sdk.capture_message("end === kvupdate_wrapper", 'info')
    return txid


def kvsearch_wrapper(kv_key):
    print("start === kvsearch_wrapper")
    sentry_sdk.capture_message("start === kvsearch_wrapper", 'info')
    kv_response = rpclib.kvsearch(KV1RPC, kv_key)
    print("end ==== kvsearch_wrapper")
    sentry_sdk.capture_message("end ==== kvsearch_wrapper", 'info')
    return kv_response


def sendtoaddress_wrapper(to_address, amount):
    print("start === sendtoaddress_wrapper")
    sentry_sdk.capture_message("start === sendtoaddress_wrapper", 'info')
    send_amount = round(amount, 10)
    txid = rpclib.sendtoaddress(BATCHRPC, to_address, send_amount)
    print("end ==== sendtoaddress_wrapper")
    sentry_sdk.capture_message("end === sendtoaddress_wrapper", 'info')
    return txid


def sendmany_wrapper(from_address, recipients_json):
    print("start === sendmany_wrapper")
    sentry_sdk.capture_message("start === sendmany_wrapper", 'info')
    txid = rpclib.sendmany(BATCHRPC, from_address, recipients_json)
    print("end === sendmany_wrapper")
    sentry_sdk.capture_message("end === sendmany_wrapper", 'info')
    return txid


def signmessage_wrapper(data):
    print("start === signmessage_wrapper")
    sentry_sdk.capture_message("start === signmessage_wrapper", 'info')
    signed_data = rpclib.signmessage(BATCHRPC, THIS_NODE_RADDRESS, data)
    print("end === signmessage_wrapper")
    sentry_sdk.capture_message("end === signmessage_wrapper", 'info')
    return signed_data


def createrawtx_wrapper(txids, vouts, to_address, amount):
    print("process === createrawtx_wrapper")
    sentry_sdk.capture_message("process === createrawtx_wrapper", 'info')
    return rpclib.createrawtransaction(BATCHRPC, txids, vouts, to_address, amount)


def decoderawtx_wrapper(tx):
    print("process === decoderawtx_wrapper")
    sentry_sdk.capture_message("process === decoderawtx_wrapper", 'info')
    return rpclib.decoderawtransaction(BATCHRPC, tx)


def gen_wallet(data, label='NoLabelOK', verbose=False):
    print("start === gen_wallet")
    sentry_sdk.capture_message("start === gen_wallet", 'info')
    if verbose:
        print("Creating a %s address signing with %s and data %s" % (label, THIS_NODE_RADDRESS, data))
    signed_data = rpclib.signmessage(BATCHRPC, THIS_NODE_RADDRESS, data)
    print("Signed data is %s" % (signed_data))
    new_wallet_json = subprocess.getoutput("php genwallet.php " + signed_data)
    new_wallet = json.loads(new_wallet_json)
    if verbose:
        print("Created wallet %s" % (new_wallet["address"]))

    print("end === gen_wallet")
    sentry_sdk.capture_message("end === gen_wallet", 'info')
    return new_wallet


# test skipped
def oracle_create(name, description, data_type):
    print("start === oracle_create")
    sentry_sdk.capture_message("start === oracle_create", 'info')
    or_responce = rpclib.oracles_create(BATCHRPC, name, description, data_type)
    print("end === oracle_create")
    sentry_sdk.capture_message("end === oracle_create", 'info')
    return or_responce


# test skipped
def oracle_fund(or_id):
    print("start === oracle_fund")
    sentry_sdk.capture_message("start === oracle_fund", 'info')
    or_responce = rpclib.oracles_fund(BATCHRPC, or_id)
    print("end === oracle_fund")
    sentry_sdk.capture_message("end === oracle_fund", 'info')
    return or_responce


# test skipped
def oracle_register(or_id, data_fee):
    print("start === oracle_register")
    sentry_sdk.capture_message("start === oracle_register", 'info')
    or_responce = rpclib.oracles_register(BATCHRPC, or_id, data_fee)
    print("end === oracle_register")
    sentry_sdk.capture_message("end === oracle_register", 'info')
    return or_responce


# test skipped
def oracle_subscribe(or_id, publisher_id, data_fee):
    print("start === oracle_subscribe")
    sentry_sdk.capture_message("start === oracle_subscribe", 'info')
    or_responce = rpclib.oracles_subscribe(BATCHRPC, or_id, publisher_id, data_fee)
    print("end === oracle_subscribe")
    sentry_sdk.capture_message("end === oracle_subscribe", 'info')
    return or_responce


# test skipped
def oracle_info(or_id):
    print("start === oracle_info")
    sentry_sdk.capture_message("start === oracle_info", 'info')
    or_responce = rpclib.oracles_info(BATCHRPC, or_id)
    print("end === oracle_info")
    sentry_sdk.capture_message("end === oracle_info", 'info')
    return or_responce


# test skipped
def oracle_data(or_id, hex_string):
    print("start === oracle_data")
    sentry_sdk.capture_message("start === oracle_data", 'info')
    or_responce = rpclib.oracles_data(BATCHRPC, or_id, hex_string)
    print("end === oracle_data")
    sentry_sdk.capture_message("end === oracle_data", 'info')
    return or_responce


# test skipped
def oracle_list():
    print("start === oracle_list")
    sentry_sdk.capture_message("start === oracle_list", 'info')
    or_responce = rpclib.oracles_list(BATCHRPC)
    print("end === oracle_list")
    sentry_sdk.capture_message("end === oracle_list", 'info')
    return or_responce


# test skipped
def oracle_samples(oracletxid, batonutxo, num):
    print("start === oracle_samples")
    sentry_sdk.capture_message("start === oracle_samples", 'info')
    or_responce = rpclib.oracles_samples(BATCHRPC, oracletxid, batonutxo, num)
    print("end === oracle_samples")
    sentry_sdk.capture_message("end === oracle_samples", 'info')
    return or_responce


def getrawmempool_wrapper():
    print("process === getrawmempool_wrapper")
    sentry_sdk.capture_message("process === getrawmempool_wrapper", 'info')
    return rpclib.get_rawmempool(BATCHRPC)


def decoderawtransaction_wrapper(rawtx):
    print("process === decoderawtransaction_wrapper")
    sentry_sdk.capture_message("process === decoderawtransaction_wrapper", 'info')
    return rpclib.decoderawtransaction(BATCHRPC, rawtx)


def check_sync():
    print("start === check_sync")
    sentry_sdk.capture_message("start === check_sync", 'info')
    general_info = rpclib.getinfo(BATCHRPC)
    sync = general_info['longestchain'] - general_info['blocks']

    print("Chain info.  Longest chain, blocks, sync diff")
    print(general_info['longestchain'])

    print(general_info['blocks'])

    print(sync)

    if sync >= BLOCKNOTIFY_CHAINSYNC_LIMIT:
        print('the chain is not synced, try again later')
        exit()

    # add if longest chain is zero exit logic

    print("Chain is synced")
    print("end === check_sync")
    sentry_sdk.capture_message("end === check_sync", 'info')
    return True


def check_node_wallet():
    print("start === check_node_wallet")
    sentry_sdk.capture_message("start === check_node_wallet", 'info')
    # check wallet management
    try:
        print("Validating node wallet with " + THIS_NODE_RADDRESS)
        is_mine = rpclib.validateaddress(BATCHRPC, THIS_NODE_RADDRESS)['ismine']
        print(is_mine)
        if is_mine is False:
            rpclib.importprivkey(BATCHRPC, THIS_NODE_WIF)
        is_mine = rpclib.validateaddress(BATCHRPC, THIS_NODE_RADDRESS)['ismine']

        print("end === check_node_wallet")
        sentry_sdk.capture_message("end === check_node_wallet", 'info')
        return is_mine
    except Exception as e:
        print(e)
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
    print("start === check_kv1_wallet")
    sentry_sdk.capture_message("start === check_kv1_wallet", 'info')
    # check wallet management
    try:
        print("Validating kv1 wallet with " + THIS_NODE_RADDRESS)
        is_mine = rpclib.validateaddress(KV1RPC, THIS_NODE_RADDRESS)['ismine']
        print(is_mine)
        if is_mine is False:
            rpclib.importprivkey(KV1RPC, THIS_NODE_WIF)
        is_mine = rpclib.validateaddress(KV1RPC, THIS_NODE_RADDRESS)['ismine']

        print("end === check_kv1_wallet")
        sentry_sdk.capture_message("end === check_kv1_wallet", 'info')
        return is_mine
    except Exception as e:
        print(e)
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
    print("process === createrawtxwithchange")
    sentry_sdk.capture_message("process === createrawtxwithchange", 'info')
    # print(to_address)
    # print(amount)
    # print(change_address)
    # print(change_amount)
    return rpclib.createrawtransactionwithchange(BATCHRPC, txids, vouts, to_address, amount, change_address,
                                                 change_amount)


def createrawtx_split_wallet(txids, vouts, to_address, amount, change_address, change_amount):
    print("process === createrawtx_split_wallet")
    sentry_sdk.capture_message("process === createrawtx_split_wallet", 'info')
    # print(to_address)
    # print(amount)
    # print(change_address)
    # print(change_amount)
    return rpclib.createrawtransactionsplit(BATCHRPC, txids, vouts, to_address, amount, change_address, change_amount)

def createrawtx(txids, vouts, to_address, amount):
    print("process === createrawtx")
    sentry_sdk.capture_message("process === createrawtx", 'info')
    print("Deprecated: use createrawtx_wrapper")
    return rpclib.createrawtransaction(BATCHRPC, txids, vouts, to_address, amount)


"""START - New function for address_amount_dict"""
def createrawtx_wrapper_addr_amount_dict(txids_vouts, address_amount_dict):
    print("process === createrawtx_wrapper_addr_amount_dict")
    sentry_sdk.capture_message("process === createrawtx_wrapper_addr_amount_dict", 'info')
    return rpclib.createrawtransaction_addr_amount_dict(BATCHRPC, txids_vouts, address_amount_dict)

def createrawtxwithchange_addr_amount_dict(txids_vouts, addr_amount_dict, change_address, change_amount):
    print("process === createrawtxwithchange_addr_amount_dict")
    sentry_sdk.capture_message("process === createrawtxwithchange_addr_amount_dict", 'info')
    return rpclib.createrawtransactionwithchange_addr_amount_dict(BATCHRPC, txids_vouts, addr_amount_dict, change_address, change_amount)
"""END - New function for address_amount_dict"""