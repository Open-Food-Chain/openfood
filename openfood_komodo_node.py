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

BATCHRPC = ""
KV1RPC = ""


def connect_batch_node():
    global BATCHRPC
    print("Connecting to: " + BATCH_NODE + ":" + BATCH_RPC_PORT)
    BATCHRPC = Proxy("http://" + BATCH_RPC_USER + ":" + BATCH_RPC_PASSWORD + "@" + BATCH_NODE + ":" + BATCH_RPC_PORT)
    return True


def connect_kv1_node():
    global KV1RPC
    print("Connecting KV to: " + KV1_NODE + ":" + KV1_RPC_PORT)
    KV1RPC = Proxy("http://" + KV1_RPC_USER + ":" + KV1_RPC_PASSWORD + "@" + KV1_NODE + ":" + KV1_RPC_PORT)
    return True


def find_oracleid_with_pubkey(pubkey):
    print("process === find oracle_id with pubkey")
    or_responce = oracle_list()
    for oracle in or_responce:
        oracle = oracle_info(oracle)
        for registered in oracle['registered']:
            if registered['publisher'] == pubkey:
                return oracle['txid']


def housekeeping_tx(amount):
    print("process === housekeeping_tx")
    return sendtoaddress_wrapper(HOUSEKEEPING_RADDRESS, amount)


def kvupdate_wrapper(kv_key, kv_value, kv_days, kv_passphrase):
    print("start === kvupdate_wrapper")
    txid = rpclib.kvupdate(KV1RPC, kv_key, kv_value, kv_days, kv_passphrase)
    print("end ==== kvupdate_wrapper")
    return txid


def kvsearch_wrapper(kv_key):
    print("start === kvsearch_wrapper")
    kv_response = rpclib.kvsearch(KV1RPC, kv_key)
    print("end ==== kvsearch_wrapper")
    return kv_response


def sendtoaddress_wrapper(to_address, amount):
    print("start === sendtoaddress_wrapper")
    send_amount = round(amount, 10)
    txid = rpclib.sendtoaddress(BATCHRPC, to_address, send_amount)
    print("end ==== sendtoaddress_wrapper")
    return txid


def sendmany_wrapper(from_address, recipients_json):
    print("start === sendmany_wrapper")
    txid = rpclib.sendmany(BATCHRPC, from_address, recipients_json)
    print("end === sendmany_wrapper")
    return txid


def signmessage_wrapper(data):
    print("start === signmessage_wrapper")
    signed_data = rpclib.signmessage(BATCHRPC, THIS_NODE_RADDRESS, data)
    print("end === signmessage_wrapper")
    return signed_data


def createrawtx_wrapper(txids, vouts, to_address, amount):
    print("process === createrawtx_wrapper")
    return rpclib.createrawtransaction(BATCHRPC, txids, vouts, to_address, amount)


def decoderawtx_wrapper(tx):
    print("process === decoderawtx_wrapper")
    return rpclib.decoderawtransaction(BATCHRPC, tx)


def gen_wallet(data, label='NoLabelOK', verbose=False):
    print("start === gen_wallet")
    if verbose:
        print("Creating a %s address signing with %s and data %s" % (label, THIS_NODE_RADDRESS, data))
    signed_data = rpclib.signmessage(BATCHRPC, THIS_NODE_RADDRESS, data)
    print("Signed data is %s" % (signed_data))
    new_wallet_json = subprocess.getoutput("php genwallet.php " + signed_data)
    new_wallet = json.loads(new_wallet_json)
    if verbose:
        print("Created wallet %s" % (new_wallet["address"]))

    print("end === gen_wallet")
    return new_wallet


# test skipped
def oracle_create(name, description, data_type):
    print("start === oracle_create")
    or_responce = rpclib.oracles_create(BATCHRPC, name, description, data_type)
    print("end === oracle_create")
    return or_responce


# test skipped
def oracle_fund(or_id):
    print("start === oracle_fund")
    or_responce = rpclib.oracles_fund(BATCHRPC, or_id)
    print("end === oracle_fund")
    return or_responce


# test skipped
def oracle_register(or_id, data_fee):
    print("start === oracle_register")
    or_responce = rpclib.oracles_register(BATCHRPC, or_id, data_fee)
    print("end === oracle_register")
    return or_responce


# test skipped
def oracle_subscribe(or_id, publisher_id, data_fee):
    print("start === oracle_subscribe")
    or_responce = rpclib.oracles_subscribe(BATCHRPC, or_id, publisher_id, data_fee)
    print("end === oracle_subscribe")
    return or_responce


# test skipped
def oracle_info(or_id):
    print("start === oracle_info")
    or_responce = rpclib.oracles_info(BATCHRPC, or_id)
    print("end === oracle_info")
    return or_responce


# test skipped
def oracle_data(or_id, hex_string):
    print("start === oracle_data")
    or_responce = rpclib.oracles_data(BATCHRPC, or_id, hex_string)
    print("end === oracle_data")
    return or_responce


# test skipped
def oracle_list():
    print("start === oracle_list")
    or_responce = rpclib.oracles_list(BATCHRPC)
    print("end === oracle_list")
    return or_responce


# test skipped
def oracle_samples(oracletxid, batonutxo, num):
    print("start === oracle_samples")
    or_responce = rpclib.oracles_samples(BATCHRPC, oracletxid, batonutxo, num)
    print("end === oracle_samples")
    return or_responce


def getrawmempool_wrapper():
    print("process === getrawmempool_wrapper")
    return rpclib.get_rawmempool(BATCHRPC)


def decoderawtransaction_wrapper(rawtx):
    print("process === decoderawtransaction_wrapper")
    return rpclib.decoderawtransaction(BATCHRPC, rawtx)


def check_sync():
    print("start === check_sync")
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
    return True


def check_node_wallet():
    print("start === check_node_wallet")
    # check wallet management
    try:
        print("Validating node wallet with " + THIS_NODE_RADDRESS)
        is_mine = rpclib.validateaddress(BATCHRPC, THIS_NODE_RADDRESS)['ismine']
        print(is_mine)
        if is_mine is False:
            rpclib.importprivkey(BATCHRPC, THIS_NODE_WIF)
        is_mine = rpclib.validateaddress(BATCHRPC, THIS_NODE_RADDRESS)['ismine']

        print("end === check_node_wallet")
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
    # check wallet management
    try:
        print("Validating kv1 wallet with " + THIS_NODE_RADDRESS)
        is_mine = rpclib.validateaddress(KV1RPC, THIS_NODE_RADDRESS)['ismine']
        print(is_mine)
        if is_mine is False:
            rpclib.importprivkey(KV1RPC, THIS_NODE_WIF)
        is_mine = rpclib.validateaddress(KV1RPC, THIS_NODE_RADDRESS)['ismine']

        print("end === check_kv1_wallet")
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
    # print(to_address)
    # print(amount)
    # print(change_address)
    # print(change_amount)
    return rpclib.createrawtransactionwithchange(BATCHRPC, txids, vouts, to_address, amount, change_address,
                                                 change_amount)


def createrawtx_split_wallet(txids, vouts, to_address, amount, change_address, change_amount):
    print("process === createrawtx_split_wallet")
    # print(to_address)
    # print(amount)
    # print(change_address)
    # print(change_amount)
    return rpclib.createrawtransactionsplit(BATCHRPC, txids, vouts, to_address, amount, change_address, change_amount)

def createrawtx(txids, vouts, to_address, amount):
    print("process === createrawtx")
    print("Deprecated: use createrawtx_wrapper")
    return rpclib.createrawtransaction(BATCHRPC, txids, vouts, to_address, amount)


"""START - New function for address_amount_dict"""
def createrawtx_wrapper_addr_amount_dict(txids_vouts, address_amount_dict):
    print("process === createrawtx_wrapper_addr_amount_dict")
    return rpclib.createrawtransaction_addr_amount_dict(BATCHRPC, txids_vouts, address_amount_dict)

def createrawtxwithchange_addr_amount_dict(txids_vouts, addr_amount_dict, change_address, change_amount):
    print("process === createrawtxwithchange_addr_amount_dict")
    return rpclib.createrawtransactionwithchange_addr_amount_dict(BATCHRPC, txids_vouts, addr_amount_dict, change_address, change_amount)
"""END - New function for address_amount_dict"""