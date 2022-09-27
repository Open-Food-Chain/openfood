import re
import os
import http
import platform
from slickrpc import Proxy


# RPC connection
def get_rpc_details(chain):
    rpcport ='';
    operating_system = platform.system()
    if operating_system == 'Darwin':
        ac_dir = os.environ['HOME'] + '/Library/Application Support/Komodo'
    elif operating_system == 'Linux':
        ac_dir = os.environ['HOME'] + '/.komodo'
    elif operating_system == 'Win64' or operating_system == 'Windows':
        ac_dir = '%s/komodo/' % os.environ['APPDATA']
    if chain == 'KMD':
        coin_config_file = str(ac_dir + '/komodo.conf')
    else:
        coin_config_file = str(ac_dir + '/' + chain + '/' + chain + '.conf')
    with open(coin_config_file, 'r') as f:
        for line in f:
            l = line.rstrip()
            if re.search('rpcuser', l):
                rpcuser = l.replace('rpcuser=', '')
            elif re.search('rpcpassword', l):
                rpcpassword = l.replace('rpcpassword=', '')
            elif re.search('rpcport', l):
                rpcport = l.replace('rpcport=', '')
    if len(rpcport) == 0:
        if chain == 'KMD':
            rpcport = 7771
        else:
            print("rpcport not in conf file, exiting")
            print("check "+coin_config_file)
            exit(1)
    return rpcuser, rpcpassword, rpcport

def def_credentials(chain):
    rpc = get_rpc_details(chain)
    try:
        rpc_connection = Proxy("http://%s:%s@127.0.0.1:%d"%(rpc[0], rpc[1], int(rpc[2])))
    except Exception:
        raise Exception("Connection error! Probably no daemon on selected port.")
    return rpc_connection

def rpc_connect(rpc_user, rpc_password, port):
    try:
        rpc_connection = Proxy("http://%s:%s@127.0.0.1:%d"%(rpc_user, rpc_password, port))
    except Exception as e:
        raise Exception(e)
    return rpc_connection


# Non CC calls
def getinfo(rpc_connection):
    try:
        getinfo = rpc_connection.getinfo()
    except Exception:
        raise Exception("Connection error!")
    return getinfo


def createrawtransactionwithchange(rpc_connection, txids, vouts, address, amount, change_address, change_amount):
    try:
        txid_vout = []

        for txid, vout in zip(txids, vouts):
            txid_vout_v1 = [{ "txid": txid, "vout":vout }]
            txid_vout.extend(txid_vout_v1)


        # address_amount = {address: amount, "RNLnzgmnDNh7LqRpbzMGdfFXVDY6ZW2kop": 0.555}
        address_amount = {address: amount, change_address: change_amount}
        rawtransaction = rpc_connection.createrawtransaction(txid_vout, address_amount)
    except Exception as e:
        raise Exception(e)
    return rawtransaction


def createrawtransaction(rpc_connection, txids, vouts, address, amount):
    try:
        txid_vout = []

        for txid, vout in zip(txids, vouts):
            txid_vout_v1 = [{ "txid": txid, "vout":vout }]
            txid_vout.extend(txid_vout_v1)


        address_amount = {address: amount}

        # print(txid_vout)
        # print(address_amount)
        rawtransaction = rpc_connection.createrawtransaction(txid_vout, address_amount)
    except Exception as e:
        raise Exception(e)
    return rawtransaction


def createrawtransactionsplit(rpc_connection, txids, vouts, address, amount, change_address, change_amount):
    try:
        txid_vout = []

        for txid, vout in zip(txids, vouts):
            txid_vout_v1 = [{ "txid": txid, "vout":vout }]
            txid_vout.extend(txid_vout_v1)

        address_amount = {address: amount/4, address: amount/4, address: amount/4, address: amount/4, change_address: change_amount}

        # print(txid_vout)
        # print(address_amount)
        rawtransaction = rpc_connection.createrawtransaction(txid_vout, address_amount)
    except Exception as e:
        raise Exception(e)
    return rawtransaction


"""START - New function for address_amount_dict"""
def createrawtransactionwithchange_addr_amount_dict(rpc_connection, txids_vouts, address_amount_dict, change_address, change_amount):
    try:
        address_amount_dict[change_address] = change_amount
        rawtransaction = rpc_connection.createrawtransaction(txids_vouts, address_amount_dict)
    except Exception as e:
        raise Exception(e)
    return rawtransaction

def createrawtransaction_addr_amount_dict(rpc_connection, txids_vouts, address_amount_dict):
    try:
        rawtransaction = rpc_connection.createrawtransaction(txids_vouts, address_amount_dict)
    except Exception as e:
        raise Exception(e)
    return rawtransaction
"""END - New function for address_amount_dict"""


#./komodo-cli signrawtransaction "0100000001958cb041d8369bbf6c2493accc4d949909a2c669cad883e232038d782eeb4fa40000000000ffffffff0140420f00000000001976a91456def632e67aa11c25ac16a0ee52893c2e5a2b6a88ac00000000"
def signrawtx(rpc_connection, tx):
    try:
        signed_tx = rpc_connection.signrawtransaction(tx)
    except Exception as e:
        raise Exception(e)
    return signed_tx

def createmultisig(rpc_connection, number, addresses):
    try:
        response = rpc_connection.createmultisig(number, addresses)
    except Exception as e:
        raise Exception(e)
    return response

def signmessage(rpc_connection, address, message):
    try:
        signature = rpc_connection.signmessage(address, message)
    except Exception as e:
        raise Exception(e)
    return signature

def decoderawtransaction(rpc_connection, tx):
    try:
        decoded = rpc_connection.decoderawtransaction(tx)
    except Exception as e:
        raise Exception(e)
    return decoded

def importprivkey(rpc_connection, privkey):
    try:
        message = rpc_connection.importprivkey(privkey)
    except Exception as e:
        raise Exception(e)
    return message

def sendtoaddress(rpc_connection, address, amount):
    try:
        message = rpc_connection.sendtoaddress(address, amount)
    except Exception as e:
        raise Exception(e)
    return message

def validateaddress(rpc_connection, address):
    try:
        valid = rpc_connection.validateaddress(address)
    except Exception as e:
        raise Exception(e)
    return valid

def sendrawtransaction(rpc_connection, hex):
    tx_id = rpc_connection.sendrawtransaction(hex)
    return tx_id

def sendmany(rpc_connection, from_account, input_json):
    try:
        response = rpc_connection.sendmany("", input_json)
    except Exception as e:
        raise Exception(e)
    return response

# TODO 
def kvupdate(RPC, kv_key, kv_value, kv_days, kv_passphrase):
    txid = RPC.kvupdate(kv_key, kv_value, kv_days, kv_passphrase)
    return txid

def kvsearch(RPC, kv_key):
    kv_response = RPC.kvsearch(kv_key)
    return kv_response

def gettransaction(rpc_connection, tx_id):
    transaction_info = rpc_connection.gettransaction(tx_id)
    return transaction_info


def getrawtransaction(rpc_connection, tx_id):
    rawtransaction = rpc_connection.getrawtransaction(tx_id)
    return rawtransaction


def getbalance(rpc_connection):
    balance = rpc_connection.getbalance()
    return balance

# Token CC calls
def token_create(rpc_connection, name, supply, description):
    token_hex = rpc_connection.tokencreate(name, supply, description)
    return token_hex


def token_info(rpc_connection, token_id):
    token_info = rpc_connection.tokeninfo(token_id)
    return token_info


#TODO: have to add option with pubkey input
def token_balance(rpc_connection, token_id):
    token_balance = rpc_connection.tokenbalance(token_id)
    return token_balance

def token_list(rpc_connection):
    token_list = rpc_connection.tokenlist()
    return token_list


def token_convert(rpc_connection, evalcode, token_id, pubkey, supply):
    token_convert_hex = rpc_connection.tokenconvert(evalcode, token_id, pubkey, supply)
    return token_convert_hex

def get_rawmempool(rpc_connection):
    mempool = rpc_connection.getrawmempool()
    return mempool

# Oracle CC calls
def oracles_create(rpc_connection, name, description, data_type):
    oracles_hex = rpc_connection.oraclescreate(name, description, data_type)
    return oracles_hex

def oracles_fund(rpc_connection, oracle_id):
    oracles_fund_hex = rpc_connection.oraclesfund(oracle_id)
    return oracles_fund_hex

def oracles_register(rpc_connection, oracle_id, data_fee):
    oracles_register_hex = rpc_connection.oraclesregister(oracle_id, data_fee)
    return oracles_register_hex


def oracles_subscribe(rpc_connection, oracle_id, publisher_id, data_fee):
    oracles_subscribe_hex = rpc_connection.oraclessubscribe(oracle_id, publisher_id, data_fee)
    return oracles_subscribe_hex


def oracles_info(rpc_connection, oracle_id):
    oracles_info = rpc_connection.oraclesinfo(oracle_id)
    return oracles_info


def oracles_data(rpc_connection, oracle_id, hex_string):
    oracles_data = rpc_connection.oraclesdata(oracle_id, hex_string)
    return oracles_data


def oracles_list(rpc_connection):
    oracles_list = rpc_connection.oracleslist()
    return oracles_list


def oracles_samples(rpc_connection, oracletxid, batonutxo, num):
    oracles_sample = rpc_connection.oraclessamples(oracletxid, batonutxo, num)
    return oracles_sample


# Gateways CC calls
# Arguments changing dynamically depends of M N, so supposed to wrap it this way
# token_id, oracle_id, coin_name, token_supply, M, N + pubkeys for each N
def gateways_bind(rpc_connection, *args):
    gateways_bind_hex = rpc_connection.gatewaysbind(*args)
    return gateways_bind_hex


def gateways_deposit(rpc_connection, gateway_id, height, coin_name,\
                     coin_txid, claim_vout, deposit_hex, proof, dest_pub, amount):
    gateways_deposit_hex = rpc_connection.gatewaysdeposit(gateway_id, str(height), coin_name,\
                     coin_txid, str(claim_vout), deposit_hex, proof, dest_pub, str(amount))
    return gateways_deposit_hex


def gateways_claim(rpc_connection, gateway_id, coin_name, deposit_txid, dest_pub, amount):
    gateways_claim_hex = rpc_connection.gatewaysclaim(gateway_id, coin_name, deposit_txid, dest_pub, str(amount))
    return gateways_claim_hex


def gateways_withdraw(rpc_connection, gateway_id, coin_name, withdraw_pub, amount):
    gateways_withdraw_hex = rpc_connection.gatewayswithdraw(gateway_id, coin_name, withdraw_pub, amount)
    return gateways_withdraw_hex

def gateways_list(rpc_connection):
    gateways_list = rpc_connection.gatewayslist()
    return gateways_list

def pegs_fund(rpc_connection, pegs_txid, token_txid, amount):
    pegsfund_hex = rpc_connection.pegsfund(pegs_txid, token_txid, str(amount))
    return pegsfund_hex

def pegs_get(rpc_connection, pegs_txid, token_txid, amount):
    pegsget_hex = rpc_connection.pegsget(pegs_txid, token_txid, str(amount))
    return pegsget_hex
