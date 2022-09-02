from .openfood_env import BATCH_NODE
from .openfood_env import BATCH_RPC_USER
from .openfood_env import BATCH_RPC_PASSWORD
from .openfood_env import GTID
from .openfood_env import BATCH_RPC_PORT
from .openfood_env import KV1_NODE
from .openfood_env import KV1_RPC_USER
from .openfood_env import KV1_RPC_PASSWORD
from .openfood_env import KV1_RPC_PORT
from .openfood_env import EXPLORER_URL
from .openfood_env import THIS_NODE_RADDRESS
from .openfood_env import THIS_NODE_WIF
from .openfood_env import BLOCKNOTIFY_CHAINSYNC_LIMIT
from .openfood_env import HOUSEKEEPING_RADDRESS
from .openfood_env import IMPORT_API_BASE_URL
from .openfood_env import DEV_IMPORT_API_RAW_REFRESCO_REQUIRE_INTEGRITY_PATH
from .openfood_env import DEV_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH
from .openfood_env import DEV_IMPORT_API_RAW_REFRESCO_TSTX_PATH
from .openfood_env import openfood_API_BASE_URL
from .openfood_env import openfood_API_ORGANIZATION
from .openfood_env import openfood_API_ORGANIZATION_CERTIFICATE_NORADDRESS
from .openfood_env import openfood_API_ORGANIZATION_CERTIFICATE
from .openfood_env import openfood_API_ORGANIZATION_LOCATION
from .openfood_env import openfood_API_ORGANIZATION_LOCATION_NORADDRESS
from .openfood_env import openfood_API_ORGANIZATION_BATCH
from .openfood_env import FUNDING_AMOUNT_CERTIFICATE
from .openfood_env import FUNDING_AMOUNT_LOCATION
from .openfood_env import FUNDING_AMOUNT_TIMESTAMPING_START
from .openfood_env import FUNDING_AMOUNT_TIMESTAMPING_END
from .openfood_env import DEV_IMPORT_API_RAW_REFRESCO_PATH
from .openfood_env import WALLET_DELIVERY_DATE
from .openfood_env import WALLET_DELIVERY_DATE_THRESHOLD_BALANCE
from .openfood_env import WALLET_DELIVERY_DATE_THRESHOLD_UTXO
from .openfood_env import WALLET_DELIVERY_DATE_THRESHOLD_UTXO_VALUE
from .openfood_env import WALLET_PON
from .openfood_env import WALLET_PON_THRESHOLD_BALANCE
from .openfood_env import WALLET_PON_THRESHOLD_UTXO
from .openfood_env import WALLET_PON_THRESHOLD_UTXO_VALUE
from .openfood_env import WALLET_MASS_BALANCE
from .openfood_env import WALLET_MASS_BALANCE_THRESHOLD_BALANCE
from .openfood_env import WALLET_MASS_BALANCE_THRESHOLD_UTXO
from .openfood_env import WALLET_MASS_BALANCE_THRESHOLD_UTXO_VALUE
from .openfood_env import WALLET_TIN
from .openfood_env import WALLET_TIN_THRESHOLD_BALANCE
from .openfood_env import WALLET_TIN_THRESHOLD_UTXO
from .openfood_env import WALLET_TIN_THRESHOLD_UTXO_VALUE
from .openfood_env import WALLET_PROD_DATE
from .openfood_env import WALLET_PROD_DATE_THRESHOLD_BALANCE
from .openfood_env import WALLET_PROD_DATE_THRESHOLD_UTXO_VALUE
from .openfood_env import WALLET_JULIAN_START
from .openfood_env import WALLET_JULIAN_START_THRESHOLD_BALANCE
from .openfood_env import WALLET_JULIAN_START_THRESHOLD_UTXO
from .openfood_env import WALLET_JULIAN_START_THRESHOLD_UTXO_VALUE
from .openfood_env import WALLET_JULIAN_STOP
from .openfood_env import WALLET_JULIAN_STOP_THRESHOLD_BALANCE
from .openfood_env import WALLET_JULIAN_STOP_THRESHOLD_UTXO
from .openfood_env import WALLET_JULIAN_STOP_THRESHOLD_UTXO_VALUE
from .openfood_env import WALLET_BB_DATE
from .openfood_env import WALLET_BB_DATE_THRESHOLD_BALANCE
from .openfood_env import WALLET_BB_DATE_THRESHOLD_UTXO
from .openfood_env import WALLET_BB_DATE_THRESHOLD_UTXO_VALUE
from .openfood_env import WALLET_ORIGIN_COUNTRY
from .openfood_env import WALLET_ORIGIN_COUNTRY_THRESHOLD_BALANCE
from .openfood_env import WALLET_ORIGIN_COUNTRY_THRESHOLD_UTXO
from .openfood_env import WALLET_ORIGIN_COUNTRY_THRESHOLD_UTXO_VALUE
from .openfood_env import KV1_ORG_POOL_WALLETS
from .openfood_env import WALLET_ALL_OUR_BATCH_LOT
from .openfood_env import WALLET_ALL_OUR_PO
from .openfood_env import WALLET_ALL_CUSTOMER_PO
from .openfood_env import CUSTOMER_RADDRESS
from .openfood_env import HK_LIB_VERSION
from .openfood_env import SATS_10K
from .openfood_env import DISCORD_WEBHOOK_URL

from dotenv import load_dotenv
from typing import List, Tuple, Dict

from . import transaction
from . import bitcoin
from . import rpclib
from .transaction import Transaction
from slickrpc import Proxy
import subprocess
import hashlib
import requests
import time
import json
load_dotenv(verbose=True)
SCRIPT_VERSION = HK_LIB_VERSION
RPC = ""
BATCHRPC=""
KV1RPC = ""
URL_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH = IMPORT_API_BASE_URL + DEV_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH
URL_IMPORT_API_RAW_REFRESCO_TSTX_PATH = IMPORT_API_BASE_URL + DEV_IMPORT_API_RAW_REFRESCO_TSTX_PATH
URL_openfood_API_ORGANIZATION = openfood_API_BASE_URL + openfood_API_ORGANIZATION
URL_openfood_API_ORGANIZATION_BATCH = openfood_API_BASE_URL + openfood_API_ORGANIZATION_BATCH
URL_openfood_API_ORGANIZATION_LOCATION = openfood_API_BASE_URL + openfood_API_ORGANIZATION_LOCATION


# helper methods
def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except ValueError as e:
        return False
    return True


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


def kvupdate_wrapper(kv_key, kv_value, kv_days, kv_passphrase):
    txid = rpclib.kvupdate(KV1RPC, kv_key, kv_value, kv_days, kv_passphrase)
    return txid


def kvsearch_wrapper(kv_key):
    kv_response = rpclib.kvsearch(KV1RPC, kv_key)
    return kv_response


# test skipped
def oracle_create(name, description, data_type):
    or_responce = rpclib.oracles_create(BATCHRPC, name, description, data_type)
    return or_responce


# test skipped
def oracle_fund(or_id):
    or_responce = rpclib.oracles_fund(BATCHRPC, or_id)
    return or_responce


# test skipped
def oracle_register(or_id, data_fee):
    or_responce = rpclib.oracles_register(BATCHRPC, or_id, data_fee)
    return or_responce


# test skipped
def oracle_subscribe(or_id, publisher_id, data_fee):
    or_responce = rpclib.oracles_subscribe(BATCHRPC, or_id, publisher_id, data_fee)
    return or_responce


# test skipped
def oracle_info(or_id):
    or_responce = rpclib.oracles_info(BATCHRPC, or_id)
    return or_responce


# test skipped
def oracle_data(or_id, hex_string):
    or_responce = rpclib.oracles_data(BATCHRPC, or_id, hex_string)
    return or_responce


# test skipped
def oracle_list():
    or_responce = rpclib.oracles_list(BATCHRPC)
    return or_responce


# test skipped
def oracle_samples(oracletxid, batonutxo, num):
    or_responce = rpclib.oracles_samples(BATCHRPC, oracletxid, batonutxo, num)
    return or_responce


def find_oracleid_with_pubkey(pubkey):
	or_responce = oracle_list()
	for oracle in or_responce:
		oracle = oracle_info(oracle)
		for registered in oracle['registered']:
			if registered['publisher'] == pubkey:
				return oracle['txid']


def pogtid(po):
    total = po + GTID
    total = total.encode()
    total = hashlib.sha256(total)
    total = total.hexdigest()
    return total


def sendtoaddress_wrapper(to_address, amount):
    send_amount = round(amount, 10)
    txid = rpclib.sendtoaddress(BATCHRPC, to_address, send_amount)
    return txid


def getrawmempool_wrapper():
    return rpclib.get_rawmempool(BATCHRPC)


def decoderawtransaction_wrapper(rawtx):
    return rpclib.decoderawtransaction(BATCHRPC, rawtx)


def sendmany_wrapper(from_address, recipients_json):
    txid = rpclib.sendmany(BATCHRPC, from_address, recipients_json)
    return txid


def signmessage_wrapper(data):
    signed_data = rpclib.signmessage(BATCHRPC, THIS_NODE_RADDRESS, data)
    return signed_data


def housekeeping_tx(amount):
    return sendtoaddress_wrapper(HOUSEKEEPING_RADDRESS, amount)


def sendtoaddressWrapper(address, amount, amount_multiplier):
    print("Deprecated: use sendtoaddress_wrapper")
    send_amount = round(amount * amount_multiplier, 10)  # rounding 10??
    txid = rpclib.sendtoaddress(BATCHRPC, address, send_amount)
    return txid


def check_sync():
    general_info = rpclib.getinfo(BATCHRPC)
    sync = general_info['longestchain'] - general_info['blocks']

    print("Chain info.  Longest chain, blocks, sync diff")
    print(general_info['longestchain'])

    print(general_info['blocks'])

    print(sync)

    if sync >= BLOCKNOTIFY_CHAINSYNC_LIMIT:
        print('the chain is not synced, try again later')
        exit()

    print("Chain is synced")
    return True


# test skipped
def get_this_node_raddress():
    return THIS_NODE_RADDRESS


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


# test skipped
def generate_pool_wallets():
    wallet_all_our_po = getOfflineWalletByName(WALLET_ALL_OUR_PO)
    wallet_all_our_batch = getOfflineWalletByName(WALLET_ALL_OUR_BATCH_LOT)
    wallet_all_customer_po = getOfflineWalletByName(WALLET_ALL_CUSTOMER_PO)
    pool_wallets = {}
    pool_wallets[str(WALLET_ALL_OUR_PO)] = wallet_all_our_po["address"]
    pool_wallets[str(WALLET_ALL_OUR_BATCH_LOT)] = wallet_all_our_batch["address"]
    pool_wallets[str(WALLET_ALL_CUSTOMER_PO)] = wallet_all_customer_po["address"]
    print("pool wallets: " + json.dumps(pool_wallets))
    return pool_wallets


# test skipped
def verify_kv_pool_wallets():
    pool_wallets = generate_pool_wallets()
    print("Verifying pool wallets in KV1")
    org_kv1_key_pool_wallets = THIS_NODE_RADDRESS + KV1_ORG_POOL_WALLETS
    kv_response = kvsearch_wrapper(org_kv1_key_pool_wallets)
    if( kv_response.get("error")):
        print("Updating with a value")
        kv_response = kvupdate_wrapper(org_kv1_key_pool_wallets, json.dumps(pool_wallets), "3", "password")
        print(kv_response)
    else:
        print("kv exists for pool wallets")


# test skipped
def organization_get_pool_wallets_by_raddress(raddress):
    print("GET POOL WALLETS BY RADDRESS: " + raddress)
    kv_response = kvsearch_wrapper(raddress + KV1_ORG_POOL_WALLETS)
    return kv_response


# test skipped
def kv_save_batch_to_raddress(batch, raddress):
    kv_response = kvupdate_wrapper(batch, raddress, "100", "password")
    return kv_response


# test skipped
def kv_save_raddress_to_data(raddress, data):
    kv_response = kvupdate_wrapper(raddress, data, "100", "password")
    return kv_response


# test skipped
def kv_get_by_raddress(raddress):
    kv_response = kvsearch_wrapper(raddress)
    return kv_response


def deprecated_fund_offline_wallet(offline_wallet_raddress):
    print("DEPRECATED WARNING: fund_offline_wallet")
    json_object = {
     offline_wallet_raddress: 11.2109
     }
    sendmany_txid = sendmany_wrapper(THIS_NODE_RADDRESS, json_object)
    return sendmany_txid


def fund_offline_wallet2(offline_wallet_raddress, send_amount):
    json_object = {
     offline_wallet_raddress: send_amount
     }
    sendmany_txid = sendmany_wrapper(THIS_NODE_RADDRESS, json_object)
    return sendmany_txid


def is_below_threshold_balance(check_this, balance_threshold):
    if check_this * 1.2 < balance_threshold * 100000000:
        return True

def save_wallets_data(data, wallet_name, folder='./wallets'):
    with open(folder+"/"+wallet_name+".json", "r") as jsonFile:
      wallet_data = json.load(jsonFile)
    wallet_data.append(data)
    with open(folder+"/"+wallet_name+".json", "w") as jsonFile:
      json.dump(wallet_data, jsonFile)

def check_offline_wallets(save=False):
    print("Check offline wallets: getXXXWallet, getBalance (if low then fund), getUTXOCount")
    funding_txid = 0
    wallet_delivery_date = getOfflineWalletByName(WALLET_DELIVERY_DATE)
    wallet_pon = getOfflineWalletByName(WALLET_PON)
    wallet_tin = getOfflineWalletByName(WALLET_TIN)
    wallet_prod_date = getOfflineWalletByName(WALLET_PROD_DATE)
    wallet_julian_start = getOfflineWalletByName(WALLET_JULIAN_START)
    wallet_julian_stop = getOfflineWalletByName(WALLET_JULIAN_STOP)
    wallet_origin_country = getOfflineWalletByName(WALLET_ORIGIN_COUNTRY)
    wallet_bb_date = getOfflineWalletByName(WALLET_BB_DATE)
    wallet_mass_balance = getOfflineWalletByName(WALLET_MASS_BALANCE)

    # print("Checking delivery date wallet: " + wallet_delivery_date['address'])
    # check balance
    wallet_delivery_date_balance = int(explorer_get_balance(wallet_delivery_date['address']))
    print(wallet_delivery_date_balance)
    if is_below_threshold_balance(wallet_delivery_date_balance, WALLET_DELIVERY_DATE_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_DELIVERY_DATE + " wallet because balance low")
        funding_txid = fund_offline_wallet2(wallet_delivery_date['address'], WALLET_DELIVERY_DATE_THRESHOLD_BALANCE/WALLET_DELIVERY_DATE_THRESHOLD_UTXO)
        print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_delivery_date['address']))
          utxos_total = len(utxos)
          if utxos_total == 0:
            utxos.append('null')
          else: utxos.sort(key = lambda json: json['amount'], reverse=False)
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_DELIVERY_DATE,
            'wallet': wallet_delivery_date['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_delivery_date_balance
          }
          save_wallets_data(wallet_data, WALLET_DELIVERY_DATE)

    wallet_mass_balance_balance = int(explorer_get_balance(wallet_mass_balance['address']))
    print(wallet_mass_balance)
    if is_below_threshold_balance(wallet_mass_balance_balance, WALLET_MASS_BALANCE_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_MASS_BALANCE + " wallet because balance low")
        funding_txid = fund_offline_wallet2(wallet_mass_balance['address'], WALLET_MASS_BALANCE_THRESHOLD_BALANCE/WALLET_MASS_BALANCE_THRESHOLD_UTXO)
        print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_mass_balance['address']))
          utxos_total = len(utxos)
          if utxos_total == '0':
            utxos.append('null')
          else: utxos.sort(key = lambda json: json['amount'], reverse=False)
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_MASS_BALANCE,
            'wallet': wallet_mass_balance['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_mass_balance_balance
          }
          save_wallets_data(wallet_data, WALLET_MASS_BALANCE)

    wallet_pon_balance = int(explorer_get_balance(wallet_pon['address']))
    print(wallet_pon_balance)
    if is_below_threshold_balance(wallet_pon_balance, WALLET_PON_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_PON + " wallet because balance low")
        funding_txid = fund_offline_wallet2(wallet_pon['address'], WALLET_PON_THRESHOLD_BALANCE/WALLET_PON_THRESHOLD_UTXO)
        print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_pon['address']))
          utxos_total = len(utxos)
          if utxos_total == '0':
            utxos.append('null')
          else: utxos.sort(key = lambda json: json['amount'], reverse=False)
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_PON,
            'wallet': wallet_pon['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_pon_balance
          }
          save_wallets_data(wallet_data, WALLET_PON)

    wallet_tin_balance = int(explorer_get_balance(wallet_tin['address']))
    print(wallet_tin_balance)
    if is_below_threshold_balance(wallet_tin_balance, WALLET_TIN_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_TIN + " wallet because balance low")
        funding_txid = fund_offline_wallet2(wallet_tin['address'], WALLET_TIN_THRESHOLD_BALANCE/WALLET_TIN_THRESHOLD_UTXO)
        print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_tin['address']))
          utxos_total = len(utxos)
          if utxos_total == '0':
            utxos.append('null')
          else: utxos.sort(key = lambda json: json['amount'], reverse=False)
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_TIN,
            'wallet': wallet_tin['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_tin_balance
          }
          save_wallets_data(wallet_data, WALLET_TIN)

    wallet_prod_date_balance = int(explorer_get_balance(wallet_prod_date['address']))
    print(wallet_prod_date_balance)
    if is_below_threshold_balance(wallet_prod_date_balance, WALLET_PROD_DATE_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_PROD_DATE + " wallet because balance low")
        funding_txid = fund_offline_wallet2(wallet_prod_date['address'], WALLET_PROD_DATE_THRESHOLD_BALANCE/WALLET_TIN_THRESHOLD_UTXO)
        print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_prod_date['address']))
          utxos_total = len(utxos)
          if utxos_total == '0':
            utxos.append('null')
          else: utxos.sort(key = lambda json: json['amount'], reverse=False)
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_PROD_DATE,
            'wallet': wallet_prod_date['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_prod_date_balance
          }
          save_wallets_data(wallet_data, WALLET_PROD_DATE)

    wallet_julian_start_balance = int(explorer_get_balance(wallet_julian_start['address']))
    print(wallet_julian_start_balance)
    if is_below_threshold_balance(wallet_julian_start_balance, WALLET_JULIAN_START_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_JULIAN_START + " wallet because balance low")
        funding_txid = fund_offline_wallet2(wallet_julian_start['address'], WALLET_JULIAN_START_THRESHOLD_BALANCE/WALLET_JULIAN_START_THRESHOLD_UTXO)
        print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_julian_start['address']))
          utxos_total = len(utxos)
          if utxos_total == '0':
            utxos.append('null')
          else: utxos.sort(key = lambda json: json['amount'], reverse=False)
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_JULIAN_START,
            'wallet': wallet_julian_start['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_julian_start_balance
          }
          save_wallets_data(wallet_data, WALLET_JULIAN_START)

    wallet_julian_stop_balance = int(explorer_get_balance(wallet_julian_stop['address']))
    print(wallet_julian_stop_balance)
    if is_below_threshold_balance(wallet_julian_stop_balance, WALLET_JULIAN_STOP_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_JULIAN_STOP + " wallet because balance low")
        funding_txid = fund_offline_wallet2(wallet_julian_stop['address'], WALLET_JULIAN_STOP_THRESHOLD_BALANCE/WALLET_JULIAN_STOP_THRESHOLD_UTXO)
        print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_julian_stop['address']))
          utxos_total = len(utxos)
          if utxos_total == '0':
            utxos.append('null')
          else: utxos.sort(key = lambda json: json['amount'], reverse=False)
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_JULIAN_STOP,
            'wallet': wallet_julian_stop['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_julian_stop_balance
          }
          save_wallets_data(wallet_data, WALLET_JULIAN_STOP)

    wallet_origin_country_balance = int(explorer_get_balance(wallet_origin_country['address']))
    print(wallet_origin_country_balance)
    if is_below_threshold_balance(wallet_origin_country_balance, WALLET_ORIGIN_COUNTRY_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_ORIGIN_COUNTRY + " wallet because balance low")
        funding_txid = fund_offline_wallet2(wallet_origin_country['address'], WALLET_ORIGIN_COUNTRY_THRESHOLD_BALANCE/WALLET_ORIGIN_COUNTRY_THRESHOLD_UTXO)
        print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_origin_country['address']))
          utxos.sort(key = lambda json: json['amount'], reverse=False)
          utxos_total = len(utxos)
          if utxos_total == '0':
            utxos.append('null')
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_ORIGIN_COUNTRY,
            'wallet': wallet_origin_country['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_origin_country_balance
          }
          save_wallets_data(wallet_data, WALLET_ORIGIN_COUNTRY)

    wallet_bb_date_balance = int(explorer_get_balance(wallet_bb_date['address']))
    print(wallet_bb_date_balance)
    if is_below_threshold_balance(wallet_bb_date_balance, WALLET_BB_DATE_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_BB_DATE + " wallet because balance low")
        funding_txid = fund_offline_wallet2(wallet_bb_date['address'], WALLET_BB_DATE_THRESHOLD_BALANCE/WALLET_BB_DATE_THRESHOLD_UTXO)
        print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_bb_date['address']))
          utxos.sort(key = lambda json: json['amount'], reverse=False)
          utxos_total = len(utxos)
          if utxos_total == '0':
            utxos.append('null')
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_BB_DATE,
            'wallet': wallet_bb_date['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_bb_date_balance
          }
          save_wallets_data(wallet_data, WALLET_BB_DATE)
    return funding_txid


# test skipped
def organization_certificate_noraddress(url, org_id, THIS_NODE_RADDRESS):
    try:
        res = requests.get(url)
    except Exception as e:
        raise Exception(e)

    certs_no_addy = res.text
    certs_no_addy = json.loads(certs_no_addy)
    # the issuer, issue date, expiry date, identifier (not the db id, the certificate serial number / identfier)

    for cert in certs_no_addy:
        raw_json = {
            "issuer": cert['issuer'],
            "issue_date": cert['date_issue'],
            "expiry_date": cert['date_expiry'],
            "identfier": cert['identifier']
        }
        raw_json = json.dumps(raw_json)
        addy = gen_wallet(raw_json)
        # id = str(cert['id'])
        # url = IMPORT_API_BASE_URL + openfood_API_ORGANIZATION_CERTIFICATE + id + "/"

        try:
            data = {"raddress": addy['address'], "pubkey": addy['pubkey']}
            res = requests.patch(url, data=data)
        except Exception as e:
            raise Exception(e)


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


def explorer_get_transaction(txid):
    print("Get transaction " + txid)
    INSIGHT_API_KOMODO_TXID = "insight-api-komodo/tx/" + txid
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_TXID)
    except Exception as e:
        raise Exception(e)
    return res.text


def explorer_get_balance(querywallet):
    print("Get balance for wallet: " + querywallet)
    INSIGHT_API_KOMODO_ADDRESS_BALANCE = "insight-api-komodo/addr/" + querywallet + "/balance"
    try:
        res = requests.get(EXPLORER_URL + INSIGHT_API_KOMODO_ADDRESS_BALANCE)
    except Exception as e:
        raise Exception(e)
    return int(res.text)


def createrawtx_wrapper(txids, vouts, to_address, amount):
    return rpclib.createrawtransaction(BATCHRPC, txids, vouts, to_address, amount)


def createrawtxwithchange(txids, vouts, to_address, amount, change_address, change_amount):
    # print(to_address)
    # print(amount)
    # print(change_address)
    # print(change_amount)
    return rpclib.createrawtransactionwithchange(BATCHRPC, txids, vouts, to_address, amount, change_address, change_amount)


def createrawtx_split_wallet(txids, vouts, to_address, amount, change_address, change_amount):
    # print(to_address)
    # print(amount)
    # print(change_address)
    # print(change_amount)
    return rpclib.createrawtransactionsplit(BATCHRPC, txids, vouts, to_address, amount, change_address, change_amount)


def createrawtx(txids, vouts, to_address, amount):
    print("Deprecated: use createrawtx_wrapper")
    return rpclib.createrawtransaction(BATCHRPC, txids, vouts, to_address, amount)

def createrawtx_dev(utxos_json, to_address, to_amount, fee, change_address=""):
    # check if utxos_json list is not empty
    num_utxo = len(utxos_json)
    if( num_utxo == 0 ):
        print("utxos are required (list)")
        return

    # check if total utxos_json < 300 to handle too much request (can be changed)
    if( num_utxo >= 300 ):
        print("too much use of utxos (max. 300)")
        return

    # calculate utxos amount
    amount = utxo_bundle_amount(utxos_json)

    # to amount = all amount of utxos_json (can be used for consolidating utxos)
    if to_amount == 'all' or to_amount == amount:
        to_amount = amount
        change_address = ""

    # amount after fee
    change_amount = round(amount - fee, 10)

    # stop if utxos amount (after fee) < to_amount
    if change_amount < to_amount:
        print(
            'insufficient amount',
            f'total amount: {amount}',
            f'send amount: {to_amount}',
            f'fee: {fee}'
        )
        return

    # get all txid utxos and convert to list
    txids = [d['txid'] for d in utxos_json]

    # get all vout utxos and convert to list
    vouts = [d['vout'] for d in utxos_json]

    # satoshis
    satoshis = [d['satoshis'] for d in utxos_json]

    # change amount (reduced by to_amount)
    change_amount = round(change_amount - to_amount, 10)

    if change_address:
        rawtx = createrawtxwithchange(txids, vouts, to_address, to_amount, change_address, change_amount)
    else:
        if change_amount > 0:
            print('change_address is required')
            return
        rawtx = createrawtx_wrapper(txids, vouts, to_address, to_amount)
    # return rawtx and satoshis (append to list)
    return {"rawtx": rawtx, "satoshis": satoshis}

def createrawtxsplit(utxo, split_count, split_value, hash160, wif):
    # get public key by private key
    txin_type, privkey, compressed = bitcoin.deserialize_privkey(wif)
    pubkey = bitcoin.public_key_from_private_key(privkey, compressed)

    # give a limitation for spliting
    if split_count > 252:
        print(
          'can\'t split into 252 utxo at once'
        )
        return

    # check sufficiency amount
    amount = utxo['amount']
    split_total = split_value * split_count
    split_total_satoshi = int(split_value * split_count * 100000000)
    if split_total > amount:
        print(
          'invalid split configuration',
          f'can\'t split {amount} as {split_count} of {split_value}'
        )
        return
    split_value_satoshi = int(split_value * 100000000)
    txid = utxo['txid']
    vout = utxo['vout']
    satoshis = utxo['satoshis']

    rev_txid = txid[::-1]
    hex_txid = ''.join([ rev_txid[x:x+2][::-1] for x in range(0, len(rev_txid), 2) ])
    vout = '{:08x}'.format(vout)
    rev_vout = vout[::-1]
    hex_vout = ''.join([ rev_vout[x:x+2][::-1] for x in range(0, len(rev_vout), 2) ])

    # using create raw transaction v.1
    rawtx = "01000000"
    # number of vin = 1 (split 1 utxo json only)
    rawtx = rawtx+"01"
    rawtx = rawtx+hex_txid+hex_vout+"00ffffffff"

    oc = int(split_count+1)
    outputCount = '{:02x}'.format(oc)
    rawtx = rawtx+outputCount
    value = '{:016x}'.format(split_value_satoshi)
    rev_value = value[::-1]
    hex_value = ''.join([ rev_value[x:x+2][::-1] for x in range(0, len(rev_value), 2) ])
    for i in range(0, split_count):
        rawtx = rawtx+hex_value
        rawtx = rawtx + "2321" + pubkey + "ac"

    # change = (satoshis - split_total_satoshi) / 100000000
    change_satoshis = satoshis - split_total_satoshi

    value = '{:016x}'.format(change_satoshis)
    rev_value = value[::-1]
    hex_value = ''.join([ rev_value[x:x+2][::-1] for x in range(0, len(rev_value), 2) ])

    rawtx = rawtx+hex_value
    # len OP_DUP OP_HASH160 len hash OP_EQUALVERIFY OP_CHECKSIG
    rawtx = rawtx+"1976a914"+hash160+"88ac"

    nlocktime = int(time.time())
    value = '{:08x}'.format(nlocktime)
    rev_value = value[::-1]
    hex_value = ''.join([ rev_value[x:x+2][::-1] for x in range(0, len(rev_value), 2) ])
    rawtx = rawtx + hex_value
    return {"rawtx": rawtx, "satoshis": [satoshis]}

def utxo_combine(utxos_json, address, wif):
    # send several utxos amount to self address (all amount) to combine utxo
    rawtx_info = createrawtx_dev(utxos_json, address, 'all', 0)
    signedtx = signtx(rawtx_info['rawtx'], rawtx_info['satoshis'], wif)
    txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    return txid

def utxo_send(utxos_json: List[Dict[str, str]], amount: float, to_address: str, wif: str, change_address=""):
    # send several utxos (all or several amount) to a spesific address
    if not utxos_json:
        raise Exception("List is empty")

    if utxos_json:
        if type(utxos_json[0]) is not dict:
            raise Exception("Value must be dict")

    if type(amount) is not float:
        raise Exception("Amount must be float")

    if type(to_address) is not str:
        raise Exception("To Address must be string")

    if type(wif) is not str:
        raise Exception("Wif must be string")

    if type(change_address) is not str:
        raise Exception("Change Address must be string")

    try:
        rawtx_info = createrawtx_dev(utxos_json, to_address, amount, 0, change_address)
        signedtx = signtx(rawtx_info['rawtx'], rawtx_info['satoshis'], wif)
        txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    except Exception as e:
        raise Exception(e)
    return txid

def utxo_split(utxo_json, address, wif, hash160):
    # send several utxos (all or several amount) to a spesific address
    rawtx_info = createrawtxsplit(utxo_json, 1, 0.0001, hash160, wif)
    signedtx = signtx(rawtx_info['rawtx'], rawtx_info['satoshis'], wif)
    txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    return txid


def utxo_slice_by_amount(utxos_json, min_amount):
    # Slice UTXOS based on certain amount
    utxos_json.sort(key = lambda json: json['amount'], reverse=True)
    utxos_slice = []
    amount = 0
    for x in utxos_json:
      if amount < min_amount:
        utxos_slice.append(x)
        amount += x["amount"]
      else: break
    if len(utxos_slice) == 0:
      print(f'Need more UTXO for minimal amount: {min_amount}')
    return utxos_slice


def utxo_slice_by_amount2(utxos_json, min_amount, raw_tx_meta):
    # Slice UTXOS based on certain amount
    utxos_json.sort(key = lambda json: json['amount'], reverse=True)
    utxos_slice = []
    attempted_txids = raw_tx_meta['attempted_txids']
    amount = 0
    print("utxo_slice_by_amount2: ", raw_tx_meta)
    for x in utxos_json:
      # Check if x exist in the raw_tx_meta
      # If yes, skip through it
      if raw_tx_meta['attempted_txids']:
        if x['txid'] in raw_tx_meta['attempted_txids']:
            continue
      if amount < min_amount:
        utxos_slice.append(x)
        attempted_txids.append(x['txid'])
        amount += x["amount"]
      else: break
    if len(utxos_slice) == 0:
      print(f'Need more UTXO for minimal amount: {min_amount}')

    raw_tx_meta['utxos_slice'] = utxos_slice
    raw_tx_meta['attempted_txids'] = attempted_txids
    return raw_tx_meta


# test skipped
def createrawtx7(utxos_json, num_utxo, to_address, to_amount, fee, change_address, split=False):
    # check createrawtx6 comments
    print("createrawtx7()")

    if( num_utxo == 0 ):
        print("ERROR: createrawtx_error, num_utxo == 0")
        return

    print("to address: " + str(to_address) + " , to amount: " + str(to_amount))
    rawtx_info = []  # return this with rawtx & amounts
    utxos = json.loads(utxos_json)
    count = 0

    txids = []
    vouts = []
    amounts = []
    amount = 0

    for utxo in utxos:
        if (utxo['amount'] > 0.2 and utxo['confirmations'] > 2) and count < num_utxo:
            count = count + 1
            vout_as_array = [utxo['vout']]
            txid_as_array = [utxo['txid']]
            txids.extend(txid_as_array)
            vouts.extend(vout_as_array)
            amount = amount + utxo['amount']
            amounts.extend([utxo['satoshis']])

    if( amount > to_amount ):
        change_amount = round(amount - fee - to_amount, 10)
    else:
        # TODO
        print("### ERROR ### Needs to be caught, the to_amount is larger than the utxo amount, need more utxos")
        return
        # change_amount = round(to_amount - amount - fee, 10)
    print("amount >=")
    print(amount)
    print("to_amount + change_amount + fee")
    print(to_amount)
    print(float(change_amount))
    print(fee)
    rawtx = ""
    if( change_amount < 0.01 ):
        print("Change too low, sending as miner fee " + str(change_amount))
        change_amount = 0
        rawtx = createrawtx(txids, vouts, to_address, round(amount - fee, 10))

    else:
        if(split):
            print("Creating raw tx for split_wallet")
            rawtx = createrawtx_split_wallet(txids, vouts, to_address, to_amount, change_address, float(change_amount))
        else:
            print("Creating raw tx with change")
            rawtx = createrawtxwithchange(txids, vouts, to_address, to_amount, change_address, float(change_amount))

    rawtx_info.append({'rawtx': rawtx})
    rawtx_info.append({'amounts': amounts})
    print("raw tx created: ")
    print(rawtx_info)

    return rawtx_info

# test skipped
def createrawtx6(utxos_json, num_utxo, to_address, to_amount, fee, change_address):
    print(to_address)
    # check this file in commit https://github.com/The-New-Fork/blocknotify-python/commit/f91a148b18840aaf08d7c7736045a8c924bd236b
    # for to_amount.  When a wallet had no utxos, the resulting change was -0.00123, some sort of mis-naming maybe?
    #to_amount = 0.00123
    # MITIGATE ^^
    if( num_utxo == 0 ):
        return

    print(to_amount)
    rawtx_info = []  # return this with rawtx & amounts
    utxos = json.loads(utxos_json)
    # utxos.reverse()
    count = 0

    txids = []
    vouts = []
    amounts = []
    amount = 0

    for objects in utxos:
        if (objects['amount'] > 0.2 and objects['confirmations'] > 2) and count < num_utxo:
            count = count + 1
            easy_typeing2 = [objects['vout']]
            easy_typeing = [objects['txid']]
            txids.extend(easy_typeing)
            vouts.extend(easy_typeing2)
            amount = amount + objects['amount']
            amounts.extend([objects['satoshis']])

    # check this file in commit https://github.com/The-New-Fork/blocknotify-python/commit/f91a148b18840aaf08d7c7736045a8c924bd236b
    # for to_amount.  When a wallet had no utxos, the resulting change was -0.00123, some sort of mis-naming maybe?
    #to_amount = 0.00123
    # change_tmp = 0
    if( amount > to_amount ):
        change_amount = round(amount - fee - to_amount, 10)
    else:
        # TODO
        print("### ERROR ### Needs to be caught, the to_amount is larger than the utxo amount, need more utxos")
        change_amount = round(to_amount - amount - fee, 10)
    print("AMOUNTS: amount, #to_amount, change_amount, fee")
    print(amount)
    print(to_amount)
    print(float(change_amount))
    print(fee)
    rawtx = ""
    if( change_amount < 0.01 ):
        print("Change too low, sending as miner fee " + str(change_amount))
        change_amount = 0
        rawtx = createrawtx(txids, vouts, to_address, round(amount - fee, 10))

    else:
        rawtx = createrawtxwithchange(txids, vouts, to_address, to_amount, change_address, float(change_amount))

    rawtx_info.append({'rawtx': rawtx})
    rawtx_info.append({'amounts': amounts})
    return rawtx_info

# deprecated
def createrawtx5(utxos_json, num_utxo, to_address, fee, change_address):
    print("DEPRECATED WARNING: createrawtx5")
    rawtx_info = []  # return this with rawtx & amounts
    utxos = json.loads(utxos_json)
    # utxos.reverse()
    count = 0

    txids = []
    vouts = []
    amounts = []
    amount = 0

    for objects in utxos:
        if (objects['amount'] > 0.00005 and objects['confirmations'] > 2) and count < num_utxo:
            count = count + 1
            easy_typeing2 = [objects['vout']]
            easy_typeing = [objects['txid']]
            txids.extend(easy_typeing)
            vouts.extend(easy_typeing2)
            amount = amount + objects['amount']
            amounts.extend([objects['satoshis']])

    # check this file in commit https://github.com/The-New-Fork/blocknotify-python/commit/f91a148b18840aaf08d7c7736045a8c924bd236b
    # for to_amount.  When a wallet had no utxos, the resulting change was -0.00123, some sort of mis-naming maybe?
    #to_amount = 0.00123
    change_tmp = 0
    change_amount = round(amount - fee - change_tmp, 10)
    print("AMOUNTS: amount, #to_amount, change_amount, fee")
    print(amount)
    # print(to_amount)
    print(change_amount)
    print(fee)

    # rawtx = createrawtxwithchange(txids, vouts, to_address, to_amount, change_address, change_amount)
    rawtx = createrawtxwithchange(txids, vouts, to_address, change_tmp, change_address, change_amount)
    rawtx_info.append({'rawtx': rawtx})
    rawtx_info.append({'amounts': amounts})
    return rawtx_info

# deprecated
def createrawtx4(utxos_json, num_utxo, to_address, fee):
    print("DEPRECATED WARNING: createrawtx4")
    rawtx_info = []  # return this with rawtx & amounts
    utxos = json.loads(utxos_json)
    utxos.reverse()
    count = 0

    txids = []
    vouts = []
    amounts = []
    amount = 0

    for objects in utxos:
        if (objects['amount'] > 0.00005) and count < num_utxo:
            count = count + 1
            easy_typeing2 = [objects['vout']]
            easy_typeing = [objects['txid']]
            txids.extend(easy_typeing)
            vouts.extend(easy_typeing2)
            amount = amount + objects['amount']
            amounts.extend([objects['satoshis']])

    amount = round(amount, 10)
    print("AMOUNT")
    print(amount)

    rawtx = createrawtx(txids, vouts, to_address, round(amount - fee, 10))
    rawtx_info.append({'rawtx': rawtx})
    rawtx_info.append({'amounts': amounts})
    return rawtx_info


def decoderawtx_wrapper(tx):
    return rpclib.decoderawtransaction(BATCHRPC, tx)


def decoderawtx(tx):
    print("Deprecated: use decoderawtx_wrapper(tx)")
    return rpclib.decoderawtransaction(BATCHRPC, tx)


def signtx(kmd_unsigned_tx_serialized, amounts, wif):
    txin_type, privkey, compressed = bitcoin.deserialize_privkey(wif)
    pubkey = bitcoin.public_key_from_private_key(privkey, compressed)

    jsontx = transaction.deserialize(kmd_unsigned_tx_serialized)
    inputs = jsontx.get('inputs')
    outputs = jsontx.get('outputs')
    locktime = jsontx.get('lockTime', 0)
    outputs_formatted = []
    # print("\n###### IN SIGNTX FUNCTION #####\n")
    # print(jsontx)
    # print(inputs)
    # print(outputs)
    # print(locktime)

    for txout in outputs:
        outputs_formatted.append([txout['type'], txout['address'], (txout['value'])])
        # print("Value of out before miner fee: " + str(txout['value']))
        # print("Value of out: " + str(txout['value']))

    # print("\nOutputs formatted:\n")
    # print(outputs_formatted)

    for txin in inputs:
        txin['type'] = txin_type
        txin['x_pubkeys'] = [pubkey]
        txin['pubkeys'] = [pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1
        txin['address'] = bitcoin.address_from_private_key(wif)
        txin['value'] = amounts[inputs.index(txin)]  # required for preimage calc

    tx = Transaction.from_io(inputs, outputs_formatted, locktime=locktime)
    # print("### TX before signing###")
    # print(tx)
    # print("### END TX ###")
    tx.sign({pubkey: (privkey, compressed)})


    # print("\nSigned tx:\n")
    # print(tx.serialize())
    # print("Return from signtx")
    return tx.serialize()


# test skipped
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

def gen_wallet(data, label='NoLabelOK', verbose=False):
    if verbose:
        print("Creating a %s address signing with %s and data %s" % (label, THIS_NODE_RADDRESS, data))
    signed_data = rpclib.signmessage(BATCHRPC, THIS_NODE_RADDRESS, data)
    print("Signed data is %s" % (signed_data))
    new_wallet_json = subprocess.getoutput("php genwallet.php " + signed_data)
    new_wallet = json.loads(new_wallet_json)
    if verbose:
        print("Created wallet %s" % (new_wallet["address"]))


    return new_wallet


def getOfflineWalletByName(name):
    obj = {
        "name": name
    }
    raw_json = json.dumps(obj)
    log_label = name
    offline_wallet = gen_wallet(raw_json, log_label)
    return offline_wallet


# test skipped
def dateToSatoshi(date):
    formatDate = int(date.replace('-', ''))
    result = round(formatDate/100000000, 10)
    print(f"converted {date} to {result} coins")
    return result


def sendToBatchMassBalance(batch_raddress, mass_balance_value, integrity_id):
    # delivery date
    print("SEND MASS BALANCE")
    mass_balance_wallet = getOfflineWalletByName(WALLET_MASS_BALANCE)
    utxos_json = explorer_get_utxos(mass_balance_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx6(utxos_json, 1, batch_raddress, round(mass_balance_value/1, 10), 0, mass_balance_wallet['address'])
    print("MASS BALANCE RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], mass_balance_wallet['wif'])
    mass_balance_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id,WALLET_MASS_BALANCE, mass_balance_wallet['address'], mass_balance_txid["txid"])
    return mass_balance_txid["txid"]


# deprecated
def massBalanceIntoApi(mass_balance_txid, mass_balance_value, id):
   url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_BATCH + str(id) + "/"
  # data = { "mass_balance_value":mass_balance_value,
   #"mass_balance_txid":mass_balance_txid}
   data = {
    #"id": 1,
    #"identifier": "ID-8038356",
    #"jds": 96,
    #"jde": 964,
    #"date_production_start": "2020-06-09",
    #"date_best_before": "2020-06-09",
    #"delivery_date": None,
    #"origin_country": "DE",
    #"pubkey": "027e0232fe7c10751bf214206d2c03c4ae4d7ea5f1eeb5c3cd5136a19ddadd4cee",
    #"raddress": "RTSEYsRCMzkWIpUBCLXWGHqdtQgjDDilVN",
    "mass_balance_value": mass_balance_value,
    "mass_balance_txid": mass_balance_txid,
    #"organization": 1
   }
   answere = requests.patch(url, data=data)
   print("post: " + answere.text)
   return answere


def rToId(batch_raddress):
   url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_BATCH
   batches = getWrapper(url)
   batches = json.loads(batches)
   for batch in batches:
       if batch['raddress'] == batch_raddress:
            return batch['id']

   return None


# test skipped
def save_batch_timestamping_tx(integrity_id, sender_name, sender_wallet, txid):
    tstx_data = {'sender_raddress': sender_wallet,
                 'tsintegrity': integrity_id, 'sender_name': sender_name, 'txid': txid}
    # print(tstx_data)
    ts_response = postWrapper(URL_IMPORT_API_RAW_REFRESCO_TSTX_PATH, tstx_data)
    print(ts_response)
    return ts_response


# deprecated
# no test
def sendAndPatchMassBalance(batch_raddress, mass_balance_value):
   txid = sendToBatchMassBalance(batch_raddress, mass_balance_value)
   id = rToId(batch_raddress)
   answere = massBalanceIntoApi(txid, mass_balance_value, id)
   return answere


# no test
def split_wallet1():
    print("split_wallet1()")
    delivery_date_wallet = getOfflineWalletByName(WALLET_DELIVERY_DATE)
    utxos_json = explorer_get_utxos(delivery_date_wallet['address'])


# no test
def sendToBatch(wallet_name, threshold, batch_raddress, amount, integrity_id):
    # print(f"SEND {wallet_name}, check accuracy")
    # save current tx state
    raw_tx_meta = {}
    attempted_txids = []

    # Generate Wallet
    if isinstance(amount, str):
        amount = dateToSatoshi(amount)

    wallet = getOfflineWalletByName(wallet_name)

    utxos_json = explorer_get_utxos(wallet['address'])
    utxos_json = json.loads(utxos_json)

    # Check if no utxos
    if len(utxos_json) == 0:
        print(f'sendToBatch {wallet_name} Error: Need more UTXO! '+ wallet['address'])
        return

    # Filter utxos that has > 2 confirmations on blockchain
    utxos_json = [x for x in utxos_json if x['confirmations'] > 2]
    if len(utxos_json) == 0:
        print(f'222 One of UTXOS must have at least 2 confirmations on blockchain')
        return

    utxo_amount = utxo_bundle_amount(utxos_json);
    if utxo_amount < threshold:
        print(f'UTXO amount ({utxo_amount}) must have value t= Threshold ({threshold})')
        return

    # Execute
    utxos_slice = utxo_slice_by_amount(utxos_json, amount)
    # print(f"Batch UTXOS used for amount {amount}:", utxos_slice)
    
    raw_tx_meta['utxos_slice'] = utxos_slice
    attempted_txids.append(str(utxos_slice[0]["txid"]))
    raw_tx_meta['attempted_txids'] = attempted_txids
    send = {}
    try:
        send = utxo_send(utxos_slice, amount, batch_raddress, wallet['wif'], wallet['address'])
    except Exception as e:
        print(f"Failed sending a UTXO from first slice, looping to next slice soon...")
        send = {"txid": []}

    # send["txid"] = None
    # send = {}
    # send["txid"] = []
    i = 0
    while (len(send["txid"]) == 0) and (i < len(utxos_json)):
    # while send["txid"] is None:
        # Execute
        raw_tx_meta = utxo_slice_by_amount2(utxos_json, amount, raw_tx_meta)
        # print(f"Batch UTXOS used for amount {amount}:", raw_tx_meta['utxos_slice'])
        try:
            send = utxo_send(raw_tx_meta['utxos_slice'], amount, batch_raddress, wallet['wif'], wallet['address'])
        except Exception as e:
            i += 1
            print(f"Trying next UTXO in loop {i} out of {len(utxos_json)}")
            # print(json.dumps(raw_tx_meta), sort_keys=False, indent=3)
            # log2discord(raw_tx_meta['utxos_slice'])


    save_batch_timestamping_tx(integrity_id, wallet_name, wallet['address'], send["txid"])
    if (send is None):
        print("222 send is none")
        log2discord(f"---\nFailed to send batch: **{batch_raddress}** to **{wallet['address']}**\nAmount sent: **{amount}**\nUTXOs:\n**{utxos_slice}**\n---")
    return send["txid"]


def sendToBatchMassBalance_deprecated(batch_raddress, mass_balance_value, integrity_id):
    # delivery date
    print("SEND MASS BALANCE")
    mass_balance_wallet = getOfflineWalletByName(WALLET_MASS_BALANCE)
    utxos_json = explorer_get_utxos(mass_balance_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx6(utxos_json, 1, batch_raddress, round(mass_balance_value/1, 10), 0, mass_balance_wallet['address'])
    print("MASS BALANCE RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], mass_balance_wallet['wif'])
    mass_balance_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id,WALLET_MASS_BALANCE, mass_balance_wallet['address'], mass_balance_txid["txid"])
    return mass_balance_txid["txid"]


def sendToBatchMassBalance(batch_raddress, amount, integrity_id):
    amount = round(amount/1, 10)
    send_batch = sendToBatch(WALLET_DELIVERY_DATE, WALLET_MASS_BALANCE_THRESHOLD_UTXO_VALUE, batch_raddress, amount, integrity_id)
    return send_batch # TXID


# test skipped
def sendToBatchDeliveryDate_deprecated(batch_raddress, delivery_date, integrity_id):
    # delivery date
    print("SEND DELIVERY DATE")
    date_as_satoshi = dateToSatoshi(delivery_date)
    print(date_as_satoshi)
    delivery_date_wallet = getOfflineWalletByName(WALLET_DELIVERY_DATE)
    utxos_json = explorer_get_utxos(delivery_date_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, date_as_satoshi, 0, delivery_date_wallet['address'])
    print("DELIVERY DATE RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], delivery_date_wallet['wif'])
    deliverydate_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id,WALLET_DELIVERY_DATE, delivery_date_wallet['address'], deliverydate_txid["txid"])
    return deliverydate_txid["txid"]


def sendToBatchDeliveryDate(batch_raddress, date, integrity_id):
    send_batch = sendToBatch(WALLET_DELIVERY_DATE, WALLET_DELIVERY_DATE_THRESHOLD_UTXO_VALUE, batch_raddress, date, integrity_id)
    return send_batch # TXID


# test skipped
def sendToBatchPDS_deprecated(batch_raddress, production_date, integrity_id):
    # delivery date
    print("SEND PRODUCTION DATE")
    date_as_satoshi = dateToSatoshi(production_date)
    print(date_as_satoshi)
    production_date_wallet = getOfflineWalletByName(WALLET_PROD_DATE)
    utxos_json = explorer_get_utxos(production_date_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, date_as_satoshi, 0, production_date_wallet['address'])
    print("PROD DATE RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], production_date_wallet['wif'])
    proddate_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id,WALLET_PROD_DATE, production_date_wallet['address'], proddate_txid["txid"])
    return proddate_txid["txid"]


def sendToBatchPDS(batch_raddress, date, integrity_id):
    send_batch = sendToBatch(WALLET_PROD_DATE, WALLET_PROD_DATE_THRESHOLD_UTXO_VALUE, batch_raddress, date, integrity_id)
    return send_batch # TXID


# test skipped
def sendToBatchBBD_deprecated(batch_raddress, bb_date, integrity_id):
    # delivery date
    print("SEND BB DATE")
    date_as_satoshi = dateToSatoshi(bb_date)
    print(date_as_satoshi)
    bb_date_wallet = getOfflineWalletByName(WALLET_BB_DATE)
    utxos_json = explorer_get_utxos(bb_date_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, date_as_satoshi, 0, bb_date_wallet['address'])
    print("BB DATE RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], bb_date_wallet['wif'])
    bbdate_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id, WALLET_BB_DATE, bb_date_wallet['address'], bbdate_txid["txid"])
    return bbdate_txid["txid"]


def sendToBatchBBD(batch_raddress, date, integrity_id):
    send_batch = sendToBatch(WALLET_BB_DATE, WALLET_BB_DATE_THRESHOLD_UTXO_VALUE, batch_raddress, date, integrity_id)
    return send_batch # TXID


# test skipped
def sendToBatchPON_deprecated(batch_raddress, pon, integrity_id):
    # purchase order number
    print("SEND PON, check PON is accurate")
    pon_as_satoshi = dateToSatoshi(pon)
    print(pon_as_satoshi)
    pon_wallet = getOfflineWalletByName(WALLET_PON)
    utxos_json = explorer_get_utxos(pon_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, pon_as_satoshi, 0, pon_wallet['address'])
    print("PON RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], pon_wallet['wif'])
    pon_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id, WALLET_PON, pon_wallet['address'], pon_txid["txid"])
    return pon_txid["txid"]


def sendToBatchPON(batch_raddress, pon, integrity_id):
    send_batch = sendToBatch(WALLET_PON, WALLET_PON_THRESHOLD_UTXO_VALUE, batch_raddress, pon, integrity_id)
    return send_batch # TXID


# test skipped
def sendToBatchTIN_deprecated(batch_raddress, tin, integrity_id):
    # purchase order number
    print("SEND PON, check PON is accurate")
    tin_as_satoshi = dateToSatoshi(tin)
    print(tin_as_satoshi)
    tin_wallet = getOfflineWalletByName(WALLET_TIN)
    utxos_json = explorer_get_utxos(tin_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, tin_as_satoshi, 0, tin_wallet['address'])
    print("PON RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], tin_wallet['wif'])
    tin_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id, WALLET_TIN, tin_wallet['address'], tin_txid["txid"])
    return tin_txid["txid"]


def sendToBatchTIN(batch_raddress, tin, integrity_id):
    send_batch = sendToBatch(WALLET_TIN, WALLET_TIN_THRESHOLD_UTXO_VALUE, batch_raddress, tin, integrity_id)
    return send_batch # TXID


# test skipped
def sendToBatchPL_deprecated(batch_raddress, pl, integrity_id):
    # product locationcreaterawtx7
    print("SEND PL, check PL is accurate")
    pl_wallet = getOfflineWalletByName(pl)
    utxos_json = explorer_get_utxos(pl_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, 0.0001, 0, pl_wallet['address'])
    print("PL RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], pl_wallet['wif'])
    pl_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id, pl, pl_wallet['address'], pl_txid["txid"])
    return pl_txid["txid"]


def sendToBatchPL(batch_raddress, pl_name, integrity_id):
    send_batch = sendToBatch(pl_name, 0, batch_raddress, 0.0001, integrity_id)
    return send_batch # TXID


# test skipped
def sendToBatchJDS_deprecated(batch_raddress, jds, integrity_id):
    # product locationcreaterawtx7
    jds_wallet = getOfflineWalletByName(WALLET_JULIAN_START)
    utxos_json = explorer_get_utxos(jds_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, 0.0001, 0, jds_wallet['address'])
    print("JDStart RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], jds_wallet['wif'])
    jds_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id, WALLET_JULIAN_START, jds_wallet['address'], jds_txid["txid"])
    return jds_txid["txid"]


def sendToBatchJDS(batch_raddress, jds, integrity_id):
  send_batch = sendToBatch(WALLET_JULIAN_START, WALLET_JULIAN_START_THRESHOLD_UTXO_VALUE, batch_raddress, 0.0001, integrity_id)
  return send_batch # TXID


# test skipped
def sendToBatchJDE_deprecated(batch_raddress, jds, integrity_id):
    # product locationcreaterawtx7
    jde_wallet = getOfflineWalletByName(WALLET_JULIAN_STOP)
    utxos_json = explorer_get_utxos(jde_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, 0.0001, 0, jde_wallet['address'])
    print("JDStop RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], jde_wallet['wif'])
    jde_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id, WALLET_JULIAN_STOP, jde_wallet['address'], jde_txid["txid"])
    return jde_txid["txid"]


def sendToBatchJDE(batch_raddress, jde, integrity_id):
  send_batch = sendToBatch(WALLET_JULIAN_STOP, WALLET_JULIAN_STOP_THRESHOLD_UTXO_VALUE, batch_raddress, 0.0001, integrity_id)
  return send_batch # TXID


# test skipped
def sendToBatchPC_deprecated(batch_raddress, pc, integrity_id):
    # product locationcreaterawtx7
    pc_wallet = getOfflineWalletByName(WALLET_ORIGIN_COUNTRY)
    utxos_json = explorer_get_utxos(pc_wallet['address'])
    print(utxos_json)
    # works sending 0
    # rawtx_info = createrawtx5(utxos_json, 1, batch_raddress, 0, delivery_date_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, 0.0001, 0, pc_wallet['address'])
    print("Product Country RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], pc_wallet['wif'])
    pc_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id, WALLET_ORIGIN_COUNTRY, pc_wallet['address'], pc_txid["txid"])
    return pc_txid["txid"]


def sendToBatchPC(batch_raddress, pc, integrity_id):
  send_batch = sendToBatch(WALLET_ORIGIN_COUNTRY, WALLET_ORIGIN_COUNTRY_THRESHOLD_UTXO_VALUE, batch_raddress, 0.0001, integrity_id)
  return send_batch # TXID


# test skipped
def send_to_batch_certificate(batch_raddress, certificate_data, integrity_id):
    # product locationcreaterawtx7
    certificate_wallet = offlineWalletGenerator_fromObjectData_certificate(certificate_data)
    utxos_json = explorer_get_utxos(certificate_wallet['address'])
    print(utxos_json)
    rawtx_info = createrawtx7(utxos_json, 1, batch_raddress, 0.0001, 0, certificate_wallet['address'])
    print("Certificate to batch RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], certificate_wallet['wif'])
    txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    save_batch_timestamping_tx(integrity_id, "CERTIFICATE", certificate_wallet['address'], txid["txid"])
    return txid["txid"]


# no test
def split_wallet_PL(THIS_NODE_RADDRESS, pl, integrity_id):
    # product locationcreaterawtx7
    print("Split PL")
    pl_wallet = getOfflineWalletByName(pl)
    utxos_json = explorer_get_utxos(pl_wallet['address'])
    rawtx_info = createrawtx7(utxos_json, 1, THIS_NODE_RADDRESS, 0.1, 0, pl_wallet['address'], True)
    print("PL RAWTX: " + str(rawtx_info))
    signedtx = signtx(rawtx_info[0]['rawtx'], rawtx_info[1]['amounts'], pl_wallet['wif'])
    pl_txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    raddress = pl_wallet['address']
    return pl_txid

def offlineWalletGenerator(objectData, log_label=''):
  raw_json = json.dumps(objectData)
  offline_wallet = gen_wallet(raw_json, log_label)
  return offline_wallet

# test skipped, can be templated for re-use
def offlineWalletGenerator_fromObjectData_certificate(objectData):
    obj = {
        "issuer": objectData['issuer'],
        "issue_date": objectData['date_issue'],
        "expiry_date": objectData['date_expiry'],
        "identfier": objectData['identifier']
    }

    print(obj)
    log_label = objectData['identifier']
    raw_json = json.dumps(obj)

    print("libopenfood->offlineWalletGenerator object data as json: " + raw_json)

    offline_wallet = gen_wallet(raw_json, log_label)

    return offline_wallet

def offlineWalletGenerator_fromObjectData_location(objectData):
    obj = {
        "name": objectData['name']
    }

    print(obj)
    raw_json = json.dumps(obj)

    print("libopenfood->offlineWalletGenerator object data as json: " + raw_json)

    offline_wallet = gen_wallet(raw_json)

    return offline_wallet

def utxo_bundle_amount(utxos_obj):
    count = 0
    list_of_ids = []
    list_of_vouts = []
    amount = 0

    for objects in utxos_obj:
        if objects['amount']:
            count = count + 1
            easy_typeing2 = [objects['vout']]
            easy_typeing = [objects['txid']]
            list_of_ids.extend(easy_typeing)
            list_of_vouts.extend(easy_typeing2)
            amount = amount + objects['amount']

    amount = round(amount, 10)
    return amount


def get_batches_no_timestamp():
    print("***** start import api timestamping integrity - raw/refresco/require_integrity/")
    url = IMPORT_API_BASE_URL + DEV_IMPORT_API_RAW_REFRESCO_REQUIRE_INTEGRITY_PATH
    print("Trying: " + url)

    try:
        res = requests.get(url)
    except Exception as e:
        print("###### REQUIRE INTEGRITY URL ERROR: ", e)
        print("20201020 - url not sending nice response " + url)

    print(res.text)

    raw_json = res.text
    batches_no_timestamp = ""

    try:
        batches_no_timestamp = json.loads(raw_json)
    except Exception as e:
        print("10009 failed to parse to json because of", e)

    print("***** New batch requires timestamping: " + str(len(batches_no_timestamp)))
    return batches_no_timestamp


def get_batches():
    print("10009 start import api - raw/refresco")
    url = IMPORT_API_BASE_URL + DEV_IMPORT_API_RAW_REFRESCO_PATH
    print("Trying: " + url)

    try:
        res = requests.get(url)
    except Exception as e:
        print("###### REQUIRE INTEGRITY URL ERROR: ", e)
        print("20201020 - url not sending nice response " + url)

    print(res.text)

    raw_json = res.text
    batches = ""

    try:
        batches = json.loads(raw_json)
    except Exception as e:
        print("10009 failed to parse to json because of", e)

    print("New batch requires timestamping: " + str(len(batches)))
    return batches


def get_certificates_no_timestamp():
    url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_CERTIFICATE_NORADDRESS
    try:
        res = requests.get(url)
    except Exception as e:
        raise Exception(e)

    certs_no_addy = json.loads(res.text)
    return certs_no_addy

def get_locations_no_timestamp():
    url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_LOCATION_NORADDRESS
    try:
        res = requests.get(url)
    except Exception as e:
        raise Exception(e)

    locs_no_addy = json.loads(res.text)
    return locs_no_addy


# test skipped
def fund_certificate(certificate_address):
    txid = sendtoaddress_wrapper(certificate_address, FUNDING_AMOUNT_CERTIFICATE)
    return txid

def fund_location(location_address):
    txid = sendtoaddress_wrapper(location_address, FUNDING_AMOUNT_LOCATION)
    return txid


def fund_address(address, amount_type):
    amount = {
        'CERTIFICATE': FUNDING_AMOUNT_CERTIFICATE,
        'LOCATION': FUNDING_AMOUNT_LOCATION
    }.get(amount_type)
    txid = sendtoaddress_wrapper(address, amount)
    return txid

def postWrapper(url, data):
    res = requests.post(url, data=data)
    if(res.status_code == 200 | res.status_code == 201):
        return res.text
    else:
        obj = json.dumps({"error": res.reason})
        return obj


def putWrapper(url, data):
    res = requests.put(url, data=data)

    if(res.status_code == 200):
        return res.text
    else:
        obj = json.dumps({"error": res.reason})
        return obj


def patchWrapper(url, data):
    res = requests.patch(url, data=data)

    if(res.status_code == 200):
        return res.text
    else:
        obj = json.dumps({"error": res.reason})
        return obj


def getWrapper(url):
    res = requests.get(url)

    if(res.status_code == 200):
        return res.text
    else:
        obj = json.dumps({"error": res.reason})
        return obj


def get_jcapi_organization():
    print("GET openfood-api organization query: " + URL_openfood_API_ORGANIZATION + "?raddress=" + THIS_NODE_RADDRESS)
    res = getWrapper(URL_openfood_API_ORGANIZATION + "?raddress=" + THIS_NODE_RADDRESS)
    organizations = json.loads(res)
    # TODO E721 do not compare types, use "isinstance()" pep8
    if type(organizations) == type(['d', 'f']):
        return organizations[0]
    return organizations

def get_jcapi_organization_batch():
    print("GET openfood-api organization query: " + URL_openfood_API_ORGANIZATION_BATCH + "?raddress=" + THIS_NODE_RADDRESS)
    res = getWrapper(URL_openfood_API_ORGANIZATION_BATCH + "?raddress=" + THIS_NODE_RADDRESS)
    locations = json.loads(res)
    # TODO E721 do not compare types, use "isinstance()" pep8
    if type(locations) == type(['d', 'f']):
        return locations[0]
    return locations

def get_jcapi_organization_location(orgid):
    print("GET openfood-api organization query: " + URL_openfood_API_ORGANIZATION_LOCATION + "?orgid=" + orgid)
    res = getWrapper(URL_openfood_API_ORGANIZATION_LOCATION + "?orgid=" + orgid)
    locations = json.loads(res)
    # TODO E721 do not compare types, use "isinstance()" pep8
    if type(locations) == type(['d', 'f']):
        return locations[0]
    return locations

# test skipped
def batch_wallets_generate_timestamping(batchObj, import_id):
    json_batch = json.dumps(batchObj)
    # anfp_wallet = gen_wallet(json_batch['anfp'], "anfp")
    # pon_wallet = gen_wallet(json_batch['pon'], "pon")
    bnfp_wallet = gen_wallet(batchObj['bnfp'], "bnfp")
    # pds_wallet = openfood.gen_wallet(data['pds'], "pds")
    # jds_wallet = openfood.gen_wallet(data['jds'], "jds")
    # jde_wallet = openfood.gen_wallet(data['jde'], "jde")
    # bbd_wallet = openfood.gen_wallet(data['bbd'], "bbd")
    # pc_wallet = openfood.gen_wallet(data['pc'], "pc")
    integrity_address = gen_wallet(json_batch, "integrity address")
    print("Timestamp-integrity raddress: " + integrity_address['address'])
    data = {"name": "timestamping",
            "integrity_address": integrity_address['address'],
            "batch": import_id,
            "batch_lot_raddress": bnfp_wallet['address']
            }
    print(data)
    batch_wallets_update_response = postWrapper(URL_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH, data)
    print("POST response: " + batch_wallets_update_response)
    return json.loads(batch_wallets_update_response)


def batch_wallets_timestamping_update(batch_integrity):
    batch_integrity_url = URL_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH + batch_integrity['id'] + "/"
    print(batch_integrity)
    batch_integrity_response = putWrapper(batch_integrity_url, batch_integrity)
    return batch_integrity_response


def batch_wallets_timestamping_start(batch_integrity, start_txid):
    batch_integrity_url = URL_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH + batch_integrity['id'] + "/"
    print(batch_integrity)
    batch_integrity['integrity_pre_tx'] = start_txid
    print(batch_integrity)
    # data = {'name': 'chris', 'integrity_address': integrity_address[
    #    'address'], 'integrity_pre_tx': integrity_start_txid, 'batch_lot_raddress': bnfp_wallet['address']}

    batch_integrity_start_response = putWrapper(batch_integrity_url, batch_integrity)
    return batch_integrity_start_response


def batch_wallets_timestamping_end(batch_integrity, end_txid):
    batch_integrity['integrity_post_tx'] = end_txid
    print(batch_integrity)
    batch_integrity_end_response = batch_wallets_timestamping_update(batch_integrity)
    return batch_integrity_end_response


def batch_wallets_fund_integrity_start(integrity_address):
    return sendtoaddress_wrapper(integrity_address, FUNDING_AMOUNT_TIMESTAMPING_START)


def batch_wallets_fund_integrity_end(integrity_address):
    return sendtoaddress_wrapper(integrity_address, FUNDING_AMOUNT_TIMESTAMPING_END)


# test skipped
def organization_get_our_pool_batch_wallet():
    kv_response = organization_get_pool_wallets_by_raddress(THIS_NODE_RADDRESS)
    print(kv_response)
    tmp = json.loads(kv_response['value'])
    tmp2 = str(tmp[WALLET_ALL_OUR_BATCH_LOT])
    return tmp2


# test skipped
def organization_get_our_pool_po_wallet():
    kv_response = organization_get_pool_wallets_by_raddress(THIS_NODE_RADDRESS)
    print(kv_response)
    tmp = json.loads(kv_response['value'])
    tmp2 = str(tmp[WALLET_ALL_OUR_PO])
    return tmp2


# test skipped
def organization_get_customer_po_wallet(CUSTOMER_RADDRESS):
    kv_response = organization_get_pool_wallets_by_raddress(CUSTOMER_RADDRESS)
    print(kv_response)
    tmp = json.loads(kv_response['value'])
    tmp2 = str(tmp[WALLET_ALL_OUR_PO])
    return tmp2


# test skipped
def organization_get_customer_batch_wallet(CUSTOMER_RADDRESS):
    kv_response = organization_get_pool_wallets_by_raddress(CUSTOMER_RADDRESS)
    print(kv_response)
    tmp = json.loads(kv_response['value'])
    tmp2 = str(tmp[WALLET_ALL_OUR_BATCH_LOT])
    return tmp2


def deprecate_organization_send_batch_links(batch_integrity):
    sample_pool_po = "RWSVFtCJfRH5ErsXJCaz9YNVKx7PijxpoV"
    sample_pool_batch_lot = "R9X5CBJjmVmJe4a533hemBf6vCW2m3BAqH"
    pool_batch_wallet = organization_get_our_pool_batch_wallet()
    pool_po = organization_get_our_pool_po_wallet()
    print("MAIN WALLET " + THIS_NODE_RADDRESS + " SENDMANY TO BATCH_LOT (bnfp), POOL_PO (pon), POOL_BATCH_LOT")
    print(pool_batch_wallet)
    customer_pool_wallet = organization_get_customer_po_wallet(CUSTOMER_RADDRESS)
    print("CUSTOMER POOL WALLET: " + customer_pool_wallet)

    json_object = {

                    pool_batch_wallet: SCRIPT_VERSION,
                    pool_po: SCRIPT_VERSION,
                   batch_integrity['batch_lot_raddress']: SCRIPT_VERSION,
                   customer_pool_wallet: SCRIPT_VERSION
                   }
    sendmany_txid = sendmany_wrapper(THIS_NODE_RADDRESS, json_object)
    return sendmany_txid


# test skipped
def deprecate_organization_send_batch_links2(batch_integrity, pon):
    pon_as_satoshi = dateToSatoshi(pon)
    pool_batch_wallet = organization_get_our_pool_batch_wallet()
    pool_po = organization_get_our_pool_po_wallet()
    customer_pool_wallet = organization_get_customer_po_wallet(CUSTOMER_RADDRESS)

    print("****** MAIN WALLET batch links sendmany ******* " + THIS_NODE_RADDRESS)
    print(pool_batch_wallet)
    print("CUSTOMER POOL WALLET: " + customer_pool_wallet)

    json_object = {
        pool_batch_wallet: SCRIPT_VERSION,
        pool_po: pon_as_satoshi,
       batch_integrity['batch_lot_raddress']: SCRIPT_VERSION,
       customer_pool_wallet: pon_as_satoshi
    }
    sendmany_txid = sendmany_wrapper(THIS_NODE_RADDRESS, json_object)
    return sendmany_txid


# test skipped
def organization_send_batch_links3(batch_integrity, pon, bnfp):
    pon_as_satoshi = dateToSatoshi(pon)
    bnfp_as_satoshi = dateToSatoshi(bnfp)
    pool_batch_wallet = organization_get_our_pool_batch_wallet()
    pool_po = organization_get_our_pool_po_wallet()
    customer_pool_wallet = organization_get_customer_po_wallet(CUSTOMER_RADDRESS)

    print("****** MAIN WALLET batch links sendmany ******* " + THIS_NODE_RADDRESS)
    print(pool_batch_wallet)
    print("CUSTOMER POOL WALLET: " + customer_pool_wallet)

    json_object = {
        pool_batch_wallet: bnfp_as_satoshi,
        pool_po: pon_as_satoshi,
        batch_integrity['batch_lot_raddress']: SATS_10K,
        customer_pool_wallet: pon_as_satoshi
   }
    print(json_object)
    sendmany_txid = sendmany_wrapper(THIS_NODE_RADDRESS, json_object)
    return sendmany_txid


def timestamping_save_batch_links(id, sendmany_txid):
    print("** txid ** (Main org wallet sendmany BATCH_LOT/POOL_PO/GTIN): " + sendmany_txid)
    tstx_data = {'sender_raddress': THIS_NODE_RADDRESS,
                 'tsintegrity': id, 'sender_name': 'ORG WALLET', 'txid': sendmany_txid}
    ts_response = postWrapper(URL_IMPORT_API_RAW_REFRESCO_TSTX_PATH, tstx_data)
    print("POST ts_response: " + ts_response)
    return ts_response


# test skipped
def timestamping_save_certificate(id, sender_name, sender_wallet, certificate_txid):
    print("** txid ** (Certificate to batch_lot): " + certificate_txid)
    tstx_data = {'sender_raddress': sender_wallet['address'],
                 'tsintegrity': id, 'sender_name': sender_name, 'txid': certificate_txid}
    print(tstx_data)
    ts_response = postWrapper(URL_IMPORT_API_RAW_REFRESCO_TSTX_PATH, tstx_data)
    print("POST ts_response: " + ts_response)
    return ts_response


# no test
def get_certificate_for_test(url):
    return getWrapper(url)


def get_all_certificate_for_organization(org_id):
    test_url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_CERTIFICATE + "?orgid=" + str(org_id)
    all_certificates = json.loads(get_certificate_for_test(test_url))
    return all_certificates


def get_all_certificate_for_batch():
    # TODO this is hardcoded, which is bad - needs to fetch by cert rules
    test_url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_CERTIFICATE
    all_certificates = json.loads(get_certificate_for_test(test_url))
    return all_certificates


def get_certificate_for_batch():
    # TODO this is hardcoded, which is bad - needs to fetch by cert rules
    test_url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_CERTIFICATE + "1/"
    certificate = json.loads(get_certificate_for_test(test_url))
    return certificate

def save_offline_wallet_sent(integrity_id, wallet_names={}):
    url = IMPORT_API_BASE_URL + 'batch/import-integrity/' + integrity_id + '/'
    data = putWrapper(url, {'offline_wallet_sent': json.dumps(wallet_names)})
    # Triggering import api log
    getWrapper(url + '?log=1')
    return json.loads(data)

def restart_offline_wallet_sent(integrity_id):
    import_integrity_url = IMPORT_API_BASE_URL + 'batch/import-integrity/' + integrity_id + '/'
    get_integrity = getWrapper(import_integrity_url)
    integrity = json.loads(get_integrity)
    data = json.loads(integrity['offline_wallet_sent'])

    import_url = IMPORT_API_BASE_URL + 'batch/import/' + integrity["batch"] + '/'
    get_batch = getWrapper(import_url)
    batch = json.loads(get_batch)

    tofix_bnfp_wallet = gen_wallet(batch['bnfp'], "bnfp")
    wallet_sent = {}
    for name in data.items():
        if data["PON"]:
            txid_pon = sendToBatchPON(tofix_bnfp_wallet['address'], batch['pon'], integrity_id)
            print("** txid ** (PON): " + txid_pon)
            wallet_sent['PON'] = True
            print('PON has been funded')
        if data["JDS"]:
            txid_julian_start = sendToBatchJDS(tofix_bnfp_wallet['address'], batch['jds'], integrity_id)
            print("** txid ** (JULIAN START): " + txid_julian_start)
            wallet_sent['JDS'] = True
            print('JDS has been funded')
        if data["JDE"]:
            txid_julian_stop = sendToBatchJDE(tofix_bnfp_wallet['address'], batch['jde'], integrity_id)
            print("** txid ** (JULIAN STOP): " + txid_julian_stop)
            wallet_sent['JDE'] = True
            print('JDE has been funded')
        if data["PC"]:
            txid_origin_country = sendToBatchPC(tofix_bnfp_wallet['address'], batch['pc'], integrity_id)
            print("** txid ** (ORIGIN COUNTRY): " + txid_origin_country)
            wallet_sent['PC'] = True
            print('PC has been funded')
        if data["BBD"]:
            txid_bb_date = sendToBatchBBD(tofix_bnfp_wallet['address'], batch['bbd'], integrity_id)
            print("** txid ** (BB DATE): " + txid_bb_date)
            wallet_sent['BBD'] = True
            print('BBD has been funded')
        if data["PDS"]:
            txid_prod_date = sendToBatchPDS(tofix_bnfp_wallet['address'], batch['pds'], integrity_id)
            print("** txid ** (PROD DATE): " + txid_prod_date)
            wallet_sent['PDS'] = True
            print('PDS has been funded')
        if data["TIN"]:
            txid_tin = sendToBatchTIN(tofix_bnfp_wallet['address'], batch['anfp'], integrity_id)
            print("** txid ** (TIN): " + txid_tin)
            wallet_sent['TIN'] = True
            print('TIN has been funded')
        if data["MB"]:
            txid_mass = sendToBatchMassBalance(tofix_bnfp_wallet['address'], batch['mass'], integrity_id)
            print("** txid  ** (MASS): " + txid_mass)
            wallet_sent['MB'] = True
            print('MB has been funded')
        if data["PL"]:
            txid_pl = sendToBatchPL(tofix_bnfp_wallet['address'], batch['pl'], integrity_id)
            print("** txid ** (PL): " + txid_pl)
            wallet_sent['PL'] = True
            print('PL has been funded')
    update_wallet_sent = save_offline_wallet_sent(integrity_id, wallet_sent)
    if update_wallet_sent: print('Integrity Updated!')
    return update_wallet_sent

def push_batch_data_consumer(jcapi_org_id, batch, batch_wallet):
        data = {'identifier': batch['bnfp'],
                'jds': batch['jds'],
                'jde': batch['jde'],
                'date_production_start': batch['pds'],
                'date_best_before': batch['bbd'],
                'origin_country': batch['pc'],
                'mass_balance': batch['mass'],
                'raddress': batch_wallet['address'],
                'pubkey': batch_wallet['pubkey'],
                'organization': jcapi_org_id}
        jcapi_response = postWrapper(URL_openfood_API_ORGANIZATION_BATCH, data=data)
        jcapi_batch_id = json.loads(jcapi_response)['id']
        print("BATCH ID @ openfood-API: " + str(jcapi_batch_id))
        return jcapi_response

def log2discord(msg=""):
    try:
        postWrapper(DISCORD_WEBHOOK_URL, {"content": msg})
    except:
        pass

def update_kv_foundation():
    pool_wallets = {}
    pool_wallets[str(WALLET_ALL_OUR_PO)] = CUSTOMER_RADDRESS
    pool_wallets[str(WALLET_ALL_OUR_BATCH_LOT)] = CUSTOMER_RADDRESS
    pool_wallets[str(WALLET_ALL_CUSTOMER_PO)] = CUSTOMER_RADDRESS
    print("Verifying pool wallets in KV1")
    org_kv1_key_pool_wallets = THIS_NODE_RADDRESS + KV1_ORG_POOL_WALLETS
    print("Updating with a value")
    kv_response = kvupdate_wrapper(org_kv1_key_pool_wallets, json.dumps(pool_wallets), "22000", "password")
    print(kv_response)


def verify_kv_foundation():
    pool_wallets = {}
    pool_wallets[str(WALLET_ALL_OUR_PO)] = CUSTOMER_RADDRESS
    pool_wallets[str(WALLET_ALL_OUR_BATCH_LOT)] = CUSTOMER_RADDRESS
    pool_wallets[str(WALLET_ALL_CUSTOMER_PO)] = CUSTOMER_RADDRESS
    print("Verifying pool wallets in KV1")
    org_kv1_key_pool_wallets = THIS_NODE_RADDRESS + KV1_ORG_POOL_WALLETS
    kv_response = kvsearch_wrapper(org_kv1_key_pool_wallets)
    print(kv_response)
    if( kv_response.get("error")):
        print("Updating with a value")
        kv_response = kvupdate_wrapper(org_kv1_key_pool_wallets, json.dumps(pool_wallets), "22", "password")
        print(kv_response)
    else:
        print("kv exists for pool wallets")

def str2int(str, length):
    return abs(hash(str)) % (10 ** length)