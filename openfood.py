from .openfood_env import GTID
from .openfood_env import EXPLORER_URL
from .openfood_env import THIS_NODE_RADDRESS
from .openfood_env import THIS_NODE_PUBKEY
from .openfood_env import IMPORT_API_BASE_URL
from .openfood_env import DEV_IMPORT_API_RAW_REFRESCO_REQUIRE_INTEGRITY_PATH
from .openfood_env import DEV_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH
from .openfood_env import DEV_IMPORT_API_RAW_REFRESCO_TSTX_PATH
from .openfood_env import openfood_API_BASE_URL
from .openfood_env import openfood_API_FOUNDATION
from .openfood_env import openfood_API_FOUNDATION_ORACLE
from .openfood_env import openfood_API_ORGANIZATION
from .openfood_env import openfood_API_ORGANIZATION_CERTIFICATE_NORADDRESS
from .openfood_env import openfood_API_ORGANIZATION_CERTIFICATE
from .openfood_env import openfood_API_ORGANIZATION_LOCATION
from .openfood_env import openfood_API_ORGANIZATION_LOCATION_NORADDRESS
from .openfood_env import openfood_API_ORGANIZATION_PRODUCT
from .openfood_env import openfood_API_ORGANIZATION_PRODUCT_NORADDRESS
from .openfood_env import openfood_API_ORGANIZATION_BATCH
from .openfood_env import FUNDING_AMOUNT_CERTIFICATE
from .openfood_env import FUNDING_AMOUNT_LOCATION
from .openfood_env import FUNDING_AMOUNT_PRODUCT
from .openfood_env import FUNDING_AMOUNT_TIMESTAMPING_START
from .openfood_env import FUNDING_AMOUNT_TIMESTAMPING_BATCH
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
from .openfood_env import WALLET_PRODUCTID
from .openfood_env import WALLET_PRODUCTID_THRESHOLD_BALANCE
from .openfood_env import BYPASS_ORACLE
from .openfood_env import WALLET_PRODUCTID_THRESHOLD_UTXO
from .openfood_env import WALLET_PRODUCTID_THRESHOLD_UTXO_VALUE
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
from .openfood_utxo_lib import *
from .openfood_explorer_lib import *
from .openfood_komodo_node import *

from dotenv import load_dotenv
import hashlib
import math
import requests
import json

load_dotenv(verbose=True)
SCRIPT_VERSION = HK_LIB_VERSION
URL_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH = IMPORT_API_BASE_URL + DEV_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH
URL_IMPORT_API_RAW_REFRESCO_TSTX_PATH = IMPORT_API_BASE_URL + DEV_IMPORT_API_RAW_REFRESCO_TSTX_PATH
URL_openfood_API_ORGANIZATION = openfood_API_BASE_URL + openfood_API_ORGANIZATION
URL_openfood_API_ORGANIZATION_BATCH = openfood_API_BASE_URL + openfood_API_ORGANIZATION_BATCH
URL_openfood_API_ORGANIZATION_LOCATION = openfood_API_BASE_URL + openfood_API_ORGANIZATION_LOCATION
URL_openfood_API_FOUNDATION = openfood_API_BASE_URL + openfood_API_FOUNDATION
URL_openfood_API_FOUNDATION_ORACLE = openfood_API_BASE_URL + openfood_API_FOUNDATION_ORACLE
from .openfood_env import URL_openfood_API_INDUSTRY
# helper methods
def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except ValueError as e:
        return False
    return True


def pogtid(po):
    total = po + GTID
    total = total.encode()
    total = hashlib.sha256(total)
    total = total.hexdigest()
    return total


def hex_to_base16_int(hex):
    return int(hex, base=16)


def hex_to_base_int(hex, base):
    return int(hex, base=base)


def get_foundation_oracle_latest_sample():
    f_oracleid = get_foundation_oracleid()
    f_baton = get_oracle_baton_address(f_oracleid)
    samplehex = oracle_samples(f_oracleid, f_baton, "1")
    try:
        print(f'f_o latest hex: {samplehex["samples"][0]["data"][0]}')
        return samplehex["samples"][0]["data"][0]
    except Exception as e:
        print(f"** Handled: {e}")
        return []


def get_foundation_addresses():
    try:
        if BYPASS_ORACLE:
            bypass = {}
            bypass = {WALLET_ALL_OUR_PO: 'RW35CuVT9542u529T8TvRa4gNTNXn7Fhys'}
            return json.dumps(bypass)
        else:
            samplehex = get_foundation_oracle_latest_sample()
            return bytes.fromhex(samplehex).decode('utf-8')
    except Exception as e:
        print(f"ERROR: configured for oracles but no oracle. Use BYPASS_ORACLE=1 in environment to use no oracle")
        print(e)


def get_foundation_addresses_old():
    samplehex = get_foundation_oracle_latest_sample()
    return bytes.fromhex(samplehex["samples"][0]["data"][0]).decode('utf-8')

def sats_to_string(arr):
    # ascii codes cannot be more then 3 characters long in this senario
    arr_ordered_no_flag = []

    for x in range(0, len(arr)):
        str_val = " "
        for val in arr:
            #print(str(val)[-len(str(x))])
            if str(val)[-len(str(x))] == str(x):
                 str_val = str(val)

        n_order = math.ceil(math.log(len(arr), 10))
        str_val = str_val[:-n_order]
        arr_ordered_no_flag.append(str_val)

    #print(arr_ordered_no_flag)
    #add them back together
    big_str = ""
    for str_val in arr_ordered_no_flag:
        big_str = big_str + str_val

    #make the string a int array ready to be converted
    int_arr = []
    for x in range(0, len(big_str), 3):
       arg = big_str[x] + big_str[x+1] + big_str[x+2] 
       int_arr.append(int(arg))
    
    #cast into byte array to convert back
    int_arr = bytes(int_arr)
    string = int_arr.decode('utf-8')
    
    return string 
   
   
def satable_string_to_sats(str_var, max_sats=100000000):
    decrese = 0
    n_tx = 10
    
    #determine order number
    while decrese < math.log(n_tx, 10):
        decrese += 1
        max_sats_len = len(str(max_sats))-decrese
        n_tx = math.ceil(len(str_var)/max_sats_len)
    

    ret = []
    for x in range(0,n_tx):
        str_x = str(x)
        
        for n in range(0, decrese - len(str_x)):
            str_x = "0" + str_x

        
        new_str = str_var[:max_sats_len] + str(x)
        str_var = str_var[max_sats_len:]
        
        ret.append(new_str)

    return ret

def int_array_to_satable(arr_int):
    final_int = 0
    build_str = ""
    max_len_val = 3

    #this is commented out, the decoder now only supports 3 digits per character, 
    #otherwise we need to add a flag signaling the size of the character,
    #this would bloat our tx too much
    #for val in arr_int:
    #    val = str(val)
    #    if len(val) > max_len_val:
    #        max_len_val = len(val)

    for val in arr_int:
        str_val = str(val)
        
        if len(str_val) < max_len_val:
            for x in range(0, max_len_val-len(str_val)):
                str_val = "0" + str_val
        
        build_str = build_str + str_val

    return build_str

def convert_ascii_string_to_bytes(str):
    byte_value = str.encode('utf-8')
    total_int = []
    for byte in byte_value:
        total_int.append(int(byte))
    return total_int

def convert_oracle_data_json_to_obj(bytes):
    bytes.pop(0)
    obj = json.loads(bytes)
    return obj


def oracle_data_gt256_hexstr_remove_length(hexstr):
    return hexstr[4:]


def oracle_data_lt256_hexstr_remove_length(hexstr):
    return hexstr[2:]


def oracle_data_insert_data_length(bytelen, bytearray):
    bytes256 = bytelen // 256
    remainder = bytelen % 256
    bytearray.insert(0, bytes256)
    bytearray.insert(0, remainder)
    return bytearray


def convert_string_oracle_data_bytes(data):
    data_to_bytearray = bytearray(data, 'utf-8')
    bytelen = int(len(data_to_bytearray))
    # using bytelen, make sure oracle format accepts this length
    if bytelen < 256:
        data_to_bytearray = oracle_data_insert_data_length(bytelen, data_to_bytearray)
    elif bytelen < 65536:
        data_to_bytearray = oracle_data_insert_data_length(bytelen, data_to_bytearray)
    else:
        raise Exception("message too large, must be less than 65536 bytes")
    print(f"convert data to bytes: {data_to_bytearray.hex()}")
    return data_to_bytearray


def format_oracle_data_bytes_gt256(data):
    data_to_bytearray = bytearray(data, 'utf-8')
    data_to_bytearray.insert(0, len(data_to_bytearray))
    print(data_to_bytearray.hex())
    raise Exception("257 to 9000 bytes not supported yet, need length in 2 bytes little endian")


def generate_pool_wallets_as_hexstr():
    pool_wallets = generate_pool_wallets()
    bytes_pool_wallets = convert_string_oracle_data_bytes(json.dumps(pool_wallets)).hex()
    return bytes_pool_wallets


def foundation_publish_pool_wallets():
    bytes_pool_wallets = generate_pool_wallets_as_hexstr()
    oracle_id = get_jcapi_foundation_oracle(get_jcapi_foundation(get_foundation_raddress())['id'])['oracle_txid']
    print(oracle_id)
    res = oracle_data(oracle_id, bytes_pool_wallets)
    print(res)
    txid = sendrawtx_wrapper(res['hex'])
    return txid


def organization_publish_pool_wallets(oracle_id):
    bytes_pool_wallets = generate_pool_wallets_as_hexstr()
    res = oracle_data(oracle_id, bytes_pool_wallets)
    txid = sendrawtx_wrapper(res['hex'])
    return txid


# test skipped
def get_this_node_raddress():
    return THIS_NODE_RADDRESS


def get_this_node_pubkey():
    return THIS_NODE_PUBKEY


def check_pubkey_compressed(pk):
    # from bitcoin_tools/utils.py, modified
    """ Checks if a given string is a public (or at least if it is formatted as if it is).

    :param pk: ECDSA public key to be checked.
    :type pk: hex str
    :return: True if the key matches the format, raise exception otherwise.
    :rtype: bool
    """
    print("Checking pubkey is valid")
    prefix = pk[0:2]
    pkl = len(pk)

    if prefix not in ["02", "03"]:
        raise Exception("Wrong compressed public key format. Start with 02 or 03 only")
    elif prefix in ["02", "03"] and pkl != 66:
        raise Exception("Wrong length for a compressed public key (66): " + str(pkl))
    else:
        return True


def check_txid(txid):
    print("Checking txid is valid")
    txidl = len(txid)
    if txidl != 64:
        raise Exception("Wrong length for a txid (64): " + str(txidl))
    else:
        return True

def check_raddress(address):
    print("Checking raddress")
    addressl = len(address)
    prefix = address[0:1]
    if prefix not in ["R"]:
        raise Exception("wrong address format, must start with R: " + str(address))
    elif prefix in ["R"] and addressl != 34:
        raise Exception("wrong length for address (34): " + str(address))
    else:
        return True


def get_oracle_baton_address(oracleid):
    res = oracle_info(oracleid)
    baton = res['registered'][0]['baton']
    return baton


# the usefulness of this function is not clear after the redesign of solution.
# currently unused.
def verify_oracle_baton_address(oracleid):
    address = get_oracle_baton_address(oracleid)
    return check_raddress(address)


def get_foundation_raddress():
    res = get_jcapi_industry()
    print(f"get_foundation_raddress(): {res['raddress']}")
    return res['raddress']


def get_foundation_pubkey():
    res = get_jcapi_industry()
    print(f"get_foundation_pubkey(): {res['pubkey']}")
    return res['pubkey']


def verify_foundation_pubkey():
    pubkey = get_foundation_pubkey()
    return check_pubkey_compressed(pubkey)


def mock_txid():
    return "0000000000000000000000000000000000000000000000000000000000000000"

def get_foundation_oracleid():
    if BYPASS_ORACLE:
        return mock_txid()
    # from API
    oracle_get_res = get_jcapi_foundation_oracle(get_jcapi_foundation(get_foundation_raddress())['id'])
    return oracle_get_res['oracle_txid']
    # from chain
    # oracletxid = find_oracleid_with_pubkey(get_foundation_pubkey())
    # return oracletxid


def verify_foundation_oracleid():
    oid = get_foundation_oracleid()
    return check_txid(oid)


def is_oracle_publisher_foundation_pk():
    if BYPASS_ORACLE:
        return True
    print("checking oracle publisher is foundation pubkey")
    o_id = get_foundation_oracleid()
    oracle_info_response = oracle_info(o_id)
    publisher = oracle_info_response['registered'][0]['publisher']
    if publisher != get_foundation_pubkey():
        raise Exception("foundation pubkey is not publisher: " + str(publisher))
    return True


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
        return False
    else:
        print("kv exists for pool wallets")
        return True

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


def fund_offline_wallet2(offline_wallet_raddress, send_amount):
    json_object = {
     offline_wallet_raddress: send_amount
     }
    sendmany_txid = sendmany_wrapper(THIS_NODE_RADDRESS, json_object)
    return sendmany_txid


def is_refuel_needed(utxos):
    # if total utxos are < 20 (THRESHOLD), then refuel
    # if old < 5 & mature < 5 & young < 5, then refuel
    if len(utxos) <= 20:
        print("***** REFUEL ***** 20 UTXOs or less")
        return True
    # Filter utxos on their confirmations
    utxos_old = [x for x in utxos if x['confirmations'] >= 300]
    utxos_mature = [x for x in utxos if 30 <= x['confirmations'] < 300]
    utxos_young = [x for x in utxos if 3 <= x['confirmations'] < 30]
    if len(utxos_old) < 5 and len(utxos_mature) < 5 and len(utxos_young) < 5:
        print("***** REFUEL ***** low count young, mature & old UTXO")
        return True
    # have enough utxos
    #print("***** NO REFUEL ***** enough utxos & confirmations")
    return False


def fund_offline_wallet3(raddress, send_amount, utxos):
    if is_refuel_needed(utxos):
        refuel_txid = fund_offline_wallet2(raddress, send_amount)
        print(f"***** REFUEL ***** latest txid {refuel_txid}")
        return refuel_txid
    return False


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
    wallet_productid = getOfflineWalletByName(WALLET_PRODUCTID)

    wallet_delivery_date_balance = int(explorer_get_balance(wallet_delivery_date['address'], WALLET_DELIVERY_DATE))
    if is_below_threshold_balance(wallet_delivery_date_balance, WALLET_DELIVERY_DATE_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_DELIVERY_DATE + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_delivery_date['address'], WALLET_DELIVERY_DATE_THRESHOLD_UTXO_VALUE)
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

    wallet_mass_balance_balance = int(explorer_get_balance(wallet_mass_balance['address'], WALLET_MASS_BALANCE))
    if is_below_threshold_balance(wallet_mass_balance_balance, WALLET_MASS_BALANCE_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_MASS_BALANCE + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_mass_balance['address'], WALLET_MASS_BALANCE_THRESHOLD_UTXO_VALUE)
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

    wallet_pon_balance = int(explorer_get_balance(wallet_pon['address'], WALLET_PON))
    if is_below_threshold_balance(wallet_pon_balance, WALLET_PON_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_PON + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_pon['address'], WALLET_PON_THRESHOLD_UTXO_VALUE)
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

    wallet_productid_balance = int(explorer_get_balance(wallet_productid['address'], WALLET_PRODUCTID))
    if is_below_threshold_balance(wallet_productid_balance, WALLET_PRODUCTID_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_PRODUCTID + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_productid['address'], WALLET_PRODUCTID_THRESHOLD_UTXO_VALUE)
            print(funding_txid)
        if save:
          utxos = json.loads(explorer_get_utxos(wallet_productid['address']))
          utxos_total = len(utxos)
          if utxos_total == '0':
            utxos.append('null')
          else: utxos.sort(key = lambda json: json['amount'], reverse=False)
          wallet_data = {
            'org_wallet': THIS_NODE_RADDRESS,
            'offline_wallet': WALLET_PRODUCTID,
            'wallet': wallet_productid['address'],
            'utxo_count': utxos_total,
            'utxo_low_value': utxos[0],
            'balance': wallet_productid_balance
          }

    wallet_tin_balance = int(explorer_get_balance(wallet_tin['address'], WALLET_TIN))
    if is_below_threshold_balance(wallet_tin_balance, WALLET_TIN_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_TIN + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_tin['address'], WALLET_TIN_THRESHOLD_UTXO_VALUE)
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

    wallet_prod_date_balance = int(explorer_get_balance(wallet_prod_date['address'], WALLET_PROD_DATE))
    if is_below_threshold_balance(wallet_prod_date_balance, WALLET_PROD_DATE_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_PROD_DATE + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_prod_date['address'], WALLET_PROD_DATE_THRESHOLD_UTXO_VALUE)
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

    wallet_julian_start_balance = int(explorer_get_balance(wallet_julian_start['address'], WALLET_JULIAN_START))
    if is_below_threshold_balance(wallet_julian_start_balance, WALLET_JULIAN_START_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_JULIAN_START + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_julian_start['address'], WALLET_JULIAN_START_THRESHOLD_UTXO_VALUE)
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

    wallet_julian_stop_balance = int(explorer_get_balance(wallet_julian_stop['address'], WALLET_JULIAN_STOP))
    if is_below_threshold_balance(wallet_julian_stop_balance, WALLET_JULIAN_STOP_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_JULIAN_STOP + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_julian_stop['address'], WALLET_JULIAN_STOP_THRESHOLD_UTXO_VALUE)
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

    wallet_origin_country_balance = int(explorer_get_balance(wallet_origin_country['address'], WALLET_ORIGIN_COUNTRY))
    if is_below_threshold_balance(wallet_origin_country_balance, WALLET_ORIGIN_COUNTRY_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_ORIGIN_COUNTRY + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_origin_country['address'], WALLET_ORIGIN_COUNTRY_THRESHOLD_UTXO_VALUE)
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

    wallet_bb_date_balance = int(explorer_get_balance(wallet_bb_date['address'], WALLET_BB_DATE))
    if is_below_threshold_balance(wallet_bb_date_balance, WALLET_BB_DATE_THRESHOLD_BALANCE):
        print("FUND the " + WALLET_BB_DATE + " wallet because balance low")
        for i in range(3):
            funding_txid = fund_offline_wallet2(wallet_bb_date['address'], WALLET_BB_DATE_THRESHOLD_UTXO_VALUE)
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


def gen_wallet_sha256hash(str):
    return gen_wallet_no_sign(hash256hex(str))


def hash256hex(str):
        return hashlib.sha256(str.encode()).hexdigest()


def get_10digit_int_sha256(str):
    return int(hash256hex(str), base=16)


def convert_alphanumeric_2d8dp(alphanumeric):
    result = round(int(str(get_10digit_int_sha256(alphanumeric))[:10])/100000000, 10)
    print (f"converting {alphanumeric} to {result} coins")
    return result


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
    if int(result) >= 100:
        print("Result coin is equal or more than 100")
    print(f"converted {date} to {result} coins")
    return result


def convert_to_sats_lt_100(item):
    formatItem = int(item.replace('-', ''))
    result = round(formatItem/100000000,10)
    if int(result) >=100:
        raise Exception(f"ERROR: sat value is greater than 100 coins, try other convert_to_sats function")
    print(f"convert_to_sats: {item} to {result}")
    return result


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


# no test
def split_wallet1():
    print("split_wallet1()")
    delivery_date_wallet = getOfflineWalletByName(WALLET_DELIVERY_DATE)
    utxos_json = explorer_get_utxos(delivery_date_wallet['address'])


def electrum_sendtoaddress(from_address, from_wif, utxo_threshold, to_address, amount):
    print("start electrum_sendtoaddress")
    # save current tx state
    raw_tx_meta = {}
    attempted_txids = []

    utxos_json = explorer_get_utxos(from_address)
    utxos_json = json.loads(utxos_json)

    # Check if no utxos
    if len(utxos_json) == 0:
        print(f'electrum_sendtoaddress {from_address} Error: Need more UTXO! {from_address}')
        return

    # Filter utxos that has > 2 confirmations on blockchain
    utxos_json = [x for x in utxos_json if x['confirmations'] > 2]
    if len(utxos_json) == 0:
        print(f'222 One of UTXOS must have at least 2 confirmations on blockchain')
        return

    utxo_amount = utxo_bundle_amount(utxos_json);
    if utxo_amount < utxo_threshold:
        print(f'UTXO amount ({utxo_amount}) must have value t= Threshold ({utxo_threshold})')
        return

    # Execute
    utxos_slice = utxo_slice_by_amount(utxos_json, amount)
    # print(f"Batch UTXOS used for amount {amount}:", utxos_slice)

    raw_tx_meta['utxos_slice'] = utxos_slice
    attempted_txids.append(str(utxos_slice[0]["txid"]))
    raw_tx_meta['attempted_txids'] = attempted_txids
    send = {}
    try:
        send = utxo_send(utxos_slice, amount, to_address, from_wif, from_address)
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
            send = utxo_send(raw_tx_meta['utxos_slice'], amount, to_address, from_wif, from_address)
        except Exception as e:
            i += 1
            print(f"Trying next UTXO in loop {i} out of {len(utxos_json)}")
            # print(json.dumps(raw_tx_meta), sort_keys=False, indent=3)
            # log2discord(raw_tx_meta['utxos_slice'])
    print("end electrum_sendtoaddress")
    return send


# no test
def sendToBatch(wallet_name, threshold, batch_raddress, amount, integrity_id):

    # sanitise amount
    if isinstance(amount, str):
        amount = dateToSatoshi(amount)

    # generate wallet by name
    wallet = getOfflineWalletByName(wallet_name)

    # sendtoaddress using electrum client code
    send = electrum_sendtoaddress(wallet['address'], wallet['wif'], threshold, batch_raddress, amount)
    if (send is None):
        print("222 send is none")
        log2discord(
            f"---\nFailed to send batch: **{wallet_name}** to **{batch_raddress}**\nAmount sent: **{amount}**\n---")
    else:
        openfood_save_batch_timestamping_tx = save_batch_timestamping_tx(integrity_id, wallet_name, wallet['address'], send["txid"])
        print(f"openfood_save_batch_timestamping_tx {openfood_save_batch_timestamping_tx}")
        print(type(openfood_save_batch_timestamping_tx))

    #return (send["txid"], json.loads(openfood_save_batch_timestamping_tx))
    return send["txid"]


def sendToBatchMassBalance(batch_raddress, amount, integrity_id):
    if amount is None:
        amount = 0.01

    amount = round(amount/1, 10)

    wallet = getOfflineWalletByName(WALLET_MASS_BALANCE)

    dict = {batch_raddress: int(amount*100000000)}

    print("dict: " + str(dict) + " amount: " + str(amount))
    
    print("wallet: " + str(wallet))

    #try:
    print("try entered")
    
    utxos = json.loads(explorer_get_utxos(wallet['address']))
    
    

    for utxo in utxos:
        test_tx, amounts = make_tx_from_scratch(dict, amount, utxo, from_addr=wallet['address'], from_pub=wallet['pubkey'], from_priv=wallet['wif'])

        print("test_tx: " + str(test_tx))
    
        test_tx = signtx(test_tx, [amounts], wallet['wif'])
    
        print("test")
    #except Exception as e:
        #print("erorrr: " + str(e)) 
        print(" ****** TEST TX ****** ")
    
        print(str(test_tx))
        res = ""
        try:
            res = broadcast_via_explorer(EXPLORER_URL, test_tx)
        except Exception as e:
            res = str(e)
            print("erorrr: " + str(e))
            print("MASS BALANCE ERR")
            #raise e
        try: 
            print("res1: " + str(res))
            #res = json.load(res)
            if 'txid' in res:
                print("final tx: " + str(res))
                save_batch_timestamping_tx(integrity_id, WALLET_MASS_BALANCE, wallet['address'], res["txid"])
                fund_offline_wallet3(wallet['address'], WALLET_MASS_BALANCE_THRESHOLD_UTXO_VALUE, utxos)
                return res['txid']

        except Exception as e:
            print("error: " + str(e))

        print("res: " + str(res))
     

    #send_batch = sendToBatch_address_amount_dict(WALLET_MASS_BALANCE, WALLET_MASS_BALANCE_THRESHOLD_UTXO_VALUE, {batch_raddress: amount}, integrity_id)
    #save_batch_timestamping_tx(integrity_id, wallet_name, wallet['address'], send["txid"])
    #fund_offline_wallet3(wallet['address'], refuel_amount,utxos_json)


    return res #send_batch # TXID


def sendToBatchDeliveryDate(batch_raddress, date, integrity_id):
    send_batch = sendToBatch_address_amount_dict(WALLET_DELIVERY_DATE, WALLET_DELIVERY_DATE_THRESHOLD_UTXO_VALUE, {batch_raddress: dateToSatoshi(date)}, integrity_id)
    return send_batch # TXID


def sendToBatchPDS(batch_raddress, date, integrity_id):
    send_batch = sendToBatch_address_amount_dict(WALLET_PROD_DATE, WALLET_PROD_DATE_THRESHOLD_UTXO_VALUE, {batch_raddress: dateToSatoshi(date)}, integrity_id)
    return send_batch # TXID


def sendToBatchBBD(batch_raddress, date, integrity_id):
    send_batch = sendToBatch_address_amount_dict(WALLET_BB_DATE, WALLET_BB_DATE_THRESHOLD_UTXO_VALUE, {batch_raddress: dateToSatoshi(date)}, integrity_id)
    return send_batch # TXID


def sendToBatchPON(batch_raddress, pon, integrity_id):
    if (len(str(pon)) > 10) or (not pon.isnumeric()):
        if (len(str(pon)) > 10):
            print("PON length is more than 10, Lenght is " + str(len(str(pon))))
        if not pon.isnumeric():
            print("PON is alphanumeric.")
        pon = convert_alphanumeric_2d8dp(pon)
    else:
        pon = dateToSatoshi(pon)
    send_batch = sendToBatch_address_amount_dict(WALLET_PON, WALLET_PON_THRESHOLD_UTXO_VALUE, {batch_raddress: pon}, integrity_id)
    return send_batch # TXID


def sendToBatchTIN(batch_raddress, tin, integrity_id):
    if (len(str(tin)) > 10) or (not tin.isnumeric()):
        if (len(str(tin)) > 10):
            print("TIN length is more than 10, Lenght is " + str(len(str(tin))))
        if not tin.isnumeric():
            print("TIN is alphanumeric.")
        tin = convert_alphanumeric_2d8dp(tin)
    else:
        tin = dateToSatoshi(tin)
    send_batch = sendToBatch_address_amount_dict(WALLET_TIN, WALLET_TIN_THRESHOLD_UTXO_VALUE, {batch_raddress: tin}, integrity_id)
    return send_batch # TXID


def sendToBatchPL(batch_raddress, pl_name, integrity_id):
    send_batch = sendToBatch_address_amount_dict(pl_name, FUNDING_AMOUNT_LOCATION, {batch_raddress: 0.001}, integrity_id)
    return send_batch # TXID


def sendToBatchJDS(batch_raddress, jds, integrity_id):
  send_batch = sendToBatch_address_amount_dict(WALLET_JULIAN_START, WALLET_JULIAN_START_THRESHOLD_UTXO_VALUE, {batch_raddress: float(jds)}, integrity_id)
  return send_batch # TXID


def sendToBatchJDE(batch_raddress, jde, integrity_id):
  send_batch = sendToBatch_address_amount_dict(WALLET_JULIAN_STOP, WALLET_JULIAN_STOP_THRESHOLD_UTXO_VALUE, {batch_raddress: float(jde)}, integrity_id)
  return send_batch # TXID


def sendToBatchPC(batch_raddress, pc, integrity_id):
  send_batch = sendToBatch_address_amount_dict(WALLET_ORIGIN_COUNTRY, WALLET_ORIGIN_COUNTRY_THRESHOLD_UTXO_VALUE, {batch_raddress: 0.0001}, integrity_id)
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


def get_certificates_no_timestamp(orgid):
    url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_CERTIFICATE_NORADDRESS + "?orgid=" + str(orgid)
    try:
        res = requests.get(url)
    except Exception as e:
        raise Exception(e)

    certs_no_addy = json.loads(res.text)
    return certs_no_addy

def get_locations_no_timestamp(orgid):
    url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_LOCATION_NORADDRESS + "?orgid=" + str(orgid)
    try:
        res = requests.get(url)
    except Exception as e:
        raise Exception(e)

    locs_no_addy = json.loads(res.text)
    return locs_no_addy


def get_products_no_timestamp(orgid):
    url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_PRODUCT_NORADDRESS + "?orgid=" + str(orgid)
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


def fund_product(product_address):
    txid = sendtoaddress_wrapper(product_address, FUNDING_AMOUNT_PRODUCT)
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
        obj = json.dumps({"error": res})
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


def get_jcapi_foundation(foundation_raddress):
    print(f"GET openfood-api foundation query: {URL_openfood_API_FOUNDATION}?raddress={foundation_raddress}")
    res = getWrapper(f"{URL_openfood_API_FOUNDATION}?raddress={foundation_raddress}")
    foundation_res = json.loads(res)
    if len(foundation_res) == 0:
        return foundation_res
    # TODO E721 do not compare types, use "isinstance()" pep8
    if type(foundation_res) == type(['d', 'f']):
        return foundation_res[0]
    return foundation_res


def get_jcapi_industry():
    print(f"GET openfood-api industry query: {URL_openfood_API_INDUSTRY}")
    res = getWrapper(URL_openfood_API_INDUSTRY)
    foundation_res = json.loads(res)
    if len(foundation_res) == 0:
        return foundation_res
    # TODO E721 do not compare types, use "isinstance()" pep8
    if type(foundation_res) == type(['d', 'f']):
        return foundation_res[0]
    return foundation_res



def get_jcapi_foundation_oracle(foundation_id):
    print("GET openfood-api oracle query: " + URL_openfood_API_FOUNDATION_ORACLE + "?foundation=" + str(foundation_id))
    res = getWrapper(URL_openfood_API_FOUNDATION_ORACLE + "?foundation=" + str(foundation_id))
    oracle_res = json.loads(res)
    if len(oracle_res) == 0:
        return oracle_res
    # TODO E721 do not compare types, use "isinstance()" pep8
    if type(oracle_res) == type(['d', 'f']):
        return oracle_res[0]
    return oracle_res


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
    batch_integrity['integrity_pre_tx'] = start_txid
    print(batch_integrity)
    # data = {'name': 'chris', 'integrity_address': integrity_address[
    #    'address'], 'integrity_pre_tx': integrity_start_txid, 'batch_lot_raddress': bnfp_wallet['address']}

    batch_integrity_start_response = putWrapper(batch_integrity_url, batch_integrity)
    return batch_integrity_start_response


def batch_wallets_timestamping_end(batch_integrity, end_txid):
    batch_integrity['integrity_post_tx'] = end_txid
    batch_integrity['ack'] = True
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
def deprecated_organization_get_customer_po_wallet(CUSTOMER_RADDRESS):
    kv_response = organization_get_pool_wallets_by_raddress(CUSTOMER_RADDRESS)
    print(kv_response)
    tmp = json.loads(kv_response['value'])
    tmp2 = str(tmp[WALLET_ALL_OUR_PO])
    return tmp2


# test skipped
def deprecated_organization_get_customer_batch_wallet(CUSTOMER_RADDRESS):
    kv_response = organization_get_pool_wallets_by_raddress(CUSTOMER_RADDRESS)
    print(kv_response)
    tmp = json.loads(kv_response['value'])
    tmp2 = str(tmp[WALLET_ALL_OUR_BATCH_LOT])
    return tmp2


# test skipped
def deprecated_organization_send_batch_links3(batch_integrity, pon, bnfp):
    print("pon is " + pon)
    if (len(str(pon)) > 10) or (not pon.isnumeric()):
        if (len(str(pon)) > 10):
            print("PON length is more than 10, Lenght is " + str(len(str(pon))))
        if not pon.isnumeric():
            print("PON is alphanumeric.")
        pon_as_satoshi = convert_alphanumeric_2d8dp(pon)
    else:
        pon_as_satoshi = dateToSatoshi(pon)
        
    print("bnfp is " + bnfp)
    if (len(str(bnfp)) > 10) or (not bnfp.isnumeric()):
        if (len(str(bnfp)) > 10):
            print("BNFP length is more than 10, Lenght is " + str(len(str(bnfp))))
        if not bnfp.isnumeric():
            print("BNFP is alphanumeric.")
        bnfp_as_satoshi = convert_alphanumeric_2d8dp(bnfp)
    else:
        bnfp_as_satoshi = dateToSatoshi(bnfp)
        
    pool_batch_wallet = organization_get_our_pool_batch_wallet()
    pool_po = organization_get_our_pool_po_wallet()
    customer_pool_wallet = organization_get_customer_po_wallet(CUSTOMER_RADDRESS)

    print("****** MAIN WALLET batch links3 sendmany from ******* " + THIS_NODE_RADDRESS)
    print(pool_batch_wallet)
    print("CUSTOMER POOL WALLET: " + customer_pool_wallet)

    json_object = {
        batch_integrity['integrity_address']: FUNDING_AMOUNT_TIMESTAMPING_BATCH,
        pool_batch_wallet: bnfp_as_satoshi,
        pool_po: pon_as_satoshi,
        batch_integrity['batch_lot_raddress']: SATS_10K,
        customer_pool_wallet: pon_as_satoshi
   }
    print(json_object)
    sendmany_txid = sendmany_wrapper(THIS_NODE_RADDRESS, json_object)
    return sendmany_txid


def calculate_sats_pon(pon):
    print(f"pon is {pon}")
    pon_as_sats = 0
    if (len(str(pon)) > 10) or (not pon.isnumeric()):
        if (len(str(pon)) > 10):
            # print("PON length is more than 10, Lenght is " + str(len(str(pon))))
            print(f"PON length is more than 10, length is {len(str(pon))}")
        if not pon.isnumeric():
            print(f"PON is alphanumeric")
        pon_as_sats = convert_alphanumeric_2d8dp(pon)
    else:
        # pon_as_sats = dateToSatoshi(pon)
        pon_as_sats = convert_to_sats_lt_100(pon)
    if pon_as_sats == 0:
        raise Exception(f"pon = 0. Not good. {pon}")
    return pon_as_sats


def calculate_sats_batch_number(batch_number):
    print(f"batch number is {batch_number}")
    batch_number_as_sats = 0
    if (len(str(batch_number)) > 10) or (not batch_number.isnumeric()):
        if (len(str(batch_number)) > 10):
            print(f"batch_number length is more than 10, length is {len(str(batch_number))}")
        if not batch_number.isnumeric():
            print("batch_number is alphanumeric.")
        batch_number_as_sats = convert_alphanumeric_2d8dp(batch_number)
    else:
        # batch_number_as_sats = dateToSatoshi(batch_number)
        batch_number_as_sats = convert_to_sats_lt_100(batch_number)
    if batch_number_as_sats == 0:
        raise Exception(f"batch_number = 0. Not good. {batch_number}")
    return batch_number_as_sats


def industry_get_collector_pon():
    #pool_batch_wallet = organization_get_our_pool_batch_wallet()
    #pool_po = organization_get_our_pool_po_wallet()
    f_addresses = get_foundation_addresses()
    print(f"industry_get_collector_pon has f_addresses {f_addresses}")
    collector_pon = json.loads(f_addresses)[WALLET_ALL_OUR_PO]
    return collector_pon


def sendmany_add_recipient(destinations, raddress, amount):
    print(f"{destinations}")
    print(f"adding sendmany recipient: {raddress}: {amount}")
    destinations.update({raddress:amount})
    print(f"{destinations}")
    return destinations


def identifier_builder_add(phrase, data):
    phrase = f"{phrase}{data}"
    return phrase


def poid_builder(pon, gs1p):
    phrase = ""
    phrase = identifier_builder_add(phrase, f"{pon}")
    phrase = identifier_builder_add(phrase, f"{gs1p}")
    pon_wallet = gen_wallet_data_hash(phrase)
    return pon_wallet


def organization_send_batch_links4(batch_integrity, pon, bnfp):
    print("pon is " + pon)
    if (len(str(pon)) > 10) or (not pon.isnumeric()):
        if (len(str(pon)) > 10):
            print("PON length is more than 10, Lenght is " + str(len(str(pon))))
        if not pon.isnumeric():
            print("PON is alphanumeric.")
        pon_as_satoshi = convert_alphanumeric_2d8dp(pon)
    else:
        pon_as_satoshi = dateToSatoshi(pon)

    print("bnfp is " + bnfp)
    if (len(str(bnfp)) > 10) or (not bnfp.isnumeric()):
        if (len(str(bnfp)) > 10):
            print("BNFP length is more than 10, Lenght is " + str(len(str(bnfp))))
        if not bnfp.isnumeric():
            print("BNFP is alphanumeric.")
        bnfp_as_satoshi = convert_alphanumeric_2d8dp(bnfp)
    else:
        bnfp_as_satoshi = dateToSatoshi(bnfp)

    #pool_batch_wallet = organization_get_our_pool_batch_wallet()
    #pool_po = organization_get_our_pool_po_wallet()
    f_addresses = get_foundation_addresses()
    customer_pool_wallet = json.loads(f_addresses)[WALLET_ALL_OUR_PO]

    print("****** MAIN WALLET batch links4 sendmany from ******* " + THIS_NODE_RADDRESS)
    print("CUSTOMER POOL WALLET: " + customer_pool_wallet)

    json_object = {
        batch_integrity['integrity_address']: FUNDING_AMOUNT_TIMESTAMPING_BATCH,
        batch_integrity['batch_lot_raddress']: SATS_10K,
        customer_pool_wallet: pon_as_satoshi
    }
    print(json_object)
    sendmany_txid = sendmany_wrapper(THIS_NODE_RADDRESS, json_object)
    return sendmany_txid


def organization_send_batch_links5(batch_integrity, pon, batch_number):
    destinations = {}
    sats_pon = calculate_sats_pon(pon)
    sats_batch_number = calculate_sats_batch_number(batch_number)
    industry_collector_pon = industry_get_collector_pon()
    destinations = sendmany_add_recipient(destinations, batch_integrity['integrity_address'], FUNDING_AMOUNT_TIMESTAMPING_BATCH)
    destinations = sendmany_add_recipient(destinations, batch_integrity['batch_lot_raddress'], sats_batch_number)
    destinations = sendmany_add_recipient(destinations, industry_collector_pon, sats_pon)
    print(f"sendmany destinations: {destinations}")
    print(f"****** MAIN WALLET batch links4 sendmany from ******* {THIS_NODE_RADDRESS}")
    sendmany_txid = sendmany_wrapper(THIS_NODE_RADDRESS, destinations)
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
                'product_id': batch['anfp'],
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


def push_industry_oracletxid(foundation_id, oracletxid):
    data = {'oracle_txid': oracletxid,
            'baton': '',
            'foundation': foundation_id }
    api_res = postWrapper(URL_openfood_API_FOUNDATION_ORACLE, data=data)
    return api_res


def push_industry_foundation(name, raddress, pubkey):
    data = {'name': name,
            'raddress': raddress,
            'pubkey': pubkey }
    api_res = postWrapper(URL_openfood_API_FOUNDATION, data=data)
    return api_res


def industry_oracle_baton_update(foundation_id, baton):
    print(f"HTTP PUT update baton {baton} for oracle belonging to foundation {foundation_id}")
    oracle = get_jcapi_foundation_oracle(foundation_id)
    oracle['baton'] = baton
    oracle_baton_update_url = URL_openfood_API_FOUNDATION_ORACLE + str(oracle['id']) + "/"
    oracle_update_response = putWrapper(oracle_baton_update_url, oracle)
    return oracle_update_response


def industry_oracle_publisher_baton_txid_update(foundation_id, publisher_baton_txid):
    print(f"HTTP PUT update publisher_baton_txid {publisher_baton_txid} for oracle belonging to foundation {foundation_id}")
    oracle = get_jcapi_foundation_oracle(foundation_id)
    oracle['publisher_baton_txid'] = publisher_baton_txid
    oracle_baton_update_url = URL_openfood_API_FOUNDATION_ORACLE + str(oracle['id']) + "/"
    oracle_update_response = putWrapper(oracle_baton_update_url, oracle)
    return oracle_update_response


def log2discord(msg=""):
    try:
        postWrapper(DISCORD_WEBHOOK_URL, {"content": msg})
    except:
        pass


def deprecated_update_kv_foundation():
    pool_wallets = {}
    pool_wallets[str(WALLET_ALL_OUR_PO)] = CUSTOMER_RADDRESS
    pool_wallets[str(WALLET_ALL_OUR_BATCH_LOT)] = CUSTOMER_RADDRESS
    pool_wallets[str(WALLET_ALL_CUSTOMER_PO)] = CUSTOMER_RADDRESS
    print("Verifying pool wallets in KV1")
    org_kv1_key_pool_wallets = THIS_NODE_RADDRESS + KV1_ORG_POOL_WALLETS
    print("Updating with a value")
    kv_response = kvupdate_wrapper(org_kv1_key_pool_wallets, json.dumps(pool_wallets), "22000", "password")
    print(kv_response)


def deprecated_verify_kv_foundation():
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


def sendToBatch_address_amount_dict(wallet_name, refuel_amount, address_amount_dict, integrity_id):
    # print(f"SEND {wallet_name}, check accuracy")
    # save current tx state
    raw_tx_meta = {}
    attempted_txids = []

    # first kv in dict is batch raddress
    batch_raddress = list(address_amount_dict.keys())[0]
    print(f"batch_raddress {batch_raddress}")

    # get amount from dict values
    #amount = sum(address_amount_dict.values())
    amount = list(address_amount_dict.values())[0]
    if type(amount) is list:
        amount = sum(amount)
    else:
        amount = amount

    wallet = getOfflineWalletByName(wallet_name)
    # print(f"{wallet_name} {wallet['address']}")

    utxos_json = explorer_get_utxos(wallet['address'])
    utxos_json = json.loads(utxos_json)
    #print(f"utxos_json {utxos_json}")

    # Check if no utxos
    if len(utxos_json) == 0:
        print(f'sendToBatch {wallet_name} Error: Need more UTXO! ' + wallet['address'])
        return

    # Filter utxos that has > 2 confirmations on blockchain
    utxos_json = [x for x in utxos_json if x['confirmations'] > 2]
    #print(f"utxos_json {utxos_json}")
    if len(utxos_json) == 0:
        print(f'222 One of UTXOS must have at least 2 confirmations on blockchain')
        return

    # Execute
    utxos_slice = utxo_slice_by_amount(utxos_json, amount)
    #print(f"utxos_slice {utxos_slice}")
    # print(f"Batch UTXOS used for amount {amount}:", utxos_slice)

    raw_tx_meta['utxos_slice'] = utxos_slice
    attempted_txids.append(str(utxos_slice[0]["txid"]))
    raw_tx_meta['attempted_txids'] = attempted_txids

    send = {}
    try:
        # send = utxo_send_address_amount_dict(utxos_slice, address_amount_dict, wallet['wif'], wallet['address'])
        send = utxo_send_address_amount_dict(utxos_slice, address_amount_dict, wallet['wif'], get_this_node_raddress())
    except Exception as e:
        print(f"Failed sending a UTXO from first slice, looping to next slice soon...")
        send = {"txid": []}

    # send["txid"] = None
    # send = {}
    # send["txid"] = []
    i = 0
    while (len(send["txid"]) == 0) and (i < len(utxos_json)):
        # Execute
        raw_tx_meta = utxo_slice_by_amount2(utxos_json, amount, raw_tx_meta)
        print(f"Batch UTXOS used for amount {amount}:", raw_tx_meta['utxos_slice'])
        print(f"address_amount_dict {address_amount_dict}")
        try:
            # send = utxo_send_address_amount_dict(raw_tx_meta['utxos_slice'], address_amount_dict, wallet['wif'], wallet['address'])
            send = utxo_send_address_amount_dict(raw_tx_meta['utxos_slice'], address_amount_dict, wallet['wif'], get_this_node_raddress())
        except Exception as e:
            i += 1
            print(f"Trying next UTXO in loop {i} out of {len(utxos_json)}")
            #print(json.dumps(raw_tx_meta), sort_keys=False, indent=3)
            # log2discord(raw_tx_meta['utxos_slice'])

    save_batch_timestamping_tx(integrity_id, wallet_name, wallet['address'], send["txid"])
    fund_offline_wallet3(wallet['address'], refuel_amount,utxos_json)
    if (send is None):
        print("222 send is none")
        log2discord(
            f"---\nFailed to send batch: **{batch_raddress}** to **{wallet['address']}**\nAmount sent: **{amount}**\nUTXOs:\n**{utxos_slice}**\n---")
    return send["txid"]
