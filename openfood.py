from .openfood_env import GTID
from .openfood_env import EXPLORER_URL
from .openfood_env import THIS_NODE_RADDRESS
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
import requests
import json

load_dotenv(verbose=True)
SCRIPT_VERSION = HK_LIB_VERSION
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


# test skipped
def get_this_node_raddress():
    return THIS_NODE_RADDRESS


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


def sendToBatchMassBalance(batch_raddress, amount, integrity_id):
    if amount is None:
        amount = 0.01
    amount = round(amount/1, 10)
    send_batch = sendToBatch(WALLET_MASS_BALANCE, WALLET_MASS_BALANCE_THRESHOLD_UTXO_VALUE, batch_raddress, amount, integrity_id)
    return send_batch # TXID


def sendToBatchDeliveryDate(batch_raddress, date, integrity_id):
    send_batch = sendToBatch(WALLET_DELIVERY_DATE, WALLET_DELIVERY_DATE_THRESHOLD_UTXO_VALUE, batch_raddress, date, integrity_id)
    return send_batch # TXID


def sendToBatchPDS(batch_raddress, date, integrity_id):
    send_batch = sendToBatch(WALLET_PROD_DATE, WALLET_PROD_DATE_THRESHOLD_UTXO_VALUE, batch_raddress, date, integrity_id)
    return send_batch # TXID


def sendToBatchBBD(batch_raddress, date, integrity_id):
    send_batch = sendToBatch(WALLET_BB_DATE, WALLET_BB_DATE_THRESHOLD_UTXO_VALUE, batch_raddress, date, integrity_id)
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
    send_batch = sendToBatch(WALLET_PON, WALLET_PON_THRESHOLD_UTXO_VALUE, batch_raddress, pon, integrity_id)
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
    send_batch = sendToBatch(WALLET_TIN, WALLET_TIN_THRESHOLD_UTXO_VALUE, batch_raddress, tin, integrity_id)
    return send_batch # TXID


def sendToBatchPL(batch_raddress, pl_name, integrity_id):
    send_batch = sendToBatch(pl_name, 0, batch_raddress, 0.0001, integrity_id)
    return send_batch # TXID


def sendToBatchJDS(batch_raddress, jds, integrity_id):
  send_batch = sendToBatch(WALLET_JULIAN_START, WALLET_JULIAN_START_THRESHOLD_UTXO_VALUE, batch_raddress, 0.0001, integrity_id)
  return send_batch # TXID


def sendToBatchJDE(batch_raddress, jde, integrity_id):
  send_batch = sendToBatch(WALLET_JULIAN_STOP, WALLET_JULIAN_STOP_THRESHOLD_UTXO_VALUE, batch_raddress, 0.0001, integrity_id)
  return send_batch # TXID


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


# test skipped
def organization_send_batch_links3(batch_integrity, pon, bnfp):
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

    print("****** MAIN WALLET batch links sendmany ******* " + THIS_NODE_RADDRESS)
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


def sendToBatch_address_amount_dict(wallet_name, threshold, address_amount_dict, integrity_id):
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
    print(f"wallet {wallet}")

    utxos_json = explorer_get_utxos(wallet['address'])
    utxos_json = json.loads(utxos_json)
    #print(f"utxos_json {utxos_json}")

    # Check if no utxos
    if len(utxos_json) == 0:
        print(f'sendToBatch {wallet_name} Error: Need more UTXO! ' + wallet['address'])
        return

    # Filter utxos that has > 2 confirmations on blockchain
    utxos_json = [x for x in utxos_json if x['confirmations'] > 2]
    print(f"utxos_json {utxos_json}")
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
        send = utxo_send_address_amount_dict(utxos_slice, address_amount_dict, wallet['wif'], wallet['address'])
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
            send = utxo_send_address_amount_dict(raw_tx_meta['utxos_slice'], address_amount_dict, wallet['wif'], wallet['address'])
        except Exception as e:
            i += 1
            print(f"Trying next UTXO in loop {i} out of {len(utxos_json)}")
            # print(json.dumps(raw_tx_meta), sort_keys=False, indent=3)
            # log2discord(raw_tx_meta['utxos_slice'])

    save_batch_timestamping_tx(integrity_id, wallet_name, wallet['address'], send["txid"])
    if (send is None):
        print("222 send is none")
        log2discord(
            f"---\nFailed to send batch: **{batch_raddress}** to **{wallet['address']}**\nAmount sent: **{amount}**\nUTXOs:\n**{utxos_slice}**\n---")
    return send["txid"]
