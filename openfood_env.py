from dotenv import load_dotenv, find_dotenv
import os, requests
import json
load_dotenv(find_dotenv(), verbose=True)

LIB_SUB_VERSION = 56
SKIP_BATCH_PROCESSING = 9000
BATCH_PROCESSING = 5000
NUM_10K = 10000
SATS_10K = round(10000/100000000, 10)
HK_LIB_VERSION = round((LIB_SUB_VERSION + NUM_10K)/100000000, 10)
HK_SKIP_BATCH_PROCESSING = round((LIB_SUB_VERSION + NUM_10K + SKIP_BATCH_PROCESSING)/100000000, 10)
HK_BATCH_PROCESSING = round((LIB_SUB_VERSION + NUM_10K + BATCH_PROCESSING)/100000000, 10)

MULTI_1X = 1
MULTI_2X = 2
MULTI_3X = 3
MULTI_4X = 4
MULTI_5X = 5

# Priority Explorer: first to last order
EXPLORER_JSON = str(os.environ['EXPLORER_LIST'])
EXPLORER_LIST = json.loads(EXPLORER_JSON)

EXPLORER_URL = ""
for explorer_name, explorer_data in EXPLORER_LIST.items():
    if explorer_data["port"] == "443":
        http_protocol = "https://"
    else:
        http_protocol = "http://"
    url = http_protocol + EXPLORER_LIST[explorer_name]["host"] + ":" + EXPLORER_LIST[explorer_name]["port"] + "/"
    try:
        res = requests.get(url + "insight-api-komodo/sync/")
        res = res.json()
        if res["status"] == 'finished':
            EXPLORER_URL = url
            break
    except:
        pass

DISCORD_WEBHOOK_URL = str(os.environ['DISCORD_WEBHOOK_URL'])

# this node wallet
# TODO remove use of deprecated THIS_NODE_WALLET was used during development
# THIS_NODE_RADDRESS is the better name to use
THIS_NODE_WALLET = str(os.environ['THIS_NODE_RADDRESS'])
THIS_NODE_RADDRESS = str(os.environ['THIS_NODE_RADDRESS'])
THIS_NODE_WIF = str(os.environ['THIS_NODE_WIF'])
THIS_NODE_PUBKEY = str(os.environ['THIS_NODE_PUBKEY'])

#GTID
GTID = str(os.environ['GTID'])

# batch rpc
BATCH_RPC_USER = str(os.environ['BATCH_SMARTCHAIN_NODE_USERNAME'])
BATCH_RPC_PASSWORD = str(os.environ['BATCH_SMARTCHAIN_NODE_PASSWORD'])
BATCH_RPC_PORT = str(os.environ['BATCH_SMARTCHAIN_NODE_RPC_PORT'])
BATCH_NODE = str(os.environ['BATCH_SMARTCHAIN_NODE_IPV4_ADDR'])

# kv rpc
KV1_RPC_USER = str(os.environ['KV1_SMARTCHAIN_NODE_USERNAME'])
KV1_RPC_PASSWORD = str(os.environ['KV1_SMARTCHAIN_NODE_PASSWORD'])
KV1_RPC_PORT = str(os.environ['KV1_SMARTCHAIN_NODE_RPC_PORT'])
KV1_NODE = str(os.environ['KV1_SMARTCHAIN_NODE_IPV4_ADDR'])

# test wallet
TEST_GEN_WALLET_PASSPHRASE = "testing123"
TEST_GEN_WALLET_PUBKEY = "035b955ecee91343cae751b6b5c5c1b0efbd3a24ff0a622d8782e11b43eb8ec5af"
TEST_GEN_WALLET_WIF = "UriaaZ1hEftNZFM8pw9TXLF3iMqn2usCJDqeSnfAVkaPEwZXstLK"
TEST_GEN_WALLET_RADDRESS = "RDLtn5usEfoukyL2XqbcuoAg1sohU3m1F1"

# import api
IMPORT_API_HOST = str(os.environ['IMPORT_API_HOST'])
IMPORT_API_PORT = str(os.environ['IMPORT_API_PORT'])
IMPORT_API_BASE_URL = "http://" + IMPORT_API_HOST + ":" + IMPORT_API_PORT + "/"

# tweakable changes
BLOCKNOTIFY_CHAINSYNC_LIMIT = 5
HOUSEKEEPING_RADDRESS = "RS7y4zjQtcNv7inZowb8M6bH3ytS1moj9A"

# integrity/
DEV_IMPORT_API_JCF_BATCH_INTEGRITY_PATH = "integrity/"
# batch/require_integrity/
DEV_IMPORT_API_JCF_BATCH_REQUIRE_INTEGRITY_PATH = "batch/require_integrity/"
# raw/refresco/require_integrity/
DEV_IMPORT_API_RAW_REFRESCO_REQUIRE_INTEGRITY_PATH = "batch/import/require_integrity/"
# raw/refresco-integrity/
DEV_IMPORT_API_RAW_REFRESCO_INTEGRITY_PATH = "batch/import-integrity/"
# raw/refresco-tstx/
DEV_IMPORT_API_RAW_REFRESCO_TSTX_PATH = "batch/import-tstx/"
# raw/refresco/
DEV_IMPORT_API_RAW_REFRESCO_PATH = "batch/import/"

# LOAD openfood ENV
openfood_API_HOST = str(os.environ['JUICYCHAIN_API_HOST'])
openfood_API_PORT = str(os.environ['JUICYCHAIN_API_PORT'])
openfood_API_VERSION_PATH = str(os.environ['JUICYCHAIN_API_VERSION_PATH'])
openfood_API_BASE_URL = "http://" + openfood_API_HOST + \
    ":" + openfood_API_PORT + "/" + openfood_API_VERSION_PATH

openfood_API_ORGANIZATION_CERTIFICATE_NORADDRESS = "certificate/noraddress/"
openfood_API_ORGANIZATION_CERTIFICATE = "certificate/"
openfood_API_ORGANIZATION_LOCATION_NORADDRESS = "location/noraddress/"
openfood_API_ORGANIZATION_LOCATION = "location/"
# TODO unused
openfood_API_ORGANIZATION_CERTIFICATE_RULE = "certificate-rule/noraddress/"
openfood_API_ORGANIZATION_BATCH = "batch/"
openfood_API_ORGANIZATION = "organization/"

# UTXO DEFAULTS
UTXO_DEFAULT = 20

# FUNDING
FUNDING_AMOUNT_CERTIFICATE = 5
FUNDING_UTXO_COUNT_CERTIFICATE = UTXO_DEFAULT
FUNDING_AMOUNT_LOCATION = 5
FUNDING_UTXO_COUNT_LOCATION = UTXO_DEFAULT
FUNDING_AMOUNT_TIMESTAMPING_START = 0.090
FUNDING_AMOUNT_TIMESTAMPING_BATCH = 0.091
FUNDING_AMOUNT_TIMESTAMPING_END = 0.092

# PAPER WALLET NAMES
#WALLET_ALL_OUR_BATCH_LOT = "_ALL_OUR_BATCH_LOT"
WALLET_ALL_OUR_BATCH_LOT = "_ALL_OUR_BATCH"
WALLET_ALL_CUSTOMER_PO = "_ALL_CUSTOMER_PO"
#WALLET_ALL_OUR_PO = "_ALL_OUR_PO"
WALLET_ALL_OUR_PO = "_ALL_OUR_PO"

# OFFLINE WALLET NAMES
WALLET_DELIVERY_DATE = "DELIVERY_DATE"
WALLET_JULIAN_START = "JULIAN_START"
WALLET_JULIAN_STOP = "JULIAN_STOP"
WALLET_BB_DATE = "BB_DATE"
WALLET_PROD_DATE = "PROD_DATE"
WALLET_ORIGIN_COUNTRY = "ORIGIN_COUNTRY"
WALLET_TIN = "TIN"
WALLET_PON = "PON"
WALLET_MASS_BALANCE = "MASS_BALANCE"


# OFFLINE WALLET BALANCE & UTXO THRESHOLD
WALLET_DELIVERY_DATE_THRESHOLD_BALANCE = 1000
WALLET_DELIVERY_DATE_THRESHOLD_UTXO = UTXO_DEFAULT
WALLET_DELIVERY_DATE_THRESHOLD_UTXO_VALUE = 0.21

WALLET_PON_THRESHOLD_BALANCE = 40000
WALLET_PON_THRESHOLD_UTXO = UTXO_DEFAULT
WALLET_PON_THRESHOLD_UTXO_VALUE = 100

WALLET_JULIAN_START_THRESHOLD_BALANCE = 1000
WALLET_JULIAN_START_THRESHOLD_UTXO = UTXO_DEFAULT
WALLET_JULIAN_START_THRESHOLD_UTXO_VALUE = 370

WALLET_JULIAN_STOP_THRESHOLD_BALANCE = 1000
WALLET_JULIAN_STOP_THRESHOLD_UTXO = UTXO_DEFAULT
WALLET_JULIAN_STOP_THRESHOLD_UTXO_VALUE = 370

WALLET_BB_DATE_THRESHOLD_BALANCE = 1000
WALLET_BB_DATE_THRESHOLD_UTXO = UTXO_DEFAULT
WALLET_BB_DATE_THRESHOLD_UTXO_VALUE = 20

WALLET_PROD_DATE_THRESHOLD_BALANCE = 1000
WALLET_PROD_DATE_THRESHOLD_UTXO = UTXO_DEFAULT
WALLET_PROD_DATE_THRESHOLD_UTXO_VALUE = 20

WALLET_ORIGIN_COUNTRY_THRESHOLD_BALANCE = 100
WALLET_ORIGIN_COUNTRY_THRESHOLD_UTXO = UTXO_DEFAULT
WALLET_ORIGIN_COUNTRY_THRESHOLD_UTXO_VALUE = 2

WALLET_TIN_THRESHOLD_BALANCE = 5000
WALLET_TIN_THRESHOLD_UTXO = UTXO_DEFAULT
WALLET_TIN_THRESHOLD_UTXO_VALUE = 10

WALLET_MASS_BALANCE_THRESHOLD_BALANCE = 2000
WALLET_MASS_BALANCE_THRESHOLD_UTXO = UTXO_DEFAULT
WALLET_MASS_BALANCE_THRESHOLD_UTXO_VALUE = 100

KV1_ORG_POOL_WALLETS = "_ORG_POOL_WALLETS"

# TMP
CUSTOMER_RADDRESS = str(os.environ['CUSTOMER_RADDRESS'])
