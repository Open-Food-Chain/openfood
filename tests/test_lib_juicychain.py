from openfood_env import EXPLORER_URL
from openfood_env import THIS_NODE_WALLET
from openfood_env import THIS_NODE_WIF
from openfood_env import THIS_NODE_RADDRESS
from openfood_env import KV1_ORG_POOL_WALLETS
from openfood_env import IMPORT_API_BASE_URL
from openfood_env import DEV_IMPORT_API_RAW_REFRESCO_PATH

#from  openfood_env import TEST_GEN_WALLET_PASSPHRASE
#from  openfood_env import TEST_GEN_WALLET_ADDRESS
#from  openfood_env import TEST_GEN_WALLET_WIF
#from  openfood_env import TEST_GEN_WALLET_PUBKEY
from openfood_env import openfood_API_BASE_URL
from openfood_env import openfood_API_ORGANIZATION_BATCH
import openfood
from dotenv import load_dotenv
import pytest
load_dotenv(verbose=True)
SCRIPT_VERSION = 0.00013111

BATCHRPC = ""

openfood.connect_batch_node()

# @pytest.fixture(scope="session", autouse=True)
# def execute_before_any_test():
#     # your setup code goes here, executed ahead of first test
#     openfood.connect_node()
#     print("here we go")


import string
import random
import time
import json
import os
import binascii
from dotenv import load_dotenv
load_dotenv(verbose=True)

def str_time_prop(start, end, format, prop):
    """Get a time at a proportion of a range of two formatted times.

    start and end should be strings specifying times formated in the
    given format (strftime-style), giving an interval [start, end].
    prop specifies how a proportion of the interval to be taken after
    start.  The returned time will be in the specified format.
    """

    stime = time.mktime(time.strptime(start, format))
    etime = time.mktime(time.strptime(end, format))

    ptime = stime + prop * (etime - stime)

    res = time.strftime(format, time.localtime(ptime))
    print(res)
    return res


def generate_random_hex(size):
	size = size/2
	size = int(size)
	hex = binascii.b2a_hex(os.urandom(size))
	hex = str(hex)
	hex = hex[2:-1]
	return hex

def random_date(start, end, prop):
	return str_time_prop(start, end, '%Y-%m-%d', prop)

def random_date_cert(start, end, prop):
        return str_time_prop(start, end, '%d-%m-%Y', prop)

def make_random_string(length):
	str = ""
	for x in range(0,length):
		str = str + random.choice(string.ascii_letters)

	return str

def get_random_number(length):
	number = random.randint(10 ** (length-1), 10 ** (length))
	return number

def days(date):
	ret = ""
	for a in date:
		if a == '-':
			ret = ""
		else:
			ret = ret + a
	return int(ret)
def create_random_batch():
	RANDOM_VAL_ANFP=get_random_number(5)
	RANDOM_VAL_DFP="100EP PA Apfelsaft naturtrüb NF"
	RANDOM_VAL_BNFP=make_random_string(10)
	RANDOM_VAL_PC="DE"
	RANDOM_VAL_PL="Herrath"
	RANDOM_VAL_RMN=11200100520
	RANDOM_VAL_PON=get_random_number(8)
	RANDOM_VAL_POP=get_random_number(2)

	PDS=random_date("2020-1-1", "2020-11-15", random.random())
	PDE=random_date(PDS, "2020-11-15", random.random())
	BBD=PDE

	JDS=days(PDS)
	JDE=days(PDE)

	params = { "anfp": RANDOM_VAL_ANFP, "dfp": RANDOM_VAL_DFP, "bnfp": RANDOM_VAL_BNFP, "pds":PDS , "pde":PDE, "jds":JDS, "jde":JDE , "bbd":BBD , "pc": RANDOM_VAL_PC, "pl": RANDOM_VAL_PL, "rmn":RANDOM_VAL_RMN, "pon":RANDOM_VAL_PON, "pop":RANDOM_VAL_POP }
	print(params)
	return params


def properties_test(tests):
	for test in tests:
		print(test)
		assert test['anfp']
		assert test['dfp']
		assert test['bnfp']
		assert test['pds']
		assert test['pde']
		assert test['jds']
		assert test['jde']
		assert test['bbd']
		assert test['pc']
		assert test['pl']
		assert test['rmn']
		assert test['pon']
		assert test['pop']


def properties_test_cert(tests):
	for test in tests:
		print(test)
		assert test['id']
		assert test['name']
		assert test['date_issue']
		assert test['date_expiry']
		assert test['issuer']
		assert test['identifier']
		assert not test['pubkey']
		assert not test['raddress']
		assert not test['txid_funding']
		assert test['organization']

def properties_test_loc(tests):
	for test in tests:
		print(test)
		assert test['id']
		assert test['name']
		assert not test['pubkey']
		assert not test['raddress']
		assert not test['txid_funding']


def properties_test_cert_with_addie(tests):
        for test in tests:
                print(test)
                assert test['id']
                assert test['name']
                assert test['date_issue']
                assert test['date_expiry']
                assert test['issuer']
                assert test['identifier']
                assert test['pubkey']
                assert test['raddress']
                assert test['organization']


# TEST FUNCTIONS
def test_postWrapperr():
    url = IMPORT_API_BASE_URL + DEV_IMPORT_API_RAW_REFRESCO_PATH
    data = create_random_batch()
    test = openfood.postWrapper(url, data)
    test = json.loads(test)
    properties_test( [ test] )


# ORACLE TEST STUFF
def test_oracle_create():
	response = openfood.oracle_create("NYWTHR","Weather in NYC","L")
	print(response)
	assert response['result'] == "success"


def test_oracle_fund():
	hex = openfood.oracle_create("chris", "this is a test", "S")
	if hex['result'] == "success":
        	response = openfood.oracle_fund(hex['hex'])
        	assert response['result']['result'] == "success"
	else:
		assert True == hex['result']

#def oracle register, first create and fund need to work...

def test_oracle_list():
	response = openfood.oracle_list()
	print(response)
	assert type(response) == type([])
	for oracle in response:
		assert oracle
		assert len(oracle) == 64


def oracle_properties(oracle):
	print(oracle)
	assert oracle['result'] == "success"
	assert oracle['txid']
	assert oracle['name']
	assert oracle['description']
	assert oracle['format']
	assert oracle['marker']
	for registered in oracle['registered']:
		assert registered['publisher']
		assert registered['baton']
		assert registered['batontxid']
		assert registered['lifetime']
		assert registered['funds']
		assert registered['datafee']

def test_oracle_info():
	response = openfood.oracle_list()
	assert response[0]
	for oracle in response:
		response = openfood.oracle_info(oracle)
		oracle_properties(response)

def test_oracle_sub():
	response = openfood.oracle_list()
	assert response[0]
	for oracle in response:
		response = openfood.oracle_info(oracle)
		oracle_properties(response)
		response = openfood.oracle_subscribe(oracle, response['registered'][0]['publisher'], "0")
		print(response)
		assert response['result'] == "success"

def test_oracle_sample():
	response = openfood.oracle_list()
	assert response[0]
	for oracle in response:
		response = openfood.oracle_info(oracle)
		response = openfood.oracle_samples(oracle, response['registered'][0]['baton'], "1")
		assert response['result'] == "success"

def test_find_oracleid_with_pubkey():
	response = openfood.oracle_list()
	assert response[0]
	for oracle in response:
		response = openfood.oracle_info(oracle)
		print(response)
		orc_res = openfood.find_oracleid_with_pubkey(response['registered'][0]['publisher'])
		assert orc_res == oracle

#po tests

def test_po_gtid_hash():
    return True


#02f2cdd772ab57eae35996c0d39ad34fe06304c4d3981ffe71a596634fa26f8744
#put is no longer used
@pytest.mark.skip
def test_putWrapperr():
    url = EXPLORER_URL
    data = {'sender_raddress': THIS_NODE_WALLET,
            'tsintegrity': "1", 'sender_name': 'ORG WALLET', 'txid': "testtest"}

    test = openfood.putWrapper(url, data)
    assert is_json(test) is True

def test_getWrapper():
    url = IMPORT_API_BASE_URL + DEV_IMPORT_API_RAW_REFRESCO_PATH

    test = openfood.getWrapper(url)
    test = json.loads(test)

    properties_test( test )


def test_certificates_no_addy():
    test = openfood.get_certificates_no_timestamp()
    properties_test_cert(test)

def test_locations_no_addy():
    test = openfood.get_locations_no_timestamp()
    properties_test_loc(test)

def test_batchess_no_addy():
    test = openfood.get_batches_no_timestamp()
    if test == []:
        print("if this is empty the rest of the import api is not testable. Run the scripts in the import api in the docker compose to fill it back up (the austria juice script)")
        assert False == True
    properties_test(test)


def test_get_batches():
    test = openfood.get_batches()

    properties_test(test)


# deprecated
def test_PatchMassBalance():
    #url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_BATCH
    #batches = openfood.getWrapper(url)
    #batches = json.loads(batches)
    #batch_raddress = batches[0]['raddress']
    mass_balance_value = random.randint(0, 1000)
    mass_balance_txid = generate_random_hex(64)
    answere = openfood.massBalanceIntoApi(mass_balance_txid, mass_balance_value, 1)
    print(answere.text)
    assert answere.status_code == 200


def test_rToId():
    url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_BATCH
    batches = openfood.getWrapper(url)
    batches = json.loads(batches)
    for batch in batches:
        id = openfood.rToId(batch['raddress'])
        assert id == batch['id']

def test_sendToBatchMassBalance():
    url = openfood_API_BASE_URL + openfood_API_ORGANIZATION_BATCH
    batches = openfood.getWrapper(url)
    batches = json.loads(batches)
    batch_raddress = batches[0]['raddress']
    mass_balance_value = random.randint(0, 1000)
    txid = openfood.sendToBatchMassBalance(batch_raddress, mass_balance_value)
    assert len(txid) == 64


@pytest.mark.skip
def test_sendToBatchDeliveryDate():
    test = openfood.sendToBatchDeliveryDate('RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b', '2021-01-01', 'bed4a507-fd0e-46ca-ad44-efa63e8e2cd7')
    assert len(test) == 64


def test_sendToBatchPON():
    test = openfood.sendToBatchPON('RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b', '2021-01-01', 'bed4a507-fd0e-46ca-ad44-efa63e8e2cd7')
    assert len(test) == 64


@pytest.mark.skip
def test_sendToBatchJDS():
    test = openfood.sendToBatchJDS('RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b', '2021-01-01', 'bed4a507-fd0e-46ca-ad44-efa63e8e2cd7')
    assert len(test) == 64


@pytest.mark.skip
def test_sendToBatchJDE():
    test = openfood.sendToBatchJDE('RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b', '2021-01-01', 'bed4a507-fd0e-46ca-ad44-efa63e8e2cd7')
    assert len(test) == 64


@pytest.mark.skip
def test_sendToBatchOriginCountry():
    pass


@pytest.mark.skip
def test_sendToBatchBBD():
    test = openfood.sendToBatchBBD('RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b', '2021-01-01', 'bed4a507-fd0e-46ca-ad44-efa63e8e2cd7')
    assert len(test) == 64


@pytest.mark.skip
def test_sendToBatchPDS():
    test = openfood.sendToBatchPDS('RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b', '2021-01-01', 'bed4a507-fd0e-46ca-ad44-efa63e8e2cd7')
    assert len(test) == 64


@pytest.mark.skip
def test_sendToBatchTIN():
    test = openfood.sendToBatchTIN('RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b', '2021-01-01', 'bed4a507-fd0e-46ca-ad44-efa63e8e2cd7')
    assert len(test) == 64


@pytest.mark.skip
def test_sendToBatchPL():
    test = openfood.sendToBatchPL('RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b', '2021-01-01', 'bed4a507-fd0e-46ca-ad44-efa63e8e2cd7')
    assert len(test) == 64


@pytest.mark.skip
def test_sendToBatchPC():
    test = openfood.sendToBatchPC('RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b', '2021-01-01', 'bed4a507-fd0e-46ca-ad44-efa63e8e2cd7')
    assert len(test) == 64


@pytest.mark.skip
def test_send_to_batch_certificate():
    pass


#it seems like this is no longer a possible call
@pytest.mark.skip
def test_patchWrapperr():
    url = EXPLORER_URL
    data = {'sender_raddress': THIS_NODE_WALLET,
            'tsintegrity': "1", 'sender_name': 'ORG WALLET', 'txid': "testtest"}

    test = openfood.patchWrapper(url, data)
    assert is_json(test) is True

def test_connect_node():
    test = openfood.connect_node()
    assert test == True


def test_connect_kv1_node():
    test = openfood.connect_kv1_node()
    assert test == True


def test_signmessage_wrapper():
    data = "chris"
    deterministic = "H/RhRKf1Na1ZG142wrAmheGYnZIXBYnaZO65/Z2oJeeoTASUd5oRhHnzejRAQ0yFdUlAb8zX1HNMRbqZJ1u+awY="
    test = openfood.signmessage_wrapper(data)

    assert test == deterministic


@pytest.mark.skip
#php seems broken
def test_offlineWalletGenerator_fromObjectData_certificate():
    obj = {
        "issuer": "chris",
        "date_issue": "mylo",
        "date_expiry": "yesterday",
        "identifier": "1010011000013"
    }

    test = openfood.offlineWalletGenerator_fromObjectData_certificate(obj)

    print(test['address'])

    assert True == False


def properties_jcapi_test(test):
	assert test['id']
	assert test['name']
	assert test['pubkey']
	assert test['raddress']


def test_get_jcapi_organization():
    test = openfood.get_jcapi_organization()
    properties_jcapi_test(test)



def test_get_certificate_for_batch():
    test = openfood.get_certificate_for_batch()
    properties_test_cert_with_addie([ test ])


@pytest.mark.skip
def test_get_all_certificate_for_batch():
    pass


def test_utxo_bundle_amount():
    utxos_obj = [
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 10,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      },
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 11,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      }
    ]

    test = openfood.utxo_bundle_amount(utxos_obj)

    assert test == 2.2


def test_createrawtx_wrapper():
    utxos_obj = [
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 10,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      },
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 11,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      }
    ]

    txids = []
    vouts = []
    amount = openfood.utxo_bundle_amount(utxos_obj)
    to_address = THIS_NODE_WALLET

    for utxo in utxos_obj:
        txids = txids + [ utxo['txid'] ]
        vouts = vouts + [ utxo['vout'] ]

    test = openfood.createrawtx_wrapper(txids, vouts, to_address, amount)
    test = openfood.decoderawtx_wrapper(test)

    print(test)
    transactions_properties(test)


def transactions_properties( tx ):
	assert tx['txid']
	assert tx['overwintered']
	assert tx['version']
	assert tx['versiongroupid']
	assert type(tx['locktime']) == type(0)
	assert tx['expiryheight']
	assert tx['vin']
	for input in tx['vin']:
		assert input['txid']
		assert input['vout']
		assert input['scriptSig']
		assert input['scriptSig']['asm'] or input['scriptSig']['asm'] == ''
		assert input['scriptSig']['hex'] or input['scriptSig']['hex'] == ''
		assert input['sequence']
	assert tx['vout']
	for input in tx['vout']:
		assert input['value']
		assert input['valueZat']
		assert type(input['n']) == type(0)
		assert input['scriptPubKey']
		assert input['scriptPubKey']['asm']
		assert input['scriptPubKey']['hex']
		assert input['scriptPubKey']['reqSigs']
		assert input['scriptPubKey']['type']
		assert input['scriptPubKey']['addresses']
		for addie in input['scriptPubKey']['addresses']:
			assert addie[0] == 'R'
			assert len(addie) == 34
	assert type(tx['vjoinsplit']) == type([])
	assert type(tx['valueBalance']) == type(0.0)
	assert type(tx['vShieldedSpend']) == type([])
	assert type(tx['vShieldedOutput']) == type([])


def test_createrawtxwithchange():
    utxos_obj = [
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 10,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      },
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 11,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      }
    ]

    txids = []
    vouts = []
    amount = openfood.utxo_bundle_amount(utxos_obj)
    change_amount = 0.2

    to_address = change_address = THIS_NODE_WALLET

    for utxo in utxos_obj:
        txids = txids + [ utxo['txid'] ]
        vouts = vouts + [ utxo['vout'] ]

    test = openfood.createrawtxwithchange(txids, vouts, to_address, amount, change_address, change_amount)

    test = openfood.decoderawtx_wrapper(test)
    test = json.dumps(test)

    assert is_json(test) == True


def sign_properties( tx ):
	assert tx[0]['rawtx']
	assert tx[1]['amounts']


@pytest.mark.skip
def test_createrawtx7():
    pass

def test_createrawtx_dev():
    utxos_obj = [
        {
            "address": "RJt3kSRU3XxikWoixmyoA8CFT8kMaSs72M",
            "txid": "20cbbb4273fef7978e349a4e8fc9dcd03cadd6f4551909adae0e4aa05171691a",
            "vout": 1,
            "scriptPubKey": "21032833aadbf22a7ab67f6623a3a840a288d305e09915dc83c81fce6af0e31aa3b0ac",
            "amount": 1.99885,
            "satoshis": 199885000,
            "height": 70509,
            "confirmations": 8623
        },
        {
            "address": "RJt3kSRU3XxikWoixmyoA8CFT8kMaSs72M",
            "txid": "29154ac1ea3024bdef07698659c83fada1e78b445b40e76dc280fd0a6896b4fa",
            "vout": 1,
            "scriptPubKey": "76a9146950bcf37e3e92533a8502c3a783a568eba4122c88ac",
            "amount": 26,
            "satoshis": 2600000000,
            "height": 70499,
            "confirmations": 8633
        }
    ]
    fee = 0
    to_address = change_address = THIS_NODE_WALLET
    test = openfood.createrawtx_dev(utxos_obj, to_address, 20, fee, change_address)
    print('result:', test)
    assert True == False

@pytest.mark.skip
def test_createrawtx6():
    pass



def test_createrawtx5():
    utxos_obj = [
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 10,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      },
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 11,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      }
    ]

    amount = openfood.utxo_bundle_amount(utxos_obj)
    fee = 0.2

    to_address = change_address = THIS_NODE_WALLET

    utxos = json.dumps(utxos_obj)

    test = openfood.createrawtx5(utxos, len(utxos_obj), to_address, fee, change_address)
    print(test)
    sign_properties(test)


@pytest.mark.skip
def test_signtx():
    kmd_unsigned_tx_serialized = "0400008085202f8902b8be1dbe757519f6ce972e1f62a4eca1d6bed2cc5817fbb151fbc32ed95579270a00000000ffffffffb8be1dbe757519f6ce972e1f62a4eca1d6bed2cc5817fbb151fbc32ed95579270b00000000ffffffff01002d3101000000001976a914cbeb5be30aaede02316436da368ee57cfcd8187988ac000000008fea01000000000000000000000000"
    utxos_obj = [
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 10,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      },
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 11,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      }
    ]

    amounts = openfood.utxo_bundle_amount(utxos_obj)

    wif = THIS_NODE_WIF

    test = openfood.signtx(kmd_unsigned_tx_serialized, amounts, wif)
    print(test)

    assert test == True


#test function not done
@pytest.mark.skip
def test_broadcast_via_explorer():
    pass
#    test = broadcast_via_explorer(explorer_url, signedtx)

@pytest.mark.skip
def test_createrawtx4():
    utxos_obj = [
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 10,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      },
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 11,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      }
    ]

    amount = openfood.utxo_bundle_amount(utxos_obj)
    fee = 0.2

    to_address = change_address = THIS_NODE_WALLET

    utxos = json.dumps(utxos_obj)

    test = openfood.createrawtx4(utxos, len(utxos_obj), to_address, fee)

    sign_properties(test)


def test_decoderawtx_wrapper():
    tx = "0400008085202f8902b8be1dbe757519f6ce972e1f62a4eca1d6bed2cc5817fbb151fbc32ed95579270a00000000ffffffffb8be1dbe757519f6ce972e1f62a4eca1d6bed2cc5817fbb151fbc32ed95579270b00000000ffffffff01002d3101000000001976a914cbeb5be30aaede02316436da368ee57cfcd8187988ac000000008fea01000000000000000000000000"
    decode = {'txid': '554f123c994f1c38b1a8e2d1f542669c84ab3eb260c372aa0b2df21e3590448d', 'overwintered': True, 'version': 4, 'versiongroupid': '892f2085', 'locktime': 0, 'expiryheight': 125583, 'vin': [{'txid': '277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8', 'vout': 10, 'scriptSig': {'asm': '', 'hex': ''}, 'sequence': 4294967295}, {'txid': '277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8', 'vout': 11, 'scriptSig': {'asm': '', 'hex': ''}, 'sequence': 4294967295}], 'vout': [{'value': 0.2, 'valueZat': 20000000, 'n': 0, 'scriptPubKey': {'asm': 'OP_DUP OP_HASH160 cbeb5be30aaede02316436da368ee57cfcd81879 OP_EQUALVERIFY OP_CHECKSIG', 'hex': '76a914cbeb5be30aaede02316436da368ee57cfcd8187988ac', 'reqSigs': 1, 'type': 'pubkeyhash', 'addresses': ['RTsRCUy4cJoyTKJfSWcidEwcj7g1Y3gTG5']}}], 'vjoinsplit': [], 'valueBalance': 0.0, 'vShieldedSpend': [], 'vShieldedOutput': []}

    test = openfood.decoderawtx_wrapper(tx)

    assert test == decode

def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except ValueError as e:
        return False
    return True


def test_check_node_wallet():
    test = openfood.check_node_wallet()
    assert test is True


def test_check_kv1_wallet():
    test = openfood.check_kv1_wallet()
    assert test is True


def test_check_sync():
    test = openfood.check_sync()
    assert type(10) == type(test)


def test_explorer_get_utxos():
    try:
        test = openfood.explorer_get_utxos("RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW")
        assert is_json(test) is True
    except Exception as e:
        assert e is True


def test_explorer_get_balance():
    test = openfood.explorer_get_balance("RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW")
    assert isinstance(test, int) is True

def test_gen_wallet():
    test_wallet = openfood.gen_wallet("TEST_GEN_WALLET_PASSPHRASE")
    assert TEST_GEN_WALLET_ADDRESS == test_wallet['address']
    assert TEST_GEN_WALLET_PUBKEY == test_wallet['pubkey']
    assert TEST_GEN_WALLET_WIF == test_wallet['wif']
    assert test_wallet['address'][0] == 'R'


def test_get_wallet_by_name():
    test_wallet = openfood.getOfflineWalletByName("Anything")
    assert test_wallet['address'][0] == 'R'


def test_get_batches_no_timestamp():
    test = openfood.get_batches_no_timestamp()
    properties_test(test)


def test_sendtoaddress_wrapper():
    test = openfood.sendtoaddress_wrapper(THIS_NODE_WALLET, 0.1)
    print(test)
    assert not(" " in test)


@pytest.mark.skip
def test_batch_wallets_generate_timestamping():
    test = openfood.get_wbatches_no_timestamp()
    test = openfood.batch_wallets_generate_timestamping(test[0], test[0]['id'])
    test = json.dumps(test)
    print(test)
    assert True == False


def test_batch_wallets_timestamping_update():
    test = openfood.get_batches()
    test = openfood.batch_wallets_timestamping_update(test[0])
    test = json.loads(test)
    properties_test( [ test ] )


def test_start_stop():
    test = openfood.get_batches_no_timestamp()
    openfood.batch_wallets_timestamping_start(test)
    openfood.batch_wallets_timestamping_end(test)


#we are here
def batch_wallets_timestamping_start(testObj):

    utxos_obj = [
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 10,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      },
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 11,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      }
    ]

    amount = openfood.utxo_bundle_amount(utxos_obj)
    fee = 0.2

    to_address = change_address = THIS_NODE_WALLET

    utxos = json.dumps(utxos_obj)

    rawtx_info = openfood.createrawtx5(utxos, len(utxos_obj), to_address, fee, change_address)
    print("info" + str(rawtx_info))
    rawtx_info = openfood.decoderawtx_wrapper(rawtx_info[0]['rawtx'])
    print("info" + str(rawtx_info))
    test = openfood.batch_wallets_timestamping_start(testObj[0], rawtx_info['txid'])

    #test = openfood.batch_wallets_generate_timestamping(test[0], test[0]['id'])
    test = json.dumps(test)

    print(test)
    assert is_json(test) == True

def batch_wallets_timestamping_end(testObj):
    utxos_obj = [
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 10,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      },
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 11,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      }
    ]

    amount = openfood.utxo_bundle_amount(utxos_obj)
    fee = 0.2

    to_address = change_address = THIS_NODE_WALLET

    utxos = json.dumps(utxos_obj)

    rawtx_info = openfood.createrawtx5(utxos, len(utxos_obj), to_address, fee, change_address)
    print("info" + str(rawtx_info))
    rawtx_info = openfood.decoderawtx_wrapper(rawtx_info[0]['rawtx'])
    print("info" + str(rawtx_info))
    test = openfood.batch_wallets_timestamping_end(testObj[0], rawtx_info['txid'])

    #test = openfood.batch_wallets_generate_timestamping(test[0], test[0]['id'])
    test = json.dumps(test)

    assert is_json(test) == True


def test_batch_wallets_fund_integrity_start():
    test = openfood.batch_wallets_fund_integrity_start(THIS_NODE_WALLET)
    assert type(int(test, 16)) == type(10)


def test_batch_wallets_fund_integrity_end():
    test = openfood.batch_wallets_fund_integrity_end(THIS_NODE_WALLET)
    assert type(int(test, 16)) == type(10)


def test_save_batch_timestamping_tx():
    pass


def test_timestamping_save_batch_links():
    test = openfood.get_batches()
    utxos_obj = [
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 10,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      },
      {
        "address": "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW",
        "txid": "277955d92ec3fb51b1fb1758ccd2bed6a1eca4621f2e97cef6197575be1dbeb8",
        "vout": 11,
        "scriptPubKey": "76a9147fd21d91b20b713c5a73fe77db4c262117b77d2888ac",
        "amount": 1.1,
        "satoshis": 110000000,
        "height": 11461,
        "confirmations": 1550
      }
    ]

    amount = openfood.utxo_bundle_amount(utxos_obj)
    fee = 0.2

    to_address = change_address = THIS_NODE_WALLET

    utxos = json.dumps(utxos_obj)

    rawtx_info = openfood.createrawtx5(utxos, len(utxos_obj), to_address, fee, change_address)
    rawtx_info = openfood.decoderawtx_wrapper(rawtx_info[0]['rawtx'])
    test = openfood.timestamping_save_batch_links(test[0]['id'], rawtx_info['txid'])
    assert test == True


def test_sendmany_wrapper():
    json_object = {THIS_NODE_WALLET: SCRIPT_VERSION}
    test = openfood.sendmany_wrapper(THIS_NODE_WALLET, json_object)
    print(test)
    assert not (" " in test)


def test_fund_offline_wallet2():
    address = "RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW"
    amount = float(openfood.explorer_get_balance(address)) / 1000000
    test = openfood.fund_offline_wallet2(address, amount)
    assert not (" " in test)


def test_fund_offline_wallet():
    test = openfood.fund_offline_wallet("RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW")
    print(test)
    assert not (" " in test)

def test_is_below_threshold_balance():
    test = openfood.is_below_threshold_balance(1*100000000, 2)
    assert test is True


def test_kvupdate_wrapper():
    # rpclib gives Insufficient funds
    pool_wallets = openfood.generate_pool_wallets()
    org_kv1_key_pool_wallets = THIS_NODE_RADDRESS + KV1_ORG_POOL_WALLETS
    kv_response = openfood.kvupdate_wrapper(org_kv1_key_pool_wallets, json.dumps(pool_wallets), "3", "password")
    assert len(kv_response['txid']) == 64

def test_kvsearch_wrapper():
    org_kv1_key_pool_wallets = THIS_NODE_RADDRESS + KV1_ORG_POOL_WALLETS
    test = openfood.kvsearch_wrapper(org_kv1_key_pool_wallets)
    if {
        "coin",
        "currentheight",
        "key",
        "keylen"
    } <= set(test):
        assert True
    else: assert False


@pytest.mark.skip
def test_organization_certificate_noraddress():
    pass


@pytest.mark.skip
def test_fund_certificate():
    pass

@pytest.mark.skip
def test_fund_location():
    pass

def test_dateToSatoshi():
    test = openfood.dateToSatoshi('2021-09-01')
    assert test == 0.20210901


def test_fund_address():
    test_location = openfood.fund_address("RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW", "LOCATION")
    test_certificate = openfood.fund_address("RLw3bxciVDqY31qSZh8L4EuM2uo3GJEVEW", "CERTIFICATE")
    assert len(test_location) == 64
    assert len(test_certificate) == 64


def test_organization_send_batch_links():
    batch = openfood.get_batches()[0]
    print(batch)
    test = openfood.organization_send_batch_links(batch)
    assert len(test) == 64


@pytest.mark.skip
def test_organization_send_batch_links2():
    pass


@pytest.mark.skip
def test_organization_send_batch_links3():
    pass


@pytest.mark.skip
def test_timestamping_save_certificate():
    pass


@pytest.mark.skip
def test_push_batch_data_consumer():
    pass


def test_generate_pool_wallets():
    test = openfood.generate_pool_wallets()
    if {
        "_ALL_OUR_PO",
        "_ALL_OUR_BATCH",
        "_ALL_CUSTOMER_PO"
    } <= set(test):
        assert True
    else: assert False


def test_verify_kv_pool_wallets():
    test = openfood.verify_kv_pool_wallets()
    assert test is None


@pytest.mark.skip
def test_organization_get_pool_wallets_by_raddress():
    pass


@pytest.mark.skip
def test_get_this_node_raddress():
    pass


@pytest.mark.skip
def test_kv_save_batch_to_raddress():
    pass


@pytest.mark.skip
def test_kv_save_raddress_to_data():
    pass


@pytest.mark.skip
def test_kv_get_by_raddress():
    pass


@pytest.mark.skip
def test_organization_get_our_pool_batch_wallet():
    pass


@pytest.mark.skip
def test_organization_get_our_pool_po_wallet():
    pass


@pytest.mark.skip
def test_organization_get_our_customer_po_wallet():
    pass


@pytest.mark.skip
def test_oracle_create():
    pass


@pytest.mark.skip
def test_oracle_fund():
    pass


@pytest.mark.skip
def test_oracle_register():
    pass


@pytest.mark.skip
def test_oracle_subscribe():
    pass


@pytest.mark.skip
def test_oracle_info():
    pass


@pytest.mark.skip
def test_oracle_data():
    pass


@pytest.mark.skip
def test_oracle_list():
    pass


@pytest.mark.skip
def test_oracle_samples():
    pass


def test_check_offline_wallets():
    test = openfood.check_offline_wallets()
    test = json.loads(test)
    if {
        "address",
        "txid",
        "vout",
        "scriptPubKey",
        "amount",
        "satoshis",
        "height",
        "confirmations"
    } <= set(test[0]):
        assert True
    else: assert False

def test_check_offline_wallets_save():
    test = openfood.check_offline_wallets(save=True)
    test = json.loads(test)
    if {
        "address",
        "txid",
        "vout",
        "scriptPubKey",
        "amount",
        "satoshis",
        "height",
        "confirmations"
    } <= set(test[0]):
        assert True
    else: assert False


@pytest.mark.skip
def test_createrawtx_split_wallet():
    pass

def test_utxo_combine():
    address = THIS_NODE_RADDRESS
    wif = THIS_NODE_WIF
    utxos_json = json.loads(openfood.explorer_get_utxos(address))
    test = openfood.combine_utxo(utxos_json, address, wif)
    if {
        "txid"
    } <= set(test):
        assert True
    else: assert False

def test_utxo_send():
    address = THIS_NODE_RADDRESS
    wif = THIS_NODE_WIF
    to_address = "RS7y4zjQtcNv7inZowb8M6bH3ytS1moj9A"
    utxos_json = json.loads(openfood.explorer_get_utxos(address))

    # send all amount from 2 utxos
    test = openfood.utxo_send(utxos_json[0:2], 'all', to_address, wif, address)
    if {
        "txid"
    } <= set(test):
        assert True
    else: assert False

def test_utxo_slice_by_amount():
  json = [{
    "address": "RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b",
    "txid": "589223264eddd85d1a8c860b334d8a24e4596902d91ced34124f48de7899867a",
    "vout": 3,
    "scriptPubKey": "76a914f59bae3253f8046547cba7b330bbc713b1daccb488ac",
    "amount": 5410,
    "satoshis": 541000000000,
    "height": 104608,
    "confirmations": 1329
    },
    {
    "address": "RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b",
    "txid": "1f9215ca76c4f13e9efe1e5f61b61b15060fdcda31f140e0a1ba0cd8797165ec",
    "vout": 1,
    "scriptPubKey": "76a914f59bae3253f8046547cba7b330bbc713b1daccb488ac",
    "amount": 2712,
    "satoshis": 271200000000,
    "height": 104541,
    "confirmations": 1396
  }]
  test = openfood.utxo_slice_by_amount(json, 5410)
  assert len(test) == 1


def test_utxo_slice_by_amount2():
  json = [{
    "address": "RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b",
    "txid": "589223264eddd85d1a8c860b334d8a24e4596902d91ced34124f48de7899867a",
    "vout": 3,
    "scriptPubKey": "76a914f59bae3253f8046547cba7b330bbc713b1daccb488ac",
    "amount": 5410,
    "satoshis": 541000000000,
    "height": 104608,
    "confirmations": 1329,
    },
    {
    "address": "RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b",
    "txid": "1f9215ca76c4f13e9efe1e5f61b61b15060fdcda31f140e0a1ba0cd8797165ec",
    "vout": 1,
    "scriptPubKey": "76a914f59bae3253f8046547cba7b330bbc713b1daccb488ac",
    "amount": 2712,
    "satoshis": 271200000000,
    "height": 104541,
    "confirmations": 1396
    },
    {
    "address": "RXfr8P7ws298FYjd1nLpfKNpE2FJEoDn4b",
    "txid": "1f9215ca76c4f13e9efe1e5f61b61b15060fdcda31f140e0a1ba0cd8797165ec",
    "vout": 1,
    "scriptPubKey": "76a914f59bae3253f8046547cba7b330bbc713b1daccb488ac",
    "amount": 3000,
    "satoshis": 271200000000,
    "height": 104541,
    "confirmations": 1396
  }
  ]
  raw_tx_meta = {}
  utxos_slice = []
  attempted_txids = ['589223264eddd85d1a8c860b334d8a24e4596902d91ced34124f48de7899867a']
  raw_tx_meta['utxos_slice'] = utxos_slice
  raw_tx_meta['attempted_txids'] = attempted_txids
  test = openfood.utxo_slice_by_amount2(json, 5410, raw_tx_meta)
  assert len(test['utxos_slice']) == 2


def test_utxo_split():
    address = THIS_NODE_RADDRESS
    wif = THIS_NODE_WIF
    utxos_json = json.loads(openfood.explorer_get_utxos(address))
    # hash160 (raddress) https://bitcoinvalued.com/tools.php
    hash160 = "F59BAE3253F8046547CBA7B330BBC713B1DACCB4"
    test = openfood.utxo_split(utxos_json[0], address, wif, hash160)
    if {
        "txid"
    } <= set(test):
        assert True
    else: assert False

def test_utxo_send2():
    address = THIS_NODE_RADDRESS
    wif = THIS_NODE_WIF
    to_address = "RS7y4zjQtcNv7inZowb8M6bH3ytS1moj9A"
    utxos_json = json.loads(openfood.explorer_get_utxos(address))
    utxos_json = utxos_json[0:2]
    amount = openfood.utxo_bundle_amount(utxos_json) - utxos_json[-1]['amount'] / 2

    test = openfood.utxo_send(utxos_json, amount, to_address, wif, address)
    if {
        "txid"
    } <= set(test):
        assert True
    else: assert False
