import logging
import os
import time
import sys

from typing import List, Tuple, Dict
from . import transaction
from . import bitcoin
from .transaction import Transaction
from .openfood import *
from .openfood_explorer_lib import *
from .openfood_komodo_node import *
#from .logs.config import *
#from .log_config import *

#setup_logger('utxo_libs', os.path.dirname(os.path.realpath(__file__)) + '/openfood.log')
#logger = logging.getLogger('utxo_libs.module')

def signtx(kmd_unsigned_tx_serialized: str, amounts: List[str], wif: str):

    print("start signtx")

    if type(kmd_unsigned_tx_serialized) is not str:
        print("kmd_unsigned_tx_serialized must be string")
        raise Exception("kmd_unsigned_tx_serialized must be string")

    if type(amounts) is not list:
        print("amounts must be list")
        raise Exception("amounts must be list")

    if type(wif) is not str:
        print("Wif must be string")
        raise Exception("Wif must be string")

    try:
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

        print("end signtx")
    except Exception as e:
        print("signtx " + str(e))
        raise Exception(e)

    # print("\nSigned tx:\n")
    # print(tx.serialize())
    # print("Return from signtx")
    return tx.serialize()


def utxo_combine(utxos_json: List[Dict[str, str]], address: str, wif: str):
    # send several utxos amount to self address (all amount) to combine utxo
    print("start utxo_combine")

    if not utxos_json:
        print("List is empty")
        raise Exception("List is empty")

    if utxos_json:
        if type(utxos_json[0]) is not dict:
            print("Value must be dict")
            raise Exception("Value must be dict")

    if type(address) is not str:
        print("Address must be string")
        raise Exception("Address must be string")

    if type(wif) is not str:
        print("Wif must be string")
        raise Exception("Wif must be string")

    try:
        rawtx_info = createrawtx_dev(utxos_json, address, 'all', 0)
        signedtx = signtx(rawtx_info['rawtx'], rawtx_info['satoshis'], wif)
        txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
        print("end utxo_combine")
    except Exception as e:
        print("utxo_combine " + str(e))
        raise Exception(e)
    return txid


def utxo_send(utxos_json: List[Dict[str, str]], amount: float, to_address: str, wif: str, change_address=""):
    # send several utxos (all or several amount) to a spesific address
    print("start utxo_send")

    if not utxos_json:
        print("List is empty")
        raise Exception("List is empty")

    if utxos_json:
        if type(utxos_json[0]) is not dict:
            print("Value must be dict")
            raise Exception("Value must be dict")

    if type(amount) is not float:
        print("Amount must be float")
        raise Exception("Amount must be float")

    if type(to_address) is not str:
        print("To Address must be string")
        raise Exception("To Address must be string")

    if type(wif) is not str:
        print("Wif must be string")
        raise Exception("Wif must be string")

    if type(change_address) is not str:
        print("Change Address must be string")
        raise Exception("Change Address must be string")

    try:
        rawtx_info = createrawtx_dev(utxos_json, to_address, amount, 0, change_address)
        signedtx = signtx(rawtx_info['rawtx'], rawtx_info['satoshis'], wif)
        txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
        print("end utxo_send")
    except Exception as e:
        print("utxo_send " + str(e))
        raise Exception(e)
    return txid


def utxo_split(utxo_json: List[Dict[str, str]], address: str, wif: str, hash160: str):
    # send several utxos (all or several amount) to a spesific address
    print("start utxo_split")
    if not utxo_json:
        print("List is empty")
        raise Exception("List is empty")

    if utxo_json:
        if type(utxo_json[0]) is not dict:
            print("Value must be dict")
            raise Exception("Value must be dict")

    if type(address) is not str:
        print("Address must be string")
        raise Exception("Address must be string")

    if type(wif) is not str:
        print("Wif must be string")
        raise Exception("Wif must be string")

    if type(hash160) is not str:
        print("Hash160 must be string")
        raise Exception("Hash160 must be string")

    try:
        rawtx_info = createrawtxsplit(utxo_json, 1, 0.0001, hash160, wif)
        signedtx = signtx(rawtx_info['rawtx'], rawtx_info['satoshis'], wif)
        txid = broadcast_via_explorer(EXPLORER_URL, signedtx)

        print("end utxo_split")
    except Exception as e:
        print("utxo_split " + str(e))
        raise Exception(e)
    return txid


def utxo_slice_by_amount(utxos_json: List[Dict[str, str]], min_amount: float):
    # Slice UTXOS based on certain amount
    print("start utxo_slice_by_amount")

    if not utxos_json:
        print("List utxos_json is empty")
        raise Exception("List utxos_json is empty")

    if utxos_json:
        if type(utxos_json[0]) is not dict:
            print("Value must be dict")
            raise Exception("Value must be dict")

    if type(min_amount) is not float:
        print("Min amount must be float")
        raise Exception("Min amount must be float")

    try:
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
        print("end utxo_slice_by_amount")
    except Exception as e:
        print("utxo_slice_by_amount " + str(e))
        raise Exception(e)
    return utxos_slice


def utxo_slice_by_amount2(utxos_json: List[Dict[str, str]], min_amount: float, raw_tx_meta: Dict[str, str]):
    # Slice UTXOS based on certain amount

    print("start utxo_slice_by_amount2")

    if not utxos_json:
        print("List utxos_json is empty")
        raise Exception("List utxos_json is empty")

    if utxos_json:
        if type(utxos_json[0]) is not dict:
            print("Value must be dict")
            raise Exception("Value must be dict")

    if type(min_amount) is not float:
        print("Min amount must be float")
        raise Exception("Min amount must be float")

    if type(raw_tx_meta) is not dict:
        print("Raw_tx_meta must be dict")
        raise Exception("Raw_tx_meta must be dict")

    try:
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

        print("end utxo_slice_by_amount2")
    except Exception as e:
        print("utxo_slice_by_amount2 " + str(e))
        raise Exception(e)
    return raw_tx_meta


def utxo_bundle_amount(utxos_obj: List[Dict[str, str]]):

    print("start utxo_bundle_amount")

    if not utxos_obj:
        print("List utxos_obj is empty")
        raise Exception("List utxos_obj is empty")

    if type(utxos_obj) is not list:
        print("Utxos obj must be list")
        raise Exception("Utxos obj must be list")

    try:
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

        print("end utxo_bundle_amount")
    except Exception as e:
        print("utxo_bundle_amount " + str(e))
        raise Exception(e)
    return amount


def createrawtx_dev(utxos_json: List[Dict[str, str]], to_address: str, to_amount: float, fee: int, change_address=""):
    # check if utxos_json list is not empty

    print("start createrawtx_dev")

    if not utxos_json:
        print("List utxos_json is empty")
        raise Exception("List utxos_json is empty")

    if utxos_json:
        if type(utxos_json[0]) is not dict:
            print("Value must be dict")
            raise Exception("Value must be dict")

    if type(to_address) is not str:
        print("To address must be string")
        raise Exception("To address must be string")

    if type(to_amount) is not float:
        print("To amount must be float")
        raise Exception("To amount must be float")
    
    if type(fee) is not int:
        print("Fee must be integer")
        raise Exception("Fee must be integer")

    try:
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

        print("end createrawtx_dev")
    except Exception as e:
        print("createrawtx_dev " + str(e))
        return Exception(e)
    # return rawtx and satoshis (append to list)
    return {"rawtx": rawtx, "satoshis": satoshis}


def createrawtxsplit(utxo: List[str], split_count: int, split_value: float, hash160: str, wif: str):
    # get public key by private key

    print("start createrawtxsplit")

    if not utxo:
        print("List is empty")
        raise Exception("List is empty")

    if type(split_count) is not int:
        print("Split_count must be integer")
        raise Exception("Split_count must be integer")

    if type(split_value) is not float:
        print("Split_value must be float")
        raise Exception("Split_value must be float")

    if type(hash160) is not str:
        print("Hash160 must be string")
        raise Exception("Hash160 must be string")

    if type(wif) is not str:
        print("Wif must be string")
        raise Exception("Wif must be string")

    try:
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
        
        print("end createrawtxsplit")
    except Exception as e:
        print("createrawtxsplit " + str(e))
        raise Exception(e)

    return {"rawtx": rawtx, "satoshis": [satoshis]}


"""START - New function for address_amount_dict"""
def utxo_send_address_amount_dict(utxos_json: List[Dict[str, str]], addr_amount_dict: Dict[str, str], wif: str, change_address=""):
    # send several utxos (all or several amount) to a spesific address
    if not utxos_json:
        raise Exception("List is empty")

    if utxos_json:
        if type(utxos_json[0]) is not dict:
            raise Exception("Value must be dict")

    if type(addr_amount_dict) is not dict:
        raise Exception("Address amount dict must be dict")

    if type(wif) is not str:
        raise Exception("Wif must be string")

    if type(change_address) is not str:
        raise Exception("Change Address must be string")

    try:
        rawtx_info = createrawtx_address_amount_dict(utxos_json, addr_amount_dict, 0, change_address)
        signedtx = signtx(rawtx_info['rawtx'], rawtx_info['satoshis'], wif)
        txid = broadcast_via_explorer(EXPLORER_URL, signedtx)
    except Exception as e:
        raise Exception(e)
    return txid


def createrawtx_address_amount_dict(utxos_json: List[Dict[str, str]], addr_amount_dict: Dict[str, str], fee: int, change_address=""):

    if not utxos_json:
        raise Exception("List is empty")

    if utxos_json:
        if type(utxos_json[0]) is not dict:
            raise Exception("Value must be dict")

    if type(addr_amount_dict) is not dict:
        raise Exception("Address amount dict must be dict")

    if type(fee) is not int:
        raise Exception("Fee must be int")

    if type(change_address) is not str:
        raise Exception("Change address must be string")
    
    num_utxo = len(utxos_json)
    if (num_utxo == 0):
        print("utxos are required(list)")
        return
    
    if (num_utxo >= 300):
        print("too much use of utxos (max. 300)")
        return
    
    amount = utxo_bundle_amount(utxos_json)
    
    to_amount = list(addr_amount_dict.values())[0]
    
    if to_amount == 'all' or to_amount == amount:
        to_amount = amount
        change_address = ""
        
    change_amount = round(amount - fee, 10)
    
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
    txid_vout = [{'txid': txids[0], 'vout': vouts[0]}]

    if change_address:
        rawtx = createrawtxwithchange_addr_amount_dict(txid_vout, addr_amount_dict, change_address, change_amount)
    else:
        if change_amount > 0:
            print('change_address is required')
            return
        rawtx = createrawtx_wrapper_addr_amount_dict(txid_vout, addr_amount_dict)
    # return rawtx and satoshis (append to list)
    return {"rawtx": rawtx, "satoshis": satoshis}
"""END - New function for address_amount_dict"""