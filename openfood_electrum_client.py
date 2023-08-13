from dotenv import load_dotenv, find_dotenv
import os
load_dotenv(find_dotenv(), verbose=True)
from slickrpc import Proxy
import json
import requests
import ecdsa
import socket
import hashlib
import base58
import binascii
import codecs
import struct

ELECTRUMRPC = ""
ELECTRUM_NODE = str(os.environ['ELECTRUM_NODE'])
ELECTRUM_RPC_PORT = str(os.environ['ELECTRUM_RPC_PORT'])

def scripthash(denariusAddress):
    #base58decode denarius address
    addrToBytes = base58.b58decode(denariusAddress)
    decodedToHex = addrToBytes.hex()

    #remove prefix
    removeZeroBytes = 2
    decodedToHexnoPrefix = decodedToHex[removeZeroBytes:]

    #remove checksum
    removeChecksum = 40
    decodedNoPrefixnoChecksum = decodedToHexnoPrefix[:removeChecksum]

    #Add OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG
    opDup = "76"
    opHash160 = "A9"
    opsBuffer = "14"
    opEqualVerify = "88"
    opChecksig = "AC"

    preparedtoHash = opDup + opHash160 + opsBuffer + decodedNoPrefixnoChecksum + opEqualVerify + opChecksig

    hashedKey = codecs.decode(preparedtoHash.upper(), 'hex')
    s = hashlib.new('sha256', hashedKey).digest()
    r = hashlib.new('ripemd160', s).digest()

    convertBigEndian = (codecs.encode(s, 'hex').decode("utf-8"))

    scriptHash = codecs.encode(codecs.decode(convertBigEndian, 'hex')[::-1], 'hex').decode()
    return scriptHash

def connect_electrum_node():
    global ELECTRUMRPC
    print("Connecting to: " + ELECTRUM_NODE + ":" + ELECTRUM_RPC_PORT)
    try:
        ELECTRUMRPC = Proxy("http://" + ELECTRUM_NODE + ":" + ELECTRUM_RPC_PORT)
        print("Electrum RPC Connected") 
        return True
    except Exception as e:
        sentry_sdk.capture_message(str(e), 'warning')

def electrum_request(command):
    try:
        with socket.create_connection((ELECTRUM_NODE, ELECTRUM_RPC_PORT)) as sock:
            sock.sendall(command.encode() + b'\n')
            while True:
                response = sock.recv(1024)
                if not response:
                    break
                return json.loads(response.decode())
    except Exception as e:
        print(f"An error occurred: {e}")

def get_utxo(address):
    address = scripthash(address)
    command = '{"id": 1, "method": "blockchain.scripthash.listunspent", "params": ["'+ address +'"]}'
    return electrum_request(command)

def transaction_get(tx_hash):
    command = '{"id": 1, "method": "blockchain.transaction.get", "params": ["'+ tx_hash +'"]}'
    return electrum_request(command)

def transaction_broadcast(tx_hash):
    raw_tx = transaction_get(tx_hash)
    raw_tx = raw_tx['result']
    command = '{"id": 1, "method": "blockchain.transaction.broadcast", "params": ["'+ raw_tx +'"]}'
    return electrum_request(command)