import openfood_utxo_lib 

print("hello world")


dict={'RGKg9LCmU5i9JL2PceLbhM9HenHmMzDU7i':1}

total = 1

wallet={'wif': 'UqdsHMPfkyEaj25PBCUyKuCy9fP4EL99KRgqYjhHYTWmneaRZoYC', 'address': 'RGKg9LCmU5i9JL2PceLbhM9HenHmMzDU7i', 'pubkey': '03bbdb8b2e5f70affe34b275899acdec3c1569b6898503fa21b40b0d537e9a2b65', 'privkey': '30861afded167d0dbb720509d697315648f649f7f29858c08d88e2c6e6f85064'}

test_tx, amounts = make_tx_from_scratch(dict, total, utxo, from_addr=wallet['address'], from_pub=wallet['pubkey'], from_priv=wallet['wif'])

print(test_tx)
