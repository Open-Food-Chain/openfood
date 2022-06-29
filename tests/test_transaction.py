# TODO: add kmd rewards claim tests

import unittest

from openfood_lib_dev import transaction
from openfood_lib_dev.bitcoin import TYPE_ADDRESS
from openfood_lib_dev.keystore import xpubkey_to_address
from openfood_lib_dev.util import bh2u, bfh

unsigned_blob = '01000000012a5c9a94fcde98f5581cd00162c60a13936ceb75389ea65bf38633b424eb4031000000005701ff4c53ff0488b21e03ef2afea18000000089689bff23e1e7fb2f161daa37270a97a3d8c2e537584b2d304ecb47b86d21fc021b010d3bd425f8cf2e04824bfdf1f1f5ff1d51fadd9a41f9e3fb8dd3403b1bfe00000000ffffffff0140420f00000000001976a914230ac37834073a42146f11ef8414ae929feaafc388ac00000000'
signed_blob = '01000000012a5c9a94fcde98f5581cd00162c60a13936ceb75389ea65bf38633b424eb4031000000006c493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6ffffffff0140420f00000000001976a914230ac37834073a42146f11ef8414ae929feaafc388ac00000000'
v2_blob = "0200000001191601a44a81e061502b7bfbc6eaa1cef6d1e6af5308ef96c9342f71dbf4b9b5000000006b483045022100a6d44d0a651790a477e75334adfb8aae94d6612d01187b2c02526e340a7fd6c8022028bdf7a64a54906b13b145cd5dab21a26bd4b85d6044e9b97bceab5be44c2a9201210253e8e0254b0c95776786e40984c1aa32a7d03efa6bdacdea5f421b774917d346feffffff026b20fa04000000001976a914024db2e87dd7cfd0e5f266c5f212e21a31d805a588aca0860100000000001976a91421919b94ae5cefcdf0271191459157cdb41c4cbf88aca6240700"

class TestBCDataStream(unittest.TestCase):

    def test_compact_size(self):
        s = transaction.BCDataStream()
        values = [0, 1, 252, 253, 2**16-1, 2**16, 2**32-1, 2**32, 2**64-1]
        for v in values:
            s.write_compact_size(v)

        with self.assertRaises(transaction.SerializationError):
            s.write_compact_size(-1)

        self.assertEqual(bh2u(s.input),
                          '0001fcfdfd00fdfffffe00000100feffffffffff0000000001000000ffffffffffffffffff')
        for v in values:
            self.assertEqual(s.read_compact_size(), v)

        with self.assertRaises(transaction.SerializationError):
            s.read_compact_size()

    def test_string(self):
        s = transaction.BCDataStream()
        with self.assertRaises(transaction.SerializationError):
            s.read_string()

        msgs = ['Hello', ' ', 'World', '', '!']
        for msg in msgs:
            s.write_string(msg)
        for msg in msgs:
            self.assertEqual(s.read_string(), msg)

        with self.assertRaises(transaction.SerializationError):
            s.read_string()

    def test_bytes(self):
        s = transaction.BCDataStream()
        s.write(b'foobar')
        self.assertEqual(s.read_bytes(3), b'foo')
        self.assertEqual(s.read_bytes(2), b'ba')
        self.assertEqual(s.read_bytes(4), b'r')
        self.assertEqual(s.read_bytes(1), b'')

class TestTransaction(unittest.TestCase):

    def test_tx_unsigned(self):
        expected = {
            'overwintered': False,
            'inputs': [{
                'type': 'p2pkh',
                'address': 'RCLHsywGcuvoiG3s67J3C3MgwnkGUhAWQV',
                'num_sig': 1,
                'prevout_hash': '3140eb24b43386f35ba69e3875eb6c93130ac66201d01c58f598defc949a5c2a',
                'prevout_n': 0,
                'pubkeys': ['02e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6'],
                'scriptSig': '01ff4c53ff0488b21e03ef2afea18000000089689bff23e1e7fb2f161daa37270a97a3d8c2e537584b2d304ecb47b86d21fc021b010d3bd425f8cf2e04824bfdf1f1f5ff1d51fadd9a41f9e3fb8dd3403b1bfe00000000',
                'sequence': 4294967295,
                'signatures': [None],
                'x_pubkeys': ['ff0488b21e03ef2afea18000000089689bff23e1e7fb2f161daa37270a97a3d8c2e537584b2d304ecb47b86d21fc021b010d3bd425f8cf2e04824bfdf1f1f5ff1d51fadd9a41f9e3fb8dd3403b1bfe00000000']}],
            'lockTime': 0,
            'outputs': [{
                'address': 'RCUUd6TUaZ78txRzkMonJsy3TjS8R2uYhW',
                'prevout_n': 0,
                'scriptPubKey': '76a914230ac37834073a42146f11ef8414ae929feaafc388ac',
                'type': TYPE_ADDRESS,
                'value': 1000000}],
                'version': 1
        }
        tx = transaction.Transaction(unsigned_blob)
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)

        self.assertEqual(tx.as_dict(), {'hex': unsigned_blob, 'complete': False, 'final': True})
        self.assertEqual(tx.get_outputs(), [('RCUUd6TUaZ78txRzkMonJsy3TjS8R2uYhW', 1000000)])
        self.assertEqual(tx.get_output_addresses(), ['RCUUd6TUaZ78txRzkMonJsy3TjS8R2uYhW'])

        self.assertTrue(tx.has_address('RCUUd6TUaZ78txRzkMonJsy3TjS8R2uYhW'))
        self.assertTrue(tx.has_address('RCLHsywGcuvoiG3s67J3C3MgwnkGUhAWQV'))
        self.assertFalse(tx.has_address('t1VHL1RP9LS7otTAqQJqFncJvfMUkwHriZr'))

        self.assertEqual(tx.serialize(), unsigned_blob)

        tx.update_signatures(signed_blob)
        self.assertEqual(tx.raw, signed_blob)

        tx.update(unsigned_blob)
        tx.raw = None
        blob = str(tx)
        self.assertEqual(transaction.deserialize(blob), expected)

    def test_tx_signed(self):
        expected = {
            'overwintered': False,
            'inputs': [{
                'type': 'p2pkh',
                'address': 'RCLHsywGcuvoiG3s67J3C3MgwnkGUhAWQV',
                'num_sig': 1,
                'prevout_hash': '3140eb24b43386f35ba69e3875eb6c93130ac66201d01c58f598defc949a5c2a',
                'prevout_n': 0,
                'pubkeys': ['02e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6'],
                'scriptSig': '493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6',
                'sequence': 4294967295,
                'signatures': ['3046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d98501'],
                'x_pubkeys': ['02e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6']}],
            'lockTime': 0,
            'outputs': [{
                'address': 'RCUUd6TUaZ78txRzkMonJsy3TjS8R2uYhW',
                'prevout_n': 0,
                'scriptPubKey': '76a914230ac37834073a42146f11ef8414ae929feaafc388ac',
                'type': TYPE_ADDRESS,
                'value': 1000000}],
            'version': 1
        }
        tx = transaction.Transaction(signed_blob)
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)
        self.assertEqual(tx.as_dict(), {'hex': signed_blob, 'complete': True, 'final': True})

        self.assertEqual(tx.serialize(), signed_blob)

        tx.update_signatures(signed_blob)

        self.assertEqual(tx.estimated_total_size(), 193)
        self.assertEqual(tx.estimated_base_size(), 193)
        self.assertEqual(tx.estimated_weight(), 772)
        self.assertEqual(tx.estimated_size(), 193)

    def test_estimated_output_size(self):
        estimated_output_size = transaction.Transaction.estimated_output_size
        self.assertEqual(estimated_output_size('RCxoWKp7M2bqpCjPC6PK2TSre4aFPUZWp6'), 34)
        self.assertEqual(estimated_output_size('bGc6AzTECnd7HZ54Y1YnpyX8UAJw4EBkue'), 32)

    def test_errors(self):
        with self.assertRaises(TypeError):
            transaction.Transaction.pay_script(output_type=None, addr='')

        with self.assertRaises(BaseException):
            xpubkey_to_address('')

    def test_parse_xpub(self):
        res = xpubkey_to_address('fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200')
        self.assertEqual(res, ('04ee98d63800824486a1cf5b4376f2f574d86e0a3009a6448105703453f3368e8e1d8d090aaecdd626a45cc49876709a3bbb6dc96a4311b3cac03e225df5f63dfc', 'RHyL8ZXMEY9BA8diyHFEAvhqnayVzMTTbt'))

    def test_version_field(self):
        tx = transaction.Transaction(v2_blob)
        self.assertEqual(tx.txid(), "b97f9180173ab141b61b9f944d841e60feec691d6daab4d4d932b24dd36606fe")

    def test_get_address_from_output_script(self):
        # the inverse of this test is in test_bitcoin: test_address_to_script
        addr_from_script = lambda script: transaction.get_address_from_output_script(bfh(script))
        ADDR = transaction.TYPE_ADDRESS

        # base58 p2pkh
        self.assertEqual((ADDR, 'RCxoWKp7M2bqpCjPC6PK2TSre4aFPUZWp6'), addr_from_script('76a91428662c67561b95c79d2257d2a93d9d151c977e9188ac'))
        self.assertEqual((ADDR, 'RKX2kWaM8soZQpErjsv8GQAnzax6k5BgWU'), addr_from_script('76a914704f4b81cadb7bf7e68c08cd3657220f680f863c88ac'))

        # base58 p2sh
        self.assertEqual((ADDR, 'bGc6AzTECnd7HZ54Y1YnpyX8UAJw4EBkue'), addr_from_script('a9142a84cf00d47f699ee7bbc1dea5ec1bdecb4ac15487'))
        self.assertEqual((ADDR, 'bb1zkytmZYjD2He2ycuus9RZfaTGSa17zf'), addr_from_script('a914f47c8954e421031ad04ecd8e7752c9479206b9d387'))

#####

    def _run_naive_tests_on_tx(self, raw_tx, txid):
        tx = transaction.Transaction(raw_tx)
        self.assertEqual(txid, tx.txid())
        self.assertEqual(raw_tx, tx.serialize())
        self.assertTrue(tx.estimated_size() >= 0)

    def test_txid_coinbase_to_p2pk(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4103400d0302ef02062f503253482f522cfabe6d6dd90d39663d10f8fd25ec88338295d4c6ce1c90d4aeb368d8bdbadcc1da3b635801000000000000000474073e03ffffffff013c25cf2d01000000434104b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7bac00000000'
        txid = 'dbaf14e1c476e76ea05a8b71921a46d6b06f0a950f17c5f9f1a03b8fae467f10'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_coinbase_to_p2pkh(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff25033ca0030400001256124d696e656420627920425443204775696c640800000d41000007daffffffff01c00d1298000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000'
        txid = '4328f9311c6defd9ae1bd7f4516b62acf64b361eb39dfcf09d9925c5fd5c61e8'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pk_to_p2pkh(self):
        raw_tx = '010000000118231a31d2df84f884ced6af11dc24306319577d4d7c340124a7e2dd9c314077000000004847304402200b6c45891aed48937241907bc3e3868ee4c792819821fcde33311e5a3da4789a02205021b59692b652a01f5f009bd481acac2f647a7d9c076d71d85869763337882e01fdffffff016c95052a010000001976a9149c4891e7791da9e622532c97f43863768264faaf88ac00000000'
        txid = '90ba90a5b115106d26663fce6c6215b8699c5d4b2672dd30756115f3337dddf9'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pk_to_p2sh(self):
        raw_tx = '0100000001e4643183d6497823576d17ac2439fb97eba24be8137f312e10fcc16483bb2d070000000048473044022032bbf0394dfe3b004075e3cbb3ea7071b9184547e27f8f73f967c4b3f6a21fa4022073edd5ae8b7b638f25872a7a308bb53a848baa9b9cc70af45fcf3c683d36a55301fdffffff011821814a0000000017a9143c640bc28a346749c09615b50211cb051faff00f8700000000'
        txid = '172bdf5a690b874385b98d7ab6f6af807356f03a26033c6a65ab79b4ac2085b5'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pkh_to_p2pkh(self):
        raw_tx = '0100000001f9dd7d33f315617530dd72264b5d9c69b815626cce3f66266d1015b1a590ba90000000006a4730440220699bfee3d280a499daf4af5593e8750b54fef0557f3c9f717bfa909493a84f60022057718eec7985b7796bb8630bf6ea2e9bf2892ac21bd6ab8f741a008537139ffe012103b4289890b40590447b57f773b5843bf0400e9cead08be225fac587b3c2a8e973fdffffff01ec24052a010000001976a914ce9ff3d15ed5f3a3d94b583b12796d063879b11588ac00000000'
        txid = '24737c68f53d4b519939119ed83b2a8d44d716d7f3ca98bcecc0fbb92c2085ce'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pkh_to_p2sh(self):
        raw_tx = '010000000195232c30f6611b9f2f82ec63f5b443b132219c425e1824584411f3d16a7a54bc000000006b4830450221009f39ac457dc8ff316e5cc03161c9eff6212d8694ccb88d801dbb32e85d8ed100022074230bb05e99b85a6a50d2b71e7bf04d80be3f1d014ea038f93943abd79421d101210317be0f7e5478e087453b9b5111bdad586038720f16ac9658fd16217ffd7e5785fdffffff0200e40b540200000017a914d81df3751b9e7dca920678cc19cac8d7ec9010b08718dfd63c2c0000001976a914303c42b63569ff5b390a2016ff44651cd84c7c8988acc7010000'
        txid = '155e4740fa59f374abb4e133b87247dccc3afc233cb97c2bf2b46bba3094aedc'
        self._run_naive_tests_on_tx(raw_tx, txid)

    # input: p2sh, not multisig
    def test_txid_regression_issue_3899(self):
        raw_tx = '0100000004328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c010000000b0009630330472d5fae685bffffffff328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c020000000b0009630359646d5fae6858ffffffff328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c030000000b000963034bd4715fae6854ffffffff328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c040000000b000963036de8705fae6860ffffffff0130750000000000001976a914b5abca61d20f9062fb1fdbb880d9d93bac36675188ac00000000'
        txid = 'f570d5d1e965ee61bcc7005f8fefb1d3abbed9d7ddbe035e2a68fa07e5fc4a0d'
        self._run_naive_tests_on_tx(raw_tx, txid)

#    def test_txid_negative_version_num(self):
#        raw_tx = 'f0b47b9a01ecf5e5c3bbf2cf1f71ecdc7f708b0b222432e914b394e24aad1494a42990ddfc000000008b483045022100852744642305a99ad74354e9495bf43a1f96ded470c256cd32e129290f1fa191022030c11d294af6a61b3da6ed2c0c296251d21d113cfd71ec11126517034b0dcb70014104a0fe6e4a600f859a0932f701d3af8e0ecd4be886d91045f06a5a6b931b95873aea1df61da281ba29cadb560dad4fc047cf47b4f7f2570da4c0b810b3dfa7e500ffffffff0240420f00000000001976a9147eeacb8a9265cd68c92806611f704fc55a21e1f588ac05f00d00000000001976a914eb3bd8ccd3ba6f1570f844b59ba3e0a667024a6a88acff7f0000'
#        txid = 'c659729a7fea5071361c2c1a68551ca2bf77679b27086cc415adeeb03852e369'
#        self._run_naive_tests_on_tx(raw_tx, txid)


class NetworkMock(object):

    def __init__(self, unspent):
        self.unspent = unspent

    def synchronous_get(self, arg):
        return self.unspent
