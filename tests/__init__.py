import unittest

from . import constant


class TestCaseForTestnet(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constant.set_testnet()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constant.set_mainnet()
