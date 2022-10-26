import os
import pytest
import requests
from typing import List, Tuple, Dict

from openfood_lib_dev import openfood
from openfood_lib_dev.openfood_komodo_node import *

def test_get_balance():
    response = getbalance()
    assert isinstance(float(response), float)

def test_get_info():
    response = getinfo()
    assert isinstance(response, dict)

def test_list_unspent():
    batch_chain = openfood.connect_batch_node()

    addr = ["RH5dNSsN3k4wfHZ2zbNBqtAQ9hJyVJWy4r"]
    response = listunspent(1, 99999, addr)
    assert isinstance(response, list)