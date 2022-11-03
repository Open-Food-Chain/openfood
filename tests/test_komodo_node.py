import os
import pytest
import requests
from typing import List, Tuple, Dict
from pprint import pprint

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

    addr = ["RAwfTfrfX1WroXgZpQWPRsSNoV8e4gS6qs"]
    response = listunspent(1, 99999, addr)
    assert isinstance(response, list)