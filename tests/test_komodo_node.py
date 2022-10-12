import pytest
import requests

from openfood_lib_dev.openfood_komodo_node import getbalance, getinfo

def test_get_balance():
    response = getbalance()
    assert isinstance(float(response), float)

def test_get_info():
    response = getinfo()
    assert isinstance(response, dict)
