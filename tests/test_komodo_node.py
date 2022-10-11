import pytest
import requests

from openfood_lib_dev.openfood_komodo_node import getbalance

def test_get_balance():
    response = getbalance()
    assert isinstance(float(response), float)
