import pytest
import requests

from openfood_lib_dev.openfood_explorer_lib import *

def test_explorer_get_balance_final():
    raddress = str(os.environ['THIS_NODE_RADDRESS'])
    response = explorer_get_balance_final(raddress)
    assert isinstance(float(response), float)

def test_explorer_get_network_status():
    response = explorer_get_network_status()
    assert isinstance(response, dict)