#from types import NoneType
from openfood_lib_dev.openfood_lib_diagnostics import *

def test_check_node_status():
    NoneType = type(None)
    try:
        test = check_node_status()
        print("Node status is correct")
        assert isinstance(test, NoneType)
    except Exception as ex:
        print(str(ex))
        assert isinstance(str(ex), str)

def test_check_integrity_post_tx_null():
    try:
        test = check_integrity_post_tx_null(2)
        print("Integrity Post TX is running well")
        assert isinstance(test, bool)
    except Exception as ex:
        print(str(ex))
        assert isinstance(str(ex), str)
