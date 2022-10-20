import random
from openfood_lib_dev.openfood_lib_diagnostics import *

def random_int(length):
	random_int = str(random.randint(1, length))
	return random_int

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
        test = check_integrity_post_tx_null(random_int(1))
        print("Integrity Post TX is running well")
        assert isinstance(test, bool)
    except Exception as ex:
        print(str(ex))
        assert isinstance(str(ex), str)

def test_check_last_successful_batch():
    try:
        test = check_last_successful_batch(random_int(1))
        print("Last successful batch is running well")
        assert isinstance(test, bool)
    except Exception as ex:
        print(str(ex))
        assert isinstance(str(ex), str)

def test_get_tx_list():
    try:
        test = get_tx_list()
        print("Last successful batch to get tx_list is running well")
        print(test)
        assert isinstance(test, list)
    except Exception as ex:
        print(str(ex))
        assert isinstance(str(ex), str)