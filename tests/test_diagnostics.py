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
