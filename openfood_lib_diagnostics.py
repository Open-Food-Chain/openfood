from openfood_lib_dev.openfood_explorer_lib import explorer_get_network_status
from openfood_lib_dev.openfood_komodo_node import getinfo

def check_node_status():
    check_sync()

def check_sync():
    explorer_get_status = explorer_get_network_status()
    komodo_info = getinfo()

    komodo_diff = abs(komodo_info['blocks'] - komodo_info['longestchain'])
    expl_komodo_block_diff = abs(explorer_get_status['info']['blocks'] - komodo_info['blocks'])
    expl_komodo_chain_diff = abs(explorer_get_status['info']['blocks'] - komodo_info['longestchain'])

    if (komodo_diff == 0 and expl_komodo_block_diff == 0 and expl_komodo_chain_diff == 0):
        return True
    else:
        if (komodo_diff == 1 or expl_komodo_block_diff == 1 or expl_komodo_chain_diff == 1):
            raise Exception('Try again, only waiting for propagation')
        elif (komodo_diff > 1 or expl_komodo_block_diff > 1 or expl_komodo_chain_diff > 1):
            raise Exception('The node could be on a fork. The difference is ' + str(expl_komodo_block_diff) + ':' + str(expl_komodo_chain_diff))