import os
import requests
import json

from openfood_lib_dev.openfood_explorer_lib import explorer_get_network_status
from openfood_lib_dev.openfood_komodo_node import getinfo

from openfood_lib_dev.openfood_env import IMPORT_API_BASE_URL
from run import *
from pprint import pprint

def check_node_status():
    check_sync()
    #check_integrity_post_tx_null(limit='')
    #check_integrity_pre_tx_null(limit='')
    #check_last_successful_batch(limit='')
    #get_tx_list()

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

def check_integrity_post_tx_null(limit):
    response = requests.get(IMPORT_API_BASE_URL + 'batch/import/null-integrity-post-tx/limit/' + str(limit))
    if response.status_code == 200:
        print("=== Response from import-api integrity_post_tx_null")
        print(response.text)
        return True
    else:
        raise Exception('Failed to hit import-api to check integrity_post_tx is null')

def check_integrity_pre_tx_null(limit):
    response = requests.get(IMPORT_API_BASE_URL + 'batch/import/null-integrity-pre-tx/limit/' + str(limit))
    if response.status_code == 200:
        print("=== Response from import-api integrity_pre_tx_null")
        data = json.loads(response.text)
        pprint(data)
        return True
    else:
        raise Exception('Failed to hit import-api to check integrity_pre_tx is null')

def check_last_successful_batch(limit):
    response = requests.get(IMPORT_API_BASE_URL + 'batch/import/last-successful-batch/limit/' + str(limit))
    if response.status_code == 200:
        print("=== Response from import-api last_successful_batch")
        print(response.text)
        return True
    else:
        raise Exception('Failed to hit import-api to check last successful batch')

def get_tx_list():
    print(IMPORT_API_BASE_URL + 'batch/import/last-successful-batch/limit/1')
    response = requests.get(IMPORT_API_BASE_URL + 'batch/import/last-successful-batch/limit/1')
    if response.status_code == 200:
        print("=== Response from import-api last_successful_batch")
        data = response.json()
        if (data['data'][0]['integrity_details'] is None):
            raise Exception('Integrity details is empty')
        else:
            result = data['data'][0]['integrity_details']['tx_list']
        return result
    else:
        raise Exception('Failed to hit import-api to check last successful batch')