from crypto_utils import adjust_nbits
from crypto_utils import calculate_merkle_root
from crypto_utils import double_sha256
from crypto_utils import nbits_to_target
from crypto_utils import uncompress_verifying_key
from crypto_utils import verify_sig

from database import get_col_height
from database import get_col_last_value
from database import get_cursor
from database import read_db

from global_vars import start_nbits
from global_vars import start_timestamp

from json import dumps

from statistics import median

from time import time

from utils import exclude_keys
from utils import integer_to_bytes
from utils import verify_checksum


    
def verify_tx(tx, utxos_mempool):
    # message will be all paramaters, signature would sign that, and checksum will be the double hash of the paramaters and the signature:
    # {paramaters, signature, checksum}
    
    data_exclude_checksum = dumps(exclude_keys(tx, {'public_key', 'txid'})).encode('utf-8')
    signed_message = dumps(exclude_keys(tx, {'public_key', 'signature', 'txid'})).encode('utf-8')

    if not verify_checksum(bytes.fromhex(tx['txid']), data_exclude_checksum):
        return False
    
    public_key_decoded = bytes.fromhex(tx['public_key'])

    if not verify_sig(signed_message, bytes.fromhex(tx['signature']), uncompress_verifying_key(public_key_decoded)):
        return False

    public_address = double_sha256(public_key_decoded).hex()

    input_total = 0

    for inp in tx['inputs']:
        if inp in utxos_mempool:
            utxos_mempool.remove(inp)

        elif get_col_height(get_cursor('utxos.db'), 'utxos_set WHERE txid=? AND output_index=? AND amount=? AND address=?', '*', (inp['txid'], inp['output_index'], inp['amount'], inp['address'])):
            pass
        
        else:
            return False

        input_total += inp['amount']

    output_total = 0

    new_mempool_utxos = []

    new_mempool_utxos.append({'txid' : tx['txid'], 'output_index' : 0, 'amount' : tx['outputs'][0]['amount'], 'address' : tx['outputs'][0]['address']})

    if len(tx['outputs']) > 1:
        if not tx['outputs'][-1]['address'] == public_address:
            return False

        new_mempool_utxos.append({'txid' : tx['txid'], 'output_index' : 1, 'amount' : tx['outputs'][1]['amount'], 'address' : tx['outputs'][1]['address']})

    for out in tx['outputs']:
        output_total += out['amount']
    
    if not input_total >= output_total:
        return False
     
    utxos_mempool += new_mempool_utxos
    
    return utxos_mempool

def verify_coinbase(coinbase, block_reward, fee_reward):
    data_exclude_checksum = dumps(exclude_keys(coinbase, {'public_key', 'txid'})).encode('utf-8')
    signed_message = dumps(exclude_keys(coinbase, {'public_key', 'signature', 'txid'})).encode('utf-8')

    if not verify_checksum(bytes.fromhex(coinbase['txid']), data_exclude_checksum):
        return False
    
    public_key_decoded = bytes.fromhex(coinbase['public_key'])

    if not verify_sig(signed_message, bytes.fromhex(coinbase['signature']), uncompress_verifying_key(public_key_decoded)):
        return False
    
    if len(coinbase['outputs']) == 2:
        fee_reward_output = coinbase['outputs'][1]

        if not fee_reward_output['amount'] == fee_reward:
            return False
        
    block_reward_output = coinbase['outputs'][0]

    if not block_reward_output['amount'] == block_reward:
        return False
    
    public_address_b64 = double_sha256(public_key_decoded).hex()

    for out in coinbase['outputs']:
        if not out['address'] == public_address_b64:
            return False
        
    if not block_reward_output['amount'] == block_reward:
        return False
    
    return True

def verify_timestamp(block_timestamp, prev_block_timestamp, last_ten_timestamps):
    current_time = time()

    if not block_timestamp > prev_block_timestamp:
        return
    
    if not block_timestamp < current_time:
        return
    
    if not block_timestamp > median(last_ten_timestamps):
        return
    
    return True

def verify_block(coinbase, block, own_mempool, own_version, block_reward, height):
    if not block['header']['version'] == own_version:
        return False
    
    fee_total = 0

    for tx in block['txs'][1:]:
        if not tx in own_mempool:
            return False

        input_total = sum(inp['amount'] for inp in tx['inputs'])
        output_total = sum(out['amount'] for out in tx['outputs'])

        fee_total += input_total - output_total
    
    if not verify_coinbase(coinbase, block_reward, fee_total):
        return False
    
    txs_exclude_coinbase = [dumps(tx).encode('utf-8') for tx in block['txs'][1:]]

    if not block['header']['merkle_root'] == calculate_merkle_root(txs_exclude_coinbase).hex():
        return False
    
    prev_hash_db = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'hash')

    if not prev_hash_db:
        prev_hash_db = (b'\x00'*32).hex()
    
    if not block['header']['prev_hash'] == prev_hash_db:
        return False
    
    prev_block_timestamp = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'timestamp')

    last_ten_timestamps = read_db(get_cursor('blockchain.db'), 'header DESC LIMIT 9', ('timestamp',), single_value=True).fetchall()

    if not prev_block_timestamp:
        prev_block_timestamp = start_timestamp

    if not last_ten_timestamps:
        last_ten_timestamps = [start_timestamp]

    if not verify_timestamp(block['header']['timestamp'], prev_block_timestamp, last_ten_timestamps):
        return False
    
    prev_nbits = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'nbits')
    height = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'height')

    if not prev_nbits:
        prev_nbits = start_nbits

    if height and (height + 1) % 3 == 0:
        prev_third_timestamp = read_db(get_cursor('blockchain.db'), 'header DESC LIMIT 1 OFFSET 2', ('timestamp',), single_value=True).fetchone()
        prev_timestamp = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'timestamp')

        time_taken = prev_timestamp - prev_third_timestamp

        nbits = adjust_nbits(prev_nbits, time_taken)
    else:
        nbits = prev_nbits

    if not block['header']['nbits'] == nbits:
        return False
    
    header_bytes = dumps(exclude_keys(block['header'], {'nonce', 'hash'})).encode('utf-8') + integer_to_bytes(block['header']['nonce'])

    header_hash = double_sha256(header_bytes)

    header_hash_int = int.from_bytes(header_hash, 'big')

    if not block['header']['hash'] == header_hash.hex():
        return False
    
    if not header_hash_int <= nbits_to_target(nbits):
        return False
    
    return True