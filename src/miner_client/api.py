from crypto_utils import calculate_merkle_root
from crypto_utils import compress_verifying_key
from crypto_utils import create_private_key
from crypto_utils import double_sha256
from crypto_utils import generate_outputs
from crypto_utils import nbits_to_target

from ecdsa import SigningKey
from ecdsa import SECP256k1

from getpass import getpass

from global_vars import version
from global_vars import seed_node_ipv4_address
from global_vars import seed_node_port

from json import dumps
from json import loads

from requests import get
from requests import post

from statistics import mode

from time import time

from utils import create_password
from utils import decrypt_file
from utils import integer_to_bytes
from utils import verify_password

def discover_nodes():
    nodes_json = get(f'http://{seed_node_ipv4_address}:{seed_node_port}/discover/nodes').json() # add potential dns seed for this
    return nodes_json

def broadcast_nodes_tx(tx, nodes):
    responses = []

    for node_net_addr in nodes:
        response = post(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/validate/tx", json=tx).json()

        responses.append(dumps(response))

    print('responses:', responses)

    validate_response = loads(mode(responses))

    return validate_response

def broadcast_nodes_block(block, nodes):
    responses = []

    for node_net_addr in nodes:        
        response = post(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/validate/block", json=block).json()
        
        responses.append(dumps(response))

    print('responses:', responses)

    validate_response = loads(mode(responses))    

    return validate_response

def send(key, amount, address, fee):
    private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)
    public_key = compress_verifying_key(private_key.get_verifying_key())

    public_key_hex = public_key.hex()

    own_address = double_sha256(public_key).hex()

    nodes = discover_nodes()

    responses = []

    for node_net_addr in nodes:
        inputs_response = get(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/utxos/address/{own_address}").json()
        inputs_mempool_response = get(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/utxos_mempool/address/{own_address}").json()
        
        responses.append(dumps((inputs_response, inputs_mempool_response)))
        
    inputs, inputs_mempool = loads(mode(responses))

    inputs += inputs_mempool

    input_total = 0

    new_inputs = []

    for inp in inputs:
        if input_total >= amount + fee:
            break

        input_total += inp['amount']
        new_inputs.append(inp)

    inputs = new_inputs

    outputs = generate_outputs(own_address, inputs, amount, address, fee)

    if not outputs: # if outputs is empty, there is insufficient funds for transaction
        return False

    tx_json = {'version' : version, 'inputs' : inputs, 'outputs' : outputs}

    signature = private_key.sign(dumps(tx_json).encode('utf-8')).hex()

    tx_json.update({'signature' : signature})

    txid = double_sha256(dumps(tx_json).encode('utf-8')).hex()

    tx_json.update({'txid' : txid})

    public_key_json = {'public_key' : public_key_hex}

    public_key_json.update(tx_json)

    tx_json = public_key_json

    validate_response = broadcast_nodes_tx(tx_json, nodes)

    return validate_response

def mine(key):
    nodes = discover_nodes()

    responses = []

    for node_net_addr in nodes:
        prev_hash_response = get(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/prev_hash").json()
        nbits_response = get(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/nbits").json()
        mempool_response = get(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/mempool").json()
        block_reward_response = get(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/block_reward").json()

        responses.append(dumps((prev_hash_response, nbits_response, mempool_response, block_reward_response)))
    
    prev_hash, nbits, mempool, block_reward = loads(mode(responses)) # gets the most common response from nodes

    fee_reward = 0

    for tx in mempool:
        inputs_total = 0
        outputs_total = 0

        for inp in tx['inputs']:
            inputs_total += inp['amount']
        
        for out in tx['outputs']:
            outputs_total += out['amount']

        fee = inputs_total - outputs_total
        fee_reward += fee

    private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)

    public_key = compress_verifying_key(private_key.get_verifying_key())

    own_address = double_sha256(public_key).hex()

    coinbase_output = [{'amount' : block_reward, 'address' : own_address}]

    if fee_reward != 0:
        coinbase_output.append({'amount' : fee_reward, 'address' : own_address})

    coinbase = {'version' : version, 'inputs' : [], 'outputs' : coinbase_output}

    signature = private_key.sign(dumps(coinbase).encode('utf-8')).hex()

    coinbase.update({'signature' : signature})

    coinbase_bytes = dumps(coinbase).encode('utf-8')

    txid = double_sha256(coinbase_bytes).hex()

    coinbase.update({'txid' : txid})

    public_key_json = {'public_key' : public_key.hex()}

    public_key_json.update(coinbase)

    coinbase = public_key_json

    merkle_root = calculate_merkle_root([dumps(tx).encode('utf-8') for tx in mempool]).hex()

    mempool.insert(0, coinbase)

    timestamp = time()

    target = nbits_to_target(nbits)

    header_params = {'version' : version, 'prev_hash' : prev_hash, 'merkle_root' : merkle_root, 'timestamp' : timestamp, 'nbits' : nbits}

    header_params_bytes = dumps(header_params).encode('utf-8')

    nonce = 0

    prev_hash_response = prev_hash

    start_time = time()

    while prev_hash_response == prev_hash:
        header_params_nonce = header_params_bytes + integer_to_bytes(nonce)

        block_hash = double_sha256(header_params_nonce)

        block_hash_int = int.from_bytes(block_hash, 'big')
        
        if block_hash_int <= target:
            header_params.update({'nonce' : nonce, 'hash' : block_hash.hex()})

            block_json = {'header' : header_params, 'txs' : mempool}

            validate_response = broadcast_nodes_block(block_json, nodes)

            return validate_response

        nonce += 1

        elapsed_time = time() - start_time

        if elapsed_time >= 10:
            prev_hash_response = mode(get(f"http://{node_net_addr['ipv4_address']}:{node_net_addr['port']}/prev_hash").json() for node_net_addr in nodes)

            start_time = time()

"""
send message:
{version, inputs, outputs, public_key, signature}

input format:
{}

"""

if __name__ == '__main__':
    file_password = create_password()
    
    while True:
        password = getpass('Enter password: ').encode('utf-8')  
        key = verify_password(password)

        if key: # if key is not None / was verified
            break
            
        print('Incorrect password, please try again')
    
    create_private_key(key)

    private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)

    verifying_key = compress_verifying_key(private_key.get_verifying_key())

    own_address = double_sha256(verifying_key).hex()

    print('own_address:', own_address)

    # print('send_address:', '78f8b71cb21f2bfafdb8383ecec1f3ed8749e71cc1dea90fee3f5b46d2794069')

    create_private_key(key)
    
    print('Press Ctrl-C to quit')
    
    while True:        
        command = input('Input command (s=send, m=mine): ')

        if command == 's':
            amount = float(input('Enter amount:\n'))
            address = input('Enter address:\n')
            fee = float(input('Enter fee:\n'))

            confirm = input(f'You are sending {amount} CJCs to the address: {address}\nwith a fee of: {fee}\nConfirm (Y or n)? ')

            if confirm == 'Y' or confirm == 'y':
                send(key, amount, address, fee)

        elif command == 'm':
            confirm = input(f'Confirm mining block (Y or n)? ')

            if confirm == 'Y' or confirm == 'y':
                print('Mining...')

                block_validate_response = mine(key)
                
                if block_validate_response['block_valid']:
                    print('Block validated')
                else:
                    print('Block not validated')
        else:
            print(f'Unknown command: {command}')
