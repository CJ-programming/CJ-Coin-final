from Crypto.Cipher.AES import new, MODE_CBC, block_size
from Crypto.Util.Padding import pad

from ecdsa import SECP256k1
from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa.util import number_to_string

from hashlib import sha256

from os.path import exists
from os.path import getsize

def create_private_key(key):
    if exists('private_key.bin') and getsize('private_key.bin') > 0:
        return

    with open('private_key.bin', 'wb') as f:
        private_key = SigningKey.generate(SECP256k1).to_string()

        cipher = new(key, MODE_CBC)

        ciphered_data = cipher.encrypt(pad(private_key, block_size))

        f.write(cipher.iv)
        f.write(ciphered_data)

def double_sha256(data):
    double_sha256_data = sha256(sha256(data).digest()).digest()
    return double_sha256_data

def calculate_merkle_root(txs):
    if len(txs) == 0:
        return b'\x00'*32

    if len(txs) == 1:
        return double_sha256(txs[0])

    new_tx_list = []

    for i in range(0, len(txs), 2):
        tx_hash1 = double_sha256(txs[i])

        if i + 1 == len(txs):
            tx_hash2 = tx_hash1
        else:
            tx_hash2 = double_sha256(txs[i+1])

        new_tx_list.append(tx_hash1 + tx_hash2)

    return calculate_merkle_root(new_tx_list)

def nbits_to_target(nbits):
    exponent = nbits >> 24
    mantissa = nbits & 0xffffff
    target = mantissa * 256 ** (exponent-3)
    return target

def compress_verifying_key(verifying_key : VerifyingKey) -> bytes:
    x = verifying_key.pubkey.point.x()
    y = verifying_key.pubkey.point.y()

    e_x = number_to_string(x, SECP256k1.order) # encoded x
    return (b'\x03' + e_x) if y % 2 else (b'\x02' + e_x)

def generate_outputs(own_address, inputs, amount, address, fee):    
    """
    input format:
    [{txid, output_index, amount, address}]
    """

    outputs = []

    utxos_balance = sum(i['amount'] for i in inputs)

    if utxos_balance >= (amount + fee):
        change = (utxos_balance - amount) - fee

        outputs.append({'amount' : amount, 'address' : address})
        outputs.append({'amount' : change, 'address' : own_address})
    
    return outputs