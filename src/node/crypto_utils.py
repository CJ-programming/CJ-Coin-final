from Crypto.Cipher.AES import new, MODE_CBC, block_size
from Crypto.Util.Padding import pad

from database import get_col_last_value
from database import get_cursor
from database import read_db
from database import read_db_json

from decimal import Decimal

from ecdsa import BadSignatureError
from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.ellipticcurve import Point
from ecdsa import SECP256k1
from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa.util import number_to_string
from ecdsa.util import string_to_number

from global_vars import start_block_reward

from hashlib import sha256

from json import loads

from math import floor
from math import log2

from os.path import exists
from os.path import getsize

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

def calculate_nbits(target):
	b = log2(target+1)
	exp = (b/8)+1
	m = floor(target / (256**(Decimal(exp)-3)))
	nbits = 2**24 * exp + m
	
	return int(nbits)

def adjust_nbits(prev_nbits, time_taken):
	prev_target = nbits_to_target(prev_nbits)
	change = time_taken / (3*60) # 1 block should take 60 seconds, adjusts every 3 blocks

	if change < 0.25:
		change = 0.25
	elif change > 4:
		change = 4

	new_target = int(Decimal(prev_target) * Decimal(change))

	return calculate_nbits(new_target)

def compress_verifying_key(verifying_key : VerifyingKey) -> bytes:
	x = verifying_key.pubkey.point.x()
	y = verifying_key.pubkey.point.y()

	e_x = number_to_string(x, SECP256k1.order) # encoded x
	return (b'\x03' + e_x) if y % 2 else (b'\x02' + e_x)

def uncompress_verifying_key(string: bytes, curve=SECP256k1) -> Point:
	is_even = string[:1] == b'\x02'
	x = string_to_number(string[1:])
	order = curve.order

	p = curve.curve.p()
	alpha = (pow(x, 3, p) + (curve.curve.a() * x) + curve.curve.b()) % p
	
	beta = square_root_mod_prime(alpha, p)

	if is_even == bool(beta & 1):
		y = p - beta

	else:
		y = beta

	point = Point(curve.curve, x, y, order)

	verifying_key = VerifyingKey.from_public_point(point, SECP256k1)

	return verifying_key

def create_private_key(key):
	if exists('private_key.bin') and getsize('private_key.bin') > 0:
		return

	with open('private_key.bin', 'wb') as f:
		private_key = SigningKey.generate(SECP256k1).to_string()

		cipher = new(key, MODE_CBC)

		ciphered_data = cipher.encrypt(pad(private_key, block_size))

		f.write(cipher.iv)
		f.write(ciphered_data)

def verify_sig(msg : bytes, sig : bytes, pub_key : VerifyingKey):
	try:
		pub_key.verify(sig, msg)    
		return True
	except BadSignatureError:
		pass

def update_block_reward():
	blockchain_height = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'height')

	block_reward = start_block_reward

	if blockchain_height == None or blockchain_height == 0:
		return block_reward

	last_block = read_db_json(get_cursor('blockchain.db'), f'txs WHERE block_height={blockchain_height}', ('outputs',), 'outputs')

	if last_block: # checks if last block is not empty
		coinbase_output = last_block[0]['outputs'][0]
		block_reward = coinbase_output['amount']

		if (blockchain_height + 1) % 10 == 0: # updates block reward every ten blocks
			block_reward /= 2

	return block_reward

def find_total_time_ten_timestamps():    
	timestamp_total = read_db(get_cursor('blockchain.db'), 'header', ('COUNT(timestamp)',), single_value=True).fetchone()

	if timestamp_total < 10:
		timestamp_1 = read_db(get_cursor('blockchain.db'), 'header ASC LIMIT 1', ('timestamp',), single_value=True).fetchone()
	
	else:
		timestamp_1 = read_db(get_cursor('blockchain.db'), 'header DESC LIMIT 1 OFFSET 9', ('timestamp',), single_value=True).fetchone()

	timestamp_2 = read_db(get_cursor('blockchain.db'), 'header ORDER BY height DESC LIMIT 1', ('timestamp',), single_value=True).fetchone()

	total_time = timestamp_2 - timestamp_1

	return total_time
