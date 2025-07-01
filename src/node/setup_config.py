import sys; sys.dont_write_bytecode = True

from base64 import b64encode

from crypto_utils import compress_verifying_key

from database import get_column_names_db
from database import get_col_last_value
from database import get_cursor
from database import init_blockchain
from database import init_peers
from database import init_utxos
from database import write_db
from database import write_db_json

from ecdsa import SECP256k1
from ecdsa import SigningKey

from global_vars import version

from json import dumps
from json import loads

from network import discover_nodes
from network import update_peers

from os.path import getsize

from platform import uname

from requests import get
from requests import post
from requests import put

from secrets import randbelow

from sqlite3 import connect
from sqlite3 import IntegrityError

from statistics import mode

from time import time

from utils import create_file
from utils import decrypt_file
from utils import get_net_addr
from utils import get_private_ipv4_address
from utils import read_json_file
from utils import write_json_file

def send_version_message(net_addr, private_key, public_key_b64_str, request_type, port): # command is post, put, or delete
	# net_addr is version, services, ip_address, and port

	services = read_json_file('config.json')['services']

	private_ipv4_address = get_private_ipv4_address()

	timestamp = time()

	addr_recv_json = {key : net_addr[key] for key in ('services', 'ipv4_address', 'port')}
	addr_from_json = {'services' : services, 'ipv4_address' : private_ipv4_address, 'port' : port}

	nonce = randbelow(2**32 - 1)

	system_info = uname()
	user_agent = f"{system_info.system}/{system_info.release} ({system_info.machine}; {system_info.node})"

	blockchain_cursor = get_cursor("blockchain.db")

	block_height = get_col_last_value(get_cursor('blockchain.db'), 'header ORDER BY height', 'height')
	 
	relay = 1 # if zero, remote node will only send transctions relevant to the bloom filter sent by the connecitng node. (SPV)

	version_message_json = {'public_key' : public_key_b64_str, 'version' : version, 'services' : services, 'timestamp' : timestamp, 'addr_recv' : addr_recv_json,\
	'addr_from' : addr_from_json, 'nonce' : nonce, 'user_agent' : user_agent, 'start_height' : block_height, 'relay' : relay}

	message_bytes = dumps(version_message_json).encode('utf-8')
	signature = private_key.sign(message_bytes)
	signature_hex = signature.hex()

	version_message_json.update({'signature' : signature_hex})

	request = f"http://{net_addr['ipv4_address']}:{net_addr['port']}/discover/version"

	if request_type == 'post':
		response = post(request, json=version_message_json).json()
	
	elif request_type == 'put':
		response = put(request, json=version_message_json).json()

	return response

def update_network_status(key, port):
	nodes_json = update_peers()

	private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)
	public_key = compress_verifying_key(private_key.get_verifying_key())

	public_key_b64_str = public_key.hex()

	for net_addr in nodes_json:
		if not net_addr == get_net_addr():
			response = send_version_message(net_addr, private_key, public_key_b64_str, 'put', port)

			print(response)

def update_seed_node_ip():
	global_vars_path = 'global_vars.py'
	
	change_seed_node = input('Would you like to change the seed node ipv4 address? (y/n): ').strip().lower()
	
	if change_seed_node == 'y':
		new_ip = input('Enter new seed node IPv4 address: ').strip()
		
		with open(global_vars_path, 'r') as file:
			lines = file.readlines()
		
		with open(global_vars_path, 'w') as file:
			for line in lines:
				if line.startswith('seed_node_ipv4_address = '):
					file.write(f"seed_node_ipv4_address = '{new_ip}'\n")
				else:
					file.write(line)
		
		print(f"Seed node IP updated to: {new_ip}")
	else:
		print("Keeping existing seed node IP")

def update_seed_node_port():
	global_vars_path = 'global_vars.py'
	
	change_seed_node = input('Would you like to change the seed node port? (y/n): ').strip().lower()
	
	if change_seed_node == 'y':
		new_port = input('Enter new seed node port: ').strip()
		
		with open(global_vars_path, 'r') as file:
			lines = file.readlines()
		
		with open(global_vars_path, 'w') as file:
			for line in lines:
				if line.startswith('seed_node_port = '):
					file.write(f"seed_node_port = '{new_port}'\n")
				else:
					file.write(line)
		
		print(f"Seed node port updated to: {new_port}")
	else:
		print("Keeping existing seed node port")

def update_port():
	change_port = input("Would you like to change the port of this node? (y/N): ").strip().lower()

	if change_port == 'y':
		new_port = input("Enter new node port: ").strip()

		config = read_json_file('config.json')

		config['port'] = new_port

		write_json_file(config, 'config.json')
	else:
		print("Keeping existing local port")

def boot_strap(key, port, request_type="post"):
	private_key = SigningKey.from_string(decrypt_file('private_key.bin', key), SECP256k1)
	public_key = compress_verifying_key(private_key.get_verifying_key())
	public_key_hex = public_key.hex()

	nodes_json = discover_nodes()
	if not nodes_json:
		return

	# Use context-managed connection
	with connect('blockchain.db', timeout=10) as conn_blockchain:
		cursor_blockchain = conn_blockchain.cursor()
		cursor_blockchain.execute("SELECT height FROM header ORDER BY height DESC LIMIT 1")
		row = cursor_blockchain.fetchone()
		block_height = row[0] if row else 0

	responses = []

	for net_addr in nodes_json: # goes through every node in seed_node list
		try:
			updated_blocks_response = get(f"http://{net_addr['ipv4_address']}:{net_addr['port']}/discover/blockchain/headers/{block_height}/-1").json()
			updated_txs_response = get(f"http://{net_addr['ipv4_address']}:{net_addr['port']}/discover/blockchain/txs/{block_height}/-1").json()
			responses.append(dumps((updated_blocks_response, updated_txs_response)))

			if net_addr != get_net_addr():
				response = send_version_message(net_addr, private_key, public_key_hex, request_type, port)

				net_addr.update({'services': dumps(net_addr['services']), 'status': 1})

				if response == {'verack': True}:
					with connect('peers.db', timeout=10) as conn_peers:
						try:
							write_db_json(conn_peers.cursor(), 'peers_set', net_addr)
						except IntegrityError:
							print("Peers updated")
		except Exception as e:
			print("Node sync error:", e)

	updated_blocks, updated_txs = loads(mode(responses))

	# Reconnect for writing blocks
	with connect('blockchain.db', timeout=10) as conn_blockchain:
		cursor_blockchain = conn_blockchain.cursor()
		header_cols = get_column_names_db(cursor_blockchain, 'header')
		txs_cols = get_column_names_db(cursor_blockchain, 'txs')

		for block, tx in zip(updated_blocks, updated_txs):
			try:
				write_db(cursor_blockchain, 'header', header_cols, block)
				write_db(cursor_blockchain, 'txs', txs_cols, tx)
			except IntegrityError:
				print("Block updated")

def init_all(node_id_hex, port):
	init_blockchain()
	init_peers()
	init_utxos()

	create_file('config.json')
	create_file('bootstrap.json')
	create_file('node_id.json')

	config_json_data = {"services" :
		{"node_network" : True, 
		"node_getutxo" : True, 
		"node_bloom" : True, 
		"node_compact_filters" : True, 
		"node_network_limited" : False},

	"port" : port
	}

	bootstrap_json_data = {"bootstrap" : False}

	node_id_json_data = {"node_id" : node_id_hex}

	if not getsize('config.json'):
		write_json_file(config_json_data, 'config.json')
	
	if not getsize('bootstrap.json'):
		write_json_file(bootstrap_json_data, 'bootstrap.json')
	
	if not getsize('node_id.json'):
		write_json_file(node_id_json_data, 'node_id.json')
