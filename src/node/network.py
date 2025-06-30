from database import get_cursor
from database import read_db_json
from database import update_db

from global_vars import version
from global_vars import seed_node_ipv4_address
from global_vars import seed_node_port

from json import dumps
from json import loads

from requests import get
from requests.exceptions import ConnectionError

from utils import consensus
from utils import get_private_ipv4_address
from utils import read_json_file

def discover_nodes():
	try:
		nodes_json = get(f'http://{seed_node_ipv4_address}:{seed_node_port}/discover/nodes').json() # add potential dns seed for this
	except ConnectionError:
		nodes_json = []

	return nodes_json

def send_ping(ipv4_address, port):
	try:
		response = get(f'http://{ipv4_address}:{port}/ping', timeout=10)
		response.raise_for_status()

		data = response.json()

		if data == 'pong':
			return True
		
	except ConnectionError:
		pass

	# returns None if ping was unsuccessful

def update_peers():
	up_peers = ()

	peers_db = read_db_json(get_cursor('peers.db'), 'peers_set', '*', 'services')

	for peer in peers_db:
		response = send_ping(peer['ipv4_address'], peer['port'])

		data_to_update_db = (peer['version'], dumps(peer['services']), peer['ipv4_address'], peer['port'], peer['node_id'])

		if not response:
			data_to_update_db += (0,) # adds new status
		
		else:
			data_to_update_db += (1,)
			up_peers += (peer,)

		update_db(get_cursor('peers.db'), 'peers_set', 'node_id', data_to_update_db, peer['node_id'])

	external_peers = ()

	for peer in up_peers:
		peer_list = get(f"http://{peer['ipv4_address']}:{peer['port']}/discover/nodes").json()
		external_peers += (peer_list,)
	
	external_peers = consensus(external_peers)

	if not external_peers: # if external_peers is None, sets variable to `()`
		external_peers = ()

	up_peers += tuple(external_peers)

	if not up_peers or not up_peers[0]: # if up_peers is empty, sets variable to `()`
		up_peers = ()

	return up_peers

def get_net_addr():
	json_file_data = read_json_file('config.json')

	ipv4_address = get_private_ipv4_address()
	services = json_file_data['services']
	port = json_file_data['port']

	net_addr = {'version' : version, 'ipv4_address' : ipv4_address, 'services' : services, 'port' : port}

	return net_addr