#!/bin/bash

mkdir network

cd network

get_private_ip() {
    ip a | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1
}

is_valid_ipv4() {
    local ip="$1"
    if [[ "$ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
        return true # Valid IPv4
    else
        return false  # Invalid IPv4
    fi
}

while true; do
	echo "How many nodes do you want on the network?"
	read nodes


	if [ "$nodes" -ge 1 ]; then
		break

	elif [ "$nodes" -lt 1 ]; then # verifies that nodes are the correct input
		echo "Error: Nodes number must be greater than or equal to one."
		continue
	else
		echo "Error: Invalid input."
		continue
	fi

	break
done;

while true; do
	echo "What do you want the ip address of the seed node to be? (default is your current private ip address)"
	read seed_node_ip

	if [ -z "$seed_node_ip" ]; then
		seed_node_ip=$(get_private_ip)

	elif ! [is_valid_ipv4 "$seed_node_ip"]; then # checks if ip is valid format
		echo "Error: Seed IP address is not valid format"
		continue

	fi

	echo "What do you want the port of the seed node to be? (default is 8133)"
	read seed_node_port

	if [ -z "$port" ]; then
		seed_node_port=8133
	fi

	break
done;

cp -r ../src/node node_1

sed -i "s/^seed_node_ipv4_address = .*/seed_node_ipv4_address = '$seed_node_ip'/" node_1/global_vars.py # configure proper seed node ip address
sed -i "s/^seed_node_port = .*/seed_node_port = '$seed_node_port'/" node_1/global_vars.py # configure proper seed node ip address

for ((i=2; i<=nodes; i++)); do # copies nodes and initialises network
	cp -r node_1 "node_$i"
done


# for fedora only: uncomment these lines:
# gnome-terminal --title="miner_client" -- bash -c "cd miner_client
# python api.py
# exec bash"

# for ((i=1; i<= nodes; i++)); do
#	gnome-terminal --title="node_$i" -- bash -c "
#	cd node_$i
#	python api.py -b
#	exec bash"
# done