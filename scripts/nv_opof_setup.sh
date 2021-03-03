#! /bin/bash

# Useful constants
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_OFF="\033[0m"

OVS_BRIDGE0=${OVS_BRIDGE1:-"ovsbr0"}
OVS_BRIDGE0_PORTS=${OVS_BRIDGE0_PORTS:-"p0 pf0vf0"}
OVS_BRIDGE1=${OVS_BRIDGE2:-"ovsbr1"}
OVS_BRIDGE1_PORTS=${OVS_BRIDGE1_PORTS:-"p1 pf1vf0"}
GRPC_PORT=pf0vf1
GRPC_IP_MASK=169.254.33.51/24

pre_check()
{
	for port in $OVS_BRIDGE0_PORTS $OVS_BRIDGE1_PORTS $GRPC_PORT
	do
		if [ ! -d /sys/class/net/$port ]; then
			echo -e "${COLOR_RED}$port is missing ${COLOR_OFF}"
			exit 1
		fi
	done
}

configure_ovs_fallback()
{
	for bri in $(ovs-vsctl list-br)
	do
		ovs-vsctl --if-exist del-br $bri
	done

	ovs-vsctl --may-exist add-br $OVS_BRIDGE0
	for port in $OVS_BRIDGE0_PORTS
	do
		ovs-vsctl add-port $OVS_BRIDGE0 $port
	done

	ovs-vsctl --may-exist add-br $OVS_BRIDGE1
	for port in $OVS_BRIDGE1_PORTS
	do
		ovs-vsctl add-port $OVS_BRIDGE1 $port
	done
	echo -e "${COLOR_GREEN}Configure ovs fallback ${COLOR_OFF}"
}

configure_grpc_interface()
{
	ip addr flush dev $GRPC_PORT
	ip addr add dev $GRPC_PORT $GRPC_IP_MASK
	echo -e "${COLOR_GREEN}Configure grpc interface ${COLOR_OFF}"
}

pre_check
configure_ovs_fallback
configure_grpc_interface
