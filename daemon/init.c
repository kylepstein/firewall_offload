/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "common.h"

uint16_t nb_rxd = RX_RING_SIZE;
uint16_t nb_txd = TX_RING_SIZE;
queueid_t nb_txq = NUM_REGULAR_Q;
queueid_t nb_rxq = NUM_REGULAR_Q;
queueid_t nb_hpq = NUM_HP_Q;
queueid_t hp_qi = NUM_REGULAR_Q + NUM_HP_Q - 1;

static void get_port_mac(portid_t port_id)
{
	struct rte_port *port = &off_config_g.ports[port_id];
	struct rte_ether_addr *port_addr = &port->eth_addr;

	if (port->is_rep) {
		rte_eth_dev_mac_addr_get(port_id, port_addr);
		rte_hash_add_key_data(off_config_g.mac_ht,
				      port_addr, &port_id);
	} else {
		rte_eth_macaddr_get(port_id, port_addr);
	}

	printf("Port(%u): MAC %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	       " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
	       port_id,
	       port_addr->addr_bytes[0], port_addr->addr_bytes[1],
	       port_addr->addr_bytes[2], port_addr->addr_bytes[3],
	       port_addr->addr_bytes[4], port_addr->addr_bytes[5]);
}

static int setup_hairpin_queues(portid_t pi, portid_t peer_pi)
{
	queueid_t qi;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
	};
	int i, diag;

	for (qi = nb_txq, i = 0; qi < nb_hpq + nb_txq; qi++) {
		hairpin_conf.peers[0].port = peer_pi;
		hairpin_conf.peers[0].queue = i + nb_rxq;
		diag = rte_eth_tx_hairpin_queue_setup
			(pi, qi, nb_txd, &hairpin_conf);
		i++;
		if (diag == 0)
			continue;

		printf("Fail to configure port %d hairpin "
				"queues\n", pi);
		return -1;
	}

	for (qi = nb_rxq, i = 0; qi < nb_hpq + nb_rxq; qi++) {
		hairpin_conf.peers[0].port = peer_pi;
		hairpin_conf.peers[0].queue = i + nb_txq;
		diag = rte_eth_rx_hairpin_queue_setup
			(pi, qi, nb_rxd, &hairpin_conf);
		i++;
		if (diag == 0)
			continue;

		printf("Fail to configure port %d hairpin "
				"queues\n", pi);
		return -1;
	}

	printf("Port(%d): Set up hairpin with peer %d\n", pi, peer_pi);

	return 0;
}

static struct rte_flow *create_fdb_miss_flow(uint16_t port_id)
{
	struct rte_flow_action_port_id dest_port;
	struct rte_flow_action action[3];
	struct rte_flow_item pattern[3];
	struct rte_flow_attr attr;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.transfer = 1;
	attr.priority = FDB_NO_MATCH_PRIORITY;

	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
	memset(&dest_port, 0, sizeof(struct rte_flow_action_port_id));
	dest_port.id = off_config_g.vf_port[port_id];
	action[1].conf = &dest_port;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	return add_simple_flow(port_id, &attr, pattern,
			       action, "Fdb miss");
}

static struct rte_flow *create_to_uplink_flow(uint16_t port_id)
{
	struct rte_flow_action_port_id dest_port;
	struct rte_flow_action action[3];
	struct rte_flow_item pattern[3];
	struct rte_flow_attr attr;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.transfer = 1;
	attr.priority = FDB_NO_MATCH_PRIORITY;

	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
	memset(&dest_port, 0, sizeof(struct rte_flow_action_port_id));
	dest_port.id = off_config_g.phy_port[port_id];
	action[1].conf = &dest_port;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	return add_simple_flow(port_id, &attr, pattern,
			       action, "Fdb miss");
}

static struct rte_flow * create_hairpin_flow(uint16_t port_id)
{
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow_action_queue dest_queue = {
		.index = hp_qi
	};
	struct rte_flow_attr attr;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.group = NIC_RX_GROUP;

	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[1].conf = &dest_queue;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	return add_simple_flow(port_id, &attr, pattern,
			       action, "Haripin");
}

static int create_sample_fwd_flow(uint16_t port_id, int proto,
				  enum flow_action action)
{
	addSessionResponse_t response;
	sessionRequest_t request;
	int ret = 0;

	//FIXME: with sample flows, num of flows can't up to 5k

	memset(&response, 0, sizeof(response));
	memset(&request, 0, sizeof(request));

	request.inlif = 1;
	request.sessId = (action == ACTION_DROP) ?
		SAMPLE_SESSION_DROP :
		SAMPLE_SESSION_FWD;

	request.actType = action;
	request.srcIP.s_addr = 0xc0010102; // 192.1.1.2
	request.dstIP.s_addr = 0xc0010103; // 192.1.1.3
	request.proto = proto;
	request.srcPort = 5002;
	request.dstPort = 5003;

	ret = opof_add_session_server(&request, &response);
	if (!ret)
		printf("Warnning: Sample flow created for session (%d)\n",
		       request.sessId);

	return ret;
}

static int init_flows(portid_t pid)
{
	struct rte_port *port = &off_config_g.ports[pid];

	if (port->is_rep) {
		if (!create_to_uplink_flow(pid))
			return -EAGAIN;
	} else {
		/* Default RX rule to forward to hairpin queue. */
		if (!create_hairpin_flow(pid))
			return -EAGAIN;
		/* Default RX rule to forward no match pkt to vport. */
		if (!create_fdb_miss_flow(pid))
			return -EAGAIN;

		create_sample_fwd_flow(pid, IPPROTO_TCP, ACTION_FORWARD);
		create_sample_fwd_flow(pid, IPPROTO_UDP, ACTION_DROP);
	}

	return 0;
}

int port_init(portid_t pid, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		},
	};
	struct rte_eth_txconf txconf;
	struct rte_eth_dev *eth_dev;
	struct rte_port *port;
	int retval;
	uint16_t q;

	if (!rte_eth_dev_is_valid_port(pid))
		return -EINVAL;

	eth_dev = &rte_eth_devices[pid];
	port = &off_config_g.ports[pid];

	if (pid == portid_pf0)
		port->is_initiator = 1;

	if (pid == portid_pf1)
		port->is_responder = 1;

	rte_eth_dev_info_get(pid, &port->dev_info);

	if (eth_dev->data->dev_flags & RTE_ETH_DEV_REPRESENTOR)
		port->is_rep = 1;

	get_port_mac(pid);

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(pid, nb_rxq + nb_hpq,
				       nb_txq + nb_hpq, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(pid, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet pid. */
	for (q = 0; q < nb_rxq; q++) {
		retval = rte_eth_rx_queue_setup(pid, q, nb_rxd,
				rte_eth_dev_socket_id(pid), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = port->dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet pid. */
	for (q = 0; q < nb_txq; q++) {
		retval = rte_eth_tx_queue_setup(pid, q, nb_txd,
				rte_eth_dev_socket_id(pid), &txconf);
		if (retval < 0)
			return retval;
	}

	if (!port->is_rep)
		setup_hairpin_queues(pid, off_config_g.peer_port[pid]);

	/* Start the Ethernet pid. */
	retval = rte_eth_dev_start(pid);
	if (retval < 0) {
		printf("ERR: Can't start eth dev");
		return retval;
	}

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(pid);
	if (retval != 0)
		return retval;

	if (init_flows(pid))
		goto err;

	return 0;

err:
	rte_flow_flush(pid, NULL);
	return -EINVAL;
}
