/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "common.h"

static struct rte_flow_item eth_item = {
	RTE_FLOW_ITEM_TYPE_ETH,
	0, 0, 0
};

static struct rte_flow_item end_item = {
	RTE_FLOW_ITEM_TYPE_END,
	0, 0, 0
};

struct rte_flow_action_count count = {
	.shared = 0,
};

static struct rte_flow_action count_action = {
	RTE_FLOW_ACTION_TYPE_COUNT,
	&count
};

struct rte_flow_action_age age = {
	.timeout = DEFAULT_TIMEOUT,
};

static struct rte_flow_action age_action = {
	RTE_FLOW_ACTION_TYPE_AGE,
	&age
};

struct rte_flow_action_jump nic_rx_group = {
	.group = NIC_RX_GROUP,
};

static struct rte_flow_action jump_action = {
	RTE_FLOW_ACTION_TYPE_JUMP,
	&nic_rx_group
};

static struct rte_flow_action drop_action = {
	RTE_FLOW_ACTION_TYPE_DROP,
};

static struct rte_flow_action end_action = {
	RTE_FLOW_ACTION_TYPE_END,
	0
};

static struct rte_flow_action actions[4];

static struct rte_flow_attr attr;

static int
port_id_is_invalid(portid_t port_id, enum print_warning warning)
{
	uint16_t pid;

	if (port_id == (portid_t)RTE_PORT_ALL)
		return 0;

	RTE_ETH_FOREACH_DEV(pid)
		if (port_id == pid)
			return 0;

	if (warning == ENABLED_WARN)
		printf("Invalid port %d\n", port_id);

	return 1;
}

static int port_flow_complain(struct rte_flow_error *error)
{
	static const char *const errstrlist[] = {
		[RTE_FLOW_ERROR_TYPE_NONE] = "no error",
		[RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
		[RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
		[RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
		[RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
		[RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER] = "transfer field",
		[RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
		[RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
		[RTE_FLOW_ERROR_TYPE_ITEM_SPEC] = "item specification",
		[RTE_FLOW_ERROR_TYPE_ITEM_LAST] = "item specification range",
		[RTE_FLOW_ERROR_TYPE_ITEM_MASK] = "item specification mask",
		[RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
		[RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
		[RTE_FLOW_ERROR_TYPE_ACTION_CONF] = "action configuration",
		[RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
	};
	const char *errstr;
	char buf[32];
	int err = rte_errno;

	if ((unsigned int)error->type >= RTE_DIM(errstrlist) ||
	    !errstrlist[error->type])
		errstr = "unknown type";
	else
		errstr = errstrlist[error->type];

	printf("%s(): Caught PMD error type %d (%s): %s%s: %s\n", __func__,
	       error->type, errstr,
	       error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ",
					error->cause), buf) : "",
	       error->message ? error->message : "(no stated reason)",
	       rte_strerror(err));
	return -err;
}

struct rte_flow *
add_simple_flow(uint16_t port_id,
		struct rte_flow_attr *attr,
		struct rte_flow_item pattern[],
		struct rte_flow_action actions[],
		const char *flow_name)
{
	struct rte_flow *flow = NULL;
	struct rte_flow_error error;
	int res;

	memset(&error, 0, sizeof(error));
	res = rte_flow_validate(port_id, attr, pattern, actions, &error);
	if (!res)
		flow = rte_flow_create(port_id, attr, pattern,
				       actions, &error);
	else
		printf("Error: %s flow validation failed\n", flow_name);

	if (!flow) {
		printf("Error: %s flow creation failed(0x%x): %s\n",
		       flow_name, error.type,
		       error.message ? error.message :
		       "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow\n");
	} else {
		offload_dbg("Port(%d): %s flow created\n",
			    port_id, flow_name);
	}

	return flow;
}

int offload_flow_add(portid_t port_id,
		     struct fw_session *session,
		     enum flow_action action)
{
	struct eth_ntuple_filter *ntuple_filter;
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item ipv4_udp_item;
	struct rte_flow_item ipv4_tcp_item;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item udp_item;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item tcp_item;
	struct rte_flow_item pattern_ipv4_5tuple[4];
	struct rte_flow *flow = NULL;
	uint8_t ipv4_proto;
	int ret = -1;

	ntuple_filter = &session->tuple;

	ntuple_filter->dst_ip_mask = 0xffffffff;
	ntuple_filter->src_ip_mask = 0xffffffff;
	ntuple_filter->dst_port_mask = 0xffff;
	ntuple_filter->src_port_mask = 0xffff;
	ntuple_filter->proto_mask = 0xff;

	/* set up parameters for validate and add */
	memset(&ipv4_spec, 0, sizeof(ipv4_spec));
	ipv4_spec.hdr.next_proto_id = ntuple_filter->proto;
	ipv4_spec.hdr.src_addr = htonl(ntuple_filter->src_ip);
	ipv4_spec.hdr.dst_addr = htonl(ntuple_filter->dst_ip);
	ipv4_proto = ipv4_spec.hdr.next_proto_id;

	memset(&ipv4_mask, 0, sizeof(ipv4_mask));
	ipv4_mask.hdr.next_proto_id = ntuple_filter->proto_mask;
	ipv4_mask.hdr.src_addr = ntuple_filter->src_ip_mask;
	ipv4_mask.hdr.src_addr = ipv4_mask.hdr.src_addr;
	ipv4_mask.hdr.dst_addr = ntuple_filter->dst_ip_mask;
	ipv4_mask.hdr.dst_addr = ipv4_mask.hdr.dst_addr;

	switch (ipv4_proto) {
	case IPPROTO_UDP:
		ipv4_udp_item.type = RTE_FLOW_ITEM_TYPE_IPV4;
		ipv4_udp_item.spec = &ipv4_spec;
		ipv4_udp_item.mask = &ipv4_mask;
		ipv4_udp_item.last = NULL;

		udp_spec.hdr.src_port = htons(ntuple_filter->src_port);
		udp_spec.hdr.dst_port = htons(ntuple_filter->dst_port);
		udp_spec.hdr.dgram_len = 0;
		udp_spec.hdr.dgram_cksum = 0;

		udp_mask.hdr.src_port = ntuple_filter->src_port_mask;
		udp_mask.hdr.dst_port = ntuple_filter->dst_port_mask;
		udp_mask.hdr.dgram_len = 0;
		udp_mask.hdr.dgram_cksum = 0;

		udp_item.type = RTE_FLOW_ITEM_TYPE_UDP;
		udp_item.spec = &udp_spec;
		udp_item.mask = &udp_mask;
		udp_item.last = NULL;

		pattern_ipv4_5tuple[1] = ipv4_udp_item;
		pattern_ipv4_5tuple[2] = udp_item;
		age.timeout = UDP_DEFAULT_TIMEOUT;
		break;
	case IPPROTO_TCP:
		ipv4_tcp_item.type = RTE_FLOW_ITEM_TYPE_IPV4;
		ipv4_tcp_item.spec = &ipv4_spec;
		ipv4_tcp_item.mask = &ipv4_mask;
		ipv4_tcp_item.last = NULL;

		memset(&tcp_spec, 0, sizeof(tcp_spec));
		tcp_spec.hdr.src_port = htons(ntuple_filter->src_port);
		tcp_spec.hdr.dst_port = htons(ntuple_filter->dst_port);
		tcp_spec.hdr.tcp_flags = RTE_TCP_ACK_FLAG;

		memset(&tcp_mask, 0, sizeof(tcp_mask));
		tcp_mask.hdr.src_port = ntuple_filter->src_port_mask;
		tcp_mask.hdr.dst_port = ntuple_filter->dst_port_mask;
		tcp_mask.hdr.tcp_flags = 0xFF;

		tcp_item.type = RTE_FLOW_ITEM_TYPE_TCP;
		tcp_item.spec = &tcp_spec;
		tcp_item.mask = &tcp_mask;
		tcp_item.last = NULL;

		pattern_ipv4_5tuple[1] = ipv4_tcp_item;
		pattern_ipv4_5tuple[2] = tcp_item;
		age.timeout = TCP_DEFAULT_TIMEOUT;
		break;
	default:
		return ret;
	}

	attr.ingress = 1;
	attr.transfer = 1;

	pattern_ipv4_5tuple[0] = eth_item;
	pattern_ipv4_5tuple[3] = end_item;

	age.context = session;

	switch(action)
	{
	case ACTION_FORWARD:
		attr.priority = FDB_FWD_PRIORITY;
		actions[0] = jump_action;
		actions[1] = age_action;
		actions[2] = count_action;
		actions[3] = end_action;
		break;
	case ACTION_DROP:
		attr.priority = FDB_DROP_PRIORITY;
		actions[0] = drop_action;
		actions[1] = age_action;
		actions[2] = count_action;
		actions[3] = end_action;
		break;
	default:
		printf("Offload flow: invalid action\n");
		return -EINVAL;
	}

	flow = add_simple_flow(port_id, &attr, pattern_ipv4_5tuple,
			       actions, "offload");

	session->flow_in = flow;

	return 0;
}

int offload_flow_query(portid_t port_id, struct rte_flow *flow,
		       uint64_t *packets, uint64_t *bytes)
{
	struct rte_flow_query_count flow_count = {
		.reset = 0,
		.hits_set = 1,
		.bytes_set = 1,
		.hits = 0,
		.bytes = 0,
	};
	struct rte_flow_action action[2];
	struct rte_flow_error error;

	if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return -EINVAL;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[0].conf = &flow_count;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x55, sizeof(error));

	if (rte_flow_query(port_id, flow, action, &flow_count, &error))
		return port_flow_complain(&error);

	*packets = flow_count.hits;
	*bytes = flow_count.bytes;

	return 0;
}

int offload_flow_destroy(portid_t port_id, struct rte_flow *flow)
{
	struct rte_flow_error error;
	int ret = 0;

	if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return -EINVAL;

	memset(&error, 0x33, sizeof(error));
	if (rte_flow_destroy(port_id, flow, &error))
		ret = port_flow_complain(&error);

	return ret;
}

void offload_flow_aged(portid_t port_id)
{
	int nb_context, total = 0, idx;
	struct rte_flow_error error;
	struct fw_session *session;
	void **contexts;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return;

	total = rte_flow_get_aged_flows(port_id, NULL, 0, &error);
	if (total < 0) {
		port_flow_complain(&error);
		return;
	}
	if (total == 0)
		return;
	contexts = malloc(sizeof(void *) * total);
	if (contexts == NULL)
		return;
	nb_context = rte_flow_get_aged_flows(port_id, contexts,
					     total, &error);
	if (nb_context != total) {
		free(contexts);
		return;
	}

	for (idx = 0; idx < nb_context; idx++) {
		session = (struct fw_session*)contexts[idx];
		if (!session)
			continue;
		ret = opof_del_flow(session);
		if (!ret)
			rte_atomic32_inc(&off_config_g.stats.aged);
	}
	free(contexts);
}

int offload_flow_flush(portid_t port_id)
{
	struct rte_flow_error error;
	int ret = 0;

	memset(&error, 0x44, sizeof(error));
	if (rte_flow_flush(port_id, &error)) {
		ret = port_flow_complain(&error);
		if (port_id_is_invalid(port_id, DISABLED_WARN) ||
		    port_id == (portid_t)RTE_PORT_ALL)
			return ret;
	}

	return ret;
}
