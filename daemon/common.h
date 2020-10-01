/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/cdefs.h>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#include "opof_serverlib.h"

#define RTE_PORT_ALL	(~(uint16_t)0x0)

#define RX_RING_SIZE	1024
#define TX_RING_SIZE	1024
#define BURST_SIZE	32

#define MAX_LCORES	(8u)
#define MAX_DPDK_PORT	(4u)
#define NUM_PHY_PORT	(2u)
#define NUM_VF_PORT	(2u)

#define MAX_PATTERN_NUM	(2u)
#define MAX_ACTION_NUM	(3u)

#define NUM_REGULAR_Q	(1)
#define NUM_HP_Q	(1)

#define MAX_SESSION		(20000u)
#define SAMPLE_SESSION_FWD	(MAX_SESSION - 1)
#define SAMPLE_SESSION_DROP	(MAX_SESSION - 2)

typedef uint16_t queueid_t;
typedef uint16_t portid_t;

extern struct fw_offload_config off_config_g;

enum {
	portid_pf0	= 0,
	portid_pf0_vf0	= 1,

	portid_pf1	= 2,
	portid_pf1_vf0	= 3
};

enum {
	INITIATOR_PORT_ID = portid_pf0,
	RESPONDER_PORT_ID = portid_pf1
};

enum {
	FDB_ROOT_PRIORITY	= 0x0,
	FDB_DROP_PRIORITY	= 0x1,
	FDB_FWD_PRIORITY	= 0x2,
	FDB_NO_MATCH_PRIORITY	= 0x3,

	NIC_RX_NO_MATCH_PRIORITY = 0x3,
};

enum {
	NIC_RX_GROUP = 0xA,
};

enum lcore_type {
	LCORE_TYPE_MIN		= 1,
	LCORE_TYPE_GRPC		= 1,
	LCORE_TYPE_AGING	= 2,
	LCORE_TYPE_MAX		= 3
};

enum {
	/* unit sec */
	DEFAULT_TIMEOUT		= 10,
	TCP_DEFAULT_TIMEOUT	= 60 * 10,
	UDP_DEFAULT_TIMEOUT	= 60 * 10
};

enum print_warning {
	ENABLED_WARN = 0,
	DISABLED_WARN
};

enum flow_action {
	ACTION_DROP	= 0,
	ACTION_FORWARD	= 1
};

struct lcore_priv {
	enum lcore_type	type;
	uint8_t		id;
};

struct aging_priv {
	uint8_t lcore_id;
};

struct rte_port {
	struct rte_eth_dev_info dev_info;   /**< PCI info + driver name */
	struct rte_eth_conf     dev_conf;   /**< Port configuration. */
	struct rte_ether_addr   eth_addr;   /**< Port ethernet address */
	struct rte_eth_stats    stats;      /**< Last port statistics */

	uint8_t			is_rep;
	uint8_t			is_initiator;
	uint8_t			is_responder;
	portid_t		id;
};

struct eth_ntuple_filter {
	uint16_t flags;          /**< Flags from RTE_NTUPLE_FLAGS_* */
	uint32_t dst_ip;         /**< Destination IP address in big endian. */
	uint32_t dst_ip_mask;    /**< Mask of destination IP address. */
	uint32_t src_ip;         /**< Source IP address in big endian. */
	uint32_t src_ip_mask;    /**< Mask of destination IP address. */
	uint16_t dst_port;       /**< Destination port in big endian. */
	uint16_t dst_port_mask;  /**< Mask of destination port. */
	uint16_t src_port;       /**< Source Port in big endian. */
	uint16_t src_port_mask;  /**< Mask of source port. */
	uint8_t proto;           /**< L4 protocol. */
	uint8_t proto_mask;      /**< Mask of L4 protocol. */
	uint8_t tcp_flags;
};

struct session_key {
	uint64_t sess_id;
};

struct fw_session {
	struct session_key		key;
	struct eth_ntuple_filter	tuple;

	struct rte_flow *flow_in;
	portid_t	port_in;
	struct rte_flow *flow_out;
	portid_t	port_out;

	uint8_t		state;
	uint8_t		close_code;
};

struct offload_stats {
	rte_atomic32_t active;
	rte_atomic32_t aged;
};

struct fw_offload_config {
	struct lcore_priv	lcores[MAX_LCORES];
	struct aging_priv	aging;
	struct rte_hash		*mac_ht;
	struct rte_hash		*session_ht;
	struct rte_port		*ports;
	struct offload_stats	stats;

	portid_t phy_port[MAX_DPDK_PORT];
	portid_t peer_port[MAX_DPDK_PORT];
	portid_t vf_port[MAX_DPDK_PORT];

	uint8_t has_grpc_addr;
	char grpc_addr[32];
	uint16_t grpc_port;
	uint8_t verbose;
};

static inline void verrmsg(const char *fmt, va_list ap)
{
	if (fmt)
		vfprintf(stderr, fmt, ap);
	putc('\n', stderr);
}

static inline void offload_dbg(const char *fmt, ...)
{
	va_list ap;
	if (!off_config_g.verbose)
		return;

	va_start(ap, fmt);
	verrmsg(fmt, ap);
	va_end(ap);
}

int port_init(portid_t pid,
	      struct rte_mempool *mbuf_pool);

void lcore_init(void);
int cmd_prompt(void);

void clean_up(void);
void force_quit(void);
int thread_mux(void *data __rte_unused);

struct rte_flow *
add_simple_flow(uint16_t port_id,
		 struct rte_flow_attr *attr,
		 struct rte_flow_item pattern[],
		 struct rte_flow_action actions[],
		 const char *flow_name);

int offload_flow_add(portid_t port_id,
		     struct fw_session * session,
		     enum flow_action action);
int offload_flow_query(portid_t port_id,
		       struct rte_flow *flow,
		       uint64_t *packets,
		       uint64_t *bytes);
int offload_flow_destroy(portid_t port_id,
			 struct rte_flow *flow);
void offload_flow_aged(portid_t port_id);
int offload_flow_flush(portid_t port_id);

int opof_del_flow(struct fw_session *session);
void opof_del_all_session_server(void);
