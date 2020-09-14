/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "common.h"
#include <signal.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

struct fw_offload_config off_config_g;

static struct rte_hash* create_mac_hash_table(void)
{
	struct rte_hash_parameters params;
	struct rte_hash *h;
	char name[16];

	memset(&params, 0, sizeof(params));
	snprintf(name, sizeof(name), "mac_ht");
	params.name = name;
	params.entries = RTE_MAX_ETHPORTS;
	params.key_len = sizeof(struct rte_ether_addr);
	params.hash_func_init_val = 0;

	h = rte_hash_create(&params);

	return h;
}

static struct rte_hash* create_session_hash_table(void)
{
	struct rte_hash_parameters params;
	struct rte_hash *h;
	char name[16];

	memset(&params, 0, sizeof(params));
	snprintf(name, sizeof(name), "session_ht");
	params.name = name;
	params.entries = MAX_SESSION;
	params.key_len = sizeof(struct session_key);
	params.hash_func_init_val = 0;

	h = rte_hash_create(&params);

	return h;
}

void clean_up(void)
{
	portid_t portid;

	opof_del_all_session_server();

	rte_hash_free(off_config_g.mac_ht);
	rte_hash_free(off_config_g.session_ht);

	RTE_ETH_FOREACH_DEV(portid) {
		printf("Port(%u): Stopping\n", portid);
		fflush(stdout);
		rte_eth_dev_stop(portid);
	}

	RTE_ETH_FOREACH_DEV(portid) {
		printf("Port(%u): Shutting down\n", portid);
		fflush(stdout);
		offload_flow_flush(portid);
		//FIXME: segfault for 2nd port
		//rte_eth_dev_close(portid);
	}

	rte_free(off_config_g.ports);
}

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\nExiting...\n");

		force_quit();

		printf("Done\n");
		/* exit with the expected status */
		signal(signum, SIG_DFL);
		kill(getpid(), signum);
	}
}

static void config_init(void)
{
	memset(&off_config_g, 0, sizeof(struct fw_offload_config));

	off_config_g.phy_port[portid_pf0] = portid_pf0;
	off_config_g.phy_port[portid_pf0_vf0] = portid_pf0;
	off_config_g.phy_port[portid_pf1] = portid_pf1;
	off_config_g.phy_port[portid_pf1_vf0] = portid_pf1;

	off_config_g.peer_port[portid_pf0] = portid_pf1;
	off_config_g.peer_port[portid_pf0_vf0] = portid_pf0_vf0;
	off_config_g.peer_port[portid_pf1] = portid_pf0;
	off_config_g.peer_port[portid_pf1_vf0] = portid_pf1_vf0;

	off_config_g.vf_port[portid_pf0] = portid_pf0_vf0;
	off_config_g.vf_port[portid_pf0_vf0] = portid_pf0_vf0;
	off_config_g.vf_port[portid_pf1] = portid_pf1_vf0;
	off_config_g.vf_port[portid_pf1_vf0] = portid_pf1_vf0;

	off_config_g.mac_ht= create_mac_hash_table();
	off_config_g.session_ht = create_session_hash_table();

	off_config_g.ports = rte_zmalloc("ports",
					 sizeof(struct rte_port) *
					 RTE_MAX_ETHPORTS,
					 RTE_CACHE_LINE_SIZE);
	if (!off_config_g.ports)
		rte_exit(EXIT_FAILURE,
			 "rte_zmalloc(%d struct rte_port) failed\n",
			 RTE_MAX_ETHPORTS);
}

int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 4)
		rte_exit(EXIT_FAILURE, "Error: 1 VF is needed for each port\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	config_init();

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool))
			rte_exit(EXIT_FAILURE,
				 "Cannot init port %"PRIu16 "\n", portid);

	lcore_init();

	rte_eal_mp_remote_launch(&thread_mux, NULL, CALL_MASTER);

	cmd_prompt();

	rte_eal_mp_wait_lcore();

	return 0;
}
