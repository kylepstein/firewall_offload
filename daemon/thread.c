/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "common.h"

void lcore_init(void)
{
	int i;

	for (i = LCORE_TYPE_MIN; i < LCORE_TYPE_MAX; i++) {
		off_config_g.lcores[i].type = (enum lcore_type)i;
		off_config_g.lcores[i].id = i;
	}

	off_config_g.aging.lcore_id = LCORE_TYPE_AGING;
}

static void aging_thread(uint32_t lcore_id)
{
	long int lwp_id;

	lwp_id = syscall(SYS_gettid);
	printf("LCORE(%u) (LWP=%ld): aging thread started\n",
	       lcore_id, lwp_id);

	while (1)
		offload_flow_aged(INITIATOR_PORT_ID);
}

static void grpc_thread(uint32_t lcore_id)
{
	const char *default_address ="localhost";
	uint16_t port = 3443;
	long int lwp_id;

	lwp_id = syscall(SYS_gettid);
	printf("LCORE(%u) (LWP=%ld): grpc thread started at %s\n",
	       lcore_id, lwp_id, default_address);

	opof_server(default_address, port, NULL, NULL);
}

int thread_mux(void *data __rte_unused)
{
	char thread_name[RTE_MAX_THREAD_NAME_LEN];
	uint32_t lcore_id = rte_lcore_id();
	const char *thread_name_pattern;
	struct lcore_priv *lcore;
	int ret = 0;

	lcore = &off_config_g.lcores[lcore_id];

	if (unlikely(lcore == NULL)) {
		ret = -1;
		goto err;
	}

	switch(lcore->type)
	{
	case LCORE_TYPE_GRPC:
		thread_name_pattern = "lcore-%u-grpc";
		grpc_thread(lcore_id);
		break;

	case LCORE_TYPE_AGING:
		thread_name_pattern = "lcore-%u-aging";
		aging_thread(lcore_id);
		break;

	case LCORE_TYPE_MAX:
	default:
		thread_name_pattern = "lcore-%u-idle";
		break;
	}

	snprintf(thread_name, sizeof(thread_name),
		 thread_name_pattern, lcore_id);
	thread_name[sizeof(thread_name) - 1] = '\0';
	rte_thread_setname(pthread_self(), thread_name);

	return ret;

err:
	printf("Thread type %d LCORE %u failed", (int)lcore->type, lcore_id);
	fflush(stdout);
	fflush(stderr);
	exit(EXIT_FAILURE);

	return ret;
}
