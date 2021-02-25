/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <ctype.h>
#include <sys/queue.h>

#include <rte_common.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline_socket.h>
#include <cmdline.h>
#include <wait.h>
#include <signal.h>
#include "nv_opof.h"

static struct cmdline *fw_offload_cl;

/*** quit ***/
/* exit application */

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__rte_unused void *parsed_result,
		__rte_unused struct cmdline *cl,
		__rte_unused void *data)
{
	pid_t my_pid = getpid();
	kill(my_pid, SIGINT);
}

cmdline_parse_token_string_t cmd_quit_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit,
				 "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,
	.data = NULL,
	.help_str = "exit application",
	.tokens = {
		(void *)&cmd_quit_tok,
		NULL,
	},
};

/*** flow_query ***/

struct cmd_flow_query_result {
	cmdline_fixed_string_t flow_query;
	uint64_t session_id;
};

static void
cmd_flow_query_parsed(void *parsed_result,
		__rte_unused struct cmdline *cl,
		__rte_unused void *data)
{
	struct cmd_flow_query_result *res = parsed_result;
	sessionResponse_t response;

	memset(&response, 0, sizeof(response));
	opof_get_session_server(res->session_id, &response);
	if(response.requestStatus == _REJECTED_SESSION_NONEXISTENT)
		printf("No such session (%lu)\n", res->session_id);
}

cmdline_parse_token_string_t cmd_flow_query_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_query_result, flow_query,
				 "flow query");

cmdline_parse_token_num_t cmd_session_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_query_result, session_id, RTE_UINT64);

cmdline_parse_inst_t cmd_flow_query = {
	.f = cmd_flow_query_parsed,
	.data = NULL,
	.help_str = "Query flow <session-id>",
	.tokens = {
		(void *)&cmd_flow_query_tok,
		(void *)&cmd_session_id,
		NULL,
	},
};

/*** flow_del***/

struct cmd_flow_del_result {
	cmdline_fixed_string_t flow_del;
	uint64_t session_id;
};

static void
cmd_flow_del_parsed(void *parsed_result,
		__rte_unused struct cmdline *cl,
		__rte_unused void *data)
{
	struct cmd_flow_del_result *res = parsed_result;
	sessionResponse_t response;

	memset(&response, 0, sizeof(response));
	opof_del_session_server(res->session_id, &response);
	if(response.requestStatus == _REJECTED_SESSION_NONEXISTENT)
		printf("No such session (%lu)\n", res->session_id);
}

cmdline_parse_token_string_t cmd_flow_del_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_del_result, flow_del,
				 "flow del");

cmdline_parse_inst_t cmd_flow_del = {
	.f = cmd_flow_del_parsed,
	.data = NULL,
	.help_str = "Del flow <session-id>",
	.tokens = {
		(void *)&cmd_flow_del_tok,
		(void *)&cmd_session_id,
		NULL,
	},
};

/*** stats query ***/

struct cmd_stats_query_result {
	cmdline_fixed_string_t stats_query;
};

static void
cmd_stats_query_parsed(__rte_unused void *parsed_result,
		__rte_unused struct cmdline *cl,
		__rte_unused void *data)
{
	struct cmd_stats_query_result *res = parsed_result;

	printf("Session stats:\n");
	printf("\tActive (%d)\n",
	       rte_atomic32_read(&off_config_g.stats.active));
	printf("\tAged (%d)\n",
	       rte_atomic32_read(&off_config_g.stats.aged));
}

cmdline_parse_token_string_t cmd_stats_query_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_query_result, stats_query,
				 "stats query");

cmdline_parse_inst_t cmd_stats_query = {
	.f = cmd_stats_query_parsed,
	.data = NULL,
	.help_str = "stats query",
	.tokens = {
		(void *)&cmd_stats_query_tok,
		NULL,
	},
};

/*** verbose ***/

struct cmd_verbose_result {
	cmdline_fixed_string_t verbose_str;
	uint8_t verbose;
};

static void
cmd_verbose_parsed(void *parsed_result,
		   __rte_unused struct cmdline *cl,
		   __rte_unused void *data)
{
	struct cmd_verbose_result *res = parsed_result;

	off_config_g.verbose = !!res->verbose;
}

cmdline_parse_token_string_t cmd_verbose_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_verbose_result, verbose,
				 "verbose");

cmdline_parse_token_num_t cmd_verbose_set =
	TOKEN_NUM_INITIALIZER(struct cmd_verbose_result, verbose, RTE_UINT8);

cmdline_parse_inst_t cmd_verbose = {
	.f = cmd_verbose_parsed,
	.data = NULL,
	.help_str = "verbose <0|1>",
	.tokens = {
		(void *)&cmd_verbose_tok,
		(void *)&cmd_verbose_set,
		NULL,
	},
};

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_flow_query,
	(cmdline_parse_inst_t *)&cmd_flow_del,
	(cmdline_parse_inst_t *)&cmd_stats_query,
	(cmdline_parse_inst_t *)&cmd_verbose,
	NULL,
};

int cmd_prompt(void)
{
	fw_offload_cl = cmdline_stdin_new(main_ctx, "> ");
	if (fw_offload_cl  == NULL) {
		return -1;
	}
	cmdline_interact(fw_offload_cl);
	cmdline_stdin_exit(fw_offload_cl);

	return 0;
}

void force_quit(void)
{
	clean_up();
	if (fw_offload_cl != NULL)
		cmdline_quit(fw_offload_cl);
}

void args_parse(int argc, char** argv)
{
	char *end;
	int opt;

	static struct option lgopts[] = {
		{ "help",	0, 0, 'h'},
		{ "address",	0, 0, 'a'},
		{ "port",	0, 0, 'p'},
		{ "timeout",	0, 0, 't'},
		{ "debug",	0, 0, 'd'},
	};

	while ((opt = getopt_long(argc, argv, "a:p:t:h:d",
				  lgopts, NULL)) != EOF) {
		switch (opt) {
		case 'a':
			strncpy(off_config_g.grpc_addr, optarg, 32);
			off_config_g.has_grpc_addr = 1;
			break;
		case 'p':
			off_config_g.grpc_port = strtoul(optarg, &end, 10);
			break;
		case 't':
			off_config_g.timeout = strtoul(optarg, &end, 10);
			break;
		case 'd':
			off_config_g.verbose = 1;
			break;

		case 'h':
			printf("\t-p, --port\tgRPC Port \n");
			printf("\t-a, --address\tAddress of gRPC Server\n");
			printf("\t-t, --timeout\tDefault aging time in sec\n");
			printf("\t-d, --debug:\tPrint debug message \n\n");
			printf("\t-h, --help:\tCommand line help \n\n");
			rte_exit(EXIT_SUCCESS, "Displayed help\n");
		default:
			printf("Invalid option: %s\n", argv[optind]);
			rte_exit(EXIT_FAILURE,
				 "Command line is incomplete or incorrect\n");
		}
	}
}
