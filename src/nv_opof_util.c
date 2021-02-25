/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>
#include <sys/stat.h>

#include "nv_opof.h"
#include "nv_opof_util.h"

static int nv_opof_log_level = NV_OPOF_LOG_DEFAULT;
static FILE *fp = NULL;
static void *ss_sp = NULL;

static char *signals [] = {
	[SIGINT] = "SIGINT",
	[SIGILL] = "SIGILL",
	[SIGBUS] = "SIGBUS",
	[SIGFPE] = "SIGFPE",
	[SIGSEGV] = "SIGSEGV",
	[SIGTERM] = "SIGTERM",
	[_NSIG] = "MAXSIGNUM",
};

int nv_opof_log_open(void)
{
	int ret;
	if (!opendir(LOG_DIR)) {
		ret = mkdir(LOG_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		if (ret) {
			ret = errno;
			fprintf(stderr, "Failed to create log directory.\n");
			return ret;
		}
	}
	fp = fopen(LOG_FILE, "w+");
	if (fp == NULL) {
		ret = errno;
		fprintf(stderr, "Failed to open log file.\n");
		return ret;
	}

	return 0;
}

void nv_opof_log_close(void)
{
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}
}

void nv_opof_set_log_level(int level)
{
	nv_opof_log_level = level;
}

int nv_opof_log(int level, const char *fmt, ...)
{
	struct stat statbuf;
	char time_buf[64];
	struct tm *tm;
	va_list vlist;
	time_t t;
	int ret;

	if (level > nv_opof_log_level)
		return 0;

	if (fp == NULL)
		return EINVAL;

	t = time(NULL);
	tm = localtime(&t);
	strftime(time_buf, sizeof(time_buf), "%d %b %Y %T", tm);

	fstat(fileno(fp), &statbuf);
	if (statbuf.st_size > LOG_FILE_SIZE) {
		fclose(fp);
		unlink(LOG_FILE_ARCHIVE);
		rename(LOG_FILE, LOG_FILE_ARCHIVE);
		ret = nv_opof_log_open();
		if (ret) {
			return ret;
		}
	}

	fprintf(fp, "%s ", time_buf);

	va_start(vlist, fmt);
	ret = vfprintf(fp, fmt, vlist);
	va_end(vlist);
	fflush(fp);

	return ret;
}

static void
nv_opof_signal_handler(int signum, siginfo_t *info, void *ucontext)
{
	(void)info;
	(void)ucontext;
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		clean_up();
		kill(getpid(), signum);
		break;
	case SIGILL:
	case SIGBUS:
	case SIGFPE:
	case SIGSEGV:
	default:
		rte_exit(EXIT_FAILURE, "EAL: exit with error");
		abort(); /* We should not be here, coredump... */
	}
}

void nv_opof_signal_handler_install(void)
{
	int ret, i;
	stack_t ss;
	struct sigaction sa;

	ss_sp = calloc(1, SIGSTKSZ);
	if (!ss_sp) {
		log_error("cannot calloc signal handler stack");
		return;
	}
	ss.ss_sp = ss_sp;
	ss.ss_size = SIGSTKSZ;
	ss.ss_flags = 0;
	ret = sigaltstack(&ss, NULL);
	if (ret == -1) {
		log_error("cannot set sigalstack");
		goto out;
	}
	sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
	sa.sa_sigaction = nv_opof_signal_handler;
	sigemptyset(&sa.sa_mask);
	for (i = 0; i < _NSIG; i++) {
		if (signals[i] == NULL)
			continue;
		ret = sigaction(i, &sa, NULL);
		if(ret == -1) {
			log_error("cannot install sighandler for %s",
				  signals[i]);
			goto out;
		}
	}
	return;

out:
	free(ss_sp);
	return;
}

void nv_opof_signal_handler_uninstall(void)
{
	struct sigaction sa;
	int i;

	if (ss_sp)
		free(ss_sp);
	ss_sp = NULL;
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	for (i = 0; i < _NSIG; i++) {
		if (signals[i] == NULL)
			continue;
		sigaction(i, &sa, NULL);
	}
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
		case 'h':
			printf("\t-p, --port\tgRPC Port \n");
			printf("\t-a, --address\tAddress of gRPC Server\n");
			printf("\t-t, --timeout\tDefault aging time in sec\n");
			printf("\t-h, --help:\tCommand line help \n\n");
			rte_exit(EXIT_SUCCESS, "Displayed help\n");
		default:
			printf("Invalid option: %s\n", argv[optind]);
			rte_exit(EXIT_FAILURE,
				 "Command line is incomplete or incorrect\n");
		}
	}
}
