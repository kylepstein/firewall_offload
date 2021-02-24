/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "common.h"

static int nv_opof_log_level = NV_OPOF_LOG_DEFAULT;
static FILE *fp = NULL;

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
