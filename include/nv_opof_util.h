/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Nvidia
 */

#ifndef NV_OPOF_UTIL_H
#define NV_OPOF_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define NV_OPOF_LOG_ERR		0
#define NV_OPOF_LOG_INFO	1
#define NV_OPOF_LOG_DEBUG	2
#define NV_OPOF_LOG_DEFAULT	NV_OPOF_LOG_DEBUG

#define LOG_FILE_SIZE		(5 * 1024 * 1024)
#define LOG_MSG_MAX_LEN		1024
#define LOG_DIR			"/opt/mellanox/firewall_offload"
#define LOG_FILE		"/opt/mellanox/firewall_offload/nv_opof.log"
#define LOG_FILE_ARCHIVE	"/opt/mellanox/firewall_offload/nv_opof.log.archive"

#define log_error(M, ...) \
	nv_opof_log(NV_OPOF_LOG_ERR, "[ERROR] %s:%d:%s: (errno: %d - %s) " M "\n", \
                    __FILE__, __LINE__, __func__, errno, strerror(errno), \
                    ##__VA_ARGS__)

#define log_info(M, ...) \
	nv_opof_log(NV_OPOF_LOG_INFO,  "[INFO]  %s:%d:%s: " M "\n", \
                    __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define log_debug(M, ...) \
	nv_opof_log(NV_OPOF_LOG_DEBUG, "[DEBUG] %s:%d:%s: " M "\n", \
                    __FILE__, __LINE__, __func__, ##__VA_ARGS__)


int nv_opof_log_open(void);
void nv_opof_log_close(void);
void nv_opof_set_log_level(int level);
int nv_opof_log(int level, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
