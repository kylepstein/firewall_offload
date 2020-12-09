/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include <stdlib.h>

#include "opof.h"
#include "opof_error.h"
#include "opof_serverlib.h"
#include "opof_test_util.h"

#include "common.h"

static void display_response(sessionResponse_t *response,
			     uint8_t *cmd)
{
	if (!off_config_g.verbose)
		return;

	printf("\n\nRequest: %s session\n", cmd);
	printf("Session ID: %ld\n",response->sessionId);
	printf("In Packets %ld\n",response->inPackets);
	printf("Out Packets: %ld\n",response->outPackets);
	printf("In Bytes: %ld\n",response->inBytes);
	printf("Out Bytes: %ld\n",response->outBytes);
	printf("Session State: %d\n",response->sessionState);
	printf("Session Close Code: %d\n",response->sessionCloseCode);
}

static void display_request(sessionRequest_t *request,
			    uint8_t *cmd)
{
	if (!off_config_g.verbose)
		return;

	printf("\n\nRequest: %s session\n", cmd);
	printf("Session ID: %ld\n",request->sessId);
	printf( "Inlif: %d\n",request->inlif);
	printf( "Outlif: %d\n",request->outlif);
	printf( "Source Port: %d\n",request->srcPort);
	printf( "Source IP: 0x%x\n", ntohl(request->srcIP.s_addr));
	printf( "Destination IP: 0x%x\n",ntohl(request->dstIP.s_addr));
	printf( "Destination Port: %d\n",request->dstPort);
	printf( "Protocol ID: %d\n",request->proto);
	printf( "IP Version: %d\n",request->ipver);
	printf( "Action Value: %d\n",request->actType);
}

int opof_del_flow(struct fw_session *session)
{
	struct rte_hash *ht = off_config_g.session_ht;
	sessionResponse_t *session_stat;
	int ret = 0;

	session_stat = rte_zmalloc("stats",
				   sizeof(sessionResponse_t),
				   RTE_CACHE_LINE_SIZE);
	opof_get_session_server(session->key.sess_id, session_stat);

	ret = offload_flow_destroy(session->port_in,session->flow_in);

	if (ret)
		goto out;

	ret = offload_flow_destroy(session->port_out,
				   session->flow_out);

	if (ret)
		goto out;

	rte_hash_del_key(ht, &session->key);


	if (rte_ring_enqueue(off_config_g.session_fifo, session_stat))
		printf("Err: no enough room in session session_fifo\n");

	rte_free(session);

	rte_atomic32_dec(&off_config_g.stats.active);

	return ret;

out:
	rte_free(session_stat);
	return ret;
}

int opof_add_session_server(sessionRequest_t *parameters,
			    addSessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret;

	memset(&key, 0, sizeof(key));

	display_request(parameters, "add");

	key.sess_id = parameters->sessId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (session) {
		offload_dbg("Session (%d) already exists",
			    session->key.sess_id);
		return _ALREADY_EXISTS;
	}

	session = rte_zmalloc("session",
			      sizeof(struct fw_session),
			      RTE_CACHE_LINE_SIZE);

	session->key.sess_id = parameters->sessId;

	session->tuple.src_ip = parameters->srcIP.s_addr;
	session->tuple.dst_ip = parameters->dstIP.s_addr;
	session->tuple.proto = parameters->proto;
	session->tuple.src_port = parameters->srcPort;
	session->tuple.dst_port = parameters->dstPort;

	session->timeout = parameters->cacheTimeout;

	if (parameters->inlif == 1) {
		session->port_in = INITIATOR_PORT_ID;
		session->port_out = RESPONDER_PORT_ID;
	} else {
		session->port_in = RESPONDER_PORT_ID;
		session->port_out = INITIATOR_PORT_ID;
	}

	ret = offload_flow_add(session->port_in, session,
			       (enum flow_action)parameters->actType,
			       DIR_IN);

	if (ret)
		return _INTERNAL;

	ret = offload_flow_add(session->port_out, session,
			       (enum flow_action)parameters->actType,
			       DIR_OUT);

	if (!ret) {
		session->state = _ESTABLISHED;
		rte_hash_add_key_data(ht, &session->key, (void *)session);
		rte_atomic32_inc(&off_config_g.stats.active);
		offload_dbg("Session (%d) added", session->key.sess_id);
	} else {
		offload_flow_destroy(session->port_in, session->flow_in);
		return _INTERNAL;
	}

	return _OK;
}

int opof_get_session_server(unsigned long sessionId,
			    sessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret;

	key.sess_id = sessionId;

	memset(response, 0, sizeof(*response));
	response->sessionId = sessionId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (!session)
		return _NOT_FOUND;

	offload_flow_query(session->port_in, session->flow_in,
			   &response->inPackets, &response->inBytes);

	offload_flow_query(session->port_out, session->flow_out,
			   &response->outPackets, &response->outBytes);

	response->sessionState = session->state;
	response->sessionCloseCode = session->close_code;

	display_response(response, "get");
	return _OK;
}

int opof_del_session_server(unsigned long sessionId,
			    sessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret;

	key.sess_id = sessionId;

	memset(response, 0, sizeof(*response));
	response->sessionId = sessionId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (!session)
		return _NOT_FOUND;

	ret = opof_del_flow(session);

	return ret ? _INTERNAL : _OK;
}

void opof_del_all_session_server(void)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	const void *next_key = NULL;
	uint32_t iter = 0;

	while (rte_hash_iterate(ht, &next_key, (void **)&session, &iter) >= 0)
		opof_del_flow(session);
}

int opof_get_closed_sessions_server(statisticsRequestArgs_t *request,
				    sessionResponse_t responses[])
{
	int size = request->pageSize;
	int deq, count, ret, i;
	sessionResponse_t **session_stats;

	count = rte_ring_count(off_config_g.session_fifo);

	size = MIN(MIN(size, count), BUFFER_MAX);

	session_stats = rte_zmalloc("temp",
				    sizeof(sessionResponse_t *) * size,
				    RTE_CACHE_LINE_SIZE);

	deq = rte_ring_dequeue_bulk(off_config_g.session_fifo,
				    (void **)session_stats, size,
				    NULL);
	if (deq) {
		for (i = 0; i < deq; i++) {
			memcpy(&responses[i], session_stats[i],
			       sizeof(sessionResponse_t));

			display_response(&responses[i], "get closed");
		}
	}

	rte_free(session_stats);

	return deq;
}

int opof_get_all_sessions_server(int pageSize, uint64_t *startSession,int
				 pageCount, sessionResponse_t **responses)
{
	return _OK;
}
