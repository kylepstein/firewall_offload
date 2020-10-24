/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */ #include <stdlib.h>

#include "opof.h"
#include "opof_error.h"
#include "opof_serverlib.h"
#include "opof_test_util.h"

#include "common.h"

static void display_response(sessionResponse_t *response)
{
	if (!off_config_g.verbose)
		return;

	printf("\n\nSession Response\n");
	printf("Session ID: %ld\n",response->sessionId);
	printf("In Packets %ld\n",response->inPackets);
	printf("Out Packets: %ld\n",response->outPackets);
	printf("In Bytes: %ld\n",response->inBytes);
	printf("Out Bytes: %ld\n",response->outBytes);
	printf("Session State: %d\n",response->sessionState);
	printf("Session Close Code: %d\n",response->sessionCloseCode);
	printf("Request Status: %d\n",response->requestStatus);
}

static void display_request(sessionRequest_t *request)
{
	if (!off_config_g.verbose)
		return;

	printf("\n\nSession Response\n");
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
	sessionResponse_t session_stat;
	int ret;

	opof_get_session_server(session->key.sess_id, &session_stat);

	ret = offload_flow_destroy(session->port_in,session->flow_in);

	if (ret) {
		ret = FAILURE;
		goto out;
	}

	ret = offload_flow_destroy(session->port_out,
				   session->flow_out);

	if (ret) {
		ret = FAILURE;
		goto out;
	}

	offload_dbg("Session (%d) deleted\n", session->key.sess_id);

	rte_hash_del_key(ht, &session->key);

	if (rte_ring_enqueue(off_config_g.session_fifo, &session_stat))
		printf("Err: no enough room in session session_fifo\n");

	rte_free(session);

	rte_atomic32_dec(&off_config_g.stats.active);

	ret = SUCCESS;

out:
	return ret;
}

int opof_add_session_server(sessionRequest_t *parameters,
			    addSessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret = 0;

	memset(&key, 0, sizeof(key));

	display_request(parameters);

	key.sess_id = parameters->sessId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (session) {
		response->requestStatus = _REJECTED_SESSION_ALREADY_EXISTS;
		offload_dbg("Session (%d) already exists\n",
			    session->key.sess_id);
		goto out;
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
		goto out;

	ret = offload_flow_add(session->port_out, session,
			       (enum flow_action)parameters->actType,
			       DIR_OUT);

	if (!ret) {
		session->state = _ESTABLISHED;
		rte_hash_add_key_data(ht, &session->key, (void *)session);
		rte_atomic32_inc(&off_config_g.stats.active);
		offload_dbg("Session (%d) added\n", session->key.sess_id);
	} else {
		goto err_flow_out;
	}

	response->requestStatus = _ACCEPTED;

	return 0;

err_flow_out:
	offload_flow_destroy(session->port_in, session->flow_in);
out:
	response->requestStatus = _REJECTED;
	return ret;
}

int opof_get_session_server(unsigned long sessionId,
			    sessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret = 0;

	key.sess_id = sessionId;

	memset(response, 0, sizeof(*response));

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (!session) {
		response->requestStatus = _REJECTED_SESSION_NONEXISTENT;
		ret = FAILURE;
		goto out;
	}

	offload_flow_query(session->port_in, session->flow_in,
			   &response->inPackets, &response->inBytes);

	offload_flow_query(session->port_out, session->flow_out,
			   &response->outPackets, &response->outBytes);

	response->sessionId = sessionId;
	response->sessionState = session->state;
	response->sessionCloseCode = session->close_code;
	response->requestStatus = _ACCEPTED;

	display_response(response);

	ret = SUCCESS;

out:
	return ret;
}

int opof_del_session_server(unsigned long sessionId,
			    sessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret = 0;

	key.sess_id = sessionId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);

	if (!session) {
		response->requestStatus = _REJECTED_SESSION_NONEXISTENT;
		ret = FAILURE;
		goto out;
	}

	ret = opof_del_flow(session);

	if (ret) {
		response->requestStatus = _REJECTED;
		goto out;
	}

	response->requestStatus = _ACCEPTED;

out:
	return ret;
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
	int deq, count, ret;

	count = rte_ring_count(off_config_g.session_fifo);

	size = MIN(MIN(size, count), BUFFER_MAX);

	deq = rte_ring_dequeue_bulk(off_config_g.session_fifo,
				    (void **)&responses,
				    size, NULL);

	if (deq) {
		offload_dbg("Dequeue (%d) closed session\n", deq);
	}

	return deq;
}

sessionResponse_t **
opof_get_all_sessions_server(statisticsRequestArgs_t *request,
			     int *sessionCount)
{
	int count = 0;
	int nresponses = request->pageSize;
	sessionResponse_t **responses;
	*sessionCount = 0;

	//responses = getAllSessions(nresponses, &count);
	*sessionCount = count;

	return responses;
}
