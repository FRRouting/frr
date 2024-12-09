// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Server socket program to simulate fpm using protobuf
 * Copyright (C) 2023 Alibaba, Inc.
 *                    Hongyu Li
 */
#include "dplaneserver.h"
#include "fpm/fpm.pb-c.h"
#include "qpb/qpb.h"

#define FPM_HEADER_SIZE 4
DEFINE_MGROUP(DPLANESERVER, "dplaneserver");
DEFINE_MTYPE(DPLANESERVER, DPLANE_BUFFER, "dplaneserver communication");
struct Dplaneserver_data dplaneserver_data = { .bufSize = 2048,
					     .messageBuffer = NULL,
					     .pos = 0,
					     .server_socket = 0,
					     .connection_socket = 0,
					     .connected = false,
					     .server_up = false };
enum fpm_msg_op fm_op;

void process_fpm_msg(fpm_msg_hdr_t *fpm_hdr)
{
	size_t msg_len = fpm_msg_len(fpm_hdr);
	Fpm__Message *msg;

	msg = fpm__message__unpack(NULL, msg_len - FPM_HEADER_SIZE,
				   (uint8_t *)fpm_msg_data(fpm_hdr));
	if (msg) {
		fm_op = msg->type;
		switch (fm_op) {
		case FPM_OP_ROUTE_INSTALL:
			if (!msg->add_route) {
				zlog_err("%s: ROUTE_INSTALL info doesn't exist",
					 __func__);
				break;
			}
			process_route_install_msg(msg->add_route);
			break;
		/* Un-handled at this time */
		case FPM_OP_ROUTE_DELETE:
			break;
		}
		fpm__message__free_unpacked(msg, NULL);
	} else {
		zlog_err("%s: unpack fpm message failed", __func__);
		return;
	}
}

int dplaneserver_init(void)
{
	struct sockaddr_in server_addr;

	dplaneserver_data.server_socket = socket(PF_INET, SOCK_STREAM,
						IPPROTO_TCP);
	if (dplaneserver_data.server_socket < 0) {
		zlog_err("%s: Can not open socket", __func__);
		return -1;
	}

	if (sockopt_reuseaddr(dplaneserver_data.server_socket) == -1) {
		zlog_err("%s: Can not set socket opt", __func__);
		return -1;
	}

	// bind port
	memset(&server_addr, 0, sizeof(server_addr));
	if (is_ipv6)
		server_addr.sin_family = AF_INET6;
	else
		server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(FPM_DEFAULT_PORT);
	server_addr.sin_addr.s_addr = FPM_DEFAULT_IP;

	if (bind(dplaneserver_data.server_socket,
		 (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		zlog_err("%s: bing socket to address failed", __func__);
		return -1;
	}

	if (listen(dplaneserver_data.server_socket, 10) == -1) {
		zlog_err("%s: listen socket failed", __func__);
		return -1;
	}

	dplaneserver_data.server_up = true;
	dplaneserver_data.messageBuffer = XMALLOC(MTYPE_DPLANE_BUFFER,
						 dplaneserver_data.bufSize);

	if (IS_DPLANE_SERVER_DEBUG)
		zlog_debug("%s: connect socket successfully", __func__);
	return 0;
}

void dplaneserver_exit(void)
{
	XFREE(MTYPE_DPLANE_BUFFER, dplaneserver_data.messageBuffer);
	if (dplaneserver_data.connected)
		close(dplaneserver_data.connection_socket);
	if (dplaneserver_data.server_up)
		close(dplaneserver_data.server_socket);
}

int dplaneserver_read_data(void)
{
	fpm_msg_hdr_t *fpm_hdr;
	size_t msg_len;
	size_t start = 0, left;
	ssize_t read_len;

	read_len = read(dplaneserver_data.connection_socket,
			dplaneserver_data.messageBuffer + dplaneserver_data.pos,
			dplaneserver_data.bufSize - dplaneserver_data.pos);

	if (read_len == 0) {
		if (IS_DPLANE_SERVER_DEBUG)
			zlog_debug("%s: socket connection closed", __func__);
		return -2;
	}
	if (read_len < 0) {
		zlog_err("%s: socket connection read error", __func__);
		return -1;
	}
	dplaneserver_data.pos += (uint32_t)read_len;
	while (true) {
		fpm_hdr = (fpm_msg_hdr_t *)(dplaneserver_data.messageBuffer +
					    start);
		left = dplaneserver_data.pos - start;
		if (left < FPM_MSG_HDR_LEN)
			break;
		/* fpm_msg_len includes header size */
		msg_len = fpm_msg_len(fpm_hdr);
		if (left < msg_len)
			break;
		if (!fpm_msg_ok(fpm_hdr, left)) {
			zlog_err("%s: fpm message header check failed", __func__);
			return -1;
		}
		process_fpm_msg(fpm_hdr);
		start += msg_len;
	}
	/* update msg buffer*/
	memmove(dplaneserver_data.messageBuffer,
		dplaneserver_data.messageBuffer + start,
		dplaneserver_data.pos - start);
	dplaneserver_data.pos = dplaneserver_data.pos - (uint32_t)start;
	return 0;
}

int dplaneserver_poll(void)
{
	struct pollfd poll_fd_set[MAX_CLIENTS + 1];

	memset(poll_fd_set, 0, sizeof(poll_fd_set));
	poll_fd_set[0].fd = dplaneserver_data.server_socket;
	poll_fd_set[0].events = POLLIN;
	while (true) {
		// poll for events
		int nready = poll(poll_fd_set, MAX_CLIENTS + 1, -1);

		if (nready == -1) {
			zlog_err("%s: failed to poll socket", __func__);
			return -1;
		}
		if (poll_fd_set[0].revents & POLLIN) {
			struct sockaddr_in client_addr;
			int i;
			socklen_t addr_len = sizeof(client_addr);
			int client_fd = accept(dplaneserver_data.server_socket,
					       (struct sockaddr *)&client_addr,
					       &addr_len);

			if (client_fd == -1) {
				zlog_err("%s: failed to accept client connection",
					 __func__);
				continue;
			}
			// add new connection to poll fd set
			for (i = 1; i <= MAX_CLIENTS; i++) {
				if (poll_fd_set[i].fd == 0) {
					if (IS_DPLANE_SERVER_DEBUG)
						zlog_debug("%s: a new client has connected",
							   __func__);
					poll_fd_set[i].fd = client_fd;
					poll_fd_set[i].events = POLLIN;
					dplaneserver_data.connection_socket =
						client_fd;
					dplaneserver_data.connected = true;
					break;
				}
			}
			if (i > MAX_CLIENTS) {
				close(client_fd);
				continue;
			}
		}
		// check for events on client sockets
		for (int i = 1; i <= MAX_CLIENTS; i++) {
			if (poll_fd_set[i].fd == 0)
				continue;
			if (poll_fd_set[i].revents & POLLIN) {
				int res = dplaneserver_read_data();
				/* if func return -1 or -2 it means errors occur*/
				if (res)
					return res;
			}
			if (poll_fd_set[i].revents &
			    (POLLERR | POLLHUP | POLLNVAL)) {
				if (IS_DPLANE_SERVER_DEBUG)
					zlog_debug("%s: socket POLLERR | POLLHUP | POLLNVAL event happened",
						   __func__);
				close(poll_fd_set[i].fd);
				poll_fd_set[i].fd = 0;
			}
		}
	}
}

void process_route_install_msg(Fpm__AddRoute *msg)
{
	struct prefix prefix;

	if (!msg->key) {
		zlog_err("%s: ROUTE_INSTALL route key doesn't exist", __func__);
		return;
	}
	if (!msg->key->prefix) {
		zlog_err("%s: ROUTE_INSTALL prefix doesn't exist", __func__);
		return;
	}

	if (msg->address_family != AF_INET && msg->address_family != AF_INET6) {
		zlog_err("%s: not ipv4 or ipv6 address family", __func__);
		return;
	}
	if (!qpb__l3_prefix__get(msg->key->prefix, msg->address_family,
				 &prefix)) {
		zlog_err("%s: failed to parse route prefix", __func__);
		return;
	}
	if (IS_DPLANE_SERVER_DEBUG)
		zlog_debug("%s: msg address family: %d, key %s prefix: %pFX length: %d",
			   __func__, msg->address_family,
			   (msg->address_family == AF_INET) ? "ipv4" : "ipv6",
			   &prefix, msg->key->prefix->length);

	json_object *json = json_object_new_object();

	json_object_int_add(json, "vrfId", (int64_t)(msg->vrf_id));
	json_object_int_add(json, "addressFamily",
			    (int64_t)(msg->address_family));
	json_object_int_add(json, "metric", (int64_t)(msg->metric));
	json_object_int_add(json, "subAddressFamily",
			    (int64_t)(msg->sub_address_family));
	json_object_int_add(json, "hasRouteType",
			    (int64_t)(msg->has_route_type));
	json_object_int_add(json, "routeType", (int64_t)(msg->route_type));
	if (msg->key) {
		json_object_string_addf(json, "prefix", "%pFXh", &prefix);
		json_object_int_add(json, "prefixLength",
				    (int64_t)(msg->key->prefix->length));
	}
	if (output_file_path) {
		FILE *fp = fopen(output_file_path, "a+");

		if (!fp) {
			zlog_err("%s open output json file failed:%s", __func__,
				 output_file_path);
		} else {
			fprintf(fp, "%s\n",
				json_object_to_json_string_ext(json,
							       JSON_C_TO_STRING_PRETTY));
			fclose(fp);
		}
	} else {
		zlog_err("%s output json file doesn't exist", __func__);
	}
	json_object_free(json);
}
