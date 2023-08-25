// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Server socket program to simulate fpm using protobuf
 * Copyright (C) 2023 Alibaba, Inc.
 *                    Hongyu Li
 */
#ifndef _DPLANESERVER_H
#define _DPLANESERVER_H

#ifdef HAVE_CONFIG_H
#include "config.h" /* Include this explicitly */
#endif

#include <arpa/inet.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "zlog.h"
#include "fpm/fpm.h"
#include "lib/json.h"
#include "fpm/fpm.pb-c.h"
#include "lib/memory.h"
#include "lib/sockunion.h"

extern char *output_file_path;
extern struct Dplaneserver_data dplaneserver_data;
extern bool is_ipv6;
extern bool debug_mode;

#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define DPLANE_SERVER_DEBUG 0x01
#define IS_DPLANE_SERVER_DEBUG (debug_mode & DPLANE_SERVER_DEBUG)

#define FPM_DEFAULT_PORT 2620
#ifndef FPM_DEFAULT_IP
#define FPM_DEFAULT_IP (htonl(INADDR_LOOPBACK))
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001 /* Internet address 127.0.0.1.  */
#endif

DECLARE_MTYPE(DPLANE_BUFFER);

struct Dplaneserver_data {
	unsigned int bufSize;
	char *messageBuffer;
	unsigned int pos;
	int server_socket;
	int connection_socket;
	bool connected;
	bool server_up;
};

enum fpm_msg_op {
	FPM_OP_NONE = 0,

	/* Route update */
	FPM_OP_ROUTE_INSTALL,
	FPM_OP_ROUTE_DELETE,
};

int dplaneserver_init(void);
void dplaneserver_exit(void);
int dplaneserver_poll(void);
int dplaneserver_read_data(void);
void process_route_install_msg(Fpm__AddRoute *msg);

#endif
