// SPDX-License-Identifier: GPL-2.0-or-later
/* SNMP cli support
 * Copyright (C) 2024 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 * Copyright (C) 2026 NVIDIA Corporation
 */
#ifndef __LIBAGENTX_H__
#define __LIBAGENTX_H__

#include <stdbool.h>
#include <stdint.h>

#include "lib/hook.h"

struct debug;

extern void libagentx_init(void);
extern bool agentx_enabled;
extern struct debug agentx_dbg;

DECLARE_HOOK(agentx_cli_enabled, (), ());
DECLARE_HOOK(agentx_cli_disabled, (), ());

/* Filled by the SNMP module for "show agentx status". */
struct agentx_cli_status {
	bool enabled;
	bool connected;
	/* Notifications still in the daemon queue, not yet sent. */
	uint32_t pending;
	/* Notifications freed: queue full, or master down past the hold. */
	uint64_t dropped;
	/* send_queued was read. Zero means the buffer is empty. */
	bool send_queued_valid;
	/* send_maximum was read from the live socket. */
	bool send_maximum_valid;
	/* True only when socket_fd was read. Unset stays 0, which is a real fd. */
	bool socket_fd_valid;
	/* Bytes already in the kernel send buffer. Not a notification count. */
	int send_queued;
	/* Live SO_SNDBUF of that socket, in bytes. */
	int send_maximum;
	/* fd of this daemon's socket connected to snmpd. Same number as ss fd=. */
	int socket_fd;
};

DECLARE_HOOK(agentx_cli_show, (struct agentx_cli_status *status), (status));

#endif
