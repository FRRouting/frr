// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra dataplane plugin for DPDK based hw offload
 *
 * Copyright (C) 2021 Nvidia
 * Anuradha Karuppiah
 */

#ifndef _ZEBRA_DPLANE_DPDK_PRIVATE_H
#define _ZEBRA_DPLANE_DPDK_PRIVATE_H

#include <zebra.h>

#include <rte_ethdev.h>

#include "zebra_dplane_dpdk.h"

/* match on eth, sip, dip, udp */
#define ZD_PBR_PATTERN_MAX 6
/* dec_ttl, set_smac, set_dmac, * phy_port, count
 */
#define ZD_PBR_ACTION_MAX 6

#define ZD_ETH_TYPE_IP 0x800

struct zd_dpdk_port {
	uint16_t port_id;		  /* dpdk port_id */
	struct rte_eth_dev_info dev_info; /* PCI info + driver name */
	uint32_t flags;
#define ZD_DPDK_PORT_FLAG_PROBED (1 << 0)
#define ZD_DPDK_PORT_FLAG_INITED (1 << 1)
};

struct zd_dpdk_stat {
	_Atomic uint32_t ignored_updates;

	_Atomic uint32_t rule_adds;
	_Atomic uint32_t rule_dels;
};

struct zd_dpdk_ctx {
	/* Stats */
	struct zd_dpdk_stat stats;
	struct zd_dpdk_port *dpdk_ports;
	int dpdk_logtype;
};

#endif
