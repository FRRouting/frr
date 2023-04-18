// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * isis_ldp_sync.h: ISIS LDP-IGP Sync  handling routines
 * Copyright (C) 2020 Volta Networks, Inc.
 */

#ifndef _ZEBRA_ISIS_LDP_SYNC_H
#define _ZEBRA_ISIS_LDP_SYNC_H

#include "zclient.h"

/* Macro to log debug message */
#define ils_debug(...)                                                         \
	do {                                                                   \
		if (IS_DEBUG_LDP_SYNC)                                         \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

extern void isis_area_ldp_sync_enable(struct isis_area *area);
extern void isis_area_ldp_sync_disable(struct isis_area *area);
extern void isis_area_ldp_sync_set_holddown(struct isis_area *area,
					    uint16_t holddown);
extern void isis_if_ldp_sync_enable(struct isis_circuit *circuit);
extern void isis_if_ldp_sync_disable(struct isis_circuit *circuit);
extern void isis_if_set_ldp_sync_holddown(struct  isis_circuit *circuit);
extern void isis_ldp_sync_if_start(struct isis_circuit *circuit,
				   bool send_state_req);
extern void isis_ldp_sync_if_complete(struct isis_circuit *circuit);
extern void isis_ldp_sync_holddown_timer_add(struct isis_circuit *circuit);
extern void
isis_ldp_sync_handle_client_close(struct zapi_client_close_info *info);
extern void isis_ldp_sync_ldp_fail(struct isis_circuit *circuit);
extern int isis_ldp_sync_state_update(struct ldp_igp_sync_if_state state);
extern int isis_ldp_sync_announce_update(struct ldp_igp_sync_announce announce);
extern void isis_ldp_sync_state_req_msg(struct isis_circuit *circuit);
extern void isis_ldp_sync_set_if_metric(struct isis_circuit *circuit,
					bool run_regen);
extern bool isis_ldp_sync_if_metric_config(struct isis_circuit *circuit,
					   int level, int metric);
extern void isis_ldp_sync_init(void);
#endif /* _ZEBRA_ISIS_LDP_SYNC_H */
