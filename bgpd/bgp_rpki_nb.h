// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP RPKI northbound — YANG module info + loadable-module ops table.
 * Copyright (C) 2026 FRRouting
 */

#ifndef _FRR_BGP_RPKI_NB_H_
#define _FRR_BGP_RPKI_NB_H_

#include "northbound.h"

/*
 * Filled by bgpd_rpki.so at module init. NULL when the module is not
 * loaded — NB writes become silent no-ops.
 */
struct rpki_nb_ops {
	void (*container_destroy)(const char *vrfname);
	void (*enable_set)(const char *vrfname, bool enabled);
	void (*polling_set)(const char *vrfname, uint32_t seconds);
	void (*expire_set)(const char *vrfname, uint32_t seconds);
	void (*retry_set)(const char *vrfname, uint16_t seconds);
	/*
	 * Install the cache at this preference. The same transport parameters
	 * leave the running connection alone. Different parameters replace it.
	 * Incomplete parameters drop a stale cache and do not install one.
	 */
	void (*cache_add_tcp)(const char *vrfname, uint8_t preference, const char *host,
			      const char *port, const char *source);
	void (*cache_add_ssh)(const char *vrfname, uint8_t preference, const char *host,
			      uint16_t port, const char *user, const char *priv_key,
			      const char *server_pub_key, const char *source);
	void (*cache_remove)(const char *vrfname, uint8_t preference);
};

extern struct rpki_nb_ops *rpki_nb_cb;
extern const struct frr_yang_module_info frr_bgp_rpki_info;

#endif /* _FRR_BGP_RPKI_NB_H_ */
