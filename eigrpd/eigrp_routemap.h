/*
 * eigrp_routemap.h
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#ifndef EIGRPD_EIGRP_ROUTEMAP_H_
#define EIGRPD_EIGRP_ROUTEMAP_H_

#include "if_rmap.h"

/**
 * entry functions for route map support
 */
extern void eigrp_route_map_update(const char *);

/**
 * support functions
 */
extern bool eigrp_routemap_prefix_apply(eigrp_t *, eigrp_interface_t *,
					int in, struct prefix *prefix);
extern void eigrp_route_map_init();
extern void eigrp_if_rmap_update(eigrp_t *, struct if_rmap *);
extern void eigrp_if_rmap_update_interface(struct interface *);
extern void eigrp_routemap_update_redistribute(eigrp_t *);
extern void eigrp_rmap_update(const char *);

#endif /* EIGRPD_EIGRP_ROUTEMAP_H_ */
