// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP Filter Functions.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
 *
 */

#ifndef EIGRPD_EIGRP_FILTER_H_
#define EIGRPD_EIGRP_FILTER_H_

extern void eigrp_distribute_update(struct distribute_ctx *ctx,
				    struct distribute *dist);
extern void eigrp_distribute_update_interface(struct interface *ifp);
extern void eigrp_distribute_update_all(struct prefix_list *plist);
extern void eigrp_distribute_update_all_wrapper(struct access_list *alist);
extern void eigrp_distribute_timer_process(struct event *thread);
extern void eigrp_distribute_timer_interface(struct event *thread);

#endif /* EIGRPD_EIGRP_FILTER_H_ */
