// SPDX-License-Identifier: GPL-2.0-or-later
/* C-Ares integration to Quagga mainloop
 * Copyright (c) 2014-2015 Timo Teräs
 */

#ifndef _FRR_RESOLVER_H
#define _FRR_RESOLVER_H

#include "frrevent.h"
#include "sockunion.h"

#ifdef __cplusplus
extern "C" {
#endif

struct resolver_query {
	void (*callback)(struct resolver_query *, const char *errstr, int n,
			 union sockunion *);

	/* used to immediate provide the result if IP literal is passed in */
	union sockunion literal_addr;
	struct event *literal_cb;
};

void resolver_init(struct event_loop *tm);
void resolver_terminate(void);
void resolver_resolve(struct resolver_query *query, int af, vrf_id_t vrf_id,
		      const char *hostname,
		      void (*cb)(struct resolver_query *, const char *, int,
				 union sockunion *));

#ifdef __cplusplus
}
#endif

#endif /* _FRR_RESOLVER_H */
