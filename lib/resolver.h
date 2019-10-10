/* C-Ares integration to Quagga mainloop
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _FRR_RESOLVER_H
#define _FRR_RESOLVER_H

#include "thread.h"
#include "sockunion.h"

struct resolver_query {
	void (*callback)(struct resolver_query *, int n, union sockunion *);
};

void resolver_init(struct thread_master *tm);
void resolver_resolve(struct resolver_query *query, int af,
		      const char *hostname, void (*cb)(struct resolver_query *,
						       int, union sockunion *));

#endif /* _FRR_RESOLVER_H */
