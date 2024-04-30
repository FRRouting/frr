// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#ifndef _CONTROL_H_
#define	_CONTROL_H_

#include "queue.h"

struct ctl_conn {
	TAILQ_ENTRY(ctl_conn)	entry;
	struct imsgev		iev;
};
TAILQ_HEAD(ctl_conns, ctl_conn);

extern struct ctl_conns ctl_conns;

int	control_init(char *);
int	control_listen(void);
void	control_cleanup(char *);
int	control_imsg_relay(struct imsg *);

#endif	/* _CONTROL_H_ */
