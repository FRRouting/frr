// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2024  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_ZLOG_RECIRCULATE_H
#define _FRR_ZLOG_RECIRCULATE_H

/* fd should be one end of a socketpair() */
extern void zlog_recirculate_subscribe(struct event_loop *tm, int fd);

#endif
