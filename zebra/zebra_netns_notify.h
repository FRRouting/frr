// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra NS collector and notifier for Network NameSpaces
 * Copyright (C) 2017 6WIND
 */

#ifndef _NETNS_NOTIFY_H
#define _NETNS_NOTIFY_H

#ifdef __cplusplus
extern "C" {
#endif

extern void zebra_ns_notify_init(void);
extern void zebra_ns_notify_parse(void);
extern void zebra_ns_notify_close(void);

extern struct zebra_privs_t zserv_privs;

#ifdef __cplusplus
}
#endif

#endif /* NETNS_NOTIFY_H */
