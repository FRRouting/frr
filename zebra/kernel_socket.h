// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Exported kernel_socket functions, exported only for convenience of
 * sysctl methods.
 */

#ifndef __ZEBRA_KERNEL_SOCKET_H
#define __ZEBRA_KERNEL_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes of zebra. */
#define ZEBRA_ERR_NOERROR                0
#define ZEBRA_ERR_RTEXIST               -1
#define ZEBRA_ERR_RTUNREACH             -2
#define ZEBRA_ERR_EPERM                 -3
#define ZEBRA_ERR_RTNOEXIST             -4
#define ZEBRA_ERR_KERNEL                -5

extern void rtm_read(struct rt_msghdr *);
extern int ifam_read(struct ifa_msghdr *);
extern int ifm_read(struct if_msghdr *);
extern int rtm_write(int, union sockunion *, union sockunion *,
		     union sockunion *, union sockunion *, unsigned int,
		     enum blackhole_type, int);
extern const struct message rtm_type_str[];

#ifdef __cplusplus
}
#endif

#endif /* __ZEBRA_KERNEL_SOCKET_H */
