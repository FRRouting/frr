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

#define IN6_LINKLOCAL_IFINDEX(a) ((a).s6_addr[2] << 8 | (a).s6_addr[3])
#define SET_IN6_LINKLOCAL_IFINDEX(a, i)                                                            \
	do {                                                                                       \
		(a).s6_addr[2] = ((i) >> 8) & 0xff;                                                \
		(a).s6_addr[3] = (i) & 0xff;                                                       \
	} while (0)

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
