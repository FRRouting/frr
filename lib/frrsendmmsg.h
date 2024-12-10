// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR sendmmsg wrapper
 * Copyright (C) 2024 by Nvidia, Inc.
 *                       Donald Sharp
 */
#ifndef __FRRSENDMMSG_H__
#define __FRRSENDMMSG_H__

#if !defined(HAVE_STRUCT_MMSGHDR_MSG_HDR) || !defined(HAVE_SENDMMSG)
/* avoid conflicts in case we have partial support */
#define mmsghdr	 frr_mmsghdr
#define sendmmsg frr_sendmmsg

struct mmsghdr {
	struct msghdr msg_hdr;
	unsigned int msg_len;
};

/* just go 1 at a time here, the loop this is used in will handle the rest */
static inline int sendmmsg(int fd, struct mmsghdr *mmh, unsigned int len,
			   int flags)
{
	int rv = sendmsg(fd, &mmh->msg_hdr, 0);

	return rv > 0 ? 1 : rv;
}
#endif

#endif
