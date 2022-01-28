/*
 * PIM for Quagga
 * Copyright (C) 2022  Dell Technologies Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef PIM6_MROUTE_H
#define PIM6_MROUTE_H

/*
  For msghdr.msg_control in Solaris 10
*/
#ifndef _XPG4_2
#define _XPG4_2
#endif
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif

#include <netinet/in.h>
#ifdef HAVE_NETINET_IP_MROUTE_H
#include <netinet/ip_mroute.h>
#endif

#define PIM_MROUTE_MIN_TTL (1)

#if defined(HAVE_LINUX_MROUTE_H)
#include <linux/mroute6.h>
#else
/*
  Below: from <linux/mroute.h>
*/

#ifndef MAXMIFS
#define MAXMIFS (256)
#endif

#ifndef SIOCGETMIFCNT
#define SIOCGETMIFCNT_IN6   SIOCPROTOPRIVATE        /* IP protocol privates */
#define SIOCGETSGCNT_IN6    (SIOCPROTOPRIVATE+1)
#define SIOCGETRPF          (SIOCPROTOPRIVATE+2)
#endif

#ifndef MRT6_INIT
#define 	MRT6_BASE   200
#define 	MRT6_INIT   (MRT6_BASE) /* Activate the kernel mroute code */
#define 	MRT6_DONE   (MRT6_BASE+1) /* Shutdown the kernel mroute */
#define 	MRT6_ADD_MIF   (MRT6_BASE+2) /* Add a virtual interface */
#define 	MRT6_DEL_MIF   (MRT6_BASE+3) /* Delete a virtual interface */
#define 	MRT6_ADD_MFC   (MRT6_BASE+4) /* Add a multicast forwarding entry */
#define 	MRT6_DEL_MFC   (MRT6_BASE+5) /* Delete a multicast forwarding entry */
#define 	MRT6_VERSION   (MRT6_BASE+6) /* Get the kernel multicast version */
#define 	MRT6_ASSERT   (MRT6_BASE+7) /* Activate PIM assert mode */
#define 	MRT6_PIM   (MRT6_BASE+8) /* enable PIM code */
#endif

#ifndef MRT6_TABLE
#define 	MRT6_TABLE   (MRT6_BASE+9) /* Specify mroute table ID */
#endif

typedef unsigned short mifi_t;

struct mif6ctl {
	mifi_t	mif6c_mifi;		/* Index of MIF */
	unsigned char mif6c_flags;	/* MIFF_ flags */
	unsigned char vifc_threshold;	/* ttl limit */
	__u16	 mif6c_pifi;		/* the index of the physical IF */
	unsigned int vifc_rate_limit;	/* Rate limiter values (NI) */
};

struct mf6cctl {
	struct sockaddr_in6 mf6cc_origin;		/* Origin of mcast	*/
	struct sockaddr_in6 mf6cc_mcastgrp;		/* Group in question	*/
	mifi_t	mf6cc_parent;			/* Where it arrived	*/
	struct if_set mf6cc_ifset;		/* Where it is going */
};

/*
 *      Group count retrieval for mrouted
 */
/*
  struct sioc_sg_req sgreq;
  memset(&sgreq, 0, sizeof(sgreq));
  memcpy(&sgreq.src, &source_addr, sizeof(sgreq.src));
  memcpy(&sgreq.grp, &group_addr, sizeof(sgreq.grp));
  ioctl(mrouter_s4, SIOCGETSGCNT, &sgreq);
 */
struct sioc_sg_req6 {
	struct sockaddr_in6 src;
	struct sockaddr_in6 grp;
	unsigned long pktcnt;
	unsigned long bytecnt;
	unsigned long wrong_if;
};

/*
 *      To get vif packet counts
 */
/*
  struct sioc_vif_req vreq;
  memset(&vreq, 0, sizeof(vreq));
  vreq.vifi = vif_index;
  ioctl(mrouter_s4, SIOCGETVIFCNT, &vreq);
 */
struct sioc_mif_req6 {
	mifi_t	mifi;		/* Which iface */
	unsigned long icount;	/* In packets */
	unsigned long ocount;	/* Out packets */
	unsigned long ibytes;	/* In bytes */
	unsigned long obytes;	/* Out bytes */
};

/*
 *      Pseudo messages used by mrouted
 */
#ifndef MRT6MSG_NOCACHE
#define MRT6MSG_NOCACHE         1               /* Kern cache fill request to mrouted */
#define MRT6MSG_WRONGVIF        2               /* For PIM assert processing (unused) */
#define MRT6MSG_WHOLEPKT        3               /* For PIM Register processing */
#endif

struct mrt6msg {
	__u8		im6_mbz;		/* must be zero		   */
	__u8		im6_msgtype;		/* what type of message    */
	__u16		im6_mif;		/* mif rec'd on		   */
	__u32		im6_pad;		/* padding for 64 bit arch */
	struct in6_addr	im6_src, im6_dst;
};
#endif

#ifndef MRT6MSG_WRVIFWHOLE
#define MRT6MSG_WRVIFWHOLE      4               /* For PIM processing */
#endif

/*
  Above: from <linux/mroute.h>
*/
#ifndef MAXIFS
#define MAXIFS MAXMIFS
#endif

struct channel_oil;

int pim_mroute_socket_enable(struct pim_instance *pim);
int pim_mroute_socket_disable(struct pim_instance *pim);

int pim_mroute_add_if(struct interface *ifp, pim_addr ifaddr,
		       unsigned char flags);
int pim_mroute_del_if(struct interface *ifp);

int pim_upstream_mroute_add(struct channel_oil *c_oil, const char *name);
int pim_upstream_mroute_iif_update(struct channel_oil *c_oil, const char *name);
int pim_static_mroute_add(struct channel_oil *c_oil, const char *name);
void pim_static_mroute_iif_update(struct channel_oil *c_oil,
				int input_vif_index,
				const char *name);
int pim_mroute_del(struct channel_oil *c_oil, const char *name);

void pim_mroute_update_counters(struct channel_oil *c_oil);
bool pim_mroute_allow_iif_in_oil(struct channel_oil *c_oil,
		int oif_index);
#endif /* PIM_MROUTE_H */
