/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

#ifndef PIM_MROUTE_H
#define PIM_MROUTE_H

/*
  For msghdr.msg_control in Solaris 10
*/
#ifndef _XPG4_2
#define _XPG4_2
#endif
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif


#define PIM_MROUTE_MIN_TTL (1)

#if PIM_IPV == 4
#include <netinet/in.h>
#ifdef HAVE_NETINET_IP_MROUTE_H
#include <netinet/ip_mroute.h>
#endif
#if defined(HAVE_LINUX_MROUTE_H)
#include <linux/mroute.h>
#else
/*
  Below: from <linux/mroute.h>
*/

#ifndef SIOCGETVIFCNT
#define SIOCGETVIFCNT   SIOCPROTOPRIVATE        /* IP protocol privates */
#define SIOCGETSGCNT    (SIOCPROTOPRIVATE+1)
#define SIOCGETRPF      (SIOCPROTOPRIVATE+2)
#endif

#ifndef MRT_INIT
#define MRT_BASE     200
#define MRT_INIT     (MRT_BASE)      /* Activate the kernel mroute code      */
#define MRT_DONE     (MRT_BASE+1)    /* Shutdown the kernel mroute           */
#define MRT_ADD_VIF  (MRT_BASE+2)    /* Add a virtual interface              */
#define MRT_DEL_VIF  (MRT_BASE+3)    /* Delete a virtual interface           */
#define MRT_ADD_MFC  (MRT_BASE+4)    /* Add a multicast forwarding entry     */
#define MRT_DEL_MFC  (MRT_BASE+5)    /* Delete a multicast forwarding entry  */
#define MRT_VERSION  (MRT_BASE+6)    /* Get the kernel multicast version     */
#define MRT_ASSERT   (MRT_BASE+7)    /* Activate PIM assert mode             */
#define MRT_PIM      (MRT_BASE+8)    /* enable PIM code      */
#endif

#ifndef MRT_TABLE
#define MRT_TABLE    (209)           /* Specify mroute table ID */
#endif

#ifndef HAVE_VIFI_T
typedef unsigned short vifi_t;
#endif

#ifndef HAVE_STRUCT_VIFCTL
struct vifctl {
	vifi_t vifc_vifi;	     /* Index of VIF */
	unsigned char vifc_flags;     /* VIFF_ flags */
	unsigned char vifc_threshold; /* ttl limit */
	unsigned int vifc_rate_limit; /* Rate limiter values (NI) */
	struct in_addr vifc_lcl_addr; /* Our address */
	struct in_addr vifc_rmt_addr; /* IPIP tunnel addr */
};
#endif

#ifndef HAVE_STRUCT_MFCCTL
struct mfcctl {
	struct in_addr mfcc_origin;       /* Origin of mcast      */
	struct in_addr mfcc_mcastgrp;     /* Group in question    */
	vifi_t mfcc_parent;		  /* Where it arrived     */
	unsigned char mfcc_ttls[MAXVIFS]; /* Where it is going    */
	unsigned int mfcc_pkt_cnt;	/* pkt count for src-grp */
	unsigned int mfcc_byte_cnt;
	unsigned int mfcc_wrong_if;
	int mfcc_expire;
};
#endif

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
#ifndef HAVE_STRUCT_SIOC_SG_REQ
struct sioc_sg_req {
	struct in_addr src;
	struct in_addr grp;
	unsigned long pktcnt;
	unsigned long bytecnt;
	unsigned long wrong_if;
};
#endif

/*
 *      To get vif packet counts
 */
/*
  struct sioc_vif_req vreq;
  memset(&vreq, 0, sizeof(vreq));
  vreq.vifi = vif_index;
  ioctl(mrouter_s4, SIOCGETVIFCNT, &vreq);
 */
#ifndef HAVE_STRUCT_SIOC_VIF_REQ
struct sioc_vif_req {
	vifi_t vifi;	  /* Which iface */
	unsigned long icount; /* In packets */
	unsigned long ocount; /* Out packets */
	unsigned long ibytes; /* In bytes */
	unsigned long obytes; /* Out bytes */
};
#endif

/*
 *      Pseudo messages used by mrouted
 */
#ifndef IGMPMSG_NOCACHE
#define IGMPMSG_NOCACHE         1               /* Kern cache fill request to mrouted */
#define IGMPMSG_WRONGVIF        2               /* For PIM assert processing (unused) */
#define IGMPMSG_WHOLEPKT        3               /* For PIM Register processing */
#endif

#ifndef HAVE_STRUCT_IGMPMSG
struct igmpmsg {
	uint32_t unused1, unused2;
	unsigned char im_msgtype; /* What is this */
	unsigned char im_mbz;     /* Must be zero */
	unsigned char im_vif;     /* Interface (this ought to be a vifi_t!) */
	unsigned char unused3;
	struct in_addr im_src, im_dst;
};
#endif

#endif /* HAVE_LINUX_MROUTE_H */

typedef struct mfcctl pim_mfcctl;

#ifndef IGMPMSG_WRVIFWHOLE
#define IGMPMSG_WRVIFWHOLE      4               /* For PIM processing */
#endif

#ifndef PIM_IPPROTO
#define PIM_IPPROTO IPPROTO_IP
#endif

#else /* PIM_IPV != 4 */

#include <netinet/ip6.h>
#ifdef HAVE_NETINET6_IP6_MROUTE_H
#include <netinet6/ip6_mroute.h>
#endif

#define IPV6_HEADER_LENGTH 40

#if defined(HAVE_LINUX_MROUTE6_H)
#include <linux/mroute6.h>
#else


#ifndef SIOCGETMIFCNT_IN6
#define SIOCGETMIFCNT_IN6   SIOCPROTOPRIVATE        /* IP protocol privates */
#define SIOCGETSGCNT_IN6    (SIOCPROTOPRIVATE+1)
#define SIOCGETRPF          (SIOCPROTOPRIVATE+2)
#endif

#ifndef MRT6_INIT
#define 	MRT6_BASE      200
#define 	MRT6_INIT      (MRT6_BASE) /* Activate the kernel mroute code */
#define 	MRT6_DONE      (MRT6_BASE+1) /* Shutdown the kernel mroute */
#define 	MRT6_ADD_MIF   (MRT6_BASE+2) /* Add a virtual interface */
#define 	MRT6_DEL_MIF   (MRT6_BASE+3) /* Delete a virtual interface */
#define 	MRT6_ADD_MFC   (MRT6_BASE+4) /* Add a multicast forwarding entry */
#define 	MRT6_DEL_MFC   (MRT6_BASE+5) /* Delete a multicast forwarding entry */
#define 	MRT6_VERSION   (MRT6_BASE+6) /* Get the kernel multicast version */
#define 	MRT6_ASSERT    (MRT6_BASE+7) /* Activate PIM assert mode */
#define 	MRT6_PIM       (MRT6_BASE+8) /* enable PIM code */
#endif

#ifndef MRT6_TABLE
#define 	MRT6_TABLE     (MRT6_BASE+9) /* Specify mroute table ID */
#endif

typedef unsigned short mifi_t;

#ifndef HAVE_STRUCT_MIF6CTL
struct mif6ctl {
	mifi_t	mif6c_mifi;		/* Index of MIF */
	unsigned char mif6c_flags;	/* MIFF_ flags */
	unsigned char vifc_threshold;	/* ttl limit */
	__u16	 mif6c_pifi;		/* the index of the physical IF */
	unsigned int vifc_rate_limit;	/* Rate limiter values (NI) */
};
#endif

#ifndef HAVE_STRUCT_MF6CCTL
struct mf6cctl {
	struct sockaddr_in6 mf6cc_origin;		/* Origin of mcast	*/
	struct sockaddr_in6 mf6cc_mcastgrp;		/* Group in question	*/
	mifi_t	mf6cc_parent;			/* Where it arrived	*/
	struct if_set mf6cc_ifset;		/* Where it is going */
};
#endif

/*
 *      Group count retrieval for mrouted
 */
/*
  struct sioc_sg_req6 sgreq;
  memset(&sgreq, 0, sizeof(sgreq));
  memcpy(&sgreq.src, &source_addr, sizeof(sgreq.src));
  memcpy(&sgreq.grp, &group_addr, sizeof(sgreq.grp));
  ioctl(mrouter_s6, SIOCGETSGCNT_IN6, &sgreq);
 */
#ifndef HAVE_STRUCT_SIOC_SG_REQ6
struct sioc_sg_req6 {
	struct sockaddr_in6 src;
	struct sockaddr_in6 grp;
	unsigned long pktcnt;
	unsigned long bytecnt;
	unsigned long wrong_if;
};
#endif

/*
 *      To get mif packet counts
 */
/*
  struct sioc_mif_req6 mreq;
  memset(&mreq, 0, sizeof(mreq));
  mreq.mifi = mif_index;
  ioctl(mrouter_s6, SIOCGETMIFCNT_IN6, &mreq);
 */
#ifndef HAVE_STRUCT_SIOC_MIF_REQ6
struct sioc_mif_req6 {
	mifi_t	mifi;		/* Which iface */
	unsigned long icount;	/* In packets */
	unsigned long ocount;	/* Out packets */
	unsigned long ibytes;	/* In bytes */
	unsigned long obytes;	/* Out bytes */
};
#endif

/*
 *      Pseudo messages used by mrouted
 */
#ifndef MRT6MSG_NOCACHE
#define MRT6MSG_NOCACHE         1               /* Kern cache fill request to mrouted */
#define MRT6MSG_WRONGMIF        2               /* For PIM assert processing (unused) */
#define MRT6MSG_WHOLEPKT        3               /* For PIM Register processing */
#endif

#ifndef HAVE_STRUCT_MRT6MSG
struct mrt6msg {
	__u8		im6_mbz;		/* must be zero		   */
	__u8		im6_msgtype;		/* what type of message    */
	__u16		im6_mif;		/* mif rec'd on		   */
	__u32		im6_pad;		/* padding for 64 bit arch */
	struct in6_addr	im6_src, im6_dst;
};
#endif
#endif

#ifndef MRT_INIT
#define 	MRT_BASE      MRT6_BASE
#define 	MRT_INIT      MRT6_INIT 
#define 	MRT_DONE      MRT6_DONE 
#define 	MRT_ADD_VIF   MRT6_ADD_MIF 
#define 	MRT_DEL_VIF   MRT6_DEL_MIF 
#define 	MRT_ADD_MFC   MRT6_ADD_MFC 
#define 	MRT_DEL_MFC   MRT6_DEL_MFC 
#define 	MRT_VERSION   MRT6_VERSION 
#define 	MRT_ASSERT    MRT6_ASSERT 
#define 	MRT_PIM       MRT6_PIM 
#endif

#ifndef MRT_TABLE
#define 	MRT_TABLE   MRT6_TABLE 
#endif

#ifndef PIM_IPPROTO
#define PIM_IPPROTO IPPROTO_IPV6
#endif

#ifndef MRT6MSG_WRMIFWHOLE
#define MRT6MSG_WRMIFWHOLE      4               /* For PIM processing */
#endif

typedef struct mf6cctl pim_mfcctl;

#define MAXVIFS IF_SETSIZE
#endif


/*
  Above: from <linux/mroute.h>
*/

struct channel_oil;

int pim_mroute_socket_enable(struct pim_instance *pim);
int pim_mroute_socket_disable(struct pim_instance *pim);

int pim_mroute_add_vif(struct interface *ifp, pim_addr ifaddr,
		       unsigned char flags);
int pim_mroute_del_vif(struct interface *ifp);

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
