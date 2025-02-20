// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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
#if defined(HAVE_LINUX_MROUTE_H)
#include <linux/mroute.h>
#endif

#if defined(HAVE_NETINET_IP_MROUTE_H)
#include <netinet/ip_mroute.h>
/*
 * MRT_TABLE of 155 is needed because it is not defined
 * on FreeBSD.  MRT_TABLE is for vrf's.  There is no
 * equivalent on BSD at this point in time.  Let's
 * just get it compiling
 */
#ifndef MRT_TABLE
#define MRT_TABLE 155
#endif
#endif

typedef struct vifctl pim_vifctl;
typedef struct igmpmsg kernmsg;
typedef struct sioc_sg_req pim_sioc_sg_req;

#define vc_vifi vifc_vifi
#define vc_flags vifc_flags
#define vc_threshold vifc_threshold
#define vc_rate_limit vifc_rate_limit
#define vc_lcl_addr vifc_lcl_addr
#define vc_lcl_ifindex vifc_lcl_ifindex
#define vc_rmt_addr vifc_rmt_addr

#define msg_im_msgtype im_msgtype
#define msg_im_vif im_vif
#define msg_im_src im_src
#define msg_im_dst im_dst

#ifndef IGMPMSG_WRVIFWHOLE
#define IGMPMSG_WRVIFWHOLE 4 /* For PIM processing */
#endif

#ifndef GMMSG_NOCACHE
#define GMMSG_NOCACHE IGMPMSG_NOCACHE       /* For PIM processing */
#define GMMSG_WHOLEPKT IGMPMSG_WHOLEPKT     /* For PIM processing */
#define GMMSG_WRONGVIF IGMPMSG_WRONGVIF     /* For PIM processing */
#define GMMSG_WRVIFWHOLE IGMPMSG_WRVIFWHOLE /* For PIM processing */
#endif

#ifndef PIM_IPPROTO
#define PIM_IPPROTO IPPROTO_IP
#endif
#ifndef PIM_SIOCGETSGCNT
#define PIM_SIOCGETSGCNT SIOCGETSGCNT
#endif

#else /* PIM_IPV != 4 */

#include <netinet/ip6.h>

#if defined(HAVE_LINUX_MROUTE6_H)
#include <linux/mroute6.h>
#endif
#if defined(HAVE_NETINET_IP6_MROUTE_H)
#include <sys/param.h>
#include <netinet6/ip6_mroute.h>

/*
 * See the v4 discussion above
 */
#ifndef MRT_TABLE
#define MRT_TABLE 155
#endif
#endif

#ifndef MRT_INIT
#define MRT_BASE MRT6_BASE
#define MRT_INIT MRT6_INIT
#define MRT_DONE MRT6_DONE
#define MRT_ADD_VIF MRT6_ADD_MIF
#define MRT_DEL_VIF MRT6_DEL_MIF
#define MRT_ADD_MFC MRT6_ADD_MFC
#define MRT_DEL_MFC MRT6_DEL_MFC
#define MRT_VERSION MRT6_VERSION
#define MRT_ASSERT MRT6_ASSERT
#define MRT_PIM MRT6_PIM
#define MRT_TABLE MRT6_TABLE
#endif

#ifndef PIM_IPPROTO
#define PIM_IPPROTO IPPROTO_IPV6
#endif

#ifndef PIM_SIOCGETSGCNT
#define PIM_SIOCGETSGCNT SIOCGETSGCNT_IN6
#endif

#ifndef MRT6MSG_WRMIFWHOLE
#define MRT6MSG_WRMIFWHOLE 4 /* For PIM processing */
#endif

#ifndef GMMSG_NOCACHE
#define GMMSG_NOCACHE MRT6MSG_NOCACHE       /* For PIM processing */
#define GMMSG_WHOLEPKT MRT6MSG_WHOLEPKT     /* For PIM processing */
#define GMMSG_WRONGVIF MRT6MSG_WRONGMIF     /* For PIM processing */
#define GMMSG_WRVIFWHOLE MRT6MSG_WRMIFWHOLE /* For PIM processing */
#endif

typedef struct mif6ctl pim_vifctl;
typedef struct mrt6msg kernmsg;
typedef mifi_t vifi_t;
typedef struct sioc_sg_req6 pim_sioc_sg_req;

#define vc_vifi mif6c_mifi
#define vc_flags mif6c_flags
#define vc_threshold vifc_threshold
#define vc_pifi mif6c_pifi
#define vc_rate_limit vifc_rate_limit

#define msg_im_msgtype im6_msgtype
#define msg_im_vif im6_mif
#define msg_im_src im6_src
#define msg_im_dst im6_dst

#ifndef MAXVIFS
#define MAXVIFS IF_SETSIZE
#endif

#define VIFF_REGISTER MIFF_REGISTER
#endif


/*
  Above: from <linux/mroute.h>
*/

struct channel_oil;
struct pim_instance;

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
int pim_mroute_msg(struct pim_instance *pim, const char *buf, size_t buf_size,
		   ifindex_t ifindex);
int pim_mroute_msg_nocache(int fd, struct interface *ifp, const kernmsg *msg);
int pim_mroute_msg_wholepkt(int fd, struct interface *ifp, const char *buf,
			    size_t len);
int pim_mroute_msg_wrongvif(int fd, struct interface *ifp, const kernmsg *msg);
int pim_mroute_msg_wrvifwhole(int fd, struct interface *ifp, const char *buf,
			      size_t len);
int pim_mroute_set(struct pim_instance *pim, int enable);
#endif /* PIM_MROUTE_H */
