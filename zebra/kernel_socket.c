/* Kernel communication using routing socket.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#ifndef HAVE_NETLINK

#include <net/if_types.h>
#ifdef __OpenBSD__
#include <netmpls/mpls.h>
#endif

#include "if.h"
#include "prefix.h"
#include "sockunion.h"
#include "connected.h"
#include "memory.h"
#include "zebra_memory.h"
#include "ioctl.h"
#include "log.h"
#include "table.h"
#include "rib.h"
#include "privs.h"
#include "vrf.h"
#include "lib_errors.h"

#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/kernel_socket.h"
#include "zebra/rib.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_ptm.h"

extern struct zebra_privs_t zserv_privs;

/*
 * Historically, the BSD routing socket has aligned data following a
 * struct sockaddr to sizeof(long), which was 4 bytes on some
 * platforms, and 8 bytes on others.  NetBSD 6 changed the routing
 * socket to align to sizeof(uint64_t), which is 8 bytes.  OS X
 * appears to align to sizeof(int), which is 4 bytes.
 *
 * Alignment of zero-sized sockaddrs is nonsensical, but historically
 * BSD defines RT_ROUNDUP(0) to be the alignment interval (rather than
 * 0).  We follow this practice without questioning it, but it is a
 * bug if quagga calls ROUNDUP with 0.
 */
#ifdef __APPLE__
#define ROUNDUP_TYPE	int
#else
#define ROUNDUP_TYPE	long
#endif

/*
 * Because of these varying conventions, the only sane approach is for
 * the <net/route.h> header to define some flavor of ROUNDUP macro.
 */

/* OS X (Xcode as of 2014-12) is known not to define RT_ROUNDUP */
#if defined(RT_ROUNDUP)
#define ROUNDUP(a)	RT_ROUNDUP(a)
#endif /* defined(RT_ROUNDUP) */

#if defined(SUNOS_5)
/* Solaris has struct sockaddr_in[6] definitions at 16 / 32 bytes size,
 * so the whole concept doesn't really apply. */
#define ROUNDUP(a)      (a)
#endif

/*
 * If ROUNDUP has not yet been defined in terms of platform-provided
 * defines, attempt to cope with heuristics.
 */
#if !defined(ROUNDUP)

/*
 * If you're porting to a platform that changed RT_ROUNDUP but doesn't
 * have it in its headers, this will break rather obviously and you'll
 * have to fix it here.
 */
#define ROUNDUP(a)                                                             \
	((a) > 0 ? (1 + (((a)-1) | (sizeof(ROUNDUP_TYPE) - 1)))                \
		 : sizeof(ROUNDUP_TYPE))

#endif /* defined(ROUNDUP) */


#if defined(SA_SIZE)
/* SAROUNDUP is the only thing we need, and SA_SIZE provides that */
#define SAROUNDUP(a)	SA_SIZE(a)
#else /* !SA_SIZE */
/*
 * Given a pointer (sockaddr or void *), return the number of bytes
 * taken up by the sockaddr and any padding needed for alignment.
 */
#if defined(HAVE_STRUCT_SOCKADDR_SA_LEN)
#define SAROUNDUP(X)   ROUNDUP(((struct sockaddr *)(X))->sa_len)
#else
/*
 * One would hope all fixed-size structure definitions are aligned,
 * but round them up nonetheless.
 */
#define SAROUNDUP(X)                                                           \
	(((struct sockaddr *)(X))->sa_family == AF_INET                        \
		 ? ROUNDUP(sizeof(struct sockaddr_in))                         \
		 : (((struct sockaddr *)(X))->sa_family == AF_INET6            \
			    ? ROUNDUP(sizeof(struct sockaddr_in6))             \
			    : (((struct sockaddr *)(X))->sa_family == AF_LINK  \
				       ? ROUNDUP(sizeof(struct sockaddr_dl))   \
				       : sizeof(struct sockaddr))))
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */

#endif /* !SA_SIZE */

/* Routing socket message types. */
const struct message rtm_type_str[] = {{RTM_ADD, "RTM_ADD"},
				       {RTM_DELETE, "RTM_DELETE"},
				       {RTM_CHANGE, "RTM_CHANGE"},
				       {RTM_GET, "RTM_GET"},
				       {RTM_LOSING, "RTM_LOSING"},
				       {RTM_REDIRECT, "RTM_REDIRECT"},
				       {RTM_MISS, "RTM_MISS"},
#ifdef RTM_LOCK
				       {RTM_LOCK, "RTM_LOCK"},
#endif /* RTM_LOCK */
#ifdef OLDADD
				       {RTM_OLDADD, "RTM_OLDADD"},
#endif /* RTM_OLDADD */
#ifdef RTM_OLDDEL
				       {RTM_OLDDEL, "RTM_OLDDEL"},
#endif /* RTM_OLDDEL */
#ifdef RTM_RESOLVE
				       {RTM_RESOLVE, "RTM_RESOLVE"},
#endif	/* RTM_RESOLVE */
				       {RTM_NEWADDR, "RTM_NEWADDR"},
				       {RTM_DELADDR, "RTM_DELADDR"},
				       {RTM_IFINFO, "RTM_IFINFO"},
#ifdef RTM_OIFINFO
				       {RTM_OIFINFO, "RTM_OIFINFO"},
#endif /* RTM_OIFINFO */
#ifdef RTM_NEWMADDR
				       {RTM_NEWMADDR, "RTM_NEWMADDR"},
#endif /* RTM_NEWMADDR */
#ifdef RTM_DELMADDR
				       {RTM_DELMADDR, "RTM_DELMADDR"},
#endif /* RTM_DELMADDR */
#ifdef RTM_IFANNOUNCE
				       {RTM_IFANNOUNCE, "RTM_IFANNOUNCE"},
#endif /* RTM_IFANNOUNCE */
				       {0}};

static const struct message rtm_flag_str[] = {{RTF_UP, "UP"},
					      {RTF_GATEWAY, "GATEWAY"},
					      {RTF_HOST, "HOST"},
					      {RTF_REJECT, "REJECT"},
					      {RTF_DYNAMIC, "DYNAMIC"},
					      {RTF_MODIFIED, "MODIFIED"},
					      {RTF_DONE, "DONE"},
#ifdef RTF_MASK
					      {RTF_MASK, "MASK"},
#endif /* RTF_MASK */
#ifdef RTF_CLONING
					      {RTF_CLONING, "CLONING"},
#endif /* RTF_CLONING */
#ifdef RTF_XRESOLVE
					      {RTF_XRESOLVE, "XRESOLVE"},
#endif /* RTF_XRESOLVE */
#ifdef RTF_LLINFO
					      {RTF_LLINFO, "LLINFO"},
#endif /* RTF_LLINFO */
					      {RTF_STATIC, "STATIC"},
					      {RTF_BLACKHOLE, "BLACKHOLE"},
#ifdef RTF_PRIVATE
					      {RTF_PRIVATE, "PRIVATE"},
#endif /* RTF_PRIVATE */
					      {RTF_PROTO1, "PROTO1"},
					      {RTF_PROTO2, "PROTO2"},
#ifdef RTF_PRCLONING
					      {RTF_PRCLONING, "PRCLONING"},
#endif /* RTF_PRCLONING */
#ifdef RTF_WASCLONED
					      {RTF_WASCLONED, "WASCLONED"},
#endif /* RTF_WASCLONED */
#ifdef RTF_PROTO3
					      {RTF_PROTO3, "PROTO3"},
#endif /* RTF_PROTO3 */
#ifdef RTF_PINNED
					      {RTF_PINNED, "PINNED"},
#endif /* RTF_PINNED */
#ifdef RTF_LOCAL
					      {RTF_LOCAL, "LOCAL"},
#endif /* RTF_LOCAL */
#ifdef RTF_BROADCAST
					      {RTF_BROADCAST, "BROADCAST"},
#endif /* RTF_BROADCAST */
#ifdef RTF_MULTICAST
					      {RTF_MULTICAST, "MULTICAST"},
#endif /* RTF_MULTICAST */
#ifdef RTF_MULTIRT
					      {RTF_MULTIRT, "MULTIRT"},
#endif /* RTF_MULTIRT */
#ifdef RTF_SETSRC
					      {RTF_SETSRC, "SETSRC"},
#endif /* RTF_SETSRC */
					      {0}};

/* Kernel routing update socket. */
int routing_sock = -1;

/* Kernel dataplane routing update socket, used in the dataplane pthread
 * context.
 */
int dplane_routing_sock = -1;

/* Yes I'm checking ugly routing socket behavior. */
/* #define DEBUG */

size_t _rta_get(caddr_t sap, void *destp, size_t destlen, bool checkaf);
size_t rta_get(caddr_t sap, void *dest, size_t destlen);
size_t rta_getattr(caddr_t sap, void *destp, size_t destlen);
size_t rta_getsdlname(caddr_t sap, void *dest, short *destlen);
const char *rtatostr(unsigned int flags, char *buf, size_t buflen);

/* Supported address family check. */
static inline int af_check(int family)
{
	if (family == AF_INET)
		return 1;
	if (family == AF_INET6)
		return 1;
	return 0;
}

size_t _rta_get(caddr_t sap, void *destp, size_t destlen, bool checkaf)
{
	struct sockaddr *sa = (struct sockaddr *)sap;
	struct sockaddr_dl *sdl;
	uint8_t *dest = destp;
	size_t tlen, copylen;

#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	copylen = sa->sa_len;
	tlen = (copylen == 0) ? sizeof(ROUNDUP_TYPE) : ROUNDUP(copylen);
#else  /* !HAVE_STRUCT_SOCKADDR_SA_LEN */
	copylen = tlen = SAROUNDUP(sap);
#endif /* !HAVE_STRUCT_SOCKADDR_SA_LEN */

	if (copylen > 0 && dest != NULL) {
		if (checkaf && af_check(sa->sa_family) == 0)
			return tlen;
		/*
		 * Handle sockaddr_dl corner case:
		 * RTA_NETMASK might be AF_LINK, but it doesn't anything
		 * relevant (e.g. zeroed out fields). Check for this
		 * case and avoid warning log message.
		 */
		if (sa->sa_family == AF_LINK) {
			sdl = (struct sockaddr_dl *)sa;
			if (sdl->sdl_index == 0 || sdl->sdl_nlen == 0)
				copylen = destlen;
		}

		if (copylen > destlen) {
			zlog_warn(
				"%s: destination buffer too small (%zu vs %zu)",
				__func__, copylen, destlen);
			memcpy(dest, sap, destlen);
		} else
			memcpy(dest, sap, copylen);
	}

	return tlen;
}

size_t rta_get(caddr_t sap, void *destp, size_t destlen)
{
	return _rta_get(sap, destp, destlen, true);
}

size_t rta_getattr(caddr_t sap, void *destp, size_t destlen)
{
	return _rta_get(sap, destp, destlen, false);
}

size_t rta_getsdlname(caddr_t sap, void *destp, short *destlen)
{
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)sap;
	uint8_t *dest = destp;
	size_t tlen, copylen;

	copylen = sdl->sdl_nlen;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	struct sockaddr *sa = (struct sockaddr *)sap;

	tlen = (sa->sa_len == 0) ? sizeof(ROUNDUP_TYPE) : ROUNDUP(sa->sa_len);
#else  /* !HAVE_STRUCT_SOCKADDR_SA_LEN */
	tlen = SAROUNDUP(sap);
#endif /* !HAVE_STRUCT_SOCKADDR_SA_LEN */

	if (copylen > 0 && dest != NULL && sdl->sdl_family == AF_LINK) {
		if (copylen > IFNAMSIZ) {
			zlog_warn(
				"%s: destination buffer too small (%zu vs %d)",
				__func__, copylen, IFNAMSIZ);
			memcpy(dest, sdl->sdl_data, IFNAMSIZ);
			dest[IFNAMSIZ] = 0;
			*destlen = IFNAMSIZ;
		} else {
			memcpy(dest, sdl->sdl_data, copylen);
			dest[copylen] = 0;
			*destlen = copylen;
		}
	} else
		*destlen = 0;

	return tlen;
}

const char *rtatostr(unsigned int flags, char *buf, size_t buflen)
{
	const char *flagstr, *bufstart;
	int bit, wlen;
	char ustr[32];

	/* Hold the pointer to the buffer beginning. */
	bufstart = buf;

	for (bit = 1; bit; bit <<= 1) {
		if ((flags & bit) == 0)
			continue;

		switch (bit) {
		case RTA_DST:
			flagstr = "DST";
			break;
		case RTA_GATEWAY:
			flagstr = "GATEWAY";
			break;
		case RTA_NETMASK:
			flagstr = "NETMASK";
			break;
#ifdef RTA_GENMASK
		case RTA_GENMASK:
			flagstr = "GENMASK";
			break;
#endif /* RTA_GENMASK */
		case RTA_IFP:
			flagstr = "IFP";
			break;
		case RTA_IFA:
			flagstr = "IFA";
			break;
#ifdef RTA_AUTHOR
		case RTA_AUTHOR:
			flagstr = "AUTHOR";
			break;
#endif /* RTA_AUTHOR */
		case RTA_BRD:
			flagstr = "BRD";
			break;
#ifdef RTA_SRC
		case RTA_SRC:
			flagstr = "SRC";
			break;
#endif /* RTA_SRC */
#ifdef RTA_SRCMASK
		case RTA_SRCMASK:
			flagstr = "SRCMASK";
			break;
#endif /* RTA_SRCMASK */
#ifdef RTA_LABEL
		case RTA_LABEL:
			flagstr = "LABEL";
			break;
#endif /* RTA_LABEL */

		default:
			snprintf(ustr, sizeof(ustr), "0x%x", bit);
			flagstr = ustr;
			break;
		}

		wlen = snprintf(buf, buflen, "%s,", flagstr);
		buf += wlen;
		buflen -= wlen;
	}

	/* Check for empty buffer. */
	if (bufstart != buf)
		buf--;

	/* Remove the last comma. */
	*buf = 0;

	return bufstart;
}

/* Dump routing table flag for debug purpose. */
static void rtm_flag_dump(int flag)
{
	const struct message *mes;
	static char buf[BUFSIZ];

	buf[0] = '\0';
	for (mes = rtm_flag_str; mes->key != 0; mes++) {
		if (mes->key & flag) {
			strlcat(buf, mes->str, BUFSIZ);
			strlcat(buf, " ", BUFSIZ);
		}
	}
	zlog_debug("Kernel: %s", buf);
}

#ifdef RTM_IFANNOUNCE
/* Interface adding function */
static int ifan_read(struct if_announcemsghdr *ifan)
{
	struct interface *ifp;

	ifp = if_lookup_by_index(ifan->ifan_index, VRF_DEFAULT);

	if (ifp)
		assert((ifp->ifindex == ifan->ifan_index)
		       || (ifp->ifindex == IFINDEX_INTERNAL));

	if ((ifp == NULL) || ((ifp->ifindex == IFINDEX_INTERNAL)
			      && (ifan->ifan_what == IFAN_ARRIVAL))) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s: creating interface for ifindex %d, name %s",
				__func__, ifan->ifan_index, ifan->ifan_name);

		/* Create Interface */
		ifp = if_get_by_name(ifan->ifan_name, VRF_DEFAULT);
		if_set_index(ifp, ifan->ifan_index);

		if_get_metric(ifp);
		if_add_update(ifp);
	} else if (ifp != NULL && ifan->ifan_what == IFAN_DEPARTURE)
		if_delete_update(ifp);

	if_get_flags(ifp);
	if_get_mtu(ifp);
	if_get_metric(ifp);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: interface %s index %d", __func__,
			   ifan->ifan_name, ifan->ifan_index);

	return 0;
}
#endif /* RTM_IFANNOUNCE */

#ifdef HAVE_BSD_IFI_LINK_STATE
/* BSD link detect translation */
static void bsd_linkdetect_translate(struct if_msghdr *ifm)
{
	if ((ifm->ifm_data.ifi_link_state >= LINK_STATE_UP)
	    || (ifm->ifm_data.ifi_link_state == LINK_STATE_UNKNOWN))
		SET_FLAG(ifm->ifm_flags, IFF_RUNNING);
	else
		UNSET_FLAG(ifm->ifm_flags, IFF_RUNNING);
}
#endif /* HAVE_BSD_IFI_LINK_STATE */

static enum zebra_link_type sdl_to_zebra_link_type(unsigned int sdlt)
{
	switch (sdlt) {
	case IFT_ETHER:
		return ZEBRA_LLT_ETHER;
	case IFT_X25:
		return ZEBRA_LLT_X25;
	case IFT_FDDI:
		return ZEBRA_LLT_FDDI;
	case IFT_PPP:
		return ZEBRA_LLT_PPP;
	case IFT_LOOP:
		return ZEBRA_LLT_LOOPBACK;
	case IFT_SLIP:
		return ZEBRA_LLT_SLIP;
	case IFT_ARCNET:
		return ZEBRA_LLT_ARCNET;
	case IFT_ATM:
		return ZEBRA_LLT_ATM;
	case IFT_LOCALTALK:
		return ZEBRA_LLT_LOCALTLK;
	case IFT_HIPPI:
		return ZEBRA_LLT_HIPPI;
#ifdef IFT_IEEE1394
	case IFT_IEEE1394:
		return ZEBRA_LLT_IEEE1394;
#endif

	default:
		return ZEBRA_LLT_UNKNOWN;
	}
}

/*
 * Handle struct if_msghdr obtained from reading routing socket or
 * sysctl (from interface_list).  There may or may not be sockaddrs
 * present after the header.
 */
int ifm_read(struct if_msghdr *ifm)
{
	struct interface *ifp = NULL;
	struct sockaddr_dl *sdl = NULL;
	char ifname[IFNAMSIZ];
	short ifnlen = 0;
	int maskbit;
	caddr_t cp;
	char fbuf[64];

	/* terminate ifname at head (for strnlen) and tail (for safety) */
	ifname[IFNAMSIZ - 1] = '\0';

	/* paranoia: sanity check structure */
	if (ifm->ifm_msglen < sizeof(struct if_msghdr)) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "ifm_read: ifm->ifm_msglen %d too short\n",
			 ifm->ifm_msglen);
		return -1;
	}

	/*
	 * Check for a sockaddr_dl following the message.  First, point to
	 * where a socakddr might be if one follows the message.
	 */
	cp = (void *)(ifm + 1);

#ifdef SUNOS_5
	/*
	 * XXX This behavior should be narrowed to only the kernel versions
	 * for which the structures returned do not match the headers.
	 *
	 * if_msghdr_t on 64 bit kernels in Solaris 9 and earlier versions
	 * is 12 bytes larger than the 32 bit version.
	 */
	if (((struct sockaddr *)cp)->sa_family == AF_UNSPEC)
		cp = cp + 12;
#endif

	/* Look up for RTA_IFP and skip others. */
	for (maskbit = 1; maskbit; maskbit <<= 1) {
		if ((maskbit & ifm->ifm_addrs) == 0)
			continue;
		if (maskbit != RTA_IFP) {
			cp += rta_get(cp, NULL, 0);
			continue;
		}

		/* Save the pointer to the structure. */
		sdl = (struct sockaddr_dl *)cp;
		cp += rta_getsdlname(cp, ifname, &ifnlen);
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: sdl ifname %s addrs {%s}", __func__,
			   (ifnlen ? ifname : "(nil)"),
			   rtatostr(ifm->ifm_addrs, fbuf, sizeof(fbuf)));

	/*
	 * Look up on ifindex first, because ifindices are the primary handle
	 * for
	 * interfaces across the user/kernel boundary, for most systems.  (Some
	 * messages, such as up/down status changes on NetBSD, do not include a
	 * sockaddr_dl).
	 */
	if ((ifp = if_lookup_by_index(ifm->ifm_index, VRF_DEFAULT)) != NULL) {
		/* we have an ifp, verify that the name matches as some systems,
		 * eg Solaris, have a 1:many association of ifindex:ifname
		 * if they dont match, we dont have the correct ifp and should
		 * set it back to NULL to let next check do lookup by name
		 */
		if (ifnlen && (strncmp(ifp->name, ifname, IFNAMSIZ) != 0)) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"%s: ifp name %s doesn't match sdl name %s",
					__func__, ifp->name, ifname);
			ifp = NULL;
		}
	}

	/*
	 * If we dont have an ifp, try looking up by name.  Particularly as some
	 * systems (Solaris) have a 1:many mapping of ifindex:ifname - the
	 * ifname
	 * is therefore our unique handle to that interface.
	 *
	 * Interfaces specified in the configuration file for which the ifindex
	 * has not been determined will have ifindex == IFINDEX_INTERNAL, and
	 * such
	 * interfaces are found by this search, and then their ifindex values
	 * can
	 * be filled in.
	 */
	if ((ifp == NULL) && ifnlen)
		ifp = if_lookup_by_name(ifname, VRF_DEFAULT);

	/*
	 * If ifp still does not exist or has an invalid index
	 * (IFINDEX_INTERNAL),
	 * create or fill in an interface.
	 */
	if ((ifp == NULL) || (ifp->ifindex == IFINDEX_INTERNAL)) {
		/*
		 * To create or fill in an interface, a sockaddr_dl (via
		 * RTA_IFP) is required.
		 */
		if (!ifnlen) {
			zlog_debug("Interface index %d (new) missing ifname",
				   ifm->ifm_index);
			return -1;
		}

#ifndef RTM_IFANNOUNCE
		/* Down->Down interface should be ignored here.
		 * See further comment below.
		 */
		if (!CHECK_FLAG(ifm->ifm_flags, IFF_UP))
			return 0;
#endif /* !RTM_IFANNOUNCE */

		if (ifp == NULL) {
			/* Interface that zebra was not previously aware of, so
			 * create. */
			ifp = if_create_name(ifname, VRF_DEFAULT);
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: creating ifp for ifindex %d",
					   __func__, ifm->ifm_index);
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s: updated/created ifp, ifname %s, ifindex %d",
				__func__, ifp->name, ifp->ifindex);
		/*
		 * Fill in newly created interface structure, or larval
		 * structure with ifindex IFINDEX_INTERNAL.
		 */
		if_set_index(ifp, ifm->ifm_index);

#ifdef HAVE_BSD_IFI_LINK_STATE /* translate BSD kernel msg for link-state */
		bsd_linkdetect_translate(ifm);
#endif /* HAVE_BSD_IFI_LINK_STATE */

		if_flags_update(ifp, ifm->ifm_flags);
#if defined(__bsdi__)
		if_kvm_get_mtu(ifp);
#else
		if_get_mtu(ifp);
#endif /* __bsdi__ */
		if_get_metric(ifp);

		/*
		 * XXX sockaddr_dl contents can be larger than the structure
		 * definition.  There are 2 big families here:
		 *  - BSD has sdl_len + sdl_data[16] + overruns sdl_data
		 *    we MUST use sdl_len here or we'll truncate data.
		 *  - Solaris has no sdl_len, but sdl_data[244]
		 *    presumably, it's not going to run past that, so sizeof()
		 *    is fine here.
		 * a nonzero ifnlen from rta_getsdlname() means sdl is valid
		 */
		ifp->ll_type = ZEBRA_LLT_UNKNOWN;
		ifp->hw_addr_len = 0;
		if (ifnlen) {
#ifdef HAVE_STRUCT_SOCKADDR_DL_SDL_LEN
			memcpy(&((struct zebra_if *)ifp->info)->sdl, sdl,
			       sdl->sdl_len);
#else
			memcpy(&((struct zebra_if *)ifp->info)->sdl, sdl,
			       sizeof(struct sockaddr_dl));
#endif /* HAVE_STRUCT_SOCKADDR_DL_SDL_LEN */

			ifp->ll_type = sdl_to_zebra_link_type(sdl->sdl_type);
			if (sdl->sdl_alen <= sizeof(ifp->hw_addr)) {
				memcpy(ifp->hw_addr, LLADDR(sdl),
				       sdl->sdl_alen);
				ifp->hw_addr_len = sdl->sdl_alen;
			}
		}

		if_add_update(ifp);
	} else
	/*
	 * Interface structure exists.  Adjust stored flags from
	 * notification.  If interface has up->down or down->up
	 * transition, call state change routines (to adjust routes,
	 * notify routing daemons, etc.).  (Other flag changes are stored
	 * but apparently do not trigger action.)
	 */
	{
		if (ifp->ifindex != ifm->ifm_index) {
			zlog_debug(
				"%s: index mismatch, ifname %s, ifp index %d, "
				"ifm index %d",
				__func__, ifp->name, ifp->ifindex,
				ifm->ifm_index);
			return -1;
		}

#ifdef HAVE_BSD_IFI_LINK_STATE /* translate BSD kernel msg for link-state */
		bsd_linkdetect_translate(ifm);
#endif /* HAVE_BSD_IFI_LINK_STATE */

		/* update flags and handle operative->inoperative transition, if
		 * any */
		if_flags_update(ifp, ifm->ifm_flags);

#ifndef RTM_IFANNOUNCE
		if (!if_is_up(ifp)) {
			/* No RTM_IFANNOUNCE on this platform, so we can never
			 * distinguish between ~IFF_UP and delete. We must
			 * presume
			 * it has been deleted.
			 * Eg, Solaris will not notify us of unplumb.
			 *
			 * XXX: Fixme - this should be runtime detected
			 * So that a binary compiled on a system with IFANNOUNCE
			 * will still behave correctly if run on a platform
			 * without
			 */
			if_delete_update(ifp);
		}
#endif /* RTM_IFANNOUNCE */
		if (if_is_up(ifp)) {
#if defined(__bsdi__)
			if_kvm_get_mtu(ifp);
#else
			if_get_mtu(ifp);
#endif /* __bsdi__ */
			if_get_metric(ifp);
		}
	}

#ifdef HAVE_NET_RT_IFLIST
	ifp->stats = ifm->ifm_data;
#endif /* HAVE_NET_RT_IFLIST */
	ifp->speed = ifm->ifm_data.ifi_baudrate / 1000000;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: interface %s index %d", __func__, ifp->name,
			   ifp->ifindex);

	return 0;
}

/* Address read from struct ifa_msghdr. */
static void ifam_read_mesg(struct ifa_msghdr *ifm, union sockunion *addr,
			   union sockunion *mask, union sockunion *brd,
			   char *ifname, short *ifnlen)
{
	caddr_t pnt, end;
	union sockunion dst;
	union sockunion gateway;
	int maskbit;
	char fbuf[64];

	pnt = (caddr_t)(ifm + 1);
	end = ((caddr_t)ifm) + ifm->ifam_msglen;

	/* Be sure structure is cleared */
	memset(mask, 0, sizeof(union sockunion));
	memset(addr, 0, sizeof(union sockunion));
	memset(brd, 0, sizeof(union sockunion));
	memset(&dst, 0, sizeof(union sockunion));
	memset(&gateway, 0, sizeof(union sockunion));

	/* We fetch each socket variable into sockunion. */
	for (maskbit = 1; maskbit; maskbit <<= 1) {
		if ((maskbit & ifm->ifam_addrs) == 0)
			continue;

		switch (maskbit) {
		case RTA_DST:
			pnt += rta_get(pnt, &dst, sizeof(dst));
			break;
		case RTA_GATEWAY:
			pnt += rta_get(pnt, &gateway, sizeof(gateway));
			break;
		case RTA_NETMASK:
			pnt += rta_getattr(pnt, mask, sizeof(*mask));
			break;
		case RTA_IFP:
			pnt += rta_getsdlname(pnt, ifname, ifnlen);
			break;
		case RTA_IFA:
			pnt += rta_get(pnt, addr, sizeof(*addr));
			break;
		case RTA_BRD:
			pnt += rta_get(pnt, brd, sizeof(*brd));
			break;

		default:
			pnt += rta_get(pnt, NULL, 0);
			break;
		}

		if (pnt > end) {
			zlog_warn("%s: overflow detected (pnt:%p end:%p)",
				  __func__, pnt, end);
			break;
		}
	}

	if (IS_ZEBRA_DEBUG_KERNEL) {
		switch (sockunion_family(addr)) {
		case AF_INET:
		case AF_INET6: {
			char buf[4][INET6_ADDRSTRLEN];
			int masklen =
				(sockunion_family(addr) == AF_INET)
					? ip_masklen(mask->sin.sin_addr)
					: ip6_masklen(mask->sin6.sin6_addr);
			zlog_debug(
				"%s: ifindex %d, ifname %s, ifam_addrs {%s}, "
				"ifam_flags 0x%x, addr %s/%d broad %s dst %s "
				"gateway %s",
				__func__, ifm->ifam_index,
				(ifnlen ? ifname : "(nil)"),
				rtatostr(ifm->ifam_addrs, fbuf, sizeof(fbuf)),
				ifm->ifam_flags,
				sockunion2str(addr, buf[0], sizeof(buf[0])),
				masklen,
				sockunion2str(brd, buf[1], sizeof(buf[1])),
				sockunion2str(&dst, buf[2], sizeof(buf[2])),
				sockunion2str(&gateway, buf[2],
					      sizeof(buf[2])));
		} break;
		default:
			zlog_debug("%s: ifindex %d, ifname %s, ifam_addrs {%s}",
				   __func__, ifm->ifam_index,
				   (ifnlen ? ifname : "(nil)"),
				   rtatostr(ifm->ifam_addrs, fbuf,
					    sizeof(fbuf)));
			break;
		}
	}

	/* Assert read up end point matches to end point */
	pnt = (caddr_t)ROUNDUP((size_t)pnt);
	if (pnt != (caddr_t)ROUNDUP((size_t)end))
		zlog_debug("ifam_read() doesn't read all socket data");
}

/* Interface's address information get. */
int ifam_read(struct ifa_msghdr *ifam)
{
	struct interface *ifp = NULL;
	union sockunion addr, mask, brd;
	char ifname[INTERFACE_NAMSIZ];
	short ifnlen = 0;
	char isalias = 0;
	int flags = 0;

	ifname[0] = ifname[INTERFACE_NAMSIZ - 1] = '\0';

	/* Allocate and read address information. */
	ifam_read_mesg(ifam, &addr, &mask, &brd, ifname, &ifnlen);

	if ((ifp = if_lookup_by_index(ifam->ifam_index, VRF_DEFAULT)) == NULL) {
		flog_warn(EC_ZEBRA_UNKNOWN_INTERFACE,
			  "%s: no interface for ifname %s, index %d", __func__,
			  ifname, ifam->ifam_index);
		return -1;
	}

	if (ifnlen && strncmp(ifp->name, ifname, INTERFACE_NAMSIZ))
		isalias = 1;

	/* N.B. The info in ifa_msghdr does not tell us whether the RTA_BRD
	   field contains a broadcast address or a peer address, so we are
	   forced to
	   rely upon the interface type. */
	if (if_is_pointopoint(ifp))
		SET_FLAG(flags, ZEBRA_IFA_PEER);

#if 0
  /* it might seem cute to grab the interface metric here, however
   * we're processing an address update message, and so some systems
   * (e.g. FBSD) dont bother to fill in ifam_metric. Disabled, but left
   * in deliberately, as comment.
   */
  ifp->metric = ifam->ifam_metric;
#endif

	/* Add connected address. */
	switch (sockunion_family(&addr)) {
	case AF_INET:
		if (ifam->ifam_type == RTM_NEWADDR)
			connected_add_ipv4(ifp, flags, &addr.sin.sin_addr,
					   ip_masklen(mask.sin.sin_addr),
					   &brd.sin.sin_addr,
					   (isalias ? ifname : NULL),
					   METRIC_MAX);
		else
			connected_delete_ipv4(ifp, flags, &addr.sin.sin_addr,
					      ip_masklen(mask.sin.sin_addr),
					      &brd.sin.sin_addr);
		break;
	case AF_INET6:
		/* Unset interface index from link-local address when IPv6 stack
		   is KAME. */
		if (IN6_IS_ADDR_LINKLOCAL(&addr.sin6.sin6_addr)) {
			SET_IN6_LINKLOCAL_IFINDEX(addr.sin6.sin6_addr, 0);
		}

		if (ifam->ifam_type == RTM_NEWADDR)
			connected_add_ipv6(ifp, flags, &addr.sin6.sin6_addr,
					   NULL,
					   ip6_masklen(mask.sin6.sin6_addr),
					   (isalias ? ifname : NULL),
					   METRIC_MAX);
		else
			connected_delete_ipv6(ifp, &addr.sin6.sin6_addr, NULL,
					      ip6_masklen(mask.sin6.sin6_addr));
		break;
	default:
		/* Unsupported family silently ignore... */
		break;
	}

	/* Check interface flag for implicit up of the interface. */
	if_refresh(ifp);

#ifdef SUNOS_5
	/* In addition to lacking IFANNOUNCE, on SUNOS IFF_UP is strange.
	 * See comments for SUNOS_5 in interface.c::if_flags_mangle.
	 *
	 * Here we take care of case where the real IFF_UP was previously
	 * unset (as kept in struct zebra_if.primary_state) and the mangled
	 * IFF_UP (ie IFF_UP set || listcount(connected) has now transitioned
	 * to unset due to the lost non-primary address having DELADDR'd.
	 *
	 * we must delete the interface, because in between here and next
	 * event for this interface-name the administrator could unplumb
	 * and replumb the interface.
	 */
	if (!if_is_up(ifp))
		if_delete_update(ifp);
#endif /* SUNOS_5 */

	return 0;
}

/* Interface function for reading kernel routing table information. */
static int rtm_read_mesg(struct rt_msghdr *rtm, union sockunion *dest,
			 union sockunion *mask, union sockunion *gate,
			 char *ifname, short *ifnlen)
{
	caddr_t pnt, end;
	int maskbit;

	/* Pnt points out socket data start point. */
	pnt = (caddr_t)(rtm + 1);
	end = ((caddr_t)rtm) + rtm->rtm_msglen;

	/* rt_msghdr version check. */
	if (rtm->rtm_version != RTM_VERSION)
		flog_warn(EC_ZEBRA_RTM_VERSION_MISMATCH,
			  "Routing message version different %d should be %d."
			  "This may cause problem\n",
			  rtm->rtm_version, RTM_VERSION);

	/* Be sure structure is cleared */
	memset(dest, 0, sizeof(union sockunion));
	memset(gate, 0, sizeof(union sockunion));
	memset(mask, 0, sizeof(union sockunion));

	/* We fetch each socket variable into sockunion. */
	/* We fetch each socket variable into sockunion. */
	for (maskbit = 1; maskbit; maskbit <<= 1) {
		if ((maskbit & rtm->rtm_addrs) == 0)
			continue;

		switch (maskbit) {
		case RTA_DST:
			pnt += rta_get(pnt, dest, sizeof(*dest));
			break;
		case RTA_GATEWAY:
			pnt += rta_get(pnt, gate, sizeof(*gate));
			break;
		case RTA_NETMASK:
			pnt += rta_getattr(pnt, mask, sizeof(*mask));
			break;
		case RTA_IFP:
			pnt += rta_getsdlname(pnt, ifname, ifnlen);
			break;

		default:
			pnt += rta_get(pnt, NULL, 0);
			break;
		}

		if (pnt > end) {
			zlog_warn("%s: overflow detected (pnt:%p end:%p)",
				  __func__, pnt, end);
			break;
		}
	}

	/* If there is netmask information set it's family same as
	   destination family*/
	if (rtm->rtm_addrs & RTA_NETMASK)
		mask->sa.sa_family = dest->sa.sa_family;

	/* Assert read up to the end of pointer. */
	if (pnt != end)
		zlog_debug("rtm_read() doesn't read all socket data.");

	return rtm->rtm_flags;
}

void rtm_read(struct rt_msghdr *rtm)
{
	int flags;
	uint8_t zebra_flags;
	union sockunion dest, mask, gate;
	char ifname[INTERFACE_NAMSIZ + 1];
	short ifnlen = 0;
	struct nexthop nh;
	struct prefix p;
	ifindex_t ifindex = 0;
	afi_t afi;
	char fbuf[64];

	zebra_flags = 0;

	/* Read destination and netmask and gateway from rtm message
	   structure. */
	flags = rtm_read_mesg(rtm, &dest, &mask, &gate, ifname, &ifnlen);
	if (!(flags & RTF_DONE))
		return;
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: got rtm of type %d (%s) addrs {%s}", __func__,
			   rtm->rtm_type,
			   lookup_msg(rtm_type_str, rtm->rtm_type, NULL),
			   rtatostr(rtm->rtm_addrs, fbuf, sizeof(fbuf)));

#ifdef RTF_CLONED /*bsdi, netbsd 1.6*/
	if (flags & RTF_CLONED)
		return;
#endif
#ifdef RTF_WASCLONED /*freebsd*/
	if (flags & RTF_WASCLONED)
		return;
#endif

	if ((rtm->rtm_type == RTM_ADD || rtm->rtm_type == RTM_CHANGE)
	    && !(flags & RTF_UP))
		return;

	/* This is connected route. */
	if (!(flags & RTF_GATEWAY))
		return;

	if (flags & RTF_PROTO1)
		SET_FLAG(zebra_flags, ZEBRA_FLAG_SELFROUTE);

	memset(&nh, 0, sizeof(nh));

	nh.vrf_id = VRF_DEFAULT;
	/* This is a reject or blackhole route */
	if (flags & RTF_REJECT) {
		nh.type = NEXTHOP_TYPE_BLACKHOLE;
		nh.bh_type = BLACKHOLE_REJECT;
	} else if (flags & RTF_BLACKHOLE) {
		nh.type = NEXTHOP_TYPE_BLACKHOLE;
		nh.bh_type = BLACKHOLE_NULL;
	}

	/*
	 * Ignore our own messages.
	 */
	if (rtm->rtm_type != RTM_GET && rtm->rtm_pid == pid)
		return;

	if (dest.sa.sa_family == AF_INET) {
		afi = AFI_IP;
		p.family = AF_INET;
		p.u.prefix4 = dest.sin.sin_addr;
		if (flags & RTF_HOST)
			p.prefixlen = IPV4_MAX_PREFIXLEN;
		else
			p.prefixlen = ip_masklen(mask.sin.sin_addr);

		if (!nh.type) {
			nh.type = NEXTHOP_TYPE_IPV4;
			nh.gate.ipv4 = gate.sin.sin_addr;
		}
	} else if (dest.sa.sa_family == AF_INET6) {
		afi = AFI_IP6;
		p.family = AF_INET6;
		p.u.prefix6 = dest.sin6.sin6_addr;
		if (flags & RTF_HOST)
			p.prefixlen = IPV6_MAX_PREFIXLEN;
		else
			p.prefixlen = ip6_masklen(mask.sin6.sin6_addr);

#ifdef KAME
		if (IN6_IS_ADDR_LINKLOCAL(&gate.sin6.sin6_addr)) {
			ifindex = IN6_LINKLOCAL_IFINDEX(gate.sin6.sin6_addr);
			SET_IN6_LINKLOCAL_IFINDEX(gate.sin6.sin6_addr, 0);
		}
#endif /* KAME */

		if (!nh.type) {
			nh.type = ifindex ? NEXTHOP_TYPE_IPV6_IFINDEX
					  : NEXTHOP_TYPE_IPV6;
			nh.gate.ipv6 = gate.sin6.sin6_addr;
			nh.ifindex = ifindex;
		}
	} else
		return;

	/*
	 * CHANGE: delete the old prefix, we have no further information
	 * to specify the route really
	 */
	if (rtm->rtm_type == RTM_CHANGE)
		rib_delete(afi, SAFI_UNICAST, VRF_DEFAULT, ZEBRA_ROUTE_KERNEL,
			   0, zebra_flags, &p, NULL, NULL, 0, RT_TABLE_MAIN, 0,
			   0, true);
	if (rtm->rtm_type == RTM_GET || rtm->rtm_type == RTM_ADD
	    || rtm->rtm_type == RTM_CHANGE)
		rib_add(afi, SAFI_UNICAST, VRF_DEFAULT, ZEBRA_ROUTE_KERNEL, 0,
			zebra_flags, &p, NULL, &nh, 0, RT_TABLE_MAIN,
			0, 0, 0, 0);
	else
		rib_delete(afi, SAFI_UNICAST, VRF_DEFAULT, ZEBRA_ROUTE_KERNEL,
			   0, zebra_flags, &p, NULL, &nh, 0, RT_TABLE_MAIN, 0,
			   0, true);
}

/* Interface function for the kernel routing table updates.  Support
 * for RTM_CHANGE will be needed.
 * Exported only for rt_socket.c
 */
int rtm_write(int message, union sockunion *dest, union sockunion *mask,
	      union sockunion *gate, union sockunion *mpls, unsigned int index,
	      enum blackhole_type bh_type, int metric)
{
	int ret;
	caddr_t pnt;
	struct interface *ifp;

	/* Sequencial number of routing message. */
	static int msg_seq = 0;

	/* Struct of rt_msghdr and buffer for storing socket's data. */
	struct {
		struct rt_msghdr rtm;
		char buf[512];
	} msg;

	if (dplane_routing_sock < 0)
		return ZEBRA_ERR_EPERM;

	/* Clear and set rt_msghdr values */
	memset(&msg, 0, sizeof(struct rt_msghdr));
	msg.rtm.rtm_version = RTM_VERSION;
	msg.rtm.rtm_type = message;
	msg.rtm.rtm_seq = msg_seq++;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_addrs |= RTA_GATEWAY;
	msg.rtm.rtm_flags = RTF_UP;
#ifdef __OpenBSD__
	msg.rtm.rtm_flags |= RTF_MPATH;
	msg.rtm.rtm_fmask = RTF_MPLS;
#endif
	msg.rtm.rtm_index = index;

	if (metric != 0) {
		msg.rtm.rtm_rmx.rmx_hopcount = metric;
		msg.rtm.rtm_inits |= RTV_HOPCOUNT;
	}

	ifp = if_lookup_by_index(index, VRF_DEFAULT);

	if (gate && (message == RTM_ADD || message == RTM_CHANGE))
		msg.rtm.rtm_flags |= RTF_GATEWAY;

/* When RTF_CLONING is unavailable on BSD, should we set some
 * other flag instead?
 */
#ifdef RTF_CLONING
	if (!gate && (message == RTM_ADD || message == RTM_CHANGE) && ifp
	    && (ifp->flags & IFF_POINTOPOINT) == 0)
		msg.rtm.rtm_flags |= RTF_CLONING;
#endif /* RTF_CLONING */

	/* If no protocol specific gateway is specified, use link
	   address for gateway. */
	if (!gate) {
		if (!ifp) {
			char dest_buf[INET_ADDRSTRLEN] = "NULL",
			     mask_buf[INET_ADDRSTRLEN] = "255.255.255.255";
			if (dest)
				inet_ntop(AF_INET, &dest->sin.sin_addr,
					  dest_buf, INET_ADDRSTRLEN);
			if (mask)
				inet_ntop(AF_INET, &mask->sin.sin_addr,
					  mask_buf, INET_ADDRSTRLEN);
			flog_warn(
				EC_ZEBRA_RTM_NO_GATEWAY,
				"%s: %s/%s: gate == NULL and no gateway found for ifindex %d",
				__func__, dest_buf, mask_buf, index);
			return -1;
		}
		gate = (union sockunion *)&((struct zebra_if *)ifp->info)->sdl;
	}

	if (mask)
		msg.rtm.rtm_addrs |= RTA_NETMASK;
	else if (message == RTM_ADD || message == RTM_CHANGE)
		msg.rtm.rtm_flags |= RTF_HOST;

#ifdef __OpenBSD__
	if (mpls) {
		msg.rtm.rtm_addrs |= RTA_SRC;
		msg.rtm.rtm_flags |= RTF_MPLS;

		if (mpls->smpls.smpls_label
		    != htonl(MPLS_LABEL_IMPLICIT_NULL << MPLS_LABEL_OFFSET))
			msg.rtm.rtm_mpls = MPLS_OP_PUSH;
	}
#endif

	/* Tagging route with flags */
	msg.rtm.rtm_flags |= (RTF_PROTO1);

	switch (bh_type) {
	case BLACKHOLE_UNSPEC:
		break;
	case BLACKHOLE_REJECT:
		msg.rtm.rtm_flags |= RTF_REJECT;
		break;
	default:
		msg.rtm.rtm_flags |= RTF_BLACKHOLE;
		break;
	}


#define SOCKADDRSET(X, R)                                                      \
	if (msg.rtm.rtm_addrs & (R)) {                                         \
		int len = SAROUNDUP(X);                                        \
		memcpy(pnt, (caddr_t)(X), len);                                \
		pnt += len;                                                    \
	}

	pnt = (caddr_t)msg.buf;

	/* Write each socket data into rtm message buffer */
	SOCKADDRSET(dest, RTA_DST);
	SOCKADDRSET(gate, RTA_GATEWAY);
	SOCKADDRSET(mask, RTA_NETMASK);
#ifdef __OpenBSD__
	SOCKADDRSET(mpls, RTA_SRC);
#endif

	msg.rtm.rtm_msglen = pnt - (caddr_t)&msg;

	ret = write(dplane_routing_sock, &msg, msg.rtm.rtm_msglen);

	if (ret != msg.rtm.rtm_msglen) {
		if (errno == EEXIST)
			return ZEBRA_ERR_RTEXIST;
		if (errno == ENETUNREACH)
			return ZEBRA_ERR_RTUNREACH;
		if (errno == ESRCH)
			return ZEBRA_ERR_RTNOEXIST;

		flog_err_sys(EC_LIB_SOCKET, "%s: write : %s (%d)", __func__,
			     safe_strerror(errno), errno);
		return ZEBRA_ERR_KERNEL;
	}
	return ZEBRA_ERR_NOERROR;
}


#include "thread.h"
#include "zebra/zserv.h"

/* For debug purpose. */
static void rtmsg_debug(struct rt_msghdr *rtm)
{
	char fbuf[64];

	zlog_debug("Kernel: Len: %d Type: %s", rtm->rtm_msglen,
		   lookup_msg(rtm_type_str, rtm->rtm_type, NULL));
	rtm_flag_dump(rtm->rtm_flags);
	zlog_debug("Kernel: message seq %d", rtm->rtm_seq);
	zlog_debug("Kernel: pid %lld, rtm_addrs {%s}", (long long)rtm->rtm_pid,
		   rtatostr(rtm->rtm_addrs, fbuf, sizeof(fbuf)));
}

/* This is pretty gross, better suggestions welcome -- mhandler */
#ifndef RTAX_MAX
#ifdef RTA_NUMBITS
#define RTAX_MAX	RTA_NUMBITS
#else
#define RTAX_MAX	8
#endif /* RTA_NUMBITS */
#endif /* RTAX_MAX */

/* Kernel routing table and interface updates via routing socket. */
static int kernel_read(struct thread *thread)
{
	int sock;
	int nbytes;
	struct rt_msghdr *rtm;

	/*
	 * This must be big enough for any message the kernel might send.
	 * Rather than determining how many sockaddrs of what size might be
	 * in each particular message, just use RTAX_MAX of sockaddr_storage
	 * for each.  Note that the sockaddrs must be after each message
	 * definition, or rather after whichever happens to be the largest,
	 * since the buffer needs to be big enough for a message and the
	 * sockaddrs together.
	 */
	union {
		/* Routing information. */
		struct {
			struct rt_msghdr rtm;
			struct sockaddr_storage addr[RTAX_MAX];
		} r;

		/* Interface information. */
		struct {
			struct if_msghdr ifm;
			struct sockaddr_storage addr[RTAX_MAX];
		} im;

		/* Interface address information. */
		struct {
			struct ifa_msghdr ifa;
			struct sockaddr_storage addr[RTAX_MAX];
		} ia;

#ifdef RTM_IFANNOUNCE
		/* Interface arrival/departure */
		struct {
			struct if_announcemsghdr ifan;
			struct sockaddr_storage addr[RTAX_MAX];
		} ian;
#endif /* RTM_IFANNOUNCE */

	} buf;

	/* Fetch routing socket. */
	sock = THREAD_FD(thread);

	nbytes = read(sock, &buf, sizeof buf);

	if (nbytes <= 0) {
		if (nbytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN)
			flog_err_sys(EC_LIB_SOCKET, "routing socket error: %s",
				     safe_strerror(errno));
		return 0;
	}

	thread_add_read(zrouter.master, kernel_read, NULL, sock, NULL);

	if (IS_ZEBRA_DEBUG_KERNEL)
		rtmsg_debug(&buf.r.rtm);

	rtm = &buf.r.rtm;

	/*
	 * Ensure that we didn't drop any data, so that processing routines
	 * can assume they have the whole message.
	 */
	if (rtm->rtm_msglen != nbytes) {
		zlog_debug(
			"kernel_read: rtm->rtm_msglen %d, nbytes %d, type %d\n",
			rtm->rtm_msglen, nbytes, rtm->rtm_type);
		return -1;
	}

	switch (rtm->rtm_type) {
	case RTM_ADD:
	case RTM_DELETE:
	case RTM_CHANGE:
		rtm_read(rtm);
		break;
	case RTM_IFINFO:
		ifm_read(&buf.im.ifm);
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
		ifam_read(&buf.ia.ifa);
		break;
#ifdef RTM_IFANNOUNCE
	case RTM_IFANNOUNCE:
		ifan_read(&buf.ian.ifan);
		break;
#endif /* RTM_IFANNOUNCE */
	default:
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("Unprocessed RTM_type: %d", rtm->rtm_type);
		break;
	}
	return 0;
}

/* Make routing socket. */
static void routing_socket(struct zebra_ns *zns)
{
	frr_with_privs(&zserv_privs) {
		routing_sock = ns_socket(AF_ROUTE, SOCK_RAW, 0, zns->ns_id);

		dplane_routing_sock =
			ns_socket(AF_ROUTE, SOCK_RAW, 0, zns->ns_id);
	}

	if (routing_sock < 0) {
		flog_err_sys(EC_LIB_SOCKET, "Can't init kernel routing socket");
		return;
	}

	if (dplane_routing_sock < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "Can't init kernel dataplane routing socket");
		return;
	}

	/* XXX: Socket should be NONBLOCK, however as we currently
	 * discard failed writes, this will lead to inconsistencies.
	 * For now, socket must be blocking.
	 */
	/*if (fcntl (routing_sock, F_SETFL, O_NONBLOCK) < 0)
	  zlog_warn ("Can't set O_NONBLOCK to routing socket");*/

	/* kernel_read needs rewrite. */
	thread_add_read(zrouter.master, kernel_read, NULL, routing_sock, NULL);
}

/* Exported interface function.  This function simply calls
   routing_socket (). */
void kernel_init(struct zebra_ns *zns)
{
	routing_socket(zns);
}

void kernel_terminate(struct zebra_ns *zns, bool complete)
{
	return;
}

#endif /* !HAVE_NETLINK */
