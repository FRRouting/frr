/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */


#include <errno.h>

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/vty.h"
#include "lib/memory.h"
#include "lib/routemap.h"
#include "lib/log.h"
#include "lib/linklist.h"
#include "lib/command.h"
#include "lib/stream.h"
#include "lib/ringbuf.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_attr.h"

#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_backend.h"

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_vnc_types.h"
#include "bgpd/bgp_zebra.h"

#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_monitor.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/vnc_export_bgp.h"
#include "bgpd/rfapi/vnc_export_bgp_p.h"
#include "bgpd/rfapi/vnc_zebra.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/rfapi_rib.h"
#include "bgpd/rfapi/rfapi_ap.h"
#include "bgpd/rfapi/rfapi_encap_tlv.h"
#include "bgpd/rfapi/vnc_debug.h"

#ifdef HAVE_GLIBC_BACKTRACE
/* for backtrace and friends */
#include <execinfo.h>
#endif /* HAVE_GLIBC_BACKTRACE */

struct ethaddr rfapi_ethaddr0 = {{0}};

#define DEBUG_RFAPI_STR "RF API debugging/testing command\n"

const char *rfapi_error_str(int code)
{
	switch (code) {
	case 0:
		return "Success";
	case ENXIO:
		return "BGP or VNC not configured";
	case ENOENT:
		return "No match";
	case EEXIST:
		return "Handle already open";
	case ENOMSG:
		return "Incomplete configuration";
	case EAFNOSUPPORT:
		return "Invalid address family";
	case EDEADLK:
		return "Called from within a callback procedure";
	case EBADF:
		return "Invalid handle";
	case EINVAL:
		return "Invalid argument";
	case ESTALE:
		return "Stale descriptor";
	default:
		return "Unknown error";
	}
}

/*------------------------------------------
 * rfapi_get_response_lifetime_default
 *
 * Returns the default lifetime for a response.
 *    rfp_start_val     value returned by rfp_start or
 *                      NULL (=use default instance)
 *
 * input:
 *    None
 *
 * output:
 *
 * return value: The bgp instance default lifetime for a response.
 --------------------------------------------*/
int rfapi_get_response_lifetime_default(void *rfp_start_val)
{
	struct bgp *bgp = rfapi_bgp_lookup_by_rfp(rfp_start_val);
	if (bgp)
		return bgp->rfapi_cfg->default_response_lifetime;
	return BGP_VNC_DEFAULT_RESPONSE_LIFETIME_DEFAULT;
}

/*------------------------------------------
 * rfapi_is_vnc_configured
 *
 * Returns if VNC is configured
 *
 * input:
 *    rfp_start_val     value returned by rfp_start or
 *                      NULL (=use default instance)
 *
 * output:
 *
 * return value: If VNC is configured for the bgpd instance
 *	0		Success
 *	ENXIO		VNC not configured
 --------------------------------------------*/
int rfapi_is_vnc_configured(void *rfp_start_val)
{
	struct bgp *bgp = rfapi_bgp_lookup_by_rfp(rfp_start_val);
	if (bgp_rfapi_is_vnc_configured(bgp) == 0)
		return 0;
	return ENXIO;
}


/*------------------------------------------
 * rfapi_get_vn_addr
 *
 * Get the virtual network address used by an NVE based on it's RFD
 *
 * input:
 *    rfd: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *
 * output:
 *
 * return value:
 *	vn		NVE virtual network address
 *------------------------------------------*/
struct rfapi_ip_addr *rfapi_get_vn_addr(void *rfd)
{
	struct rfapi_descriptor *rrfd = (struct rfapi_descriptor *)rfd;
	return &rrfd->vn_addr;
}

/*------------------------------------------
 * rfapi_get_un_addr
 *
 * Get the underlay network address used by an NVE based on it's RFD
 *
 * input:
 *    rfd: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *
 * output:
 *
 * return value:
 *	un		NVE underlay network address
 *------------------------------------------*/
struct rfapi_ip_addr *rfapi_get_un_addr(void *rfd)
{
	struct rfapi_descriptor *rrfd = (struct rfapi_descriptor *)rfd;
	return &rrfd->un_addr;
}

int rfapi_ip_addr_cmp(struct rfapi_ip_addr *a1, struct rfapi_ip_addr *a2)
{
	if (a1->addr_family != a2->addr_family)
		return a1->addr_family - a2->addr_family;

	if (a1->addr_family == AF_INET) {
		return IPV4_ADDR_CMP(&a1->addr.v4, &a2->addr.v4);
	}

	if (a1->addr_family == AF_INET6) {
		return IPV6_ADDR_CMP(&a1->addr.v6, &a2->addr.v6);
	}

	assert(1);
	/* NOTREACHED */
	return 1;
}

static int rfapi_find_node(struct bgp *bgp, struct rfapi_ip_addr *vn_addr,
			   struct rfapi_ip_addr *un_addr,
			   struct route_node **node)
{
	struct rfapi *h;
	struct prefix p;
	struct route_node *rn;
	int rc;
	afi_t afi;

	if (!bgp) {
		return ENXIO;
	}

	h = bgp->rfapi;
	if (!h) {
		return ENXIO;
	}

	afi = family2afi(un_addr->addr_family);
	if (!afi) {
		return EAFNOSUPPORT;
	}

	if ((rc = rfapiRaddr2Qprefix(un_addr, &p)))
		return rc;

	rn = route_node_lookup(h->un[afi], &p);

	if (!rn)
		return ENOENT;

	route_unlock_node(rn);

	*node = rn;

	return 0;
}


int rfapi_find_rfd(struct bgp *bgp, struct rfapi_ip_addr *vn_addr,
		   struct rfapi_ip_addr *un_addr, struct rfapi_descriptor **rfd)
{
	struct route_node *rn;
	int rc;

	rc = rfapi_find_node(bgp, vn_addr, un_addr, &rn);

	if (rc)
		return rc;

	for (*rfd = (struct rfapi_descriptor *)(rn->info); *rfd;
	     *rfd = (*rfd)->next) {
		if (!rfapi_ip_addr_cmp(&(*rfd)->vn_addr, vn_addr))
			break;
	}

	if (!*rfd)
		return ENOENT;

	return 0;
}

/*------------------------------------------
 * rfapi_find_handle
 *
 * input:
 *	un		underlay network address
 *	vn		virtual network address
 *
 * output:
 *	pHandle		pointer to location to store handle
 *
 * return value:
 *	0		Success
 *	ENOENT		no matching handle
 *	ENXIO		BGP or VNC not configured
 *------------------------------------------*/
static int rfapi_find_handle(struct bgp *bgp, struct rfapi_ip_addr *vn_addr,
			     struct rfapi_ip_addr *un_addr,
			     rfapi_handle *handle)
{
	struct rfapi_descriptor **rfd;

	rfd = (struct rfapi_descriptor **)handle;

	return rfapi_find_rfd(bgp, vn_addr, un_addr, rfd);
}

static int rfapi_find_handle_vty(struct vty *vty, struct rfapi_ip_addr *vn_addr,
				 struct rfapi_ip_addr *un_addr,
				 rfapi_handle *handle)
{
	struct bgp *bgp;
	struct rfapi_descriptor **rfd;

	bgp = bgp_get_default(); /* assume 1 instance for now */

	rfd = (struct rfapi_descriptor **)handle;

	return rfapi_find_rfd(bgp, vn_addr, un_addr, rfd);
}

static int is_valid_rfd(struct rfapi_descriptor *rfd)
{
	rfapi_handle hh;

	if (!rfd || rfd->bgp == NULL)
		return 0;

	if (CHECK_FLAG(
		    rfd->flags,
		    RFAPI_HD_FLAG_IS_VRF)) /* assume VRF/internal are valid */
		return 1;

	if (rfapi_find_handle(rfd->bgp, &rfd->vn_addr, &rfd->un_addr, &hh))
		return 0;

	if (rfd != hh)
		return 0;

	return 1;
}

/*
 * check status of descriptor
 */
int rfapi_check(void *handle)
{
	struct rfapi_descriptor *rfd = (struct rfapi_descriptor *)handle;
	rfapi_handle hh;
	int rc;

	if (!rfd || rfd->bgp == NULL)
		return EINVAL;

	if (CHECK_FLAG(
		    rfd->flags,
		    RFAPI_HD_FLAG_IS_VRF)) /* assume VRF/internal are valid */
		return 0;

	if ((rc = rfapi_find_handle(rfd->bgp, &rfd->vn_addr, &rfd->un_addr,
				    &hh)))
		return rc;

	if (rfd != hh)
		return ENOENT;

	if (!rfd->rfg)
		return ESTALE;

	return 0;
}


void del_vnc_route(struct rfapi_descriptor *rfd,
		   struct peer *peer, /* rfd->peer for RFP regs */
		   struct bgp *bgp, safi_t safi, struct prefix *p,
		   struct prefix_rd *prd, uint8_t type, uint8_t sub_type,
		   struct rfapi_nexthop *lnh, int kill)
{
	afi_t afi; /* of the VN address */
	struct bgp_node *bn;
	struct bgp_info *bi;
	char buf[PREFIX_STRLEN];
	char buf2[RD_ADDRSTRLEN];
	struct prefix_rd prd0;

	prefix2str(p, buf, sizeof(buf));

	afi = family2afi(p->family);
	assert(afi == AFI_IP || afi == AFI_IP6);

	if (safi == SAFI_ENCAP) {
		memset(&prd0, 0, sizeof(prd0));
		prd0.family = AF_UNSPEC;
		prd0.prefixlen = 64;
		prd = &prd0;
	}
	bn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, prd);

	vnc_zlog_debug_verbose(
		"%s: peer=%p, prefix=%s, prd=%s afi=%d, safi=%d bn=%p, bn->info=%p",
		__func__, peer, buf,
		prefix_rd2str(prd, buf2, sizeof(buf2)), afi, safi, bn,
		(bn ? bn->info : NULL));

	for (bi = (bn ? bn->info : NULL); bi; bi = bi->next) {

		vnc_zlog_debug_verbose(
			"%s: trying bi=%p, bi->peer=%p, bi->type=%d, bi->sub_type=%d, bi->extra->vnc.export.rfapi_handle=%p, local_pref=%u",
			__func__, bi, bi->peer, bi->type, bi->sub_type,
			(bi->extra ? bi->extra->vnc.export.rfapi_handle : NULL),
			((bi->attr
			  && CHECK_FLAG(bi->attr->flag,
					ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
				 ? bi->attr->local_pref
				 : 0));

		if (bi->peer == peer && bi->type == type
		    && bi->sub_type == sub_type && bi->extra
		    && bi->extra->vnc.export.rfapi_handle == (void *)rfd) {

			vnc_zlog_debug_verbose("%s: matched it", __func__);

			break;
		}
	}

	if (lnh) {
		/*
		 * lnh set means to JUST delete the local nexthop from this
		 * route. Leave the route itself in place.
		 * TBD add return code reporting of success/failure
		 */
		if (!bi || !bi->extra
		    || !bi->extra->vnc.export.local_nexthops) {
			/*
			 * no local nexthops
			 */
			vnc_zlog_debug_verbose(
				"%s: lnh list already empty at prefix %s",
				__func__, buf);
			goto done;
		}

		/*
		 * look for it
		 */
		struct listnode *node;
		struct rfapi_nexthop *pLnh = NULL;

		for (ALL_LIST_ELEMENTS_RO(bi->extra->vnc.export.local_nexthops,
					  node, pLnh)) {

			if (prefix_same(&pLnh->addr, &lnh->addr)) {
				break;
			}
		}

		if (pLnh) {
			listnode_delete(bi->extra->vnc.export.local_nexthops,
					pLnh);

			/* silly rabbit, listnode_delete doesn't invoke
			 * list->del on data */
			rfapi_nexthop_free(pLnh);
		} else {
			vnc_zlog_debug_verbose("%s: desired lnh not found %s",
					       __func__, buf);
		}
		goto done;
	}

	/*
	 * loop back to import tables
	 * Do this before removing from BGP RIB because rfapiProcessWithdraw
	 * might refer to it
	 */
	rfapiProcessWithdraw(peer, rfd, p, prd, NULL, afi, safi, type, kill);

	if (bi) {
		char buf[PREFIX_STRLEN];

		prefix2str(p, buf, sizeof(buf));
		vnc_zlog_debug_verbose(
			"%s: Found route (safi=%d) to delete at prefix %s",
			__func__, safi, buf);

		if (safi == SAFI_MPLS_VPN) {
			struct bgp_node *prn = NULL;
			struct bgp_table *table = NULL;

			prn = bgp_node_get(bgp->rib[afi][safi],
					   (struct prefix *)prd);
			if (prn->info) {
				table = (struct bgp_table *)(prn->info);

				vnc_import_bgp_del_vnc_host_route_mode_resolve_nve(
					bgp, prd, table, p, bi);
			}
			bgp_unlock_node(prn);
		}

		/*
		 * Delete local_nexthops list
		 */
		if (bi->extra && bi->extra->vnc.export.local_nexthops) {
			list_delete_and_null(
				&bi->extra->vnc.export.local_nexthops);
		}

		bgp_aggregate_decrement(bgp, p, bi, afi, safi);
		bgp_info_delete(bn, bi);
		bgp_process(bgp, bn, afi, safi);
	} else {
		vnc_zlog_debug_verbose(
			"%s: Couldn't find route (safi=%d) at prefix %s",
			__func__, safi, buf);
	}
done:
	bgp_unlock_node(bn);
}

struct rfapi_nexthop *rfapi_nexthop_new(struct rfapi_nexthop *copyme)
{
	struct rfapi_nexthop *new =
		XCALLOC(MTYPE_RFAPI_NEXTHOP, sizeof(struct rfapi_nexthop));
	if (copyme)
		*new = *copyme;
	return new;
}

void rfapi_nexthop_free(void *p)
{
	struct rfapi_nexthop *goner = p;
	XFREE(MTYPE_RFAPI_NEXTHOP, goner);
}

struct rfapi_vn_option *rfapi_vn_options_dup(struct rfapi_vn_option *existing)
{
	struct rfapi_vn_option *p;
	struct rfapi_vn_option *head = NULL;
	struct rfapi_vn_option *tail = NULL;

	for (p = existing; p; p = p->next) {
		struct rfapi_vn_option *new;

		new = XCALLOC(MTYPE_RFAPI_VN_OPTION,
			      sizeof(struct rfapi_vn_option));
		*new = *p;
		new->next = NULL;
		if (tail)
			(tail)->next = new;
		tail = new;
		if (!head) {
			head = new;
		}
	}
	return head;
}

void rfapi_un_options_free(struct rfapi_un_option *p)
{
	struct rfapi_un_option *next;

	while (p) {
		next = p->next;
		XFREE(MTYPE_RFAPI_UN_OPTION, p);
		p = next;
	}
}

void rfapi_vn_options_free(struct rfapi_vn_option *p)
{
	struct rfapi_vn_option *next;

	while (p) {
		next = p->next;
		XFREE(MTYPE_RFAPI_VN_OPTION, p);
		p = next;
	}
}

/* Based on bgp_redistribute_add() */
void add_vnc_route(struct rfapi_descriptor *rfd, /* cookie, VPN UN addr, peer */
		   struct bgp *bgp, int safi, struct prefix *p,
		   struct prefix_rd *prd, struct rfapi_ip_addr *nexthop,
		   uint32_t *local_pref,
		   uint32_t *lifetime, /* NULL => dont send lifetime */
		   struct bgp_tea_options *rfp_options,
		   struct rfapi_un_option *options_un,
		   struct rfapi_vn_option *options_vn,
		   struct ecommunity *rt_export_list, /* Copied, not consumed */
		   uint32_t *med,		   /* NULL => don't set med */
		   uint32_t *label,		   /* low order 3 bytes */
		   uint8_t type, uint8_t sub_type, /* RFP, NORMAL or REDIST */
		   int flags)
{
	afi_t afi; /* of the VN address */
	struct bgp_info *new;
	struct bgp_info *bi;
	struct bgp_node *bn;

	struct attr attr = {0};
	struct attr *new_attr;
	uint32_t label_val;

	struct bgp_attr_encap_subtlv *encaptlv;
	char buf[PREFIX_STRLEN];
	char buf2[RD_ADDRSTRLEN];
#if 0 /* unused? */
  struct prefix pfx_buf;
#endif

	struct rfapi_nexthop *lnh = NULL; /* local nexthop */
	struct rfapi_vn_option *vo;
	struct rfapi_l2address_option *l2o = NULL;
	struct rfapi_ip_addr *un_addr = &rfd->un_addr;

	bgp_encap_types TunnelType = BGP_ENCAP_TYPE_RESERVED;
	struct bgp_redist *red;

	if (safi == SAFI_ENCAP
	    && !(bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP)) {

		/*
		 * Encap mode not enabled. UN addresses will be communicated
		 * via VNC Tunnel subtlv instead.
		 */
		vnc_zlog_debug_verbose(
			"%s: encap mode not enabled, not adding SAFI_ENCAP route",
			__func__);
		return;
	}

#if 0 /* unused? */
  if ((safi == SAFI_MPLS_VPN) && (flags & RFAPI_AHR_SET_PFX_TO_NEXTHOP))
    {

      if (rfapiRaddr2Qprefix (nexthop, &pfx_buf))
        {
          vnc_zlog_debug_verbose
            ("%s: can't set pfx to vn addr, not adding SAFI_MPLS_VPN route",
             __func__);
          return;
        }
      p = &pfx_buf;
    }
#endif
	for (vo = options_vn; vo; vo = vo->next) {
		if (RFAPI_VN_OPTION_TYPE_L2ADDR == vo->type) {
			l2o = &vo->v.l2addr;
			if (RFAPI_0_ETHERADDR(&l2o->macaddr))
				l2o = NULL; /* not MAC resolution */
		}
		if (RFAPI_VN_OPTION_TYPE_LOCAL_NEXTHOP == vo->type) {
			lnh = &vo->v.local_nexthop;
		}
	}

	if (label)
		label_val = *label;
	else
		label_val = MPLS_LABEL_IMPLICIT_NULL;

	prefix_rd2str(prd, buf2, sizeof(buf2));

	afi = family2afi(p->family);
	assert(afi == AFI_IP || afi == AFI_IP6);

	vnc_zlog_debug_verbose("%s: afi=%s, safi=%s", __func__, afi2str(afi),
			       safi2str(safi));

	/* Make default attribute. Produces already-interned attr.aspath */
	/* Cripes, the memory management of attributes is byzantine */

	bgp_attr_default_set(&attr, BGP_ORIGIN_INCOMPLETE);

	/*
	 * At this point:
	 * attr: static
	 *  extra: dynamically allocated, owned by attr
	 *  aspath: points to interned hash from aspath hash table
	 */


	/*
	 * Route-specific un_options get added to the VPN SAFI
	 * advertisement tunnel encap attribute.  (the per-NVE
	 * "default" un_options are put into the 1-per-NVE ENCAP
	 * SAFI advertisement). The VPN SAFI also gets the
	 * default un_options if there are no route-specific options.
	 */
	if (options_un) {
		struct rfapi_un_option *uo;

		for (uo = options_un; uo; uo = uo->next) {
			if (RFAPI_UN_OPTION_TYPE_TUNNELTYPE == uo->type) {
				TunnelType = rfapi_tunneltype_option_to_tlv(
					bgp, un_addr, &uo->v.tunnel, &attr,
					l2o != NULL);
			}
		}
	} else {
		/*
		 * Add encap attr
		 * These are the NVE-specific "default" un_options which are
		 * put into the 1-per-NVE ENCAP advertisement.
		 */
		if (rfd->default_tunneltype_option.type) {
			TunnelType = rfapi_tunneltype_option_to_tlv(
				bgp, un_addr, &rfd->default_tunneltype_option,
				&attr, l2o != NULL);
		} else /* create default for local addse  */
			if (type == ZEBRA_ROUTE_BGP
			    && sub_type == BGP_ROUTE_RFP)
			TunnelType = rfapi_tunneltype_option_to_tlv(
				bgp, un_addr, NULL, &attr, l2o != NULL);
	}

	if (TunnelType == BGP_ENCAP_TYPE_MPLS) {
		if (safi == SAFI_ENCAP) {
			/* Encap SAFI not used with MPLS  */
			vnc_zlog_debug_verbose(
				"%s: mpls tunnel type, encap safi omitted",
				__func__);
			aspath_unintern(&attr.aspath); /* Unintern original. */
			return;
		}
	}

	if (local_pref) {
		attr.local_pref = *local_pref;
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);
	}

	if (med) {
		attr.med = *med;
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);
	}

	/* override default weight assigned by bgp_attr_default_set() */
	attr.weight = rfd->peer ? rfd->peer->weight[afi][safi] : 0;

	/*
	 * NB: ticket 81: do not reset attr.aspath here because it would
	 * cause iBGP peers to drop route
	 */

	/*
	 * Set originator ID for routes imported from BGP directly.
	 * These routes could be synthetic, and therefore could
	 * reuse the peer pointers of the routes they are derived
	 * from. Setting the originator ID to "us" prevents the
	 * wrong originator ID from being sent when this route is
	 * sent from a route reflector.
	 */
	if (type == ZEBRA_ROUTE_BGP_DIRECT
	    || type == ZEBRA_ROUTE_BGP_DIRECT_EXT) {
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID);
		attr.originator_id = bgp->router_id;
	}


	/* Set up vnc attribute (sub-tlv for Prefix Lifetime) */
	if (lifetime && *lifetime != RFAPI_INFINITE_LIFETIME) {
		uint32_t lt;

		encaptlv =
			XCALLOC(MTYPE_ENCAP_TLV,
				sizeof(struct bgp_attr_encap_subtlv) + 4);
		assert(encaptlv);
		encaptlv->type =
			BGP_VNC_SUBTLV_TYPE_LIFETIME; /* prefix lifetime */
		encaptlv->length = 4;
		lt = htonl(*lifetime);
		memcpy(encaptlv->value, &lt, 4);
		attr.vnc_subtlvs = encaptlv;
		vnc_zlog_debug_verbose(
			"%s: set Encap Attr Prefix Lifetime to %d", __func__,
			*lifetime);
	}

	/* add rfp options to vnc attr */
	if (rfp_options) {

		if (flags & RFAPI_AHR_RFPOPT_IS_VNCTLV) {

			/*
			 * this flag means we're passing a pointer to an
			 * existing encap tlv chain which we should copy.
			 * It's a hack to avoid adding yet another argument
			 * to add_vnc_route()
			 */
			encaptlv = encap_tlv_dup(
				(struct bgp_attr_encap_subtlv *)rfp_options);
			if (attr.vnc_subtlvs) {
				attr.vnc_subtlvs->next = encaptlv;
			} else {
				attr.vnc_subtlvs = encaptlv;
			}

		} else {
			struct bgp_tea_options *hop;
			/* XXX max of one tlv present so far from above code */
			struct bgp_attr_encap_subtlv *tail = attr.vnc_subtlvs;

			for (hop = rfp_options; hop; hop = hop->next) {

				/*
				 * Construct subtlv
				 */
				encaptlv = XCALLOC(
					MTYPE_ENCAP_TLV,
					sizeof(struct bgp_attr_encap_subtlv)
					+ 2 + hop->length);
				assert(encaptlv);
				encaptlv->type =
					BGP_VNC_SUBTLV_TYPE_RFPOPTION; /* RFP
									  option
									  */
				encaptlv->length = 2 + hop->length;
				*((uint8_t *)(encaptlv->value) + 0) = hop->type;
				*((uint8_t *)(encaptlv->value) + 1) =
					hop->length;
				memcpy(((uint8_t *)encaptlv->value) + 2,
				       hop->value, hop->length);

				/*
				 * add to end of subtlv chain
				 */
				if (tail) {
					tail->next = encaptlv;
				} else {
					attr.vnc_subtlvs = encaptlv;
				}
				tail = encaptlv;
			}
		}
	}

	/*
	 * At this point:
	 * attr: static
	 *  extra: dynamically allocated, owned by attr
	 *      vnc_subtlvs: dynamic chain, length 1
	 *  aspath: points to interned hash from aspath hash table
	 */


	attr.ecommunity = ecommunity_new();
	assert(attr.ecommunity);

	if (TunnelType != BGP_ENCAP_TYPE_MPLS
	    && TunnelType != BGP_ENCAP_TYPE_RESERVED) {
		/*
		 * Add BGP Encapsulation Extended Community. Format described in
		 * section 4.5 of RFC 5512.
		 * Always include when not MPLS type, to disambiguate this case.
		 */
		struct ecommunity_val beec;

		memset(&beec, 0, sizeof(beec));
		beec.val[0] = ECOMMUNITY_ENCODE_OPAQUE;
		beec.val[1] = ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP;
		beec.val[6] = ((TunnelType) >> 8) & 0xff;
		beec.val[7] = (TunnelType)&0xff;
		ecommunity_add_val(attr.ecommunity, &beec);
	}

	/*
	 * Add extended community attributes to match rt export list
	 */
	if (rt_export_list) {
		attr.ecommunity =
			ecommunity_merge(attr.ecommunity, rt_export_list);
	}

	if (attr.ecommunity->size) {
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);
	} else {
		ecommunity_free(&attr.ecommunity);
		attr.ecommunity = NULL;
	}
	vnc_zlog_debug_verbose("%s: attr.ecommunity=%p", __func__,
			       attr.ecommunity);


	/*
	 * At this point:
	 * attr: static
	 *  extra: dynamically allocated, owned by attr
	 *      vnc_subtlvs: dynamic chain, length 1
	 *      ecommunity: dynamic 2-part
	 *  aspath: points to interned hash from aspath hash table
	 */

	/* stuff nexthop in attr_extra; which field depends on IPv4 or IPv6 */
	switch (nexthop->addr_family) {
	case AF_INET:
		/*
		 * set this field to prevent bgp_route.c code from setting
		 * mp_nexthop_global_in to self
		 */
		attr.nexthop.s_addr = nexthop->addr.v4.s_addr;

		attr.mp_nexthop_global_in = nexthop->addr.v4;
		attr.mp_nexthop_len = 4;
		break;

	case AF_INET6:
		attr.mp_nexthop_global = nexthop->addr.v6;
		attr.mp_nexthop_len = 16;
		break;

	default:
		assert(0);
	}


	prefix2str(p, buf, sizeof(buf));

	/*
	 * At this point:
	 *
	 * attr: static
	 *  extra: dynamically allocated, owned by attr
	 *      vnc_subtlvs: dynamic chain, length 1
	 *      ecommunity: dynamic 2-part
	 *  aspath: points to interned hash from aspath hash table
	 */

	red = bgp_redist_lookup(bgp, afi, type, 0);

	if (red && red->redist_metric_flag) {
		attr.med = red->redist_metric;
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);
	}

	bn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, prd);

	/*
	 * bgp_attr_intern creates a new reference to a cached
	 * attribute, but leaves the following bits of trash:
	 * - old attr
	 * - old attr->extra (free via bgp_attr_extra_free(attr))
	 *
	 * Note that it frees the original attr->extra->ecommunity
	 * but leaves the new attribute pointing to the ORIGINAL
	 * vnc options (which therefore we needn't free from the
	 * static attr)
	 */
	new_attr = bgp_attr_intern(&attr);

	aspath_unintern(&attr.aspath); /* Unintern original. */

	/*
	 * At this point:
	 *
	 * attr: static
	 *  extra: dynamically allocated, owned by attr
	 *      vnc_subtlvs: dynamic chain, length 1
	 *      ecommunity: POINTS TO INTERNED ecom, THIS REF NOT COUNTED
	 *
	 * new_attr: an attr that is part of the hash table, distinct
	 *           from attr which is static.
	 *  extra: dynamically allocated, owned by new_attr (in hash table)
	 *      vnc_subtlvs: POINTS TO SAME dynamic chain AS attr
	 *      ecommunity: POINTS TO interned/refcounted dynamic 2-part AS attr
	 *  aspath: POINTS TO interned/refcounted hashed block
	 */
	for (bi = bn->info; bi; bi = bi->next) {
		/* probably only need to check
		 * bi->extra->vnc.export.rfapi_handle */
		if (bi->peer == rfd->peer && bi->type == type
		    && bi->sub_type == sub_type && bi->extra
		    && bi->extra->vnc.export.rfapi_handle == (void *)rfd) {

			break;
		}
	}

	if (bi) {

		/*
		 * Adding new local_nexthop, which does not by itself change
		 * what is advertised via BGP
		 */
		if (lnh) {
			if (!bi->extra->vnc.export.local_nexthops) {
				/* TBD make arrangements to free when needed */
				bi->extra->vnc.export.local_nexthops =
					list_new();
				bi->extra->vnc.export.local_nexthops->del =
					rfapi_nexthop_free;
			}

			/*
			 * already present?
			 */
			struct listnode *node;
			struct rfapi_nexthop *pLnh = NULL;

			for (ALL_LIST_ELEMENTS_RO(
				     bi->extra->vnc.export.local_nexthops, node,
				     pLnh)) {

				if (prefix_same(&pLnh->addr, &lnh->addr)) {
					break;
				}
			}

			/*
			 * Not present, add new one
			 */
			if (!pLnh) {
				pLnh = rfapi_nexthop_new(lnh);
				listnode_add(
					bi->extra->vnc.export.local_nexthops,
					pLnh);
			}
		}

		if (attrhash_cmp(bi->attr, new_attr)
		    && !CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)) {
			bgp_attr_unintern(&new_attr);
			bgp_unlock_node(bn);

			vnc_zlog_debug_any(
				"%s: Found route (safi=%d) at prefix %s, no change",
				__func__, safi, buf);

			goto done;
		} else {
			/* The attribute is changed. */
			bgp_info_set_flag(bn, bi, BGP_INFO_ATTR_CHANGED);

			if (safi == SAFI_MPLS_VPN) {
				struct bgp_node *prn = NULL;
				struct bgp_table *table = NULL;

				prn = bgp_node_get(bgp->rib[afi][safi],
						   (struct prefix *)prd);
				if (prn->info) {
					table = (struct bgp_table *)(prn->info);

					vnc_import_bgp_del_vnc_host_route_mode_resolve_nve(
						bgp, prd, table, p, bi);
				}
				bgp_unlock_node(prn);
			}

			/* Rewrite BGP route information. */
			if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
				bgp_info_restore(bn, bi);
			else
				bgp_aggregate_decrement(bgp, p, bi, afi, safi);
			bgp_attr_unintern(&bi->attr);
			bi->attr = new_attr;
			bi->uptime = bgp_clock();


			if (safi == SAFI_MPLS_VPN) {
				struct bgp_node *prn = NULL;
				struct bgp_table *table = NULL;

				prn = bgp_node_get(bgp->rib[afi][safi],
						   (struct prefix *)prd);
				if (prn->info) {
					table = (struct bgp_table *)(prn->info);

					vnc_import_bgp_add_vnc_host_route_mode_resolve_nve(
						bgp, prd, table, p, bi);
				}
				bgp_unlock_node(prn);
			}

			/* Process change. */
			bgp_aggregate_increment(bgp, p, bi, afi, safi);
			bgp_process(bgp, bn, afi, safi);
			bgp_unlock_node(bn);

			vnc_zlog_debug_any(
				"%s: Found route (safi=%d) at prefix %s, changed attr",
				__func__, safi, buf);

			goto done;
		}
	}


	new = bgp_info_new();
	new->type = type;
	new->sub_type = sub_type;
	new->peer = rfd->peer;
	SET_FLAG(new->flags, BGP_INFO_VALID);
	new->attr = new_attr;
	new->uptime = bgp_clock();

	/* save backref to rfapi handle */
	assert(bgp_info_extra_get(new));
	new->extra->vnc.export.rfapi_handle = (void *)rfd;
	encode_label(label_val, &new->extra->label[0]);

	/* debug */

	if (VNC_DEBUG(VERBOSE)) {
		vnc_zlog_debug_verbose("%s: printing BI", __func__);
		rfapiPrintBi(NULL, new);
	}

	bgp_aggregate_increment(bgp, p, new, afi, safi);
	bgp_info_add(bn, new);

	if (safi == SAFI_MPLS_VPN) {
		struct bgp_node *prn = NULL;
		struct bgp_table *table = NULL;

		prn = bgp_node_get(bgp->rib[afi][safi], (struct prefix *)prd);
		if (prn->info) {
			table = (struct bgp_table *)(prn->info);

			vnc_import_bgp_add_vnc_host_route_mode_resolve_nve(
				bgp, prd, table, p, new);
		}
		bgp_unlock_node(prn);
		encode_label(label_val, &bn->local_label);
	}

	bgp_unlock_node(bn);
	bgp_process(bgp, bn, afi, safi);

	vnc_zlog_debug_any(
		"%s: Added route (safi=%s) at prefix %s (bn=%p, prd=%s)",
		__func__, safi2str(safi), buf, bn, buf2);

done:
	/* Loop back to import tables */
	rfapiProcessUpdate(rfd->peer, rfd, p, prd, new_attr, afi, safi, type,
			   sub_type, &label_val);
	vnc_zlog_debug_verbose("%s: looped back import route (safi=%d)",
			       __func__, safi);
}

uint32_t rfp_cost_to_localpref(uint8_t cost)
{
	return 255 - cost;
}

static void rfapiTunnelRouteAnnounce(struct bgp *bgp,
				     struct rfapi_descriptor *rfd,
				     uint32_t *pLifetime)
{
	struct prefix_rd prd;
	struct prefix pfx_vn;
	int rc;
	uint32_t local_pref = rfp_cost_to_localpref(0);

	rc = rfapiRaddr2Qprefix(&(rfd->vn_addr), &pfx_vn);
	assert(!rc);

	/*
	 * Construct route distinguisher = 0
	 */
	memset(&prd, 0, sizeof(prd));
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	add_vnc_route(rfd,	/* rfapi descr, for export list  & backref */
		      bgp,	/* which bgp instance */
		      SAFI_ENCAP, /* which SAFI */
		      &pfx_vn,    /* prefix to advertise */
		      &prd,       /* route distinguisher to use */
		      &rfd->un_addr, /* nexthop */
		      &local_pref,
		      pLifetime, /* max lifetime of child VPN routes */
		      NULL,      /* no rfp options  for ENCAP safi */
		      NULL,      /* rfp un options */
		      NULL,      /* rfp vn options */
		      rfd->rt_export_list, NULL, /* med */
		      NULL,			 /* label: default */
		      ZEBRA_ROUTE_BGP, BGP_ROUTE_RFP, 0);
}


/***********************************************************************
 *			RFP processing behavior configuration
 ***********************************************************************/

/*------------------------------------------
 * rfapi_rfp_set_configuration
 *
 * This is used to change rfapi's processing behavior based on
 * RFP requirements.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    rfapi_rfp_cfg     Pointer to configuration structure
 *
 * output:
 *    none
 *
 * return value:
 *	0		Success
 *	ENXIO		Unabled to locate configured BGP/VNC
--------------------------------------------*/
int rfapi_rfp_set_configuration(void *rfp_start_val, struct rfapi_rfp_cfg *new)
{
	struct rfapi_rfp_cfg *rcfg;
	struct bgp *bgp;

	bgp = rfapi_bgp_lookup_by_rfp(rfp_start_val);

	if (!new || !bgp || !bgp->rfapi_cfg)
		return ENXIO;

	rcfg = &bgp->rfapi_cfg->rfp_cfg;
	rcfg->download_type = new->download_type;
	rcfg->ftd_advertisement_interval = new->ftd_advertisement_interval;
	rcfg->holddown_factor = new->holddown_factor;

	if (rcfg->use_updated_response != new->use_updated_response) {
		rcfg->use_updated_response = new->use_updated_response;
		if (rcfg->use_updated_response)
			rfapiMonitorCallbacksOn(bgp);
		else
			rfapiMonitorCallbacksOff(bgp);
	}
	if (rcfg->use_removes != new->use_removes) {
		rcfg->use_removes = new->use_removes;
		if (rcfg->use_removes)
			rfapiMonitorResponseRemovalOn(bgp);
		else
			rfapiMonitorResponseRemovalOff(bgp);
	}
	return 0;
}

/*------------------------------------------
 * rfapi_rfp_set_cb_methods
 *
 * Change registered callback functions for asynchronous notifications
 * from RFAPI to the RFP client.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    methods		Pointer to struct rfapi_rfp_cb_methods containing
 *			pointers to callback methods as described above
 *
 * return value:
 *	0		Success
 *	ENXIO		BGP or VNC not configured
 *------------------------------------------*/
int rfapi_rfp_set_cb_methods(void *rfp_start_val,
			     struct rfapi_rfp_cb_methods *methods)
{
	struct rfapi *h;
	struct bgp *bgp;

	bgp = rfapi_bgp_lookup_by_rfp(rfp_start_val);
	if (!bgp)
		return ENXIO;

	h = bgp->rfapi;
	if (!h)
		return ENXIO;

	h->rfp_methods = *methods;

	return 0;
}

/***********************************************************************
 *			NVE Sessions
 ***********************************************************************/
/*
 * Caller must supply an already-allocated rfd with the "caller"
 * fields already set (vn_addr, un_addr, callback, cookie)
 * The advertised_prefixes[] array elements should be NULL to
 * have this function set them to newly-allocated radix trees.
 */
static int rfapi_open_inner(struct rfapi_descriptor *rfd, struct bgp *bgp,
			    struct rfapi *h, struct rfapi_nve_group_cfg *rfg)
{
	int ret;

	if (h->flags & RFAPI_INCALLBACK)
		return EDEADLK;

	/*
	 * Fill in configured fields
	 */

	/*
	 * If group's RD is specified as "auto", then fill in based
	 * on NVE's VN address
	 */
	rfd->rd = rfg->rd;

	if (rfd->rd.family == AF_UNIX) {
		ret = rfapi_set_autord_from_vn(&rfd->rd, &rfd->vn_addr);
		if (ret != 0)
			return ret;
	}
	rfd->rt_export_list = (rfg->rt_export_list)
				      ? ecommunity_dup(rfg->rt_export_list)
				      : NULL;
	rfd->response_lifetime = rfg->response_lifetime;
	rfd->rfg = rfg;

	/*
	 * Fill in BGP peer structure
	 */
	rfd->peer = peer_new(bgp);
	rfd->peer->status = Established; /* keep bgp core happy */
	bgp_sync_delete(rfd->peer);      /* don't need these */

	/*
	 * since this peer is not on the I/O thread, this lock is not strictly
	 * necessary, but serves as a reminder to those who may meddle...
	 */
	pthread_mutex_lock(&rfd->peer->io_mtx);
	{
		// we don't need any I/O related facilities
		if (rfd->peer->ibuf)
			stream_fifo_free(rfd->peer->ibuf);
		if (rfd->peer->obuf)
			stream_fifo_free(rfd->peer->obuf);

		if (rfd->peer->ibuf_work)
			ringbuf_del(rfd->peer->ibuf_work);
		if (rfd->peer->obuf_work)
			stream_free(rfd->peer->obuf_work);

		rfd->peer->ibuf = NULL;
		rfd->peer->obuf = NULL;
		rfd->peer->obuf_work = NULL;
		rfd->peer->ibuf_work = NULL;
	}
	pthread_mutex_unlock(&rfd->peer->io_mtx);

	{ /* base code assumes have valid host pointer */
		char buf[BUFSIZ];
		buf[0] = 0;

		if (rfd->vn_addr.addr_family == AF_INET) {
			inet_ntop(AF_INET, &rfd->vn_addr.addr.v4, buf, BUFSIZ);
		} else if (rfd->vn_addr.addr_family == AF_INET6) {
			inet_ntop(AF_INET6, &rfd->vn_addr.addr.v6, buf, BUFSIZ);
		}
		rfd->peer->host = XSTRDUP(MTYPE_BGP_PEER_HOST, buf);
	}
	/* Mark peer as belonging to HD */
	SET_FLAG(rfd->peer->flags, PEER_FLAG_IS_RFAPI_HD);

	/*
	 * Set min prefix lifetime to max value so it will get set
	 * upon first rfapi_register()
	 */
	rfd->min_prefix_lifetime = UINT32_MAX;

/*
 * Allocate response tables if needed
 */
#define RFD_RTINIT_AFI(rh, ary, afi)                                           \
	do {                                                                   \
		if (!ary[afi]) {                                               \
			ary[afi] = route_table_init();                         \
			ary[afi]->info = rh;                                   \
		}                                                              \
	} while (0)

#define RFD_RTINIT(rh, ary)                                                    \
	do {                                                                   \
		RFD_RTINIT_AFI(rh, ary, AFI_IP);                               \
		RFD_RTINIT_AFI(rh, ary, AFI_IP6);                              \
		RFD_RTINIT_AFI(rh, ary, AFI_L2VPN);                            \
	} while (0)

	RFD_RTINIT(rfd, rfd->rib);
	RFD_RTINIT(rfd, rfd->rib_pending);
	RFD_RTINIT(rfd, rfd->rsp_times);

	/*
	 * Link to Import Table
	 */
	rfd->import_table = rfg->rfapi_import_table;
	rfd->import_table->refcount += 1;

	rfapiApInit(&rfd->advertised);

	/*
	 * add this NVE descriptor to the list of NVEs in the NVE group
	 */
	if (!rfg->nves) {
		rfg->nves = list_new();
	}
	listnode_add(rfg->nves, rfd);

	vnc_direct_bgp_add_nve(bgp, rfd);
	vnc_zebra_add_nve(bgp, rfd);

	return 0;
}

/* moved from rfapi_register */
int rfapi_init_and_open(struct bgp *bgp, struct rfapi_descriptor *rfd,
			struct rfapi_nve_group_cfg *rfg)
{
	struct rfapi *h = bgp->rfapi;
	char buf_vn[BUFSIZ];
	char buf_un[BUFSIZ];
	afi_t afi_vn, afi_un;
	struct prefix pfx_un;
	struct route_node *rn;


	rfapi_time(&rfd->open_time);

	if (rfg->type == RFAPI_GROUP_CFG_VRF)
		SET_FLAG(rfd->flags, RFAPI_HD_FLAG_IS_VRF);

	rfapiRfapiIpAddr2Str(&rfd->vn_addr, buf_vn, BUFSIZ);
	rfapiRfapiIpAddr2Str(&rfd->un_addr, buf_un, BUFSIZ);

	vnc_zlog_debug_verbose("%s: new RFD with VN=%s UN=%s cookie=%p",
			       __func__, buf_vn, buf_un, rfd->cookie);

	if (rfg->type != RFAPI_GROUP_CFG_VRF) /* unclear if needed for VRF */
	{
		listnode_add(&h->descriptors, rfd);
		if (h->descriptors.count > h->stat.max_descriptors) {
			h->stat.max_descriptors = h->descriptors.count;
		}

		/*
		 * attach to UN radix tree
		 */
		afi_vn = family2afi(rfd->vn_addr.addr_family);
		afi_un = family2afi(rfd->un_addr.addr_family);
		assert(afi_vn && afi_un);
		assert(!rfapiRaddr2Qprefix(&rfd->un_addr, &pfx_un));

		rn = route_node_get(h->un[afi_un], &pfx_un);
		assert(rn);
		rfd->next = rn->info;
		rn->info = rfd;
		rfd->un_node = rn;
	}
	return rfapi_open_inner(rfd, bgp, h, rfg);
}

struct rfapi_vn_option *rfapiVnOptionsDup(struct rfapi_vn_option *orig)
{
	struct rfapi_vn_option *head = NULL;
	struct rfapi_vn_option *tail = NULL;
	struct rfapi_vn_option *vo = NULL;

	for (vo = orig; vo; vo = vo->next) {
		struct rfapi_vn_option *new;

		new = XCALLOC(MTYPE_RFAPI_VN_OPTION,
			      sizeof(struct rfapi_vn_option));
		memcpy(new, vo, sizeof(struct rfapi_vn_option));
		new->next = NULL;

		if (tail) {
			tail->next = new;
		} else {
			head = tail = new;
		}
	}
	return head;
}

struct rfapi_un_option *rfapiUnOptionsDup(struct rfapi_un_option *orig)
{
	struct rfapi_un_option *head = NULL;
	struct rfapi_un_option *tail = NULL;
	struct rfapi_un_option *uo = NULL;

	for (uo = orig; uo; uo = uo->next) {
		struct rfapi_un_option *new;

		new = XCALLOC(MTYPE_RFAPI_UN_OPTION,
			      sizeof(struct rfapi_un_option));
		memcpy(new, uo, sizeof(struct rfapi_un_option));
		new->next = NULL;

		if (tail) {
			tail->next = new;
		} else {
			head = tail = new;
		}
	}
	return head;
}

struct bgp_tea_options *rfapiOptionsDup(struct bgp_tea_options *orig)
{
	struct bgp_tea_options *head = NULL;
	struct bgp_tea_options *tail = NULL;
	struct bgp_tea_options *hop = NULL;

	for (hop = orig; hop; hop = hop->next) {
		struct bgp_tea_options *new;

		new = XCALLOC(MTYPE_BGP_TEA_OPTIONS,
			      sizeof(struct bgp_tea_options));
		memcpy(new, hop, sizeof(struct bgp_tea_options));
		new->next = NULL;
		if (hop->value) {
			new->value = XCALLOC(MTYPE_BGP_TEA_OPTIONS_VALUE,
					     hop->length);
			memcpy(new->value, hop->value, hop->length);
		}
		if (tail) {
			tail->next = new;
		} else {
			head = tail = new;
		}
	}
	return head;
}

void rfapiFreeBgpTeaOptionChain(struct bgp_tea_options *p)
{
	struct bgp_tea_options *next;

	while (p) {
		next = p->next;

		if (p->value) {
			XFREE(MTYPE_BGP_TEA_OPTIONS_VALUE, p->value);
			p->value = NULL;
		}
		XFREE(MTYPE_BGP_TEA_OPTIONS, p);

		p = next;
	}
}

void rfapiAdbFree(struct rfapi_adb *adb)
{
	XFREE(MTYPE_RFAPI_ADB, adb);
}

static int
rfapi_query_inner(void *handle, struct rfapi_ip_addr *target,
		  struct rfapi_l2address_option *l2o, /* may be NULL */
		  struct rfapi_next_hop_entry **ppNextHopEntry)
{
	afi_t afi;
	struct prefix p;
	struct prefix p_original;
	struct route_node *rn;
	struct rfapi_descriptor *rfd = (struct rfapi_descriptor *)handle;
	struct bgp *bgp = rfd->bgp;
	struct rfapi_next_hop_entry *pNHE = NULL;
	struct rfapi_ip_addr *self_vn_addr = NULL;
	int eth_is_0 = 0;
	int use_eth_resolution = 0;
	struct rfapi_next_hop_entry *i_nhe;

	/* preemptive */
	if (!bgp) {
		vnc_zlog_debug_verbose("%s: No BGP instance, returning ENXIO",
				       __func__);
		return ENXIO;
	}
	if (!bgp->rfapi) {
		vnc_zlog_debug_verbose("%s: No RFAPI instance, returning ENXIO",
				       __func__);
		return ENXIO;
	}
	if (bgp->rfapi->flags & RFAPI_INCALLBACK) {
		vnc_zlog_debug_verbose(
			"%s: Called during calback, returning EDEADLK",
			__func__);
		return EDEADLK;
	}

	if (!is_valid_rfd(rfd)) {
		vnc_zlog_debug_verbose("%s: invalid handle, returning EBADF",
				       __func__);
		return EBADF;
	}

	rfd->rsp_counter++;		  /* dedup: identify this generation */
	rfd->rsp_time = rfapi_time(NULL); /* response content dedup */
	rfd->ftd_last_allowed_time =
		bgp_clock()
		- bgp->rfapi_cfg->rfp_cfg.ftd_advertisement_interval;

	if (l2o) {
		if (!memcmp(l2o->macaddr.octet, rfapi_ethaddr0.octet,
			    ETH_ALEN)) {
			eth_is_0 = 1;
		}
		/* per t/c Paul/Lou 151022 */
		if (!eth_is_0 || l2o->logical_net_id) {
			use_eth_resolution = 1;
		}
	}

	if (ppNextHopEntry)
		*ppNextHopEntry = NULL;

	/*
	 * Save original target in prefix form. In case of L2-based queries,
	 * p_original will be modified to reflect the L2 target
	 */
	assert(!rfapiRaddr2Qprefix(target, &p_original));

	if (bgp->rfapi_cfg->rfp_cfg.download_type == RFAPI_RFP_DOWNLOAD_FULL) {
		/* convert query to 0/0 when full-table download is enabled */
		memset((char *)&p, 0, sizeof(p));
		p.family = target->addr_family;
	} else {
		p = p_original;
	}

	{
		char buf[PREFIX_STRLEN];
		char *s;

		prefix2str(&p, buf, sizeof(buf));
		vnc_zlog_debug_verbose("%s(rfd=%p, target=%s, ppNextHop=%p)",
				       __func__, rfd, buf, ppNextHopEntry);

		s = ecommunity_ecom2str(rfd->import_table->rt_import_list,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		vnc_zlog_debug_verbose(
			"%s rfd->import_table=%p, rfd->import_table->rt_import_list: %s",
			__func__, rfd->import_table, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	afi = family2afi(p.family);
	assert(afi);

	if (CHECK_FLAG(bgp->rfapi_cfg->flags,
		       BGP_VNC_CONFIG_FILTER_SELF_FROM_RSP)) {
		self_vn_addr = &rfd->vn_addr;
	}

	if (use_eth_resolution) {
		uint32_t logical_net_id = l2o->logical_net_id;
		struct ecommunity *l2com;

		/*
		 * fix up p_original to contain L2 address
		 */
		rfapiL2o2Qprefix(l2o, &p_original);

		l2com = bgp_rfapi_get_ecommunity_by_lni_label(
			bgp, 1, logical_net_id, l2o->label);
		if (l2com) {
			uint8_t *v = l2com->val;
			logical_net_id = (v[5] << 16) + (v[6] << 8) + (v[7]);
		}
		/*
		 * Ethernet/L2-based lookup
		 *
		 * Always returns IT node corresponding to route
		 */

		if (RFAPI_RFP_DOWNLOAD_FULL
		    == bgp->rfapi_cfg->rfp_cfg.download_type) {
			eth_is_0 = 1;
		}

		rn = rfapiMonitorEthAdd(
			bgp, rfd, (eth_is_0 ? &rfapi_ethaddr0 : &l2o->macaddr),
			logical_net_id);

		if (eth_is_0) {
			struct rfapi_ip_prefix rprefix;

			memset(&rprefix, 0, sizeof(rprefix));
			rprefix.prefix.addr_family = target->addr_family;
			if (target->addr_family == AF_INET) {
				rprefix.length = 32;
			} else {
				rprefix.length = 128;
			}

			pNHE = rfapiEthRouteTable2NextHopList(
				logical_net_id, &rprefix,
				rfd->response_lifetime, self_vn_addr,
				rfd->rib[afi], &p_original);
			goto done;
		}

	} else {

		/*
		 * IP-based lookup
		 */

		rn = rfapiMonitorAdd(bgp, rfd, &p);

		/*
		 * If target address is 0, this request is special: means to
		 * return ALL routes in the table
		 *
		 * Monitors for All-Routes queries get put on a special list,
		 * not in the VPN tree
		 */
		if (RFAPI_0_PREFIX(&p)) {

			vnc_zlog_debug_verbose("%s: 0-prefix", __func__);

			/*
			 * Generate nexthop list for caller
			 */
			pNHE = rfapiRouteTable2NextHopList(
				rfd->import_table->imported_vpn[afi],
				rfd->response_lifetime, self_vn_addr,
				rfd->rib[afi], &p_original);
			goto done;
		}

		if (rn) {
			route_lock_node(rn); /* so we can unlock below */
		} else {
			/*
			 * returns locked node. Don't unlock yet because the
			 * unlock
			 * might free it before we're done with it. This
			 * situation
			 * could occur when rfapiMonitorGetAttachNode() returns
			 * a
			 * newly-created default node.
			 */
			rn = rfapiMonitorGetAttachNode(rfd, &p);
		}
	}

	assert(rn);
	if (!rn->info) {
		route_unlock_node(rn);
		vnc_zlog_debug_verbose(
			"%s: VPN route not found, returning ENOENT", __func__);
		return ENOENT;
	}

	if (VNC_DEBUG(RFAPI_QUERY)) {
		rfapiShowImportTable(NULL, "query",
				     rfd->import_table->imported_vpn[afi], 1);
	}

	if (use_eth_resolution) {

		struct rfapi_ip_prefix rprefix;

		memset(&rprefix, 0, sizeof(rprefix));
		rprefix.prefix.addr_family = target->addr_family;
		if (target->addr_family == AF_INET) {
			rprefix.length = 32;
		} else {
			rprefix.length = 128;
		}

		pNHE = rfapiEthRouteNode2NextHopList(
			rn, &rprefix, rfd->response_lifetime, self_vn_addr,
			rfd->rib[afi], &p_original);


	} else {
		/*
		 * Generate answer to query
		 */
		pNHE = rfapiRouteNode2NextHopList(rn, rfd->response_lifetime,
						  self_vn_addr, rfd->rib[afi],
						  &p_original);
	}

	route_unlock_node(rn);

done:
	if (ppNextHopEntry) {
		/* only count if caller gets it */
		++bgp->rfapi->response_immediate_count;
	}

	if (!pNHE) {
		vnc_zlog_debug_verbose("%s: NO NHEs, returning ENOENT",
				       __func__);
		return ENOENT;
	}

	/*
	 * count nexthops for statistics
	 */
	for (i_nhe = pNHE; i_nhe; i_nhe = i_nhe->next) {
		++rfd->stat_count_nh_reachable;
	}

	if (ppNextHopEntry) {
		*ppNextHopEntry = pNHE;
	} else {
		rfapi_free_next_hop_list(pNHE);
	}

	vnc_zlog_debug_verbose("%s: success", __func__);
	return 0;
}

/*
 * support on-the-fly reassignment of an already-open nve to a new
 * nve-group in the event that its original nve-group is
 * administratively deleted.
 */
static int rfapi_open_rfd(struct rfapi_descriptor *rfd, struct bgp *bgp)
{
	struct prefix pfx_vn;
	struct prefix pfx_un;
	struct rfapi_nve_group_cfg *rfg;
	struct rfapi *h;
	struct rfapi_cfg *hc;
	int rc;

	h = bgp->rfapi;
	if (!h)
		return ENXIO;

	hc = bgp->rfapi_cfg;
	if (!hc)
		return ENXIO;

	rc = rfapiRaddr2Qprefix(&rfd->vn_addr, &pfx_vn);
	assert(!rc);

	rc = rfapiRaddr2Qprefix(&rfd->un_addr, &pfx_un);
	assert(!rc);

	/*
	 * Find the matching nve group config block
	 */
	rfg = bgp_rfapi_cfg_match_group(hc, &pfx_vn, &pfx_un);
	if (!rfg) {
		return ENOENT;
	}

	/*
	 * check nve group config block for required values
	 */
	if (!rfg->rt_export_list || !rfg->rfapi_import_table) {

		return ENOMSG;
	}

	rc = rfapi_open_inner(rfd, bgp, h, rfg);
	if (rc) {
		return rc;
	}

	/*
	 * re-advertise registered routes, this time as part of new NVE-group
	 */
	rfapiApReadvertiseAll(bgp, rfd);

	/*
	 * re-attach callbacks to import table
	 */
	if (!(bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_CALLBACK_DISABLE)) {
		rfapiMonitorAttachImportHd(rfd);
	}

	return 0;
}

/*------------------------------------------
 * rfapi_open
 *
 * This function initializes a NVE record and associates it with
 * the specified VN and underlay network addresses
 *
 * input:
 *      rfp_start_val   value returned by rfp_start
 *	vn		NVE virtual network address
 *
 *	un		NVE underlay network address
 *
 *	default_options	Default options to use on registrations.
 *			For now only tunnel type is supported.
 *			May be overridden per-prefix in rfapi_register().
 *			Caller owns (rfapi_open() does not free)
 *
 *	response_cb	Pointer to next hop list update callback function or
 *			NULL when no callbacks are desired.
 *
 *	userdata	Passed to subsequent response_cb invocations.
 *
 * output:
 *	response_lifetime The length of time that responses sent to this
 *			NVE are valid.
 *
 *	pHandle		pointer to location to store rfapi handle. The
 *			handle must be passed on subsequent rfapi_ calls.
 *
 *
 * return value:
 *	0		Success
 *	EEXIST		NVE with this {vn,un} already open
 *	ENOENT		No matching nve group config
 *	ENOMSG		Matched nve group config was incomplete
 *	ENXIO		BGP or VNC not configured
 *	EAFNOSUPPORT	Matched nve group specifies auto-assignment of RD,
 *			but underlay network address is not IPv4
 *	EDEADLK		Called from within a callback procedure
 *------------------------------------------*/
int rfapi_open(void *rfp_start_val, struct rfapi_ip_addr *vn,
	       struct rfapi_ip_addr *un,
	       struct rfapi_un_option *default_options,
	       uint32_t *response_lifetime,
	       void *userdata, /* callback cookie */
	       rfapi_handle *pHandle)
{
	struct bgp *bgp;
	struct rfapi *h;
	struct rfapi_descriptor *rfd;
	struct rfapi_cfg *hc;
	struct rfapi_nve_group_cfg *rfg;

	struct prefix pfx_vn;
	struct prefix pfx_un;

	int rc;
	rfapi_handle hh = NULL;
	int reusing_provisional = 0;

	{
		char buf[2][INET_ADDRSTRLEN];
		vnc_zlog_debug_verbose(
			"%s: VN=%s UN=%s", __func__,
			rfapiRfapiIpAddr2Str(vn, buf[0], INET_ADDRSTRLEN),
			rfapiRfapiIpAddr2Str(un, buf[1], INET_ADDRSTRLEN));
	}

	assert(pHandle);
	*pHandle = NULL;

	bgp = rfapi_bgp_lookup_by_rfp(rfp_start_val);
	if (!bgp)
		return ENXIO;

	h = bgp->rfapi;
	if (!h)
		return ENXIO;

	hc = bgp->rfapi_cfg;
	if (!hc)
		return ENXIO;

	if (h->flags & RFAPI_INCALLBACK)
		return EDEADLK;

	rc = rfapiRaddr2Qprefix(vn, &pfx_vn);
	assert(!rc);

	rc = rfapiRaddr2Qprefix(un, &pfx_un);
	assert(!rc);

	/*
	 * already have a descriptor with VN and UN?
	 */
	if (!rfapi_find_handle(bgp, vn, un, &hh)) {
		/*
		 * we might have set up a handle for static routes before
		 * this NVE was opened. In that case, reuse the handle
		 */
		rfd = hh;
		if (!CHECK_FLAG(rfd->flags, RFAPI_HD_FLAG_PROVISIONAL)) {
			return EEXIST;
		}

		/*
		 * reuse provisional descriptor
		 * hh is not NULL
		 */
		reusing_provisional = 1;
	}

	/*
	 * Find the matching nve group config block
	 */
	rfg = bgp_rfapi_cfg_match_group(hc, &pfx_vn, &pfx_un);
	if (!rfg) {
		++h->stat.count_unknown_nves;
		{
			char buf[2][INET_ADDRSTRLEN];
			zlog_notice("%s: no matching group VN=%s UN=%s",
				    __func__,
				    rfapiRfapiIpAddr2Str(vn, buf[0],
							 INET_ADDRSTRLEN),
				    rfapiRfapiIpAddr2Str(un, buf[1],
							 INET_ADDRSTRLEN));
		}
		return ENOENT;
	}

	/*
	 * check nve group config block for required values
	 */
	if (!rfg->rt_export_list || !rfg->rfapi_import_table) {

		++h->stat.count_unknown_nves;
		return ENOMSG;
	}

	/*
	 * If group config specifies auto-rd assignment, check that
	 * VN address is IPv4|v6 so we don't fail in rfapi_open_inner().
	 * Check here so we don't need to unwind memory allocations, &c.
	 */
	if ((rfg->rd.family == AF_UNIX) && (vn->addr_family != AF_INET)
	    && (vn->addr_family != AF_INET6)) {
		return EAFNOSUPPORT;
	}

	if (hh) {
		/*
		 * reusing provisional rfd
		 */
		rfd = hh;
	} else {
		rfd = XCALLOC(MTYPE_RFAPI_DESC,
			      sizeof(struct rfapi_descriptor));
	}
	assert(rfd);

	rfd->bgp = bgp;
	if (default_options) {
		struct rfapi_un_option *p;

		for (p = default_options; p; p = p->next) {
			if ((RFAPI_UN_OPTION_TYPE_PROVISIONAL == p->type)) {
				rfd->flags |= RFAPI_HD_FLAG_PROVISIONAL;
			}
			if ((RFAPI_UN_OPTION_TYPE_TUNNELTYPE == p->type)) {
				rfd->default_tunneltype_option = p->v.tunnel;
			}
		}
	}

	/*
	 * Fill in caller fields
	 */
	rfd->vn_addr = *vn;
	rfd->un_addr = *un;
	rfd->cookie = userdata;

	if (!reusing_provisional) {
		rc = rfapi_init_and_open(bgp, rfd, rfg);
		/*
		 * This can fail only if the VN address is IPv6 and the group
		 * specified auto-assignment of RDs, which only works for v4,
		 * and the check above should catch it.
		 *
		 * Another failure possibility is that we were called
		 * during an rfapi callback. Also checked above.
		 */
		assert(!rc);
	}

	if (response_lifetime)
		*response_lifetime = rfd->response_lifetime;
	*pHandle = rfd;
	return 0;
}

/*
 * For use with debug functions
 */
static int rfapi_set_response_cb(struct rfapi_descriptor *rfd,
				 rfapi_response_cb_t *response_cb)
{
	if (!is_valid_rfd(rfd))
		return EBADF;
	rfd->response_cb = response_cb;
	return 0;
}

/*
 * rfapi_close_inner
 *
 * Does almost all the work of rfapi_close, except:
 *	1. preserves the descriptor (doesn't free it)
 *	2. preserves the prefix query list (i.e., rfd->mon list)
 *	3. preserves the advertised prefix list (rfd->advertised)
 *	4. preserves the rib and rib_pending tables
 *
 * The purpose of organizing it this way is to support on-the-fly
 * reassignment of an already-open nve to a new nve-group in the
 * event that its original nve-group is administratively deleted.
 */
static int rfapi_close_inner(struct rfapi_descriptor *rfd, struct bgp *bgp)
{
	int rc;
	struct prefix pfx_vn;
	struct prefix_rd prd; /* currently always 0 for VN->UN */

	if (!is_valid_rfd(rfd))
		return EBADF;

	rc = rfapiRaddr2Qprefix(&rfd->vn_addr, &pfx_vn);
	assert(!rc); /* should never have bad AF in stored vn address */

	/*
	 * update exported routes to reflect disappearance of this NVE as
	 * nexthop
	 */
	vnc_direct_bgp_del_nve(bgp, rfd);
	vnc_zebra_del_nve(bgp, rfd);

	/*
	 * unlink this HD's monitors from import table
	 */
	rfapiMonitorDetachImportHd(rfd);

	/*
	 * Unlink from Import Table
	 * NB rfd->import_table will be NULL if we are closing a stale
	 * descriptor
	 */
	if (rfd->import_table)
		rfapiImportTableRefDelByIt(bgp, rfd->import_table);
	rfd->import_table = NULL;

	/*
	 * Construct route distinguisher
	 */
	memset(&prd, 0, sizeof(prd));
	prd = rfd->rd;
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	/*
	 * withdraw tunnel
	 */
	del_vnc_route(rfd, rfd->peer, bgp, SAFI_ENCAP,
		      &pfx_vn, /* prefix being advertised */
		      &prd,    /* route distinguisher to use (0 for ENCAP) */
		      ZEBRA_ROUTE_BGP, BGP_ROUTE_RFP, NULL, 0); /* no kill */

	/*
	 * Construct route distinguisher for VPN routes
	 */
	prd = rfd->rd;
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	/*
	 * find all VPN routes associated with this rfd and delete them, too
	 */
	rfapiApWithdrawAll(bgp, rfd);

	/*
	 * remove this nve descriptor from the list of nves
	 * associated with the nve group
	 */
	if (rfd->rfg) {
		listnode_delete(rfd->rfg->nves, rfd);
		rfd->rfg = NULL; /* XXX mark as orphaned/stale */
	}

	if (rfd->rt_export_list)
		ecommunity_free(&rfd->rt_export_list);
	rfd->rt_export_list = NULL;

	/*
	 * free peer structure (possibly delayed until its
	 * refcount reaches zero)
	 */
	if (rfd->peer) {
		vnc_zlog_debug_verbose("%s: calling peer_delete(%p), #%d",
				       __func__, rfd->peer, rfd->peer->lock);
		peer_delete(rfd->peer);
	}
	rfd->peer = NULL;

	return 0;
}

int rfapi_close(void *handle)
{
	struct rfapi_descriptor *rfd = (struct rfapi_descriptor *)handle;
	int rc;
	struct route_node *node;
	struct bgp *bgp;
	struct rfapi *h;

	vnc_zlog_debug_verbose("%s: rfd=%p", __func__, rfd);

#if RFAPI_WHO_IS_CALLING_ME
#ifdef HAVE_GLIBC_BACKTRACE
#define RFAPI_DEBUG_BACKTRACE_NENTRIES 5
	{
		void *buf[RFAPI_DEBUG_BACKTRACE_NENTRIES];
		char **syms;
		int i;
		size_t size;

		size = backtrace(buf, RFAPI_DEBUG_BACKTRACE_NENTRIES);
		syms = backtrace_symbols(buf, size);
		for (i = 0; i < size && i < RFAPI_DEBUG_BACKTRACE_NENTRIES;
		     ++i) {
			vnc_zlog_debug_verbose("backtrace[%2d]: %s", i,
					       syms[i]);
		}
		free(syms);
	}
#endif
#endif

	bgp = rfd->bgp;
	if (!bgp)
		return ENXIO;

	h = bgp->rfapi;
	if (!h)
		return ENXIO;

	if (!is_valid_rfd(rfd))
		return EBADF;

	if (h->flags & RFAPI_INCALLBACK) {
		/*
		 * Queue these close requests for processing after callback
		 * is finished
		 */
		if (!CHECK_FLAG(rfd->flags,
				RFAPI_HD_FLAG_CLOSING_ADMINISTRATIVELY)) {
			work_queue_add(h->deferred_close_q, handle);
			vnc_zlog_debug_verbose(
				"%s: added handle %p to deferred close queue",
				__func__, handle);
		}
		return 0;
	}

	if (CHECK_FLAG(rfd->flags, RFAPI_HD_FLAG_CLOSING_ADMINISTRATIVELY)) {

		vnc_zlog_debug_verbose("%s administrative close rfd=%p",
				       __func__, rfd);

		if (h && h->rfp_methods.close_cb) {
			vnc_zlog_debug_verbose(
				"%s calling close callback rfd=%p", __func__,
				rfd);

			/*
			 * call the callback fairly early so that it can still
			 * lookup un/vn
			 * from handle, etc.
			 *
			 * NB RFAPI_INCALLBACK is tested above, so if we reach
			 * this point
			 * we are not already in the context of a callback.
			 */
			h->flags |= RFAPI_INCALLBACK;
			(*h->rfp_methods.close_cb)(handle, EIDRM);
			h->flags &= ~RFAPI_INCALLBACK;
		}
	}

	if (rfd->rfg) {
		/*
		 * Orphaned descriptors have already done this part, so do
		 * only for non-orphaned descriptors.
		 */
		if ((rc = rfapi_close_inner(rfd, bgp)))
			return rc;
	}

	/*
	 * Remove descriptor from UN index
	 * (remove from chain at node)
	 */
	rc = rfapi_find_node(bgp, &rfd->vn_addr, &rfd->un_addr, &node);
	if (!rc) {
		struct rfapi_descriptor *hh;

		if (node->info == rfd) {
			node->info = rfd->next;
		} else {

			for (hh = node->info; hh; hh = hh->next) {
				if (hh->next == rfd) {
					hh->next = rfd->next;
					break;
				}
			}
		}
		route_unlock_node(node);
	}

	/*
	 * remove from descriptor list
	 */
	listnode_delete(&h->descriptors, rfd);

	/*
	 * Delete monitor list items and free monitor structures
	 */
	(void)rfapiMonitorDelHd(rfd);

	/*
	 * release advertised prefix data
	 */
	rfapiApRelease(&rfd->advertised);

	/*
	 * Release RFP callback RIB
	 */
	rfapiRibFree(rfd);

	/*
	 * free descriptor
	 */
	memset(rfd, 0, sizeof(struct rfapi_descriptor));
	XFREE(MTYPE_RFAPI_DESC, rfd);

	return 0;
}

/*
 * Reopen a nve descriptor. If the descriptor's NVE-group
 * does not exist (e.g., if it has been administratively removed),
 * reassignment to a new NVE-group is attempted.
 *
 * If NVE-group reassignment fails, the descriptor becomes "stale"
 * (rfd->rfg == NULL implies "stale:). The only permissible API operation
 * on a stale descriptor is rfapi_close(). Any other rfapi_* API operation
 * on the descriptor will return ESTALE.
 *
 * Reopening a descriptor is a potentially expensive operation, because
 * it involves withdrawing any routes advertised by the NVE, withdrawing
 * the NVE's route queries, and then re-adding them all after a new
 * NVE-group is assigned. There are also possible route-export affects
 * caused by deleting and then adding the NVE: advertised prefixes
 * and nexthop lists for exported routes can turn over.
 */
int rfapi_reopen(struct rfapi_descriptor *rfd, struct bgp *bgp)
{
	struct rfapi *h;
	int rc;

	if ((rc = rfapi_close_inner(rfd, bgp))) {
		return rc;
	}
	if ((rc = rfapi_open_rfd(rfd, bgp))) {

		h = bgp->rfapi;

		assert(!CHECK_FLAG(h->flags, RFAPI_INCALLBACK));

		if (CHECK_FLAG(rfd->flags,
			       RFAPI_HD_FLAG_CLOSING_ADMINISTRATIVELY)
		    && h && h->rfp_methods.close_cb) {

			/*
			 * NB RFAPI_INCALLBACK is tested above, so if we reach
			 * this point
			 * we are not already in the context of a callback.
			 */
			h->flags |= RFAPI_INCALLBACK;
			(*h->rfp_methods.close_cb)((rfapi_handle)rfd, ESTALE);
			h->flags &= ~RFAPI_INCALLBACK;
		}
		return rc;
	}
	return 0;
}

/***********************************************************************
 *			NVE Routes
 ***********************************************************************/
/*
 * Announce reachability to this prefix via the NVE
 */
int rfapi_register(void *handle, struct rfapi_ip_prefix *prefix,
		   uint32_t lifetime, /* host byte order */
		   struct rfapi_un_option *options_un,
		   struct rfapi_vn_option *options_vn,
		   rfapi_register_action action)
{
	struct rfapi_descriptor *rfd = (struct rfapi_descriptor *)handle;
	struct bgp *bgp;
	struct prefix p;
	struct prefix *pfx_ip = NULL;
	struct prefix_rd prd;
	afi_t afi;
	struct prefix pfx_mac_buf;
	struct prefix *pfx_mac = NULL;
	struct prefix pfx_vn_buf;
	const char *action_str = NULL;
	uint32_t *label = NULL;
	struct rfapi_vn_option *vo;
	struct rfapi_l2address_option *l2o = NULL;
	struct prefix_rd *prd_override = NULL;

	switch (action) {
	case RFAPI_REGISTER_ADD:
		action_str = "add";
		break;
	case RFAPI_REGISTER_WITHDRAW:
		action_str = "withdraw";
		break;
	case RFAPI_REGISTER_KILL:
		action_str = "kill";
		break;
	default:
		assert(0);
		break;
	}

	/*
	 * Inspect VN options
	 */
	for (vo = options_vn; vo; vo = vo->next) {
		if (RFAPI_VN_OPTION_TYPE_L2ADDR == vo->type) {
			l2o = &vo->v.l2addr;
		}
		if (RFAPI_VN_OPTION_TYPE_INTERNAL_RD == vo->type) {
			prd_override = &vo->v.internal_rd;
		}
	}

	/*********************************************************************
	 *			advertise prefix
	 *********************************************************************/

	/*
	 * set <p> based on <prefix>
	 */
	assert(!rfapiRprefix2Qprefix(prefix, &p));

	afi = family2afi(prefix->prefix.addr_family);
	assert(afi);


	{
		char buf[PREFIX_STRLEN];

		prefix2str(&p, buf, sizeof(buf));
		vnc_zlog_debug_verbose(
			"%s(rfd=%p, pfx=%s, lifetime=%d, opts_un=%p, opts_vn=%p, action=%s)",
			__func__, rfd, buf, lifetime, options_un, options_vn,
			action_str);
	}

	/*
	 * These tests come after the prefix conversion so that we can
	 * print the prefix in a debug message before failing
	 */

	bgp = rfd->bgp;
	if (!bgp) {
		vnc_zlog_debug_verbose("%s: no BGP instance: returning ENXIO",
				       __func__);
		return ENXIO;
	}
	if (!bgp->rfapi) {
		vnc_zlog_debug_verbose("%s: no RFAPI instance: returning ENXIO",
				       __func__);
		return ENXIO;
	}
	if (!rfd->rfg) {
		if (RFAPI_REGISTER_ADD == action) {
			++bgp->rfapi->stat.count_registrations_failed;
		}
		vnc_zlog_debug_verbose(
			"%s: rfd=%p, no RF GRP instance: returning ESTALE",
			__func__, rfd);
		return ESTALE;
	}

	if (bgp->rfapi->flags & RFAPI_INCALLBACK) {
		if (RFAPI_REGISTER_ADD == action) {
			++bgp->rfapi->stat.count_registrations_failed;
		}
		vnc_zlog_debug_verbose("%s: in callback: returning EDEADLK",
				       __func__);
		return EDEADLK;
	}

	if (!is_valid_rfd(rfd)) {
		if (RFAPI_REGISTER_ADD == action) {
			++bgp->rfapi->stat.count_registrations_failed;
		}
		vnc_zlog_debug_verbose("%s: invalid handle: returning EBADF",
				       __func__);
		return EBADF;
	}

	/*
	 * Is there a MAC address in this registration?
	 */
	if (l2o && !RFAPI_0_ETHERADDR(&l2o->macaddr)) {
		rfapiL2o2Qprefix(l2o, &pfx_mac_buf);
		pfx_mac = &pfx_mac_buf;
	}

	/*
	 * Is there an IP prefix in this registration?
	 */
	if (!(RFAPI_0_PREFIX(&p) && RFAPI_HOST_PREFIX(&p))) {
		pfx_ip = &p;
	} else {
		if (!pfx_mac) {
			vnc_zlog_debug_verbose(
				"%s: missing mac addr that is required for host 0 pfx",
				__func__);
			if (RFAPI_REGISTER_ADD == action) {
				++bgp->rfapi->stat.count_registrations_failed;
			}
			return EINVAL;
		}
		if (rfapiRaddr2Qprefix(&rfd->vn_addr, &pfx_vn_buf)) {
			vnc_zlog_debug_verbose(
				"%s: handle has bad vn_addr: returning EBADF",
				__func__);
			if (RFAPI_REGISTER_ADD == action) {
				++bgp->rfapi->stat.count_registrations_failed;
			}
			return EBADF;
		}
	}

	if (RFAPI_REGISTER_ADD == action) {
		++bgp->rfapi->stat.count_registrations;
	}

	/*
	 * Figure out if this registration is missing an IP address
	 *
	 * MAC-addr based:
	 *
	 *  In RFAPI, we use prefixes in family AF_LINK to store
	 *  the MAC addresses. These prefixes are used for the
	 *  list of advertised prefixes and in the RFAPI import
	 *  tables.
	 *
	 *  In BGP proper, we use the prefix matching the NVE's
	 *  VN address with a host prefix-length (i.e., 32 or 128).
	 *
	 */
	if (l2o && l2o->logical_net_id && RFAPI_0_PREFIX(&p)
	    && RFAPI_HOST_PREFIX(&p)) {

		rfapiL2o2Qprefix(l2o, &pfx_mac_buf);
		pfx_mac = &pfx_mac_buf;
	}

	/*
	 * Construct route distinguisher
	 */
	if (prd_override) {
		prd = *prd_override;
	} else {
		memset(&prd, 0, sizeof(prd));
		if (pfx_mac) {
			prd.family = AF_UNSPEC;
			prd.prefixlen = 64;
			encode_rd_type(RD_TYPE_VNC_ETH, prd.val);
			if (l2o->local_nve_id
			    || !(rfd->rfg->flags & RFAPI_RFG_L2RD)) {
				/*
				 * If Local NVE ID is specified in message, use
				 * it.
				 * (if no local default configured, also use it
				 * even if 0)
				 */
				prd.val[1] = l2o->local_nve_id;
			} else {
				if (rfd->rfg->l2rd) {
					/*
					 * locally-configured literal value
					 */
					prd.val[1] = rfd->rfg->l2rd;
				} else {
					/*
					 * 0 means auto:vn, which means use LSB
					 * of VN addr
					 */
					if (rfd->vn_addr.addr_family
					    == AF_INET) {
						prd.val[1] =
							*(((char *)&rfd->vn_addr
								   .addr.v4
								   .s_addr)
							  + 3);
					} else {
						prd.val[1] =
							*(((char *)&rfd->vn_addr
								   .addr.v6
								   .s6_addr)
							  + 15);
					}
				}
			}
			memcpy(prd.val + 2, pfx_mac->u.prefix_eth.octet, 6);
		} else {
			prd = rfd->rd;
			prd.family = AF_UNSPEC;
			prd.prefixlen = 64;
		}
	}


	if (action == RFAPI_REGISTER_WITHDRAW
	    || action == RFAPI_REGISTER_KILL) {

		int adv_tunnel = 0;

		/*
		 * withdraw previous advertisement
		 */
		del_vnc_route(
			rfd, rfd->peer, bgp, SAFI_MPLS_VPN,
			pfx_ip ? pfx_ip
			       : &pfx_vn_buf, /* prefix being advertised */
			&prd, /* route distinguisher (0 for ENCAP) */
			ZEBRA_ROUTE_BGP, BGP_ROUTE_RFP, NULL,
			action == RFAPI_REGISTER_KILL);

		if (0 == rfapiApDelete(bgp, rfd, &p, pfx_mac, &prd,
				       &adv_tunnel)) {
			if (adv_tunnel)
				rfapiTunnelRouteAnnounce(
					bgp, rfd, &rfd->max_prefix_lifetime);
		}

	} else {

		int adv_tunnel = 0;
		uint32_t local_pref;
		struct ecommunity *rtlist = NULL;
		struct ecommunity_val ecom_value;

		if (!rfapiApCount(rfd)) {
			/*
			 * make sure we advertise tunnel route upon adding the
			 * first VPN route
			 */
			adv_tunnel = 1;
		}

		if (rfapiApAdd(bgp, rfd, &p, pfx_mac, &prd, lifetime,
			       prefix->cost, l2o)) {
			adv_tunnel = 1;
		}

		vnc_zlog_debug_verbose("%s: adv_tunnel = %d", __func__,
				       adv_tunnel);
		if (adv_tunnel) {
			vnc_zlog_debug_verbose("%s: announcing tunnel route",
					       __func__);
			rfapiTunnelRouteAnnounce(bgp, rfd,
						 &rfd->max_prefix_lifetime);
		}

		vnc_zlog_debug_verbose("%s: calling add_vnc_route", __func__);

		local_pref = rfp_cost_to_localpref(prefix->cost);

		if (l2o && l2o->label)
			label = &l2o->label;

		if (pfx_mac) {
			struct ecommunity *l2com = NULL;

			if (label) {
				l2com = bgp_rfapi_get_ecommunity_by_lni_label(
					bgp, 1, l2o->logical_net_id, *label);
			}
			if (l2com) {
				rtlist = ecommunity_dup(l2com);
			} else {
				/*
				 * If mac address is set, add an RT based on the
				 * registered LNI
				 */
				memset((char *)&ecom_value, 0,
				       sizeof(ecom_value));
				ecom_value.val[1] = ECOMMUNITY_ROUTE_TARGET;
				ecom_value.val[5] =
					(l2o->logical_net_id >> 16) & 0xff;
				ecom_value.val[6] =
					(l2o->logical_net_id >> 8) & 0xff;
				ecom_value.val[7] =
					(l2o->logical_net_id >> 0) & 0xff;
				rtlist = ecommunity_new();
				ecommunity_add_val(rtlist, &ecom_value);
			}
			if (l2o->tag_id) {
				as_t as = bgp->as;
				uint16_t val = l2o->tag_id;
				memset((char *)&ecom_value, 0,
				       sizeof(ecom_value));
				ecom_value.val[1] = ECOMMUNITY_ROUTE_TARGET;
				if (as > BGP_AS_MAX) {
					ecom_value.val[0] =
						ECOMMUNITY_ENCODE_AS4;
					ecom_value.val[2] = (as >> 24) & 0xff;
					ecom_value.val[3] = (as >> 16) & 0xff;
					ecom_value.val[4] = (as >> 8) & 0xff;
					ecom_value.val[5] = as & 0xff;
				} else {
					ecom_value.val[0] =
						ECOMMUNITY_ENCODE_AS;
					ecom_value.val[2] = (as >> 8) & 0xff;
					ecom_value.val[3] = as & 0xff;
				}
				ecom_value.val[6] = (val >> 8) & 0xff;
				ecom_value.val[7] = val & 0xff;
				if (rtlist == NULL)
					rtlist = ecommunity_new();
				ecommunity_add_val(rtlist, &ecom_value);
			}
		}

		/*
		 * advertise prefix via tunnel endpoint
		 */
		add_vnc_route(
			rfd, /* rfapi descr, for export list & backref */
			bgp, /* which bgp instance */
			SAFI_MPLS_VPN, /* which SAFI */
			(pfx_ip ? pfx_ip
				: &pfx_vn_buf), /* prefix being advertised */
			&prd, /* route distinguisher to use (0 for ENCAP) */
			&rfd->vn_addr, /* nexthop */
			&local_pref,
			&lifetime, /* prefix lifetime -> Tunnel Encap attr */
			NULL, options_un, /* rfapi un options */
			options_vn,       /* rfapi vn options */
			(rtlist ? rtlist : rfd->rt_export_list), NULL, /* med */
			label, /* label: default */
			ZEBRA_ROUTE_BGP, BGP_ROUTE_RFP, 0);

		if (rtlist)
			ecommunity_free(&rtlist); /* sets rtlist = NULL */
	}

	vnc_zlog_debug_verbose("%s: success", __func__);
	return 0;
}

int rfapi_query(void *handle, struct rfapi_ip_addr *target,
		struct rfapi_l2address_option *l2o, /* may be NULL */
		struct rfapi_next_hop_entry **ppNextHopEntry)
{
	struct rfapi_descriptor *rfd = (struct rfapi_descriptor *)handle;
	struct bgp *bgp = rfd->bgp;
	int rc;

	assert(ppNextHopEntry);
	*ppNextHopEntry = NULL;

	if (bgp && bgp->rfapi) {
		bgp->rfapi->stat.count_queries++;
	}

	if (!rfd->rfg) {
		if (bgp && bgp->rfapi)
			++bgp->rfapi->stat.count_queries_failed;
		return ESTALE;
	}

	if ((rc = rfapi_query_inner(handle, target, l2o, ppNextHopEntry))) {
		if (bgp && bgp->rfapi)
			++bgp->rfapi->stat.count_queries_failed;
	}
	return rc;
}

int rfapi_query_done(rfapi_handle handle, struct rfapi_ip_addr *target)
{
	struct prefix p;
	int rc;
	struct rfapi_descriptor *rfd = (struct rfapi_descriptor *)handle;
	struct bgp *bgp = rfd->bgp;

	if (!rfd->rfg)
		return ESTALE;

	assert(target);
	rc = rfapiRaddr2Qprefix(target, &p);
	assert(!rc);

	if (!is_valid_rfd(rfd))
		return EBADF;

	/* preemptive */
	if (!bgp || !bgp->rfapi)
		return ENXIO;

	if (bgp->rfapi->flags & RFAPI_INCALLBACK)
		return EDEADLK;

	rfapiMonitorDel(bgp, rfd, &p);

	return 0;
}

int rfapi_query_done_all(rfapi_handle handle, int *count)
{
	struct rfapi_descriptor *rfd = (struct rfapi_descriptor *)handle;
	struct bgp *bgp = rfd->bgp;
	;
	int num;

	if (!rfd->rfg)
		return ESTALE;

	if (!is_valid_rfd(rfd))
		return EBADF;

	/* preemptive */
	if (!bgp || !bgp->rfapi)
		return ENXIO;

	if (bgp->rfapi->flags & RFAPI_INCALLBACK)
		return EDEADLK;

	num = rfapiMonitorDelHd(rfd);

	if (count)
		*count = num;

	return 0;
}

void rfapi_free_next_hop_list(struct rfapi_next_hop_entry *list)
{
	struct rfapi_next_hop_entry *nh;
	struct rfapi_next_hop_entry *next;

	for (nh = list; nh; nh = next) {
		next = nh->next;
		rfapi_un_options_free(nh->un_options);
		nh->un_options = NULL;
		rfapi_vn_options_free(nh->vn_options);
		nh->vn_options = NULL;
		XFREE(MTYPE_RFAPI_NEXTHOP, nh);
	}
}

/*
 * NULL handle => return total count across all nves
 */
uint32_t rfapi_monitor_count(void *handle)
{
	struct bgp *bgp = bgp_get_default();
	uint32_t count;

	if (handle) {
		struct rfapi_descriptor *rfd =
			(struct rfapi_descriptor *)handle;
		count = rfd->monitor_count;
	} else {

		if (!bgp || !bgp->rfapi)
			return 0;

		count = bgp->rfapi->monitor_count;
	}

	return count;
}

/***********************************************************************
 *			CLI/CONFIG
 ***********************************************************************/

DEFUN (debug_rfapi_show_nves,
       debug_rfapi_show_nves_cmd,
       "debug rfapi-dev show nves",
       DEBUG_STR
       DEBUG_RFAPI_STR
       SHOW_STR
       "NVE Information\n")
{
	rfapiPrintMatchingDescriptors(vty, NULL, NULL);
	return CMD_SUCCESS;
}

DEFUN (
  debug_rfapi_show_nves_vn_un,
  debug_rfapi_show_nves_vn_un_cmd,
  "debug rfapi-dev show nves <vn|un> <A.B.C.D|X:X::X:X>", /* prefix also ok */
  DEBUG_STR
  DEBUG_RFAPI_STR
  SHOW_STR
  "NVE Information\n"
  "Specify virtual network\n"
  "Specify underlay network interface\n"
  "IPv4 address\n"
  "IPv6 address\n")
{
	struct prefix pfx;

	if (!str2prefix(argv[5]->arg, &pfx)) {
		vty_out(vty, "Malformed address \"%s\"\n", argv[5]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (pfx.family != AF_INET && pfx.family != AF_INET6) {
		vty_out(vty, "Invalid address \"%s\"\n", argv[5]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv[4]->arg[0] == 'u') {
		rfapiPrintMatchingDescriptors(vty, NULL, &pfx);
	} else {
		rfapiPrintMatchingDescriptors(vty, &pfx, NULL);
	}
	return CMD_SUCCESS;
}

/*
 * Note: this function does not flush vty output, so if it is called
 * with a stream pointing to a vty, the user will have to type something
 * before the callback output shows up
 */
static void test_nexthops_callback(
	//    struct rfapi_ip_addr        *target,
	struct rfapi_next_hop_entry *next_hops, void *userdata)
{
	void *stream = userdata;

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	fp(out, "Nexthops Callback, Target=(");
	// rfapiPrintRfapiIpAddr(stream, target);
	fp(out, ")\n");

	rfapiPrintNhl(stream, next_hops);

	rfapi_free_next_hop_list(next_hops);
}

DEFUN (debug_rfapi_open,
       debug_rfapi_open_cmd,
       "debug rfapi-dev open vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X>",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "rfapi_open\n"
       "indicate vn addr follows\n"
       "virtual network interface IPv4 address\n"
       "virtual network interface IPv6 address\n"
       "indicate xt addr follows\n"
       "underlay network interface IPv4 address\n"
       "underlay network interface IPv6 address\n")
{
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	uint32_t lifetime;
	int rc;
	rfapi_handle handle;

	/*
	 * Get VN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[4]->arg, &vn)))
		return rc;

	/*
	 * Get UN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[6]->arg, &un)))
		return rc;

	rc = rfapi_open(rfapi_get_rfp_start_val_by_bgp(bgp_get_default()), &vn,
			&un, /*&uo */ NULL, &lifetime, NULL, &handle);

	vty_out(vty, "rfapi_open: status %d, handle %p, lifetime %d\n", rc,
		handle, lifetime);

	rc = rfapi_set_response_cb(handle, test_nexthops_callback);

	vty_out(vty, "rfapi_set_response_cb: status %d\n", rc);

	return CMD_SUCCESS;
}


DEFUN (debug_rfapi_close_vn_un,
       debug_rfapi_close_vn_un_cmd,
       "debug rfapi-dev close vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X>",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "rfapi_close\n"
       "indicate vn addr follows\n"
       "virtual network interface IPv4 address\n"
       "virtual network interface IPv6 address\n"
       "indicate xt addr follows\n"
       "underlay network interface IPv4 address\n"
       "underlay network interface IPv6 address\n")
{
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	rfapi_handle handle;
	int rc;

	/*
	 * Get VN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[4]->arg, &vn)))
		return rc;


	/*
	 * Get UN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[6]->arg, &un)))
		return rc;


	if (rfapi_find_handle_vty(vty, &vn, &un, &handle)) {
		vty_out(vty, "can't locate handle matching vn=%s, un=%s\n",
			argv[4]->arg, argv[6]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	rc = rfapi_close(handle);

	vty_out(vty, "rfapi_close(handle=%p): status %d\n", handle, rc);

	return CMD_SUCCESS;
}

DEFUN (debug_rfapi_close_rfd,
       debug_rfapi_close_rfd_cmd,
       "debug rfapi-dev close rfd HANDLE",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "rfapi_close\n"
       "indicate handle follows\n" "rfapi handle in hexadecimal\n")
{
	rfapi_handle handle;
	int rc;
	char *endptr = NULL;

	handle = (rfapi_handle)(uintptr_t)(strtoull(argv[4]->arg, &endptr, 16));

	if (*endptr != '\0' || (uintptr_t)handle == UINTPTR_MAX) {
		vty_out(vty, "Invalid value: %s\n", argv[4]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	rc = rfapi_close(handle);

	vty_out(vty, "rfapi_close(handle=%p): status %d\n", handle, rc);

	return CMD_SUCCESS;
}

DEFUN (debug_rfapi_register_vn_un,
       debug_rfapi_register_vn_un_cmd,
       "debug rfapi-dev register vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> prefix <A.B.C.D/M|X:X::X:X/M> lifetime SECONDS",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "rfapi_register\n"
       "indicate vn addr follows\n"
       "virtual network IPv4 interface address\n"
       "virtual network IPv6 interface address\n"
       "indicate un addr follows\n"
       "underlay network IPv4 interface address\n"
       "underlay network IPv6 interface address\n"
       "indicate prefix follows\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "indicate lifetime follows\n"
       "lifetime\n")
{
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	rfapi_handle handle;
	struct prefix pfx;
	uint32_t lifetime;
	struct rfapi_ip_prefix hpfx;
	int rc;

	/*
	 * Get VN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[4]->arg, &vn)))
		return rc;


	/*
	 * Get UN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[6]->arg, &un)))
		return rc;


	if (rfapi_find_handle_vty(vty, &vn, &un, &handle)) {
		vty_out(vty, "can't locate handle matching vn=%s, un=%s\n",
			argv[4]->arg, argv[6]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * Get prefix to advertise
	 */
	if (!str2prefix(argv[8]->arg, &pfx)) {
		vty_out(vty, "Malformed prefix \"%s\"\n", argv[8]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (pfx.family != AF_INET && pfx.family != AF_INET6) {
		vty_out(vty, "Bad family for prefix \"%s\"\n", argv[8]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	rfapiQprefix2Rprefix(&pfx, &hpfx);

	if (strmatch(argv[10]->text, "infinite")) {
		lifetime = RFAPI_INFINITE_LIFETIME;
	} else {
		lifetime = strtoul(argv[10]->arg, NULL, 10);
	}


	rc = rfapi_register(handle, &hpfx, lifetime, NULL, NULL, 0);
	if (rc) {
		vty_out(vty, "rfapi_register failed with rc=%d (%s)\n", rc,
			strerror(rc));
	}

	return CMD_SUCCESS;
}

DEFUN (debug_rfapi_register_vn_un_l2o,
       debug_rfapi_register_vn_un_l2o_cmd,
       "debug rfapi-dev register vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> prefix <A.B.C.D/M|X:X::X:X/M> lifetime SECONDS macaddr YY:YY:YY:YY:YY:YY lni (0-16777215)",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "rfapi_register\n"
       "indicate vn addr follows\n"
       "virtual network IPv4 interface address\n"
       "virtual network IPv6 interface address\n"
       "indicate un addr follows\n"
       "underlay network IPv4 interface address\n"
       "underlay network IPv6 interface address\n"
       "indicate prefix follows\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "indicate lifetime follows\n"
       "Seconds of lifetime\n"
       "indicate MAC address follows\n"
       "MAC address\n"
       "indicate lni follows\n"
       "lni value range\n")
{
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	rfapi_handle handle;
	struct prefix pfx;
	uint32_t lifetime;
	struct rfapi_ip_prefix hpfx;
	int rc;
	struct rfapi_vn_option optary[10]; /* XXX must be big enough */
	struct rfapi_vn_option *opt = NULL;
	int opt_next = 0;

	/*
	 * Get VN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[4]->arg, &vn)))
		return rc;


	/*
	 * Get UN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[6]->arg, &un)))
		return rc;


	if (rfapi_find_handle_vty(vty, &vn, &un, &handle)) {
		vty_out(vty, "can't locate handle matching vn=%s, un=%s\n",
			argv[4]->arg, argv[6]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * Get prefix to advertise
	 */
	if (!str2prefix(argv[8]->arg, &pfx)) {
		vty_out(vty, "Malformed prefix \"%s\"\n", argv[8]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (pfx.family != AF_INET && pfx.family != AF_INET6) {
		vty_out(vty, "Bad family for prefix \"%s\"\n", argv[8]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	rfapiQprefix2Rprefix(&pfx, &hpfx);

	if (strmatch(argv[10]->text, "infinite")) {
		lifetime = RFAPI_INFINITE_LIFETIME;
	} else {
		lifetime = strtoul(argv[10]->arg, NULL, 10);
	}

	/* L2 option parsing START */
	memset(optary, 0, sizeof(optary));
	optary[opt_next].v.l2addr.logical_net_id =
		strtoul(argv[14]->arg, NULL, 10);
	if ((rc = rfapiStr2EthAddr(argv[12]->arg,
				   &optary[opt_next].v.l2addr.macaddr))) {
		vty_out(vty, "Bad mac address \"%s\"\n", argv[12]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	optary[opt_next].type = RFAPI_VN_OPTION_TYPE_L2ADDR;
	if (opt_next) {
		optary[opt_next - 1].next = optary + opt_next;
	} else {
		opt = optary;
	}
	++opt_next;
	/* L2 option parsing END */

	/* TBD fixme */
	rc = rfapi_register(handle, &hpfx, lifetime, NULL /* &uo */, opt, 0);
	if (rc) {
		vty_out(vty, "rfapi_register failed with rc=%d (%s)\n", rc,
			strerror(rc));
	}

	return CMD_SUCCESS;
}


DEFUN (debug_rfapi_unregister_vn_un,
       debug_rfapi_unregister_vn_un_cmd,
       "debug rfapi-dev unregister vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> prefix <A.B.C.D/M|X:X::X:X/M>",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "rfapi_register\n"
       "indicate vn addr follows\n"
       "virtual network interface address\n"
       "indicate xt addr follows\n"
       "underlay network interface address\n"
       "indicate prefix follows\n" "prefix")
{
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	rfapi_handle handle;
	struct prefix pfx;
	struct rfapi_ip_prefix hpfx;
	int rc;

	/*
	 * Get VN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[4]->arg, &vn)))
		return rc;


	/*
	 * Get UN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[6]->arg, &un)))
		return rc;


	if (rfapi_find_handle_vty(vty, &vn, &un, &handle)) {
		vty_out(vty, "can't locate handle matching vn=%s, un=%s\n",
			argv[4]->arg, argv[6]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * Get prefix to advertise
	 */
	if (!str2prefix(argv[8]->arg, &pfx)) {
		vty_out(vty, "Malformed prefix \"%s\"\n", argv[8]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (pfx.family != AF_INET && pfx.family != AF_INET6) {
		vty_out(vty, "Bad family for prefix \"%s\"\n", argv[8]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	rfapiQprefix2Rprefix(&pfx, &hpfx);

	rfapi_register(handle, &hpfx, 0, NULL, NULL, 1);

	return CMD_SUCCESS;
}

DEFUN (debug_rfapi_query_vn_un,
       debug_rfapi_query_vn_un_cmd,
       "debug rfapi-dev query vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> target <A.B.C.D|X:X::X:X>",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "rfapi_query\n"
       "indicate vn addr follows\n"
       "virtual network interface IPv4 address\n"
       "virtual network interface IPv6 address\n"
       "indicate un addr follows\n"
       "IPv4 un address\n"
       "IPv6 un address\n"
       "indicate target follows\n"
       "target IPv4 address\n"
       "target IPv6 address\n")
{
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	struct rfapi_ip_addr target;
	rfapi_handle handle;
	int rc;
	struct rfapi_next_hop_entry *pNextHopEntry;

	/*
	 * Get VN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[4]->arg, &vn)))
		return rc;


	/*
	 * Get UN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[6]->arg, &un)))
		return rc;


	/*
	 * Get target addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[8]->arg, &target)))
		return rc;


	if (rfapi_find_handle_vty(vty, &vn, &un, &handle)) {
		vty_out(vty, "can't locate handle matching vn=%s, un=%s\n",
			argv[4]->arg, argv[6]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * options parameter not used? Set to NULL for now
	 */
	rc = rfapi_query(handle, &target, NULL, &pNextHopEntry);

	if (rc) {
		vty_out(vty, "rfapi_query failed with rc=%d (%s)\n", rc,
			strerror(rc));
	} else {
		/*
		 * print nexthop list
		 */
		test_nexthops_callback(/*&target, */ pNextHopEntry,
				       vty); /* frees nh list! */
	}

	return CMD_SUCCESS;
}


DEFUN (debug_rfapi_query_vn_un_l2o,
       debug_rfapi_query_vn_un_l2o_cmd,
       "debug rfapi-dev query vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> lni LNI target YY:YY:YY:YY:YY:YY",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "rfapi_query\n"
       "indicate vn addr follows\n"
       "virtual network interface IPv4 address\n"
       "virtual network interface IPv6 address\n"
       "indicate xt addr follows\n"
       "underlay network interface IPv4 address\n"
       "underlay network interface IPv6 address\n"
       "logical network ID follows\n"
       "logical network ID\n"
       "indicate target MAC addr follows\n"
       "target MAC addr\n")
{
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	struct rfapi_ip_addr target;
	rfapi_handle handle;
	int rc;
	struct rfapi_next_hop_entry *pNextHopEntry;
	struct rfapi_l2address_option l2o_buf;
	struct bgp_tea_options hopt;
	uint8_t valbuf[14];

	/*
	 * Get VN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[4]->arg, &vn)))
		return rc;


	/*
	 * Get UN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[6]->arg, &un)))
		return rc;


#if 0 /* there is no IP target arg here ?????? */
  /*
   * Get target addr
   */
  if ((rc = rfapiCliGetRfapiIpAddr (vty, argv[2], &target)))
    return rc;
#else
	vty_out(vty, "%% This command is broken.\n");
	return CMD_WARNING_CONFIG_FAILED;
#endif

	if (rfapi_find_handle_vty(vty, &vn, &un, &handle)) {
		vty_out(vty, "can't locate handle matching vn=%s, un=%s\n",
			argv[4]->arg, argv[6]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * Set up L2 parameters
	 */
	memset(&l2o_buf, 0, sizeof(l2o_buf));
	if (rfapiStr2EthAddr(argv[10]->arg, &l2o_buf.macaddr)) {
		vty_out(vty, "Bad mac address \"%s\"\n", argv[10]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	l2o_buf.logical_net_id = strtoul(argv[8]->arg, NULL, 10);

	/* construct option chain */

	memset(valbuf, 0, sizeof(valbuf));
	memcpy(valbuf, &l2o_buf.macaddr.octet, ETH_ALEN);
	valbuf[11] = (l2o_buf.logical_net_id >> 16) & 0xff;
	valbuf[12] = (l2o_buf.logical_net_id >> 8) & 0xff;
	valbuf[13] = l2o_buf.logical_net_id & 0xff;

	memset(&hopt, 0, sizeof(hopt));
	hopt.options_count = 1;
	hopt.options_length = sizeof(valbuf); /* is this right? */
	hopt.type = RFAPI_VN_OPTION_TYPE_L2ADDR;
	hopt.length = sizeof(valbuf);
	hopt.value = valbuf;


	/*
	 * options parameter not used? Set to NULL for now
	 */
	rc = rfapi_query(handle, &target, &l2o_buf, &pNextHopEntry);

	if (rc) {
		vty_out(vty, "rfapi_query failed with rc=%d (%s)\n", rc,
			strerror(rc));
	} else {
		/*
		 * print nexthop list
		 */
		/* TBD enhance to print L2 information */
		test_nexthops_callback(/*&target, */ pNextHopEntry,
				       vty); /* frees nh list! */
	}

	return CMD_SUCCESS;
}


DEFUN (debug_rfapi_query_done_vn_un,
       debug_rfapi_query_vn_un_done_cmd,
       "debug rfapi-dev query done vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> target <A.B.C.D|X:X::X:X>",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "rfapi_query_done\n"
       "rfapi_query_done\n"
       "indicate vn addr follows\n"
       "virtual network interface IPv4 address\n"
       "virtual network interface IPv6 address\n"
       "indicate xt addr follows\n"
       "underlay network interface IPv4 address\n"
       "underlay network interface IPv6 address\n"
       "indicate target follows\n"
       "Target IPv4 address\n"
       "Target IPv6 address\n")
{
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	struct rfapi_ip_addr target;
	rfapi_handle handle;
	int rc;

	/*
	 * Get VN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[5]->arg, &vn)))
		return rc;


	/*
	 * Get UN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[7]->arg, &un)))
		return rc;


	/*
	 * Get target addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[9]->arg, &target)))
		return rc;


	if (rfapi_find_handle_vty(vty, &vn, &un, &handle)) {
		vty_out(vty, "can't locate handle matching vn=%s, un=%s\n",
			argv[5]->arg, argv[7]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * options parameter not used? Set to NULL for now
	 */
	rc = rfapi_query_done(handle, &target);

	vty_out(vty, "rfapi_query_done returned %d\n", rc);

	return CMD_SUCCESS;
}

DEFUN (debug_rfapi_show_import,
       debug_rfapi_show_import_cmd,
       "debug rfapi-dev show import",
       DEBUG_STR
       DEBUG_RFAPI_STR
       SHOW_STR
       "import\n")
{
	struct bgp *bgp;
	struct rfapi *h;
	struct rfapi_import_table *it;
	char *s;
	int first_l2 = 1;

	/*
	 * Show all import tables
	 */

	bgp = bgp_get_default(); /* assume 1 instance for now */
	if (!bgp) {
		vty_out(vty, "No BGP instance\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	h = bgp->rfapi;
	if (!h) {
		vty_out(vty, "No RFAPI instance\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * Iterate over all import tables; do a filtered import
	 * for the afi/safi combination
	 */


	for (it = h->imports; it; it = it->next) {
		s = ecommunity_ecom2str(it->rt_import_list,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		vty_out(vty, "Import Table %p, RTs: %s\n", it, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);

		rfapiShowImportTable(vty, "IP VPN", it->imported_vpn[AFI_IP],
				     1);
		rfapiShowImportTable(vty, "IP ENCAP",
				     it->imported_encap[AFI_IP], 0);
		rfapiShowImportTable(vty, "IP6 VPN", it->imported_vpn[AFI_IP6],
				     1);
		rfapiShowImportTable(vty, "IP6 ENCAP",
				     it->imported_encap[AFI_IP6], 0);
	}

	if (h->import_mac) {
		void *cursor = NULL;
		uint32_t lni;
		uintptr_t lni_as_ptr;
		int rc;
		char buf[BUFSIZ];

		for (rc = skiplist_next(h->import_mac, (void **)&lni_as_ptr,
					(void **)&it, &cursor);
		     !rc;
		     rc = skiplist_next(h->import_mac, (void **)&lni_as_ptr,
					(void **)&it, &cursor)) {

			if (it->imported_vpn[AFI_L2VPN]) {
				lni = lni_as_ptr;
				if (first_l2) {
					vty_out(vty,
						"\nLNI-based Ethernet Tables:\n");
					first_l2 = 0;
				}
				snprintf(buf, BUFSIZ, "L2VPN LNI=%u", lni);
				rfapiShowImportTable(
					vty, buf, it->imported_vpn[AFI_L2VPN],
					1);
			}
		}
	}

	rfapiShowImportTable(vty, "CE IT - IP VPN",
			     h->it_ce->imported_vpn[AFI_IP], 1);

	return CMD_SUCCESS;
}

DEFUN (debug_rfapi_show_import_vn_un,
       debug_rfapi_show_import_vn_un_cmd,
       "debug rfapi-dev show import vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X>",
       DEBUG_STR
       DEBUG_RFAPI_STR
       SHOW_STR
       "import\n"
       "indicate vn addr follows\n"
       "virtual network interface IPv4 address\n"
       "virtual network interface IPv6 address\n"
       "indicate xt addr follows\n"
       "underlay network interface IPv4 address\n"
       "underlay network interface IPv6 address\n")
{
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	rfapi_handle handle;
	int rc;
	struct rfapi_descriptor *rfd;

	/*
	 * Get VN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[5]->arg, &vn)))
		return rc;


	/*
	 * Get UN addr
	 */
	if ((rc = rfapiCliGetRfapiIpAddr(vty, argv[7]->arg, &un)))
		return rc;


	if (rfapi_find_handle_vty(vty, &vn, &un, &handle)) {
		vty_out(vty, "can't locate handle matching vn=%s, un=%s\n",
			argv[5]->arg, argv[7]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	rfd = (struct rfapi_descriptor *)handle;

	rfapiShowImportTable(vty, "IP VPN",
			     rfd->import_table->imported_vpn[AFI_IP], 1);
	rfapiShowImportTable(vty, "IP ENCAP",
			     rfd->import_table->imported_encap[AFI_IP], 0);
	rfapiShowImportTable(vty, "IP6 VPN",
			     rfd->import_table->imported_vpn[AFI_IP6], 1);
	rfapiShowImportTable(vty, "IP6 ENCAP",
			     rfd->import_table->imported_encap[AFI_IP6], 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rfapi_response_omit_self,
       debug_rfapi_response_omit_self_cmd,
       "debug rfapi-dev response-omit-self <on|off>",
       DEBUG_STR
       DEBUG_RFAPI_STR
       "Omit self in RFP responses\n"
       "filter out self from responses\n" "leave self in responses\n")
{
	struct bgp *bgp = bgp_get_default();

	if (!bgp) {
		vty_out(vty, "No BGP process is configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!bgp->rfapi_cfg) {
		vty_out(vty, "VNC not configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (strmatch(argv[3]->text, "on"))
		SET_FLAG(bgp->rfapi_cfg->flags,
			 BGP_VNC_CONFIG_FILTER_SELF_FROM_RSP);
	else
		UNSET_FLAG(bgp->rfapi_cfg->flags,
			   BGP_VNC_CONFIG_FILTER_SELF_FROM_RSP);

	return CMD_SUCCESS;
}


#ifdef RFAPI_DEBUG_SKIPLIST_CLI

#include "lib/skiplist.h"
DEFUN (skiplist_test_cli,
       skiplist_test_cli_cmd,
       "skiplist test",
       "skiplist command\n"
       "test\n")
{
	skiplist_test(vty);

	return CMD_SUCCESS;
}

DEFUN (skiplist_debug_cli,
       skiplist_debug_cli_cmd,
       "skiplist debug",
       "skiplist command\n"
       "debug\n")
{
	skiplist_debug(vty, NULL);
	return CMD_SUCCESS;
}

#endif /* RFAPI_DEBUG_SKIPLIST_CLI */

void rfapi_init(void)
{
	bgp_rfapi_cfg_init();
	vnc_debug_init();

	install_element(ENABLE_NODE, &debug_rfapi_show_import_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_show_import_vn_un_cmd);

	install_element(ENABLE_NODE, &debug_rfapi_open_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_close_vn_un_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_close_rfd_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_register_vn_un_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_unregister_vn_un_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_query_vn_un_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_query_vn_un_done_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_query_vn_un_l2o_cmd);

	install_element(ENABLE_NODE, &debug_rfapi_response_omit_self_cmd);

	/* Need the following show commands for gpz test scripts */
	install_element(ENABLE_NODE, &debug_rfapi_show_nves_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_show_nves_vn_un_cmd);
	install_element(ENABLE_NODE, &debug_rfapi_register_vn_un_l2o_cmd);

#ifdef RFAPI_DEBUG_SKIPLIST_CLI
	install_element(ENABLE_NODE, &skiplist_test_cli_cmd);
	install_element(ENABLE_NODE, &skiplist_debug_cli_cmd);
#endif

	rfapi_vty_init();
}

#ifdef DEBUG_RFAPI
static void rfapi_print_exported(struct bgp *bgp)
{
	struct bgp_node *rdn;
	struct bgp_node *rn;
	struct bgp_info *bi;

	if (!bgp)
		return;

	for (rdn = bgp_table_top(bgp->rib[AFI_IP][SAFI_MPLS_VPN]); rdn;
	     rdn = bgp_route_next(rdn)) {
		if (!rdn->info)
			continue;
		fprintf(stderr, "%s: vpn rdn=%p\n", __func__, rdn);
		for (rn = bgp_table_top(rdn->info); rn;
		     rn = bgp_route_next(rn)) {
			if (!rn->info)
				continue;
			fprintf(stderr, "%s: rn=%p\n", __func__, rn);
			for (bi = rn->info; bi; bi = bi->next) {
				rfapiPrintBi((void *)2, bi); /* 2 => stderr */
			}
		}
	}
	for (rdn = bgp_table_top(bgp->rib[AFI_IP][SAFI_ENCAP]); rdn;
	     rdn = bgp_route_next(rdn)) {
		if (!rdn->info)
			continue;
		fprintf(stderr, "%s: encap rdn=%p\n", __func__, rdn);
		for (rn = bgp_table_top(rdn->info); rn;
		     rn = bgp_route_next(rn)) {
			if (!rn->info)
				continue;
			fprintf(stderr, "%s: rn=%p\n", __func__, rn);
			for (bi = rn->info; bi; bi = bi->next) {
				rfapiPrintBi((void *)2, bi); /* 2 => stderr */
			}
		}
	}
}
#endif /* defined(DEBUG_RFAPI) */

/*
 * Free all memory to prepare for clean exit as seen by valgrind memcheck
 */
void rfapi_delete(struct bgp *bgp)
{
	extern void rfp_clear_vnc_nve_all(void); /* can't fix correctly yet */

	/*
	 * This clears queries and registered routes, and closes nves
	 */
	if (bgp->rfapi)
		rfp_clear_vnc_nve_all();
	bgp_rfapi_cfg_destroy(bgp, bgp->rfapi_cfg);
	bgp->rfapi_cfg = NULL;
	bgp_rfapi_destroy(bgp, bgp->rfapi);
	bgp->rfapi = NULL;
#ifdef DEBUG_RFAPI
	/*
	 * show what's left in the BGP MPLSVPN RIB
	 */
	rfapi_print_exported(bgp);
#endif
}

int rfapi_set_autord_from_vn(struct prefix_rd *rd, struct rfapi_ip_addr *vn)
{
	vnc_zlog_debug_verbose("%s: auto-assigning RD", __func__);
	if (vn->addr_family != AF_INET && vn->addr_family != AF_INET6) {
		vnc_zlog_debug_verbose(
			"%s: can't auto-assign RD, VN addr family is not IPv4"
			"|v6",
			__func__);
		return EAFNOSUPPORT;
	}
	rd->family = AF_UNSPEC;
	rd->prefixlen = 64;
	rd->val[1] = RD_TYPE_IP;
	if (vn->addr_family == AF_INET) {
		memcpy(rd->val + 2, &vn->addr.v4.s_addr, 4);
	} else { /* is v6 */
		memcpy(rd->val + 2, &vn->addr.v6.s6_addr32[3],
		       4); /* low order 4 bytes */
	}
	{
		char buf[RD_ADDRSTRLEN];

		vnc_zlog_debug_verbose("%s: auto-RD is set to %s", __func__,
				       prefix_rd2str(rd, buf, sizeof(buf)));
	}
	return 0;
}

/*------------------------------------------
 * rfapi_bgp_lookup_by_rfp
 *
 * Find bgp instance pointer based on value returned by rfp_start
 *
 * input:
 *      rfp_start_val     value returned by rfp_startor
 *                        NULL (=get default instance)
 *
 * output:
 *	none
 *
 * return value:
 *	bgp             bgp instance pointer
 *      NULL = not found
 *
 --------------------------------------------*/
struct bgp *rfapi_bgp_lookup_by_rfp(void *rfp_start_val)
{
	struct bgp *bgp = NULL;
	struct listnode *node, *nnode;

	if (rfp_start_val == NULL)
		bgp = bgp_get_default();
	else
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
			if (bgp->rfapi != NULL
			    && bgp->rfapi->rfp == rfp_start_val)
				return bgp;
	return bgp;
}

/*------------------------------------------
 * rfapi_get_rfp_start_val_by_bgp
 *
 * Find bgp instance pointer based on value returned by rfp_start
 *
 * input:
 *	bgp             bgp instance pointer
 *
 * output:
 *	none
 *
 * return value:
 *	rfp_start_val
 *      NULL = not found
 *
 --------------------------------------------*/
void *rfapi_get_rfp_start_val_by_bgp(struct bgp *bgp)
{
	if (!bgp || !bgp->rfapi)
		return NULL;
	return bgp->rfapi->rfp;
}

/***********************************************************************
 *		 RFP group specific configuration
 ***********************************************************************/
static void *rfapi_rfp_get_or_init_group_config_default(struct rfapi_cfg *rfc,
							struct vty *vty,
							uint32_t size)
{
	if (rfc->default_rfp_cfg == NULL && size > 0) {
		rfc->default_rfp_cfg = XCALLOC(MTYPE_RFAPI_RFP_GROUP_CFG, size);
		vnc_zlog_debug_verbose("%s: allocated, size=%d", __func__,
				       size);
	}
	return rfc->default_rfp_cfg;
}

static void *rfapi_rfp_get_or_init_group_config_nve(struct rfapi_cfg *rfc,
						    struct vty *vty,
						    uint32_t size)
{
	struct rfapi_nve_group_cfg *rfg =
		VTY_GET_CONTEXT_SUB(rfapi_nve_group_cfg);

	/* make sure group is still in list */
	if (!rfg || !listnode_lookup(rfc->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return NULL;
	}

	if (rfg->rfp_cfg == NULL && size > 0) {
		rfg->rfp_cfg = XCALLOC(MTYPE_RFAPI_RFP_GROUP_CFG, size);
		vnc_zlog_debug_verbose("%s: allocated, size=%d", __func__,
				       size);
	}
	return rfg->rfp_cfg;
}

static void *rfapi_rfp_get_or_init_group_config_l2(struct rfapi_cfg *rfc,
						   struct vty *vty,
						   uint32_t size)
{
	struct rfapi_l2_group_cfg *rfg =
		VTY_GET_CONTEXT_SUB(rfapi_l2_group_cfg);

	/* make sure group is still in list */
	if (!rfg || !listnode_lookup(rfc->l2_groups, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current L2 group no longer exists\n");
		return NULL;
	}
	if (rfg->rfp_cfg == NULL && size > 0) {
		rfg->rfp_cfg = XCALLOC(MTYPE_RFAPI_RFP_GROUP_CFG, size);
		vnc_zlog_debug_verbose("%s: allocated, size=%d", __func__,
				       size);
	}
	return rfg->rfp_cfg;
}

/*------------------------------------------
 * rfapi_rfp_init_group_config_ptr_vty
 *
 * This is used to init or return a previously init'ed group specific
 * configuration pointer. Group is identified by vty context.
 * NOTE: size is ignored when a previously init'ed value is returned.
 * RFAPI frees rfp_cfg_group when group is deleted during reconfig,
 * bgp restart or shutdown.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    type              group type
 *    vty               quagga vty context
 *    size              number of bytes to allocation
 *
 * output:
 *    none
 *
 * return value:
 *    rfp_cfg_group     NULL or Pointer to configuration structure
--------------------------------------------*/
void *rfapi_rfp_init_group_config_ptr_vty(void *rfp_start_val,
					  rfapi_rfp_cfg_group_type type,
					  struct vty *vty, uint32_t size)
{
	struct bgp *bgp;
	void *ret = NULL;

	if (rfp_start_val == NULL || vty == NULL)
		return NULL;

	bgp = rfapi_bgp_lookup_by_rfp(rfp_start_val);
	if (!bgp || !bgp->rfapi_cfg)
		return NULL;

	switch (type) {
	case RFAPI_RFP_CFG_GROUP_DEFAULT:
		ret = rfapi_rfp_get_or_init_group_config_default(bgp->rfapi_cfg,
								 vty, size);
		break;
	case RFAPI_RFP_CFG_GROUP_NVE:
		ret = rfapi_rfp_get_or_init_group_config_nve(bgp->rfapi_cfg,
							     vty, size);
		break;
	case RFAPI_RFP_CFG_GROUP_L2:
		ret = rfapi_rfp_get_or_init_group_config_l2(bgp->rfapi_cfg, vty,
							    size);
		break;
	default:
		zlog_err("%s: Unknown group type=%d", __func__, type);
		/* should never happen */
		assert("Unknown type" == NULL);
		break;
	}
	return ret;
}

/*------------------------------------------
 * rfapi_rfp_get_group_config_ptr_vty
 *
 * This is used to get group specific configuration pointer.
 * Group is identified by type and vty context.
 * RFAPI frees rfp_cfg_group when group is deleted during reconfig,
 * bgp restart or shutdown.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    type              group type
 *    vty               quagga vty context
 *
 * output:
 *    none
 *
 * return value:
 *    rfp_cfg_group     Pointer to configuration structure
--------------------------------------------*/
void *rfapi_rfp_get_group_config_ptr_vty(void *rfp_start_val,
					 rfapi_rfp_cfg_group_type type,
					 struct vty *vty)
{
	return rfapi_rfp_init_group_config_ptr_vty(rfp_start_val, type, vty, 0);
}

static void *
rfapi_rfp_get_group_config_name_nve(struct rfapi_cfg *rfc, const char *name,
				    void *criteria,
				    rfp_group_config_search_cb_t *search_cb)
{
	struct rfapi_nve_group_cfg *rfg;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(rfc->nve_groups_sequential, node, rfg)) {
		if (!strcmp(rfg->name, name) && /* name match */
		    (search_cb == NULL || !search_cb(criteria, rfg->rfp_cfg)))
			return rfg->rfp_cfg;
	}
	return NULL;
}

static void *
rfapi_rfp_get_group_config_name_l2(struct rfapi_cfg *rfc, const char *name,
				   void *criteria,
				   rfp_group_config_search_cb_t *search_cb)
{
	struct rfapi_l2_group_cfg *rfg;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(rfc->l2_groups, node, rfg)) {
		if (!strcmp(rfg->name, name) && /* name match */
		    (search_cb == NULL || !search_cb(criteria, rfg->rfp_cfg)))
			return rfg->rfp_cfg;
	}
	return NULL;
}

/*------------------------------------------
 * rfapi_rfp_get_group_config_ptr_name
 *
 * This is used to get group specific configuration pointer.
 * Group is identified by type and name context.
 * RFAPI frees rfp_cfg_group when group is deleted during reconfig,
 * bgp restart or shutdown.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    type              group type
 *    name              group name
 *    criteria          RFAPI caller provided serach criteria
 *    search_cb         optional rfp_group_config_search_cb_t
 *
 * output:
 *    none
 *
 * return value:
 *    rfp_cfg_group     Pointer to configuration structure
--------------------------------------------*/
void *rfapi_rfp_get_group_config_ptr_name(
	void *rfp_start_val, rfapi_rfp_cfg_group_type type, const char *name,
	void *criteria, rfp_group_config_search_cb_t *search_cb)
{
	struct bgp *bgp;
	void *ret = NULL;

	if (rfp_start_val == NULL || name == NULL)
		return NULL;

	bgp = rfapi_bgp_lookup_by_rfp(rfp_start_val);
	if (!bgp || !bgp->rfapi_cfg)
		return NULL;

	switch (type) {
	case RFAPI_RFP_CFG_GROUP_DEFAULT:
		ret = bgp->rfapi_cfg->default_rfp_cfg;
		break;
	case RFAPI_RFP_CFG_GROUP_NVE:
		ret = rfapi_rfp_get_group_config_name_nve(bgp->rfapi_cfg, name,
							  criteria, search_cb);
		break;
	case RFAPI_RFP_CFG_GROUP_L2:
		ret = rfapi_rfp_get_group_config_name_l2(bgp->rfapi_cfg, name,
							 criteria, search_cb);
		break;
	default:
		zlog_err("%s: Unknown group type=%d", __func__, type);
		/* should never happen */
		assert("Unknown type" == NULL);
		break;
	}
	return ret;
}

/*------------------------------------------
 * rfapi_rfp_get_l2_group_config_ptr_lni
 *
 * This is used to get group specific configuration pointer.
 * Group is identified by type and logical network identifier.
 * RFAPI frees rfp_cfg_group when group is deleted during reconfig,
 * bgp restart or shutdown.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    type              group type
 *    logical_net_id    group logical network identifier
 *    criteria          RFAPI caller provided serach criteria
 *    search_cb         optional rfp_group_config_search_cb_t
 *
 * output:
 *    none
 *
 * return value:
 *    rfp_cfg_group     Pointer to configuration structure
--------------------------------------------*/
void *
rfapi_rfp_get_l2_group_config_ptr_lni(void *rfp_start_val,
				      uint32_t logical_net_id, void *criteria,
				      rfp_group_config_search_cb_t *search_cb)
{
	struct bgp *bgp;
	struct rfapi_l2_group_cfg *rfg;
	struct listnode *node;

	if (rfp_start_val == NULL)
		return NULL;

	bgp = rfapi_bgp_lookup_by_rfp(rfp_start_val);
	if (!bgp || !bgp->rfapi_cfg)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->l2_groups, node, rfg)) {
		if (rfg->logical_net_id == logical_net_id
		    && (search_cb == NULL
			|| !search_cb(criteria, rfg->rfp_cfg))) {
			if (rfg->rfp_cfg == NULL)
				vnc_zlog_debug_verbose(
					"%s: returning rfp group config for lni=0",
					__func__);
			return rfg->rfp_cfg;
		}
	}
	return NULL;
}
