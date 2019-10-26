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

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/agg_table.h"
#include "lib/vty.h"
#include "lib/memory.h"
#include "lib/routemap.h"
#include "lib/log.h"
#include "lib/log_int.h"
#include "lib/linklist.h"
#include "lib/command.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"

#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_backend.h"

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_vnc_types.h"
#include "bgpd/bgp_label.h"

#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_monitor.h"
#include "bgpd/rfapi/rfapi_rib.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/rfapi_ap.h"
#include "bgpd/rfapi/rfapi_encap_tlv.h"
#include "bgpd/rfapi/vnc_debug.h"

#define DEBUG_L2_EXTRA 0
#define DEBUG_SHOW_EXTRA 0

#define VNC_SHOW_STR "VNC information\n"

/* format related utilies */


#define FMT_MIN      60         /* seconds */
#define FMT_HOUR    (60  * FMT_MIN)
#define FMT_DAY     (24  * FMT_HOUR)
#define FMT_YEAR    (365 * FMT_DAY)

char *rfapiFormatSeconds(uint32_t seconds, char *buf, size_t len)
{
	int year, day, hour, min;

	if (seconds >= FMT_YEAR) {
		year = seconds / FMT_YEAR;
		seconds -= year * FMT_YEAR;
	} else
		year = 0;

	if (seconds >= FMT_DAY) {
		day = seconds / FMT_DAY;
		seconds -= day * FMT_DAY;
	} else
		day = 0;

	if (seconds >= FMT_HOUR) {
		hour = seconds / FMT_HOUR;
		seconds -= hour * FMT_HOUR;
	} else
		hour = 0;

	if (seconds >= FMT_MIN) {
		min = seconds / FMT_MIN;
		seconds -= min * FMT_MIN;
	} else
		min = 0;

	if (year > 0) {
		snprintf(buf, len, "%dy%dd%dh", year, day, hour);
	} else if (day > 0) {
		snprintf(buf, len, "%dd%dh%dm", day, hour, min);
	} else {
		snprintf(buf, len, "%02d:%02d:%02d", hour, min, seconds);
	}

	return buf;
}

char *rfapiFormatAge(time_t age, char *buf, size_t len)
{
	time_t now, age_adjusted;

	now = rfapi_time(NULL);
	age_adjusted = now - age;

	return rfapiFormatSeconds(age_adjusted, buf, len);
}


/*
 * Reimplementation of quagga/lib/prefix.c function, but
 * for RFAPI-style prefixes
 */
void rfapiRprefixApplyMask(struct rfapi_ip_prefix *rprefix)
{
	uint8_t *pnt;
	int index;
	int offset;

	static uint8_t maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
				    0xf8, 0xfc, 0xfe, 0xff};

	switch (rprefix->prefix.addr_family) {
	case AF_INET:
		index = rprefix->length / 8;
		if (index < 4) {
			pnt = (uint8_t *)&rprefix->prefix.addr.v4;
			offset = rprefix->length % 8;
			pnt[index] &= maskbit[offset];
			index++;
			while (index < 4)
				pnt[index++] = 0;
		}
		break;

	case AF_INET6:
		index = rprefix->length / 8;
		if (index < 16) {
			pnt = (uint8_t *)&rprefix->prefix.addr.v6;
			offset = rprefix->length % 8;
			pnt[index] &= maskbit[offset];
			index++;
			while (index < 16)
				pnt[index++] = 0;
		}
		break;

	default:
		assert(0);
	}
}

/*
 * translate a quagga prefix into a rfapi IP address. The
 * prefix is REQUIRED to be 32 bits for IPv4 and 128 bits for IPv6
 *
 * RETURNS:
 *
 *	0	Success
 *	<0	Error
 */
int rfapiQprefix2Raddr(struct prefix *qprefix, struct rfapi_ip_addr *raddr)
{
	memset(raddr, 0, sizeof(struct rfapi_ip_addr));
	raddr->addr_family = qprefix->family;
	switch (qprefix->family) {
	case AF_INET:
		if (qprefix->prefixlen != 32)
			return -1;
		raddr->addr.v4 = qprefix->u.prefix4;
		break;
	case AF_INET6:
		if (qprefix->prefixlen != 128)
			return -1;
		raddr->addr.v6 = qprefix->u.prefix6;
		break;
	default:
		return -1;
	}
	return 0;
}

/*
 * Translate Quagga prefix to RFAPI prefix
 */
/* rprefix->cost set to 0 */
void rfapiQprefix2Rprefix(struct prefix *qprefix,
			  struct rfapi_ip_prefix *rprefix)
{
	memset(rprefix, 0, sizeof(struct rfapi_ip_prefix));
	rprefix->length = qprefix->prefixlen;
	rprefix->prefix.addr_family = qprefix->family;
	switch (qprefix->family) {
	case AF_INET:
		rprefix->prefix.addr.v4 = qprefix->u.prefix4;
		break;
	case AF_INET6:
		rprefix->prefix.addr.v6 = qprefix->u.prefix6;
		break;
	default:
		assert(0);
	}
}

int rfapiRprefix2Qprefix(struct rfapi_ip_prefix *rprefix,
			 struct prefix *qprefix)
{
	memset(qprefix, 0, sizeof(struct prefix));
	qprefix->prefixlen = rprefix->length;
	qprefix->family = rprefix->prefix.addr_family;

	switch (rprefix->prefix.addr_family) {
	case AF_INET:
		qprefix->u.prefix4 = rprefix->prefix.addr.v4;
		break;
	case AF_INET6:
		qprefix->u.prefix6 = rprefix->prefix.addr.v6;
		break;
	default:
		return EAFNOSUPPORT;
	}
	return 0;
}

/*
 * returns 1 if prefixes have same addr family, prefix len, and address
 * Note that host bits matter in this comparison!
 *
 * For paralellism with quagga/lib/prefix.c. if we need a comparison
 * where host bits are ignored, call that function rfapiRprefixCmp.
 */
int rfapiRprefixSame(struct rfapi_ip_prefix *hp1, struct rfapi_ip_prefix *hp2)
{
	if (hp1->prefix.addr_family != hp2->prefix.addr_family)
		return 0;
	if (hp1->length != hp2->length)
		return 0;
	if (hp1->prefix.addr_family == AF_INET)
		if (IPV4_ADDR_SAME(&hp1->prefix.addr.v4, &hp2->prefix.addr.v4))
			return 1;
	if (hp1->prefix.addr_family == AF_INET6)
		if (IPV6_ADDR_SAME(&hp1->prefix.addr.v6, &hp2->prefix.addr.v6))
			return 1;
	return 0;
}

int rfapiRaddr2Qprefix(struct rfapi_ip_addr *hia, struct prefix *pfx)
{
	memset(pfx, 0, sizeof(struct prefix));
	pfx->family = hia->addr_family;

	switch (hia->addr_family) {
	case AF_INET:
		pfx->prefixlen = 32;
		pfx->u.prefix4 = hia->addr.v4;
		break;
	case AF_INET6:
		pfx->prefixlen = 128;
		pfx->u.prefix6 = hia->addr.v6;
		break;
	default:
		return EAFNOSUPPORT;
	}
	return 0;
}

void rfapiL2o2Qprefix(struct rfapi_l2address_option *l2o, struct prefix *pfx)
{
	memset(pfx, 0, sizeof(struct prefix));
	pfx->family = AF_ETHERNET;
	pfx->prefixlen = 48;
	pfx->u.prefix_eth = l2o->macaddr;
}

char *rfapiEthAddr2Str(const struct ethaddr *ea, char *buf, int bufsize)
{
	return prefix_mac2str(ea, buf, bufsize);
}

int rfapiStr2EthAddr(const char *str, struct ethaddr *ea)
{
	unsigned int a[6];
	int i;

	if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x", a + 0, a + 1, a + 2, a + 3,
		   a + 4, a + 5)
	    != 6) {

		return EINVAL;
	}

	for (i = 0; i < 6; ++i)
		ea->octet[i] = a[i] & 0xff;

	return 0;
}

const char *rfapi_ntop(int af, const void *src, char *buf, socklen_t size)
{
	if (af == AF_ETHERNET) {
		return rfapiEthAddr2Str((const struct ethaddr *)src, buf, size);
	}

	return inet_ntop(af, src, buf, size);
}

int rfapiDebugPrintf(void *dummy, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vzlog(LOG_DEBUG, format, args);
	va_end(args);
	return 0;
}

static int rfapiStdioPrintf(void *stream, const char *format, ...)
{
	FILE *file = NULL;

	va_list args;
	va_start(args, format);

	switch ((uintptr_t)stream) {
	case 1:
		file = stdout;
		break;
	case 2:
		file = stderr;
		break;
	default:
		assert(0);
	}

	vfprintf(file, format, args);
	va_end(args);
	return 0;
}

/* Fake out for debug logging */
static struct vty vty_dummy_zlog;
static struct vty vty_dummy_stdio;
#define HVTYNL ((vty == &vty_dummy_zlog)? "": "\n")

static const char *str_vty_newline(struct vty *vty)
{
	if (vty == &vty_dummy_zlog)
		return "";
	return "\n";
}

int rfapiStream2Vty(void *stream,			   /* input */
		    int (**fp)(void *, const char *, ...), /* output */
		    struct vty **vty,			   /* output */
		    void **outstream,			   /* output */
		    const char **vty_newline)		   /* output */
{

	if (!stream) {
		vty_dummy_zlog.type = VTY_SHELL; /* for VTYNL */
		*vty = &vty_dummy_zlog;
		*fp = (int (*)(void *, const char *, ...))rfapiDebugPrintf;
		*outstream = NULL;
		*vty_newline = str_vty_newline(*vty);
		return (vzlog_test(LOG_DEBUG));
	}

	if (((uintptr_t)stream == (uintptr_t)1)
	    || ((uintptr_t)stream == (uintptr_t)2)) {

		vty_dummy_stdio.type = VTY_SHELL; /* for VTYNL */
		*vty = &vty_dummy_stdio;
		*fp = (int (*)(void *, const char *, ...))rfapiStdioPrintf;
		*outstream = stream;
		*vty_newline = str_vty_newline(*vty);
		return 1;
	}

	*vty = stream; /* VTYNL requires vty to be legit */
	*fp = (int (*)(void *, const char *, ...))vty_out;
	*outstream = stream;
	*vty_newline = str_vty_newline(*vty);
	return 1;
}

/* called from bgpd/bgp_vty.c'route_vty_out() */
void rfapi_vty_out_vncinfo(struct vty *vty, struct prefix *p,
			   struct bgp_path_info *bpi, safi_t safi)
{
	char *s;
	uint32_t lifetime;

	/*
	 * Print, on an indented line:
	 *  UN address [if VPN route and VNC UN addr subtlv]
	 *  EC list
	 *  VNC lifetime
	 */
	vty_out(vty, "    ");

	if (safi == SAFI_MPLS_VPN) {
		struct prefix pfx_un;

		if (!rfapiGetVncTunnelUnAddr(bpi->attr, &pfx_un)) {
			char buf[BUFSIZ];
			vty_out(vty, "UN=%s",
				inet_ntop(pfx_un.family, pfx_un.u.val, buf,
					  BUFSIZ));
		}
	}

	if (bpi->attr->ecommunity) {
		s = ecommunity_ecom2str(bpi->attr->ecommunity,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		vty_out(vty, " EC{%s}", s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	if (bpi->extra != NULL) {
		if (bpi->extra->label[0] == BGP_PREVENT_VRF_2_VRF_LEAK)
			vty_out(vty, " label=VRF2VRF");
		else
			vty_out(vty, " label=%u",
				decode_label(&bpi->extra->label[0]));
	}

	if (!rfapiGetVncLifetime(bpi->attr, &lifetime)) {
		vty_out(vty, " life=%d", lifetime);
	}

	vty_out(vty, " type=%s, subtype=%d", zebra_route_string(bpi->type),
		bpi->sub_type);

	vty_out(vty, "%s", HVTYNL);
}

void rfapiPrintAttrPtrs(void *stream, struct attr *attr)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	char buf[BUFSIZ];

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	fp(out, "Attr[%p]:%s", attr, HVTYNL);
	if (!attr)
		return;

	/* IPv4 Nexthop */
	inet_ntop(AF_INET, &attr->nexthop, buf, BUFSIZ);
	fp(out, "  nexthop=%s%s", buf, HVTYNL);

	fp(out, "  aspath=%p, refcnt=%d%s", attr->aspath,
	   (attr->aspath ? attr->aspath->refcnt : 0), HVTYNL);
	fp(out, "  community=%p, refcnt=%d%s", attr->community,
	   (attr->community ? attr->community->refcnt : 0), HVTYNL);

	fp(out, "  ecommunity=%p, refcnt=%d%s", attr->ecommunity,
	   (attr->ecommunity ? attr->ecommunity->refcnt : 0), HVTYNL);
	fp(out, "  cluster=%p, refcnt=%d%s", attr->cluster,
	   (attr->cluster ? attr->cluster->refcnt : 0), HVTYNL);
	fp(out, "  transit=%p, refcnt=%d%s", attr->transit,
	   (attr->transit ? attr->transit->refcnt : 0), HVTYNL);
}

/*
 * Print BPI in an Import Table
 */
void rfapiPrintBi(void *stream, struct bgp_path_info *bpi)
{
	char buf[BUFSIZ];
	char *s;

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	char line[BUFSIZ];
	char *p = line;
	int r;
	int has_macaddr = 0;
	struct ethaddr macaddr = {{0}};
	struct rfapi_l2address_option l2o_buf;
	uint8_t l2hid = 0; /* valid if has_macaddr */

#define REMAIN (BUFSIZ - (p-line))
#define INCP {p += (r > REMAIN)? REMAIN: r;}

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	if (!bpi)
		return;

	if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED) && bpi->extra
	    && bpi->extra->vnc.import.timer) {
		struct thread *t =
			(struct thread *)bpi->extra->vnc.import.timer;
		r = snprintf(p, REMAIN, " [%4lu] ",
			     thread_timer_remain_second(t));
		INCP;

	} else {
		r = snprintf(p, REMAIN, "        ");
		INCP;
	}

	if (bpi->extra) {
		/* TBD This valid only for SAFI_MPLS_VPN, but not for encap */
		if (decode_rd_type(bpi->extra->vnc.import.rd.val)
		    == RD_TYPE_VNC_ETH) {
			has_macaddr = 1;
			memcpy(macaddr.octet, bpi->extra->vnc.import.rd.val + 2,
			       6);
			l2hid = bpi->extra->vnc.import.rd.val[1];
		}
	}

	/*
	 * Print these items:
	 *          type/subtype
	 *          nexthop address
	 *          lifetime
	 *          RFP option sizes (they are opaque values)
	 *          extended communities (RTs)
	 */
	uint32_t lifetime;
	int printed_1st_gol = 0;
	struct bgp_attr_encap_subtlv *pEncap;
	struct prefix pfx_un;
	int af = BGP_MP_NEXTHOP_FAMILY(bpi->attr->mp_nexthop_len);

	/* Nexthop */
	if (af == AF_INET) {
		r = snprintf(p, REMAIN, "%s",
			     inet_ntop(AF_INET,
				       &bpi->attr->mp_nexthop_global_in, buf,
				       BUFSIZ));
		INCP;
	} else if (af == AF_INET6) {
		r = snprintf(p, REMAIN, "%s",
			     inet_ntop(AF_INET6, &bpi->attr->mp_nexthop_global,
				       buf, BUFSIZ));
		INCP;
	} else {
		r = snprintf(p, REMAIN, "?");
		INCP;
	}

	/*
	 * VNC tunnel subtlv, if present, contains UN address
	 */
	if (!rfapiGetVncTunnelUnAddr(bpi->attr, &pfx_un)) {
		r = snprintf(
			p, REMAIN, " un=%s",
			inet_ntop(pfx_un.family, pfx_un.u.val, buf, BUFSIZ));
		INCP;
	}

	/* Lifetime */
	if (rfapiGetVncLifetime(bpi->attr, &lifetime)) {
		r = snprintf(p, REMAIN, " nolife");
		INCP;
	} else {
		if (lifetime == 0xffffffff)
			r = snprintf(p, REMAIN, " %6s", "infini");
		else
			r = snprintf(p, REMAIN, " %6u", lifetime);
		INCP;
	}

	/* RFP option lengths */
	for (pEncap = bpi->attr->vnc_subtlvs; pEncap; pEncap = pEncap->next) {

		if (pEncap->type == BGP_VNC_SUBTLV_TYPE_RFPOPTION) {
			if (printed_1st_gol) {
				r = snprintf(p, REMAIN, ",");
				INCP;
			} else {
				r = snprintf(p, REMAIN,
					     " "); /* leading space */
				INCP;
			}
			r = snprintf(p, REMAIN, "%d", pEncap->length);
			INCP;
			printed_1st_gol = 1;
		}
	}

	/* RT list */
	if (bpi->attr->ecommunity) {
		s = ecommunity_ecom2str(bpi->attr->ecommunity,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		r = snprintf(p, REMAIN, " %s", s);
		INCP;
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	r = snprintf(p, REMAIN, " bpi@%p", bpi);
	INCP;

	r = snprintf(p, REMAIN, " p@%p", bpi->peer);
	INCP;

	if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED)) {
		r = snprintf(p, REMAIN, " HD=yes");
		INCP;
	} else {
		r = snprintf(p, REMAIN, " HD=no");
		INCP;
	}

	if (bpi->attr->weight) {
		r = snprintf(p, REMAIN, " W=%d", bpi->attr->weight);
		INCP;
	}

	if (bpi->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)) {
		r = snprintf(p, REMAIN, " LP=%d", bpi->attr->local_pref);
		INCP;
	} else {
		r = snprintf(p, REMAIN, " LP=unset");
		INCP;
	}

	r = snprintf(p, REMAIN, " %c:%u", zebra_route_char(bpi->type),
		     bpi->sub_type);
	INCP;

	fp(out, "%s%s", line, HVTYNL);

	if (has_macaddr) {
		fp(out, "        RD HID=%d ETH=%02x:%02x:%02x:%02x:%02x:%02x%s",
		   l2hid, macaddr.octet[0], macaddr.octet[1], macaddr.octet[2],
		   macaddr.octet[3], macaddr.octet[4], macaddr.octet[5],
		   HVTYNL);
	}

	if (!rfapiGetL2o(bpi->attr, &l2o_buf)) {
		fp(out,
		   "        L2O ETH=%02x:%02x:%02x:%02x:%02x:%02x LBL=%d LNI=%d LHI=%hhu%s",
		   l2o_buf.macaddr.octet[0], l2o_buf.macaddr.octet[1],
		   l2o_buf.macaddr.octet[2], l2o_buf.macaddr.octet[3],
		   l2o_buf.macaddr.octet[4], l2o_buf.macaddr.octet[5],
		   l2o_buf.label, l2o_buf.logical_net_id, l2o_buf.local_nve_id,
		   HVTYNL);
	}
	if (bpi->extra && bpi->extra->vnc.import.aux_prefix.family) {
		const char *sp;

		sp = rfapi_ntop(bpi->extra->vnc.import.aux_prefix.family,
				&bpi->extra->vnc.import.aux_prefix.u.prefix,
				buf, BUFSIZ);
		buf[BUFSIZ - 1] = 0;
		if (sp) {
			fp(out, "        IP: %s%s", sp, HVTYNL);
		}
	}
	{
		struct rfapi_un_option *uo =
			rfapi_encap_tlv_to_un_option(bpi->attr);
		if (uo) {
			rfapi_print_tunneltype_option(stream, 8, &uo->v.tunnel);
			rfapi_un_options_free(uo);
		}
	}
}

char *rfapiMonitorVpn2Str(struct rfapi_monitor_vpn *m, char *buf, int size)
{
	char buf_pfx[BUFSIZ];
	char buf_vn[BUFSIZ];
	char buf_un[BUFSIZ];
	int rc;

	rfapiRfapiIpAddr2Str(&m->rfd->un_addr, buf_vn, BUFSIZ);
	rfapiRfapiIpAddr2Str(&m->rfd->vn_addr, buf_un, BUFSIZ);

	rc = snprintf(buf, size,
		      "m=%p, next=%p, rfd=%p(vn=%s un=%s), p=%s/%d, node=%p", m,
		      m->next, m->rfd, buf_vn, buf_un,
		      inet_ntop(m->p.family, &m->p.u.prefix, buf_pfx, BUFSIZ),
		      m->p.prefixlen, m->node);
	buf[size - 1] = 0;
	if (rc >= size)
		return NULL;
	return buf;
}

static void rfapiDebugPrintMonitorVpn(void *stream, struct rfapi_monitor_vpn *m)
{
	char buf[BUFSIZ];

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	rfapiMonitorVpn2Str(m, buf, BUFSIZ);
	fp(out, "    Mon %s%s", buf, HVTYNL);
}

static void rfapiDebugPrintMonitorEncap(void *stream,
					struct rfapi_monitor_encap *m)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out = NULL;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	fp(out, "    Mon m=%p, next=%p, node=%p, bpi=%p%s", m, m->next, m->node,
	   m->bpi, HVTYNL);
}

void rfapiShowItNode(void *stream, struct agg_node *rn)
{
	struct bgp_path_info *bpi;
	char buf[BUFSIZ];

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	fp(out, "%s/%d @%p #%d%s",
	   rfapi_ntop(rn->p.family, &rn->p.u.prefix, buf, BUFSIZ),
	   rn->p.prefixlen, rn, rn->lock, HVTYNL);

	for (bpi = rn->info; bpi; bpi = bpi->next) {
		rfapiPrintBi(stream, bpi);
	}

	/* doesn't show montors */
}

void rfapiShowImportTable(void *stream, const char *label, struct agg_table *rt,
			  int isvpn)
{
	struct agg_node *rn;
	char buf[BUFSIZ];

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	fp(out, "Import Table [%s]%s", label, HVTYNL);

	for (rn = agg_route_top(rt); rn; rn = agg_route_next(rn)) {
		struct bgp_path_info *bpi;

		if (rn->p.family == AF_ETHERNET) {
			rfapiEthAddr2Str(&rn->p.u.prefix_eth, buf, BUFSIZ);
		} else {
			inet_ntop(rn->p.family, &rn->p.u.prefix, buf, BUFSIZ);
		}

		fp(out, "%s/%d @%p #%d%s", buf, rn->p.prefixlen, rn,
		   rn->lock - 1, /* account for loop iterator locking */
		   HVTYNL);

		for (bpi = rn->info; bpi; bpi = bpi->next) {
			rfapiPrintBi(stream, bpi);
		}

		if (isvpn) {
			struct rfapi_monitor_vpn *m;
			for (m = RFAPI_MONITOR_VPN(rn); m; m = m->next) {
				rfapiDebugPrintMonitorVpn(stream, m);
			}
		} else {
			struct rfapi_monitor_encap *m;
			for (m = RFAPI_MONITOR_ENCAP(rn); m; m = m->next) {
				rfapiDebugPrintMonitorEncap(stream, m);
			}
		}
	}
}

int rfapiShowVncQueries(void *stream, struct prefix *pfx_match)
{
	struct bgp *bgp;
	struct rfapi *h;
	struct listnode *node;
	struct rfapi_descriptor *rfd;

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	int printedheader = 0;

	int nves_total = 0;
	int nves_with_queries = 0;
	int nves_displayed = 0;

	int queries_total = 0;
	int queries_displayed = 0;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return CMD_WARNING;

	bgp = bgp_get_default(); /* assume 1 instance for now */
	if (!bgp) {
		vty_out(vty, "No BGP instance\n");
		return CMD_WARNING;
	}

	h = bgp->rfapi;
	if (!h) {
		vty_out(vty, "No RFAPI instance\n");
		return CMD_WARNING;
	}

	for (ALL_LIST_ELEMENTS_RO(&h->descriptors, node, rfd)) {

		struct agg_node *rn;
		int printedquerier = 0;


		++nves_total;

		if (rfd->mon
		    || (rfd->mon_eth && skiplist_count(rfd->mon_eth))) {
			++nves_with_queries;
		} else {
			continue;
		}

		/*
		 * IP Queries
		 */
		if (rfd->mon) {
			for (rn = agg_route_top(rfd->mon); rn;
			     rn = agg_route_next(rn)) {
				struct rfapi_monitor_vpn *m;
				char buf_remain[BUFSIZ];
				char buf_pfx[BUFSIZ];

				if (!rn->info)
					continue;

				m = rn->info;

				++queries_total;

				if (pfx_match
				    && !prefix_match(pfx_match, &rn->p)
				    && !prefix_match(&rn->p, pfx_match))
					continue;

				++queries_displayed;

				if (!printedheader) {
					++printedheader;
					fp(out, "\n");
					fp(out, "%-15s %-15s %-15s %-10s\n",
					   "VN Address", "UN Address", "Target",
					   "Remaining");
				}

				if (!printedquerier) {
					char buf_vn[BUFSIZ];
					char buf_un[BUFSIZ];

					rfapiRfapiIpAddr2Str(&rfd->un_addr,
							     buf_un, BUFSIZ);
					rfapiRfapiIpAddr2Str(&rfd->vn_addr,
							     buf_vn, BUFSIZ);

					fp(out, "%-15s %-15s", buf_vn, buf_un);
					printedquerier = 1;

					++nves_displayed;
				} else
					fp(out, "%-15s %-15s", "", "");
				buf_remain[0] = 0;
				if (m->timer) {
					rfapiFormatSeconds(
						thread_timer_remain_second(
							m->timer),
						buf_remain, BUFSIZ);
				}
				fp(out, " %-15s %-10s\n",
				   inet_ntop(m->p.family, &m->p.u.prefix,
					     buf_pfx, BUFSIZ),
				   buf_remain);
			}
		}

		/*
		 * Ethernet Queries
		 */
		if (rfd->mon_eth && skiplist_count(rfd->mon_eth)) {

			int rc;
			void *cursor;
			struct rfapi_monitor_eth *mon_eth;

			for (cursor = NULL,
			    rc = skiplist_next(rfd->mon_eth, NULL,
					       (void **)&mon_eth, &cursor);
			     rc == 0;
			     rc = skiplist_next(rfd->mon_eth, NULL,
						(void **)&mon_eth, &cursor)) {

				char buf_remain[BUFSIZ];
				char buf_pfx[BUFSIZ];
				struct prefix pfx_mac;

				++queries_total;

				vnc_zlog_debug_verbose(
					"%s: checking rfd=%p mon_eth=%p",
					__func__, rfd, mon_eth);

				memset((void *)&pfx_mac, 0,
				       sizeof(struct prefix));
				pfx_mac.family = AF_ETHERNET;
				pfx_mac.prefixlen = 48;
				pfx_mac.u.prefix_eth = mon_eth->macaddr;

				if (pfx_match
				    && !prefix_match(pfx_match, &pfx_mac)
				    && !prefix_match(&pfx_mac, pfx_match))
					continue;

				++queries_displayed;

				if (!printedheader) {
					++printedheader;
					fp(out, "\n");
					fp(out,
					   "%-15s %-15s %-17s %10s %-10s\n",
					   "VN Address", "UN Address", "Target",
					   "LNI", "Remaining");
				}

				if (!printedquerier) {
					char buf_vn[BUFSIZ];
					char buf_un[BUFSIZ];

					rfapiRfapiIpAddr2Str(&rfd->un_addr,
							     buf_un, BUFSIZ);
					rfapiRfapiIpAddr2Str(&rfd->vn_addr,
							     buf_vn, BUFSIZ);

					fp(out, "%-15s %-15s", buf_vn, buf_un);
					printedquerier = 1;

					++nves_displayed;
				} else
					fp(out, "%-15s %-15s", "", "");
				buf_remain[0] = 0;
				if (mon_eth->timer) {
					rfapiFormatSeconds(
						thread_timer_remain_second(
							mon_eth->timer),
						buf_remain, BUFSIZ);
				}
				fp(out, " %-17s %10d %-10s\n",
				   rfapi_ntop(pfx_mac.family, &pfx_mac.u.prefix,
					      buf_pfx, BUFSIZ),
				   mon_eth->logical_net_id, buf_remain);
			}
		}
	}

	if (queries_total) {
		fp(out, "\n");
		fp(out, "Displayed %d out of %d total queries\n",
		   queries_displayed, queries_total);
	}
	return CMD_SUCCESS;
}

static int rfapiPrintRemoteRegBi(struct bgp *bgp, void *stream,
				 struct agg_node *rn, struct bgp_path_info *bpi)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;
	struct prefix pfx_un;
	struct prefix pfx_vn;
	uint8_t cost;
	uint32_t lifetime;
	bgp_encap_types tun_type = BGP_ENCAP_TYPE_MPLS;/*Default tunnel type*/

	char buf_pfx[BUFSIZ];
	char buf_ntop[BUFSIZ];
	char buf_un[BUFSIZ];
	char buf_vn[BUFSIZ];
	char buf_lifetime[BUFSIZ];
	int nlines = 0;

	if (!stream)
		return 0; /* for debug log, print into buf & call output once */

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return 0;

	/*
	 * Prefix
	 */
	buf_pfx[0] = 0;
	snprintf(buf_pfx, BUFSIZ, "%s/%d",
		 rfapi_ntop(rn->p.family, &rn->p.u.prefix, buf_ntop, BUFSIZ),
		 rn->p.prefixlen);
	buf_pfx[BUFSIZ - 1] = 0;
	nlines++;

	/*
	 * UN addr
	 */
	buf_un[0] = 0;
	if (!rfapiGetUnAddrOfVpnBi(bpi, &pfx_un)) {
		snprintf(buf_un, BUFSIZ, "%s",
			 inet_ntop(pfx_un.family, &pfx_un.u.prefix, buf_ntop,
				   BUFSIZ));
	}

	bgp_attr_extcom_tunnel_type(bpi->attr, &tun_type);
	/*
	 * VN addr
	 */
	buf_vn[0] = 0;
	rfapiNexthop2Prefix(bpi->attr, &pfx_vn);
	if (tun_type == BGP_ENCAP_TYPE_MPLS) {
		/* MPLS carries un in nrli next hop (same as vn for IP tunnels)
		 */
		snprintf(buf_un, BUFSIZ, "%s",
			 inet_ntop(pfx_vn.family, &pfx_vn.u.prefix, buf_ntop,
				   BUFSIZ));
		if (bpi->extra) {
			uint32_t l = decode_label(&bpi->extra->label[0]);
			snprintf(buf_vn, BUFSIZ, "Label: %d", l);
		} else /* should never happen */
		{
			snprintf(buf_vn, BUFSIZ, "Label: N/A");
		}
	} else {
		snprintf(buf_vn, BUFSIZ, "%s",
			 inet_ntop(pfx_vn.family, &pfx_vn.u.prefix, buf_ntop,
				   BUFSIZ));
	}
	buf_vn[BUFSIZ - 1] = 0;
	buf_un[BUFSIZ - 1] = 0;

	/*
	 * Cost is encoded in local_pref as (255-cost)
	 * See rfapi_import.c'rfapiRouteInfo2NextHopEntry() for conversion
	 * back to cost.
	 */
	uint32_t local_pref;

	if (bpi->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
		local_pref = bpi->attr->local_pref;
	else
		local_pref = 0;
	cost = (local_pref > 255) ? 0 : 255 - local_pref;

	fp(out, "%-20s ", buf_pfx);
	fp(out, "%-15s ", buf_vn);
	fp(out, "%-15s ", buf_un);
	fp(out, "%-4d ", cost);

	/* Lifetime */
	/* NB rfapiGetVncLifetime sets infinite value when returning !0 */
	if (rfapiGetVncLifetime(bpi->attr, &lifetime)
	    || (lifetime == RFAPI_INFINITE_LIFETIME)) {

		fp(out, "%-10s ", "infinite");
	} else {
		time_t t_lifetime = lifetime;
		rfapiFormatSeconds(t_lifetime, buf_lifetime, BUFSIZ);
		fp(out, "%-10s ", buf_lifetime);
	}

	if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED) && bpi->extra
	    && bpi->extra->vnc.import.timer) {

		uint32_t remaining;
		time_t age;
		char buf_age[BUFSIZ];

		struct thread *t =
			(struct thread *)bpi->extra->vnc.import.timer;
		remaining = thread_timer_remain_second(t);

#if RFAPI_REGISTRATIONS_REPORT_AGE
		/*
		 * Calculate when the timer started. Doing so here saves
		 * us a timestamp field in "struct bgp_path_info".
		 *
		 * See rfapi_import.c'rfapiBiStartWithdrawTimer() for the
		 * original calculation.
		 */
		age = rfapiGetHolddownFromLifetime(lifetime, factor)
		      - remaining;
#else /* report remaining time */
		age = remaining;
#endif
		rfapiFormatSeconds(age, buf_age, BUFSIZ);

		fp(out, "%-10s ", buf_age);

	} else if (RFAPI_LOCAL_BI(bpi)) {

		char buf_age[BUFSIZ];

		if (bpi->extra && bpi->extra->vnc.import.create_time) {
			rfapiFormatAge(bpi->extra->vnc.import.create_time,
				       buf_age, BUFSIZ);
		} else {
			buf_age[0] = '?';
			buf_age[1] = 0;
		}
		fp(out, "%-10s ", buf_age);
	}
	fp(out, "%s", HVTYNL);

	if (rn->p.family == AF_ETHERNET) {
		/*
		 * If there is a corresponding IP address && != VN address,
		 * print that on the next line
		 */

		if (bpi->extra && bpi->extra->vnc.import.aux_prefix.family) {
			const char *sp;

			sp = rfapi_ntop(
				bpi->extra->vnc.import.aux_prefix.family,
				&bpi->extra->vnc.import.aux_prefix.u.prefix,
				buf_ntop, BUFSIZ);
			buf_ntop[BUFSIZ - 1] = 0;

			if (sp && strcmp(buf_vn, sp) != 0) {
				fp(out, "  IP: %s", sp);
				if (nlines == 1)
					nlines++;
			}
		}
	}
	if (tun_type != BGP_ENCAP_TYPE_MPLS && bpi->extra) {
		uint32_t l = decode_label(&bpi->extra->label[0]);
		if (!MPLS_LABEL_IS_NULL(l)) {
			fp(out, "  Label: %d", l);
			if (nlines == 1)
				nlines++;
		}
	}
	if (nlines > 1)
		fp(out, "%s", HVTYNL);

	return 1;
}

static int rfapiShowRemoteRegistrationsIt(struct bgp *bgp, void *stream,
					  struct rfapi_import_table *it,
					  struct prefix *prefix_only,
					  int show_expiring, /* either/or */
					  int show_local, int show_remote,
					  int show_imported, /* either/or */
					  uint32_t *pLni) /* AFI_L2VPN only */
{
	afi_t afi;
	int printed_rtlist_hdr = 0;

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;
	int total = 0;
	int printed = 0;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return printed;

	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

		struct agg_node *rn;

		if (!it->imported_vpn[afi])
			continue;

		for (rn = agg_route_top(it->imported_vpn[afi]); rn;
		     rn = agg_route_next(rn)) {

			struct bgp_path_info *bpi;
			int count_only;

			/* allow for wider or more narrow mask from user */
			if (prefix_only && !prefix_match(prefix_only, &rn->p)
			    && !prefix_match(&rn->p, prefix_only))
				count_only = 1;
			else
				count_only = 0;

			for (bpi = rn->info; bpi; bpi = bpi->next) {

				if (!show_local && RFAPI_LOCAL_BI(bpi)) {

					/* local route from RFP */
					continue;
				}

				if (!show_remote && !RFAPI_LOCAL_BI(bpi)) {

					/* remote route */
					continue;
				}

				if (show_expiring
				    && !CHECK_FLAG(bpi->flags,
						   BGP_PATH_REMOVED))
					continue;

				if (!show_expiring
				    && CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED))
					continue;

				if (bpi->type == ZEBRA_ROUTE_BGP_DIRECT
				    || bpi->type
					       == ZEBRA_ROUTE_BGP_DIRECT_EXT) {
					if (!show_imported)
						continue;
				} else {
					if (show_imported)
						continue;
				}

				total++;
				if (count_only == 1)
					continue;
				if (!printed_rtlist_hdr) {
					const char *agetype = "";
					char *s;
					const char *type = "";
					if (show_imported) {
						type = "Imported";
					} else {
						if (show_expiring) {
							type = "Holddown";
						} else {
							if (RFAPI_LOCAL_BI(
								    bpi)) {
								type = "Local";
							} else {
								type = "Remote";
							}
						}
					}

					s = ecommunity_ecom2str(
						it->rt_import_list,
						ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

					if (pLni) {
						fp(out,
						   "%s[%s] L2VPN Network 0x%x (%u) RT={%s}",
						   HVTYNL, type, *pLni,
						   (*pLni & 0xfff), s);
					} else {
						fp(out, "%s[%s] Prefix RT={%s}",
						   HVTYNL, type, s);
					}
					XFREE(MTYPE_ECOMMUNITY_STR, s);

					if (it->rfg && it->rfg->name) {
						fp(out, " %s \"%s\"",
						   (it->rfg->type == RFAPI_GROUP_CFG_VRF
							    ? "VRF"
							    : "NVE group"),
						   it->rfg->name);
					}
					fp(out, "%s", HVTYNL);
					if (show_expiring) {
#if RFAPI_REGISTRATIONS_REPORT_AGE
						agetype = "Age";
#else
						agetype = "Remaining";
#endif
					} else if (show_local) {
						agetype = "Age";
					}

					printed_rtlist_hdr = 1;

					fp(out,
					   "%-20s %-15s %-15s %4s %-10s %-10s%s",
					   (pLni ? "L2 Address/IP" : "Prefix"),
					   "VN Address", "UN Address", "Cost",
					   "Lifetime", agetype, HVTYNL);
				}
				printed += rfapiPrintRemoteRegBi(bgp, stream,
								 rn, bpi);
			}
		}
	}

	if (printed > 0) {

		const char *type = "prefixes";

		if (show_imported) {
			type = "imported prefixes";
		} else {
			if (show_expiring) {
				type = "prefixes in holddown";
			} else {
				if (show_local && !show_remote) {
					type = "locally registered prefixes";
				} else if (!show_local && show_remote) {
					type = "remotely registered prefixes";
				}
			}
		}

		fp(out, "Displayed %d out of %d %s%s", printed, total, type,
		   HVTYNL);
#if DEBUG_SHOW_EXTRA
		fp(out, "IT table above: it=%p%s", it, HVTYNL);
#endif
	}
	return printed;
}


/*
 * rfapiShowRemoteRegistrations
 *
 * Similar to rfapiShowImportTable() above. This function
 * is mean to produce the "remote" portion of the output
 * of "show vnc registrations".
 */
int rfapiShowRemoteRegistrations(void *stream, struct prefix *prefix_only,
				 int show_expiring, int show_local,
				 int show_remote, int show_imported)
{
	struct bgp *bgp;
	struct rfapi *h;
	struct rfapi_import_table *it;
	int printed = 0;

	bgp = bgp_get_default();
	if (!bgp) {
		return printed;
	}

	h = bgp->rfapi;
	if (!h) {
		return printed;
	}

	for (it = h->imports; it; it = it->next) {
		printed += rfapiShowRemoteRegistrationsIt(
			bgp, stream, it, prefix_only, show_expiring, show_local,
			show_remote, show_imported, NULL);
	}

	if (h->import_mac) {
		void *cursor = NULL;
		int rc;
		uintptr_t lni_as_ptr;
		uint32_t lni;
		uint32_t *pLni;

		for (rc = skiplist_next(h->import_mac, (void **)&lni_as_ptr,
					(void **)&it, &cursor);
		     !rc;
		     rc = skiplist_next(h->import_mac, (void **)&lni_as_ptr,
					(void **)&it, &cursor)) {
			pLni = NULL;
			if ((lni_as_ptr & 0xffffffff) == lni_as_ptr) {
				lni = (uint32_t)(lni_as_ptr & 0xffffffff);
				pLni = &lni;
			}

			printed += rfapiShowRemoteRegistrationsIt(
				bgp, stream, it, prefix_only, show_expiring,
				show_local, show_remote, show_imported, pLni);
		}
	}

	return printed;
}

/*------------------------------------------
 * rfapiRfapiIpAddr2Str
 *
 * UI helper: generate string from rfapi_ip_addr
 *
 * input:
 *	a			IP v4/v6 address
 *
 * output
 *	buf			put string here
 *	bufsize			max space to write
 *
 * return value:
 *	NULL			conversion failed
 *	non-NULL		pointer to buf
 --------------------------------------------*/
const char *rfapiRfapiIpAddr2Str(struct rfapi_ip_addr *a, char *buf,
				 int bufsize)
{
	const char *rc = NULL;

	switch (a->addr_family) {
	case AF_INET:
		rc = inet_ntop(a->addr_family, &a->addr.v4, buf, bufsize);
		break;
	case AF_INET6:
		rc = inet_ntop(a->addr_family, &a->addr.v6, buf, bufsize);
		break;
	}
	return rc;
}

void rfapiPrintRfapiIpAddr(void *stream, struct rfapi_ip_addr *a)
{
	char buf[BUFSIZ];
	const char *rc = NULL;

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out = NULL;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	rc = rfapiRfapiIpAddr2Str(a, buf, BUFSIZ);

	if (rc)
		fp(out, "%s", buf);
}

const char *rfapiRfapiIpPrefix2Str(struct rfapi_ip_prefix *p, char *buf,
				   int bufsize)
{
	struct rfapi_ip_addr *a = &p->prefix;
	const char *rc = NULL;

	switch (a->addr_family) {
	case AF_INET:
		rc = inet_ntop(a->addr_family, &a->addr.v4, buf, bufsize);
		break;
	case AF_INET6:
		rc = inet_ntop(a->addr_family, &a->addr.v6, buf, bufsize);
		break;
	}

	if (rc) {
		int alen = strlen(buf);
		int remaining = bufsize - alen - 1;
		int slen;

		if (remaining > 0) {
			slen = snprintf(buf + alen, remaining, "/%u",
					p->length);
			if (slen < remaining) /* see man page for snprintf(3) */
				return rc;
		}
	}

	return NULL;
}

void rfapiPrintRfapiIpPrefix(void *stream, struct rfapi_ip_prefix *p)
{
	char buf[BUFSIZ];
	const char *rc;

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out = NULL;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	rc = rfapiRfapiIpPrefix2Str(p, buf, BUFSIZ);

	if (rc)
		fp(out, "%s:%u", buf, p->cost);
	else
		fp(out, "?/?:?");
}

void rfapiPrintRd(struct vty *vty, struct prefix_rd *prd)
{
	char buf[RD_ADDRSTRLEN];

	prefix_rd2str(prd, buf, sizeof(buf));
	vty_out(vty, "%s", buf);
}

void rfapiPrintAdvertisedInfo(struct vty *vty, struct rfapi_descriptor *rfd,
			      safi_t safi, struct prefix *p)
{
	afi_t afi; /* of the VN address */
	struct bgp_node *bn;
	struct bgp_path_info *bpi;
	uint8_t type = ZEBRA_ROUTE_BGP;
	struct bgp *bgp;
	int printed = 0;
	struct prefix_rd prd0;
	struct prefix_rd *prd;

	/*
	 * Find the bgp_path in the RIB corresponding to this
	 * prefix and rfd
	 */

	afi = family2afi(p->family);
	assert(afi == AFI_IP || afi == AFI_IP6);

	bgp = bgp_get_default(); /* assume 1 instance for now */
	assert(bgp);

	if (safi == SAFI_ENCAP) {
		memset(&prd0, 0, sizeof(prd0));
		prd0.family = AF_UNSPEC;
		prd0.prefixlen = 64;
		prd = &prd0;
	} else {
		prd = &rfd->rd;
	}
	bn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, prd);

	vty_out(vty, "  bn=%p%s", bn, HVTYNL);

	for (bpi = bgp_node_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->peer == rfd->peer && bpi->type == type
		    && bpi->sub_type == BGP_ROUTE_RFP && bpi->extra
		    && bpi->extra->vnc.export.rfapi_handle == (void *)rfd) {

			rfapiPrintBi(vty, bpi);
			printed = 1;
		}
	}

	if (!printed) {
		vty_out(vty, "    --?--%s", HVTYNL);
		return;
	}
}

void rfapiPrintDescriptor(struct vty *vty, struct rfapi_descriptor *rfd)
{
	/* pHD un-addr vn-addr pCB cookie rd lifetime */
	/* RT export list */
	/* RT import list */
	/* list of advertised prefixes */
	/* dump import table */

	char *s;
	void *cursor;
	int rc;
	afi_t afi;
	struct rfapi_adb *adb;
	char buf[PREFIX_STRLEN];

	vty_out(vty, "%-10p ", rfd);
	rfapiPrintRfapiIpAddr(vty, &rfd->un_addr);
	vty_out(vty, " ");
	rfapiPrintRfapiIpAddr(vty, &rfd->vn_addr);
	vty_out(vty, " %p %p ", rfd->response_cb, rfd->cookie);
	rfapiPrintRd(vty, &rfd->rd);
	vty_out(vty, " %d", rfd->response_lifetime);
	vty_out(vty, " %s", (rfd->rfg ? rfd->rfg->name : "<orphaned>"));
	vty_out(vty, "%s", HVTYNL);

	vty_out(vty, " Peer %p #%d%s", rfd->peer, rfd->peer->lock, HVTYNL);

	/* export RT list */
	if (rfd->rt_export_list) {
		s = ecommunity_ecom2str(rfd->rt_export_list,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		vty_out(vty, " Export %s%s", s, HVTYNL);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	} else {
		vty_out(vty, " Export (nil)%s", HVTYNL);
	}

	/* import RT list */
	if (rfd->import_table) {
		s = ecommunity_ecom2str(rfd->import_table->rt_import_list,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		vty_out(vty, " Import %s%s", s, HVTYNL);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	} else {
		vty_out(vty, " Import (nil)%s", HVTYNL);
	}

	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		uint8_t family;

		family = afi2family(afi);
		if (!family)
			continue;

		cursor = NULL;
		for (rc = skiplist_next(rfd->advertised.ipN_by_prefix, NULL,
					(void **)&adb, &cursor);
		     rc == 0;
		     rc = skiplist_next(rfd->advertised.ipN_by_prefix, NULL,
					(void **)&adb, &cursor)) {

			/* group like family prefixes together in output */
			if (family != adb->u.s.prefix_ip.family)
				continue;

			prefix2str(&adb->u.s.prefix_ip, buf, sizeof(buf));

			vty_out(vty, "  Adv Pfx: %s%s", buf, HVTYNL);
			rfapiPrintAdvertisedInfo(vty, rfd, SAFI_MPLS_VPN,
						 &adb->u.s.prefix_ip);
		}
	}
	for (rc = skiplist_next(rfd->advertised.ip0_by_ether, NULL,
				(void **)&adb, &cursor);
	     rc == 0; rc = skiplist_next(rfd->advertised.ip0_by_ether, NULL,
					 (void **)&adb, &cursor)) {

		prefix2str(&adb->u.s.prefix_eth, buf, sizeof(buf));

		vty_out(vty, "  Adv Pfx: %s%s", buf, HVTYNL);

		/* TBD update the following function to print ethernet info */
		/* Also need to pass/use rd */
		rfapiPrintAdvertisedInfo(vty, rfd, SAFI_MPLS_VPN,
					 &adb->u.s.prefix_ip);
	}
	vty_out(vty, "%s", HVTYNL);
}

/*
 * test scripts rely on first line for each nve starting in 1st column,
 * leading whitespace for additional detail of that nve
 */
void rfapiPrintMatchingDescriptors(struct vty *vty, struct prefix *vn_prefix,
				   struct prefix *un_prefix)
{
	struct bgp *bgp;
	struct rfapi *h;
	struct listnode *ln;
	struct rfapi_descriptor *rfd;
	int printed = 0;

	bgp = bgp_get_default(); /* assume 1 instance for now */
	if (!bgp)
		return;

	h = bgp->rfapi;
	assert(h);

	for (ln = listhead(&h->descriptors); ln; ln = listnextnode(ln)) {
		rfd = listgetdata(ln);

		struct prefix pfx;

		if (vn_prefix) {
			assert(!rfapiRaddr2Qprefix(&rfd->vn_addr, &pfx));
			if (!prefix_match(vn_prefix, &pfx))
				continue;
		}

		if (un_prefix) {
			assert(!rfapiRaddr2Qprefix(&rfd->un_addr, &pfx));
			if (!prefix_match(un_prefix, &pfx))
				continue;
		}

		if (!printed) {
			/* print column header */
			vty_out(vty, "%s %s %s %s %s %s %s %s%s", "descriptor",
				"un-addr", "vn-addr", "callback", "cookie",
				"RD", "lifetime", "group", HVTYNL);
		}
		rfapiPrintDescriptor(vty, rfd);
		printed = 1;
	}
}


/*
 * Parse an address and put into a struct prefix
 */
int rfapiCliGetPrefixAddr(struct vty *vty, const char *str, struct prefix *p)
{
	if (!str2prefix(str, p)) {
		vty_out(vty, "Malformed address \"%s\"%s", str ? str : "null",
			HVTYNL);
		return CMD_WARNING;
	}
	switch (p->family) {
	case AF_INET:
		if (p->prefixlen != 32) {
			vty_out(vty, "Not a host address: \"%s\"%s", str,
				HVTYNL);
			return CMD_WARNING;
		}
		break;
	case AF_INET6:
		if (p->prefixlen != 128) {
			vty_out(vty, "Not a host address: \"%s\"%s", str,
				HVTYNL);
			return CMD_WARNING;
		}
		break;
	default:
		vty_out(vty, "Invalid address \"%s\"%s", str, HVTYNL);
		return CMD_WARNING;
	}
	return 0;
}

int rfapiCliGetRfapiIpAddr(struct vty *vty, const char *str,
			   struct rfapi_ip_addr *hai)
{
	struct prefix pfx;
	int rc;

	rc = rfapiCliGetPrefixAddr(vty, str, &pfx);
	if (rc)
		return rc;

	hai->addr_family = pfx.family;
	if (pfx.family == AF_INET)
		hai->addr.v4 = pfx.u.prefix4;
	else
		hai->addr.v6 = pfx.u.prefix6;

	return 0;
}

/*
 * Note: this function does not flush vty output, so if it is called
 * with a stream pointing to a vty, the user will have to type something
 * before the callback output shows up
 */
void rfapiPrintNhl(void *stream, struct rfapi_next_hop_entry *next_hops)
{
	struct rfapi_next_hop_entry *nh;
	int count;

	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

#define REMAIN (BUFSIZ - (p-line))
#define INCP {p += (r > REMAIN)? REMAIN: r;}

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	for (nh = next_hops, count = 1; nh; nh = nh->next, ++count) {

		char line[BUFSIZ];
		char *p = line;
		int r;

		r = snprintf(p, REMAIN, "%3d  pfx=", count);
		INCP;

		if (rfapiRfapiIpPrefix2Str(&nh->prefix, p, REMAIN)) {
			/* it fit, so count length */
			r = strlen(p);
		} else {
			/* didn't fit */
			goto truncate;
		}
		INCP;

		r = snprintf(p, REMAIN, ", un=");
		INCP;

		if (rfapiRfapiIpAddr2Str(&nh->un_address, p, REMAIN)) {
			/* it fit, so count length */
			r = strlen(p);
		} else {
			/* didn't fit */
			goto truncate;
		}
		INCP;

		r = snprintf(p, REMAIN, ", vn=");
		INCP;

		if (rfapiRfapiIpAddr2Str(&nh->vn_address, p, REMAIN)) {
			/* it fit, so count length */
			r = strlen(p);
		} else {
			/* didn't fit */
			goto truncate;
		}
		INCP;

	truncate:
		line[BUFSIZ - 1] = 0;
		fp(out, "%s%s", line, HVTYNL);

		/*
		 * options
		 */
		if (nh->vn_options) {
			struct rfapi_vn_option *vo;
			char offset[] = "     ";

			for (vo = nh->vn_options; vo; vo = vo->next) {
				char pbuf[100];

				switch (vo->type) {
				case RFAPI_VN_OPTION_TYPE_L2ADDR:
					rfapiEthAddr2Str(&vo->v.l2addr.macaddr,
							 pbuf, sizeof(pbuf));
					fp(out,
					   "%sL2 %s LBL=0x%06x NETID=0x%06x NVEID=%d%s",
					   offset, pbuf,
					   (vo->v.l2addr.label & 0x00ffffff),
					   (vo->v.l2addr.logical_net_id
					    & 0x00ffffff),
					   vo->v.l2addr.local_nve_id, HVTYNL);
					break;

				case RFAPI_VN_OPTION_TYPE_LOCAL_NEXTHOP:
					prefix2str(&vo->v.local_nexthop.addr,
						   pbuf, sizeof(pbuf));
					fp(out, "%sLNH %s cost=%d%s", offset,
					   pbuf, vo->v.local_nexthop.cost,
					   HVTYNL);
					break;

				default:
					fp(out,
					   "%svn option type %d (unknown)%s",
					   offset, vo->type, HVTYNL);
					break;
				}
			}
		}
		if (nh->un_options) {
			struct rfapi_un_option *uo;
			char offset[] = "     ";

			for (uo = nh->un_options; uo; uo = uo->next) {
				switch (uo->type) {
				case RFAPI_UN_OPTION_TYPE_TUNNELTYPE:
					rfapi_print_tunneltype_option(
						stream, 8, &uo->v.tunnel);
					break;
				default:
					fp(out, "%sUN Option type %d%s", offset,
					   uo->type, vty_newline);
					break;
				}
			}
		}
	}
}

/***********************************************************************
 *			STATIC ROUTES
 ***********************************************************************/

/*
 * Add another nexthop to the NHL
 */
static void rfapiAddDeleteLocalRfpPrefix(struct rfapi_ip_addr *un_addr,
					 struct rfapi_ip_addr *vn_addr,
					 struct rfapi_ip_prefix *rprefix,
					 int is_add,
					 uint32_t lifetime, /* add only */
					 struct rfapi_vn_option *vn_options,
					 struct rfapi_next_hop_entry **head,
					 struct rfapi_next_hop_entry **tail)
{
	struct rfapi_next_hop_entry *new;

	/*
	 * construct NHL
	 */

	new = XCALLOC(MTYPE_RFAPI_NEXTHOP, sizeof(struct rfapi_next_hop_entry));
	new->prefix = *rprefix;
	new->un_address = *un_addr;
	new->vn_address = *vn_addr;

	new->vn_options = vn_options;
	if (is_add) {
		new->lifetime = lifetime;
	} else {
		new->lifetime = RFAPI_REMOVE_RESPONSE_LIFETIME;
	}

	if (*tail)
		(*tail)->next = new;
	*tail = new;
	if (!*head) {
		*head = new;
	}
}


static int
register_add(struct vty *vty, struct cmd_token *carg_prefix,
	     struct cmd_token *carg_vn, struct cmd_token *carg_un,
	     struct cmd_token *carg_cost,     /* optional */
	     struct cmd_token *carg_lifetime, /* optional */
	     struct cmd_token *carg_macaddr,  /* optional */
	     struct cmd_token
		     *carg_vni, /* mac present=>mandatory Virtual Network ID */
	     int argc, struct cmd_token **argv)
{
	const char *arg_prefix = carg_prefix ? carg_prefix->arg : NULL;
	const char *arg_vn = carg_vn ? carg_vn->arg : NULL;
	const char *arg_un = carg_un ? carg_un->arg : NULL;
	const char *arg_cost = carg_cost ? carg_cost->arg : NULL;
	const char *arg_lifetime = carg_lifetime ? carg_lifetime->arg : NULL;
	const char *arg_macaddr = carg_macaddr ? carg_macaddr->arg : NULL;
	const char *arg_vni = carg_vni ? carg_vni->arg : NULL;
	struct rfapi_ip_addr vn_address;
	struct rfapi_ip_addr un_address;
	struct prefix pfx;
	struct rfapi_ip_prefix rpfx;
	uint32_t cost;
	uint32_t lnh_cost;
	uint32_t lifetime;
	rfapi_handle rfd;
	struct rfapi_vn_option optary[10]; /* XXX must be big enough */
	struct rfapi_vn_option *opt = NULL;
	int opt_next = 0;

	int rc = CMD_WARNING_CONFIG_FAILED;
	char *endptr;
	struct bgp *bgp;
	struct rfapi *h;
	struct rfapi_cfg *rfapi_cfg;

	const char *arg_lnh = NULL;
	const char *arg_lnh_cost = NULL;

	bgp = bgp_get_default(); /* assume 1 instance for now */
	if (!bgp) {
		if (vty)
			vty_out(vty, "BGP not configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	h = bgp->rfapi;
	rfapi_cfg = bgp->rfapi_cfg;
	if (!h || !rfapi_cfg) {
		if (vty)
			vty_out(vty, "RFAPI not configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (; argc; --argc, ++argv) {
		if (strmatch(argv[0]->text, "local-next-hop")) {
			if (arg_lnh) {
				vty_out(vty,
					"local-next-hop specified more than once\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			if (argc <= 1) {
				vty_out(vty,
					"Missing parameter for local-next-hop\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			++argv;
			--argc;
			arg_lnh = argv[0]->arg;
		}
		if (strmatch(argv[0]->text, "local-cost")) {
			if (arg_lnh_cost) {
				vty_out(vty,
					"local-cost specified more than once\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			if (argc <= 1) {
				vty_out(vty,
					"Missing parameter for local-cost\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			++argv;
			--argc;
			arg_lnh_cost = argv[0]->arg;
		}
	}

	if ((rc = rfapiCliGetRfapiIpAddr(vty, arg_vn, &vn_address)))
		goto fail;
	if ((rc = rfapiCliGetRfapiIpAddr(vty, arg_un, &un_address)))
		goto fail;

	/* arg_prefix is optional if mac address is given */
	if (arg_macaddr && !arg_prefix) {
		/*
		 * fake up a 0/32 or 0/128 prefix
		 */
		switch (vn_address.addr_family) {
		case AF_INET:
			arg_prefix = "0.0.0.0/32";
			break;
		case AF_INET6:
			arg_prefix = "0::0/128";
			break;
		default:
			vty_out(vty,
				"Internal error, unknown VN address family\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (!str2prefix(arg_prefix, &pfx)) {
		vty_out(vty, "Malformed prefix \"%s\"\n", arg_prefix);
		goto fail;
	}
	if (pfx.family != AF_INET && pfx.family != AF_INET6) {
		vty_out(vty, "prefix \"%s\" has invalid address family\n",
			arg_prefix);
		goto fail;
	}


	memset(optary, 0, sizeof(optary));

	if (arg_cost) {
		endptr = NULL;
		cost = strtoul(arg_cost, &endptr, 10);
		if (*endptr != '\0' || cost > 255) {
			vty_out(vty, "%% Invalid %s value\n", "cost");
			goto fail;
		}
	} else {
		cost = 255;
	}

	if (arg_lifetime) {
		if (!strcmp(arg_lifetime, "infinite")) {
			lifetime = RFAPI_INFINITE_LIFETIME;
		} else {
			endptr = NULL;
			lifetime = strtoul(arg_lifetime, &endptr, 10);
			if (*endptr != '\0') {
				vty_out(vty, "%% Invalid %s value\n",
					"lifetime");
				goto fail;
			}
		}
	} else {
		lifetime = RFAPI_INFINITE_LIFETIME; /* default infinite */
	}

	if (arg_lnh_cost) {
		if (!arg_lnh) {
			vty_out(vty,
				"%% %s may only be specified with local-next-hop\n",
				"local-cost");
			goto fail;
		}
		endptr = NULL;
		lnh_cost = strtoul(arg_lnh_cost, &endptr, 10);
		if (*endptr != '\0' || lnh_cost > 255) {
			vty_out(vty, "%% Invalid %s value\n", "local-cost");
			goto fail;
		}
	} else {
		lnh_cost = 255;
	}

	if (arg_lnh) {
		if (!arg_prefix) {
			vty_out(vty,
				"%% %s may only be specified with prefix\n",
				"local-next-hop");
			goto fail;
		}
		if ((rc = rfapiCliGetPrefixAddr(
			     vty, arg_lnh,
			     &optary[opt_next].v.local_nexthop.addr))) {

			goto fail;
		}

		optary[opt_next].v.local_nexthop.cost = lnh_cost;
		optary[opt_next].type = RFAPI_VN_OPTION_TYPE_LOCAL_NEXTHOP;

		if (opt_next) {
			optary[opt_next - 1].next = optary + opt_next;
		} else {
			opt = optary;
		}
		++opt_next;
	}

	if (arg_vni && !arg_macaddr) {
		vty_out(vty, "%% %s may only be specified with mac address\n",
			"virtual-network-identifier");
		goto fail;
	}

	if (arg_macaddr) {
		if (!arg_vni) {
			vty_out(vty,
				"Missing \"vni\" parameter (mandatory with mac)\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		optary[opt_next].v.l2addr.logical_net_id =
			strtoul(arg_vni, NULL, 10);

		if ((rc = rfapiStr2EthAddr(
			     arg_macaddr,
			     &optary[opt_next].v.l2addr.macaddr))) {
			vty_out(vty, "Invalid %s value\n", "mac address");
			goto fail;
		}
		/* TBD label, NVE ID */

		optary[opt_next].type = RFAPI_VN_OPTION_TYPE_L2ADDR;

		if (opt_next) {
			optary[opt_next - 1].next = optary + opt_next;
		} else {
			opt = optary;
		}
		++opt_next;
	}

	vnc_zlog_debug_verbose(
		"%s: vn=%s, un=%s, prefix=%s, cost=%s, lifetime=%s, lnh=%s",
		__func__, arg_vn, arg_un, arg_prefix,
		(arg_cost ? arg_cost : "NULL"),
		(arg_lifetime ? arg_lifetime : "NULL"),
		(arg_lnh ? arg_lnh : "NULL"));

	rfapiQprefix2Rprefix(&pfx, &rpfx);

	rpfx.cost = cost & 255;

	/* look up rf descriptor, call open if it doesn't exist  */
	rc = rfapi_find_rfd(bgp, &vn_address, &un_address,
			    (struct rfapi_descriptor **)&rfd);
	if (rc) {
		if (ENOENT == rc) {
			struct rfapi_un_option uo;

			/*
			 * flag descriptor as provisionally opened for static
			 * route
			 * registration so that we can fix up the other
			 * parameters
			 * when the real open comes along
			 */
			memset(&uo, 0, sizeof(uo));
			uo.type = RFAPI_UN_OPTION_TYPE_PROVISIONAL;

			rc = rfapi_open(rfapi_get_rfp_start_val_by_bgp(bgp),
					&vn_address, &un_address,
					&uo,	/* flags */
					NULL, NULL, /* no userdata */
					&rfd);
			if (rc) {
				vty_out(vty,
					"Can't open session for this NVE: %s\n",
					rfapi_error_str(rc));
				rc = CMD_WARNING_CONFIG_FAILED;
				goto fail;
			}
		} else {
			vty_out(vty, "Can't find session for this NVE: %s\n",
				rfapi_error_str(rc));
			goto fail;
		}
	}

	rc = rfapi_register(rfd, &rpfx, lifetime, NULL, opt,
			    RFAPI_REGISTER_ADD);
	if (!rc) {
		struct rfapi_next_hop_entry *head = NULL;
		struct rfapi_next_hop_entry *tail = NULL;
		struct rfapi_vn_option *vn_opt_new;

		vnc_zlog_debug_verbose(
			"%s: rfapi_register succeeded, returning 0", __func__);

		if (h->rfp_methods.local_cb) {
			struct rfapi_descriptor *r =
				(struct rfapi_descriptor *)rfd;
			vn_opt_new = rfapi_vn_options_dup(opt);

			rfapiAddDeleteLocalRfpPrefix(&r->un_addr, &r->vn_addr,
						     &rpfx, 1, lifetime,
						     vn_opt_new, &head, &tail);
			if (head) {
				h->flags |= RFAPI_INCALLBACK;
				(*h->rfp_methods.local_cb)(head, r->cookie);
				h->flags &= ~RFAPI_INCALLBACK;
			}
			head = tail = NULL;
		}
		return 0;
	}

	vnc_zlog_debug_verbose("%s: rfapi_register failed", __func__);
	vty_out(vty, "\n");
	vty_out(vty, "Registration failed.\n");
	vty_out(vty,
		"Confirm that either the VN or UN address matches a configured NVE group.\n");
	return CMD_WARNING_CONFIG_FAILED;

fail:
	vnc_zlog_debug_verbose("%s: fail, rc=%d", __func__, rc);
	return rc;
}

/************************************************************************
 *		Add prefix With LNH_OPTIONS...
 ************************************************************************/
DEFUN (add_vnc_prefix_cost_life_lnh,
       add_vnc_prefix_cost_life_lnh_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> cost (0-255) lifetime (1-4294967295) LNH_OPTIONS...",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Administrative cost   [default: 255]\n"
       "Administrative cost\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n"
       "[local-next-hop (A.B.C.D|X:X::X:X)] [local-cost <0-255>]\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], argv[9], argv[11],
			    /* mac vni */
			    NULL, NULL, argc - 12, argv + 12);
}

DEFUN (add_vnc_prefix_life_cost_lnh,
       add_vnc_prefix_life_cost_lnh_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> lifetime (1-4294967295) cost (0-255) LNH_OPTIONS...",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n"
       "Administrative cost   [default: 255]\n"
       "Administrative cost\n"
       "[local-next-hop (A.B.C.D|X:X::X:X)] [local-cost <0-255>]\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], argv[11], argv[9],
			    /* mac vni */
			    NULL, NULL, argc - 12, argv + 12);
}

DEFUN (add_vnc_prefix_cost_lnh,
       add_vnc_prefix_cost_lnh_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> cost (0-255) LNH_OPTIONS...",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Administrative cost   [default: 255]\n"
       "Administrative cost\n"
       "[local-next-hop (A.B.C.D|X:X::X:X)] [local-cost <0-255>]\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], argv[9], NULL,
			    /* mac vni */
			    NULL, NULL, argc - 10, argv + 10);
}

DEFUN (add_vnc_prefix_life_lnh,
       add_vnc_prefix_life_lnh_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> lifetime (1-4294967295) LNH_OPTIONS...",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n"
       "[local-next-hop (A.B.C.D|X:X::X:X)] [local-cost <0-255>]\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], NULL, argv[9],
			    /* mac vni */
			    NULL, NULL, argc - 10, argv + 10);
}

DEFUN (add_vnc_prefix_lnh,
       add_vnc_prefix_lnh_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> LNH_OPTIONS...",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "[local-next-hop (A.B.C.D|X:X::X:X)] [local-cost <0-255>]\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], NULL, NULL,
			    /* mac vni */
			    NULL, NULL, argc - 8, argv + 8);
}

/************************************************************************
 *		Add prefix Without LNH_OPTIONS...
 ************************************************************************/
DEFUN (add_vnc_prefix_cost_life,
       add_vnc_prefix_cost_life_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> cost (0-255) lifetime (1-4294967295)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Administrative cost   [default: 255]\n"
       "Administrative cost\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], argv[9], argv[11],
			    /* mac vni */
			    NULL, NULL, 0, NULL);
}

DEFUN (add_vnc_prefix_life_cost,
       add_vnc_prefix_life_cost_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> lifetime (1-4294967295) cost (0-255)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n"
       "Administrative cost   [default: 255]\n"
       "Administrative cost\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], argv[11], argv[9],
			    /* mac vni */
			    NULL, NULL, 0, NULL);
}

DEFUN (add_vnc_prefix_cost,
       add_vnc_prefix_cost_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> cost (0-255)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Administrative cost   [default: 255]\n"
       "Administrative cost\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], argv[9], NULL,
			    /* mac vni */
			    NULL, NULL, 0, NULL);
}

DEFUN (add_vnc_prefix_life,
       add_vnc_prefix_life_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> lifetime (1-4294967295)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], NULL, argv[9],
			    /* mac vni */
			    NULL, NULL, 0, NULL);
}

DEFUN (add_vnc_prefix,
       add_vnc_prefix_cmd,
       "add vnc prefix <A.B.C.D/M|X:X::X:X/M> vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X>",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[3], argv[5], argv[7], NULL, NULL,
			    /* mac vni */
			    NULL, NULL, 0, NULL);
}

/************************************************************************
 *			Mac address registrations
 ************************************************************************/
DEFUN (add_vnc_mac_vni_prefix_cost_life,
       add_vnc_mac_vni_prefix_cost_life_cmd,
       "add vnc mac YY:YY:YY:YY:YY:YY virtual-network-identifier (1-4294967295) vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> prefix <A.B.C.D/M|X:X::X:X/M> cost (0-255) lifetime (1-4294967295)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify mac address information\n"
       "MAC address\n"
       "Virtual Network Identifier follows\n"
       "Virtual Network Identifier\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "Administrative cost   [default: 255]\n"
       "Administrative cost\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[11], argv[7], argv[9], argv[13], argv[15],
			    /* mac vni */
			    argv[3], argv[5], 0, NULL);
}


DEFUN (add_vnc_mac_vni_prefix_life,
       add_vnc_mac_vni_prefix_life_cmd,
       "add vnc mac YY:YY:YY:YY:YY:YY virtual-network-identifier (1-4294967295) vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> prefix <A.B.C.D/M|X:X::X:X/M> lifetime (1-4294967295)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify mac address information\n"
       "MAC address\n"
       "Virtual Network Identifier follows\n"
       "Virtual Network Identifier\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[11], argv[7], argv[9], NULL, argv[13],
			    /* mac vni */
			    argv[3], argv[5], 0, NULL);
}

DEFUN (add_vnc_mac_vni_prefix_cost,
       add_vnc_mac_vni_prefix_cost_cmd,
       "add vnc mac YY:YY:YY:YY:YY:YY virtual-network-identifier (1-4294967295) vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> prefix <A.B.C.D/M|X:X::X:X/M> cost (0-255)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify mac address information\n"
       "MAC address\n"
       "Virtual Network Identifier follows\n"
       "Virtual Network Identifier\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "Administrative cost   [default: 255]\n" "Administrative cost\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[11], argv[7], argv[9], argv[13], NULL,
			    /* mac vni */
			    argv[3], argv[5], 0, NULL);
}

DEFUN (add_vnc_mac_vni_prefix,
       add_vnc_mac_vni_prefix_cmd,
       "add vnc mac YY:YY:YY:YY:YY:YY virtual-network-identifier (1-4294967295) vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> prefix <A.B.C.D/M|X:X::X:X/M>",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify mac address information\n"
       "MAC address\n"
       "Virtual Network Identifier follows\n"
       "Virtual Network Identifier\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n" "IPv6 prefix\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, argv[11], argv[7], argv[9], NULL, NULL,
			    /* mac vni */
			    argv[3], argv[5], 0, NULL);
}

DEFUN (add_vnc_mac_vni_cost_life,
       add_vnc_mac_vni_cost_life_cmd,
       "add vnc mac YY:YY:YY:YY:YY:YY virtual-network-identifier (1-4294967295) vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> cost (0-255) lifetime (1-4294967295)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify mac address information\n"
       "MAC address\n"
       "Virtual Network Identifier follows\n"
       "Virtual Network Identifier\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Administrative cost   [default: 255]\n"
       "Administrative cost\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n")
{
	/*                       pfx      vn       un       cost     life */
	return register_add(vty, NULL, argv[7], argv[9], argv[11], argv[13],
			    /* mac vni */
			    argv[3], argv[5], 0, NULL);
}


DEFUN (add_vnc_mac_vni_cost,
       add_vnc_mac_vni_cost_cmd,
       "add vnc mac YY:YY:YY:YY:YY:YY virtual-network-identifier (1-4294967295) vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> cost (0-255)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify mac address information\n"
       "MAC address\n"
       "Virtual Network Identifier follows\n"
       "Virtual Network Identifier\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Administrative cost   [default: 255]\n" "Administrative cost\n")
{
	/*                       pfx      vn       un    cost     life */
	return register_add(vty, NULL, argv[7], argv[9], argv[11], NULL,
			    /* mac vni */
			    argv[3], argv[5], 0, NULL);
}


DEFUN (add_vnc_mac_vni_life,
       add_vnc_mac_vni_life_cmd,
       "add vnc mac YY:YY:YY:YY:YY:YY virtual-network-identifier (1-4294967295) vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X> lifetime (1-4294967295)",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify mac address information\n"
       "MAC address\n"
       "Virtual Network Identifier follows\n"
       "Virtual Network Identifier\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Registration lifetime [default: infinite]\n"
       "Lifetime value in seconds\n")
{
	/*                       pfx      vn       un    cost  life */
	return register_add(vty, NULL, argv[7], argv[9], NULL, argv[11],
			    /* mac vni */
			    argv[3], argv[5], 0, NULL);
}


DEFUN (add_vnc_mac_vni,
       add_vnc_mac_vni_cmd,
       "add vnc mac YY:YY:YY:YY:YY:YY virtual-network-identifier (1-4294967295) vn <A.B.C.D|X:X::X:X> un <A.B.C.D|X:X::X:X>",
       "Add registration\n"
       "VNC Information\n"
       "Add/modify mac address information\n"
       "MAC address\n"
       "Virtual Network Identifier follows\n"
       "Virtual Network Identifier\n"
       "VN address of NVE\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "UN IPv4 interface address\n" "UN IPv6 interface address\n")
{
	/*                       pfx      vn       un    cost  life */
	return register_add(vty, NULL, argv[7], argv[9], NULL, NULL,
			    /* mac vni */
			    argv[3], argv[5], 0, NULL);
}

/************************************************************************
 *			Delete prefix
 ************************************************************************/

struct rfapi_local_reg_delete_arg {
	/*
	 * match parameters
	 */
	struct bgp *bgp;
	struct rfapi_ip_addr un_address; /* AF==0: wildcard */
	struct rfapi_ip_addr vn_address; /* AF==0: wildcard */
	struct prefix prefix;		 /* AF==0: wildcard */
	struct prefix_rd rd;		 /* plen!=64: wildcard */
	struct rfapi_nve_group_cfg *rfg; /* NULL: wildcard */

	struct rfapi_l2address_option_match l2o;

	/*
	 * result parameters
	 */
	struct vty *vty;
	uint32_t reg_count;
	uint32_t pfx_count;
	uint32_t query_count;

	uint32_t failed_pfx_count;

	uint32_t nve_count;
	struct skiplist *nves;

	uint32_t remote_active_nve_count;
	uint32_t remote_active_pfx_count;
	uint32_t remote_holddown_nve_count;
	uint32_t remote_holddown_pfx_count;
};

struct nve_addr {
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	struct rfapi_descriptor *rfd;
	struct rfapi_local_reg_delete_arg *cda;
};

static void nve_addr_free(void *hap)
{
	((struct nve_addr *)hap)->cda->nve_count += 1;
	XFREE(MTYPE_RFAPI_NVE_ADDR, hap);
}

static int nve_addr_cmp(void *k1, void *k2)
{
	struct nve_addr *a = (struct nve_addr *)k1;
	struct nve_addr *b = (struct nve_addr *)k2;
	int ret = 0;

	if (!a || !b) {
		return (a - b);
	}
	if (a->un.addr_family != b->un.addr_family) {
		return (a->un.addr_family - b->un.addr_family);
	}
	if (a->vn.addr_family != b->vn.addr_family) {
		return (a->vn.addr_family - b->vn.addr_family);
	}
	if (a->un.addr_family == AF_INET) {
		ret = IPV4_ADDR_CMP(&a->un.addr.v4, &b->un.addr.v4);
		if (ret != 0) {
			return ret;
		}
	} else if (a->un.addr_family == AF_INET6) {
		ret = IPV6_ADDR_CMP(&a->un.addr.v6, &b->un.addr.v6);
		if (ret != 0) {
			return ret;
		}
	} else {
		assert(0);
	}
	if (a->vn.addr_family == AF_INET) {
		ret = IPV4_ADDR_CMP(&a->vn.addr.v4, &b->vn.addr.v4);
		if (ret != 0)
			return ret;
	} else if (a->vn.addr_family == AF_INET6) {
		ret = IPV6_ADDR_CMP(&a->vn.addr.v6, &b->vn.addr.v6);
		if (ret == 0) {
			return ret;
		}
	} else {
		assert(0);
	}
	return 0;
}

static int parse_deleter_args(struct vty *vty, struct bgp *bgp,
			      const char *arg_prefix, const char *arg_vn,
			      const char *arg_un, const char *arg_l2addr,
			      const char *arg_vni, const char *arg_rd,
			      struct rfapi_nve_group_cfg *arg_rfg,
			      struct rfapi_local_reg_delete_arg *rcdarg)
{
	int rc = CMD_WARNING;

	memset(rcdarg, 0, sizeof(struct rfapi_local_reg_delete_arg));

	rcdarg->vty = vty;
	if (bgp == NULL)
		bgp = bgp_get_default();
	rcdarg->bgp = bgp;
	rcdarg->rfg = arg_rfg; /* may be NULL */

	if (arg_vn && strcmp(arg_vn, "*")) {
		if ((rc = rfapiCliGetRfapiIpAddr(vty, arg_vn,
						 &rcdarg->vn_address)))
			return rc;
	}
	if (arg_un && strcmp(arg_un, "*")) {
		if ((rc = rfapiCliGetRfapiIpAddr(vty, arg_un,
						 &rcdarg->un_address)))
			return rc;
	}
	if (arg_prefix && strcmp(arg_prefix, "*")) {

		if (!str2prefix(arg_prefix, &rcdarg->prefix)) {
			vty_out(vty, "Malformed prefix \"%s\"\n", arg_prefix);
			return rc;
		}
	}

	if (arg_l2addr) {
		if (!arg_vni) {
			vty_out(vty, "Missing VNI\n");
			return rc;
		}
		if (strcmp(arg_l2addr, "*")) {
			if ((rc = rfapiStr2EthAddr(arg_l2addr,
						   &rcdarg->l2o.o.macaddr))) {
				vty_out(vty, "Malformed L2 Address \"%s\"\n",
					arg_l2addr);
				return rc;
			}
			rcdarg->l2o.flags |= RFAPI_L2O_MACADDR;
		}
		if (strcmp(arg_vni, "*")) {
			rcdarg->l2o.o.logical_net_id =
				strtoul(arg_vni, NULL, 10);
			rcdarg->l2o.flags |= RFAPI_L2O_LNI;
		}
	}
	if (arg_rd) {
		if (!str2prefix_rd(arg_rd, &rcdarg->rd)) {
			vty_out(vty, "Malformed RD \"%s\"\n", arg_rd);
			return rc;
		}
	}

	return CMD_SUCCESS;
}

static int
parse_deleter_tokens(struct vty *vty, struct bgp *bgp,
		     struct cmd_token *carg_prefix, struct cmd_token *carg_vn,
		     struct cmd_token *carg_un, struct cmd_token *carg_l2addr,
		     struct cmd_token *carg_vni, struct cmd_token *carg_rd,
		     struct rfapi_nve_group_cfg *arg_rfg,
		     struct rfapi_local_reg_delete_arg *rcdarg)
{
	const char *arg_prefix = carg_prefix ? carg_prefix->arg : NULL;
	const char *arg_vn = carg_vn ? carg_vn->arg : NULL;
	const char *arg_un = carg_un ? carg_un->arg : NULL;
	const char *arg_l2addr = carg_l2addr ? carg_l2addr->arg : NULL;
	const char *arg_vni = carg_vni ? carg_vni->arg : NULL;
	const char *arg_rd = carg_rd ? carg_rd->arg : NULL;
	return parse_deleter_args(vty, bgp, arg_prefix, arg_vn, arg_un,
				  arg_l2addr, arg_vni, arg_rd, arg_rfg, rcdarg);
}

static void record_nve_in_cda_list(struct rfapi_local_reg_delete_arg *cda,
				   struct rfapi_ip_addr *un_address,
				   struct rfapi_ip_addr *vn_address,
				   struct rfapi_descriptor *rfd)
{
	struct nve_addr ha;
	struct nve_addr *hap;

	memset(&ha, 0, sizeof(ha));
	ha.un = *un_address;
	ha.vn = *vn_address;
	ha.rfd = rfd;

	if (!cda->nves)
		cda->nves = skiplist_new(0, nve_addr_cmp, nve_addr_free);

	if (skiplist_search(cda->nves, &ha, (void *)&hap)) {
		hap = XCALLOC(MTYPE_RFAPI_NVE_ADDR, sizeof(struct nve_addr));
		assert(hap);
		ha.cda = cda;
		*hap = ha;
		skiplist_insert(cda->nves, hap, hap);
	}
}

static void clear_vnc_responses(struct rfapi_local_reg_delete_arg *cda)
{
	struct rfapi *h;
	struct rfapi_descriptor *rfd;
	int query_count = 0;
	struct listnode *node;
	struct bgp *bgp_default = bgp_get_default();

	if (cda->vn_address.addr_family && cda->un_address.addr_family) {
		/*
		 * Single nve case
		 */
		if (rfapi_find_rfd(bgp_default, &cda->vn_address,
				   &cda->un_address, &rfd))
			return;

		rfapiRibClear(rfd);
		rfapi_query_done_all(rfd, &query_count);
		cda->query_count += query_count;

		/*
		 * Track unique nves seen
		 */
		record_nve_in_cda_list(cda, &rfd->un_addr, &rfd->vn_addr, rfd);
		return;
	}

	/*
	 * wildcard case
	 */

	if (!bgp_default)
		return; /* ENXIO */

	h = bgp_default->rfapi;

	if (!h)
		return; /* ENXIO */

	for (ALL_LIST_ELEMENTS_RO(&h->descriptors, node, rfd)) {
		/*
		 * match un, vn addresses of NVEs
		 */
		if (cda->un_address.addr_family
		    && rfapi_ip_addr_cmp(&cda->un_address, &rfd->un_addr)) {
			continue;
		}
		if (cda->vn_address.addr_family
		    && rfapi_ip_addr_cmp(&cda->vn_address, &rfd->vn_addr)) {
			continue;
		}

		rfapiRibClear(rfd);

		rfapi_query_done_all(rfd, &query_count);
		cda->query_count += query_count;

		/*
		 * Track unique nves seen
		 */
		record_nve_in_cda_list(cda, &rfd->un_addr, &rfd->vn_addr, rfd);
	}
}

/*
 * TBD need to count deleted prefixes and nves?
 *
 * ENXIO	BGP or VNC not configured
 */
static int rfapiDeleteLocalPrefixesByRFD(struct rfapi_local_reg_delete_arg *cda,
					 struct rfapi_descriptor *rfd)
{
	struct rfapi_ip_addr *pUn; /* NULL = wildcard */
	struct rfapi_ip_addr *pVn; /* NULL = wildcard */
	struct prefix *pPrefix;    /* NULL = wildcard */
	struct prefix_rd *pPrd;    /* NULL = wildcard */

	struct rfapi_ip_prefix rprefix;
	struct rfapi_next_hop_entry *head = NULL;
	struct rfapi_next_hop_entry *tail = NULL;

#if DEBUG_L2_EXTRA
	vnc_zlog_debug_verbose("%s: entry", __func__);
#endif

	pUn = (cda->un_address.addr_family ? &cda->un_address : NULL);
	pVn = (cda->vn_address.addr_family ? &cda->vn_address : NULL);
	pPrefix = (cda->prefix.family ? &cda->prefix : NULL);
	pPrd = (cda->rd.prefixlen == 64 ? &cda->rd : NULL);

	if (pPrefix) {
		rfapiQprefix2Rprefix(pPrefix, &rprefix);
	}

	do /* to preserve old code structure */
	{
		struct rfapi *h = cda->bgp->rfapi;
		;
		struct rfapi_adb *adb;
		int rc;
		int deleted_from_this_nve;
		struct nve_addr ha;
		struct nve_addr *hap;

#if DEBUG_L2_EXTRA
		vnc_zlog_debug_verbose("%s: rfd=%p", __func__, rfd);
#endif

		/*
		 * match un, vn addresses of NVEs
		 */
		if (pUn && (rfapi_ip_addr_cmp(pUn, &rfd->un_addr)))
			break;
		if (pVn && (rfapi_ip_addr_cmp(pVn, &rfd->vn_addr)))
			break;

#if DEBUG_L2_EXTRA
		vnc_zlog_debug_verbose("%s: un, vn match", __func__);
#endif

		/*
		 * match prefix
		 */

		deleted_from_this_nve = 0;

		{
			struct skiplist *sl;
			struct rfapi_ip_prefix rp;
			void *cursor;
			struct list *adb_delete_list;

			/*
			 * The advertisements are stored in a skiplist.
			 * Withdrawing
			 * the registration deletes the advertisement from the
			 * skiplist, which we can't do while iterating over that
			 * same skiplist using the current skiplist API.
			 *
			 * Strategy: iterate over the skiplist and build another
			 * list containing only the matching ADBs. Then delete
			 * _everything_ in that second list (which can be done
			 * using either skiplists or quagga linklists).
			 */
			adb_delete_list = list_new();

			/*
			 * Advertised IP prefixes (not 0/32 or 0/128)
			 */
			sl = rfd->advertised.ipN_by_prefix;

			for (cursor = NULL,
			    rc = skiplist_next(sl, NULL, (void **)&adb,
					       &cursor);
			     !rc; rc = skiplist_next(sl, NULL, (void **)&adb,
						     &cursor)) {

				if (pPrefix) {
					if (!prefix_same(pPrefix,
							 &adb->u.s.prefix_ip)) {
#if DEBUG_L2_EXTRA
						vnc_zlog_debug_verbose(
							"%s: adb=%p, prefix doesn't match, skipping",
							__func__, adb);
#endif
						continue;
					}
				}
				if (pPrd) {
					if (memcmp(pPrd->val, adb->u.s.prd.val,
						   8)
					    != 0) {
#if DEBUG_L2_EXTRA
						vnc_zlog_debug_verbose(
							"%s: adb=%p, RD doesn't match, skipping",
							__func__, adb);
#endif
						continue;
					}
				}
				if (CHECK_FLAG(cda->l2o.flags,
					       RFAPI_L2O_MACADDR)) {
					if (memcmp(cda->l2o.o.macaddr.octet,
						   adb->u.s.prefix_eth.u
							   .prefix_eth.octet,
						   ETH_ALEN)) {
#if DEBUG_L2_EXTRA
						vnc_zlog_debug_verbose(
							"%s: adb=%p, macaddr doesn't match, skipping",
							__func__, adb);
#endif
						continue;
					}
				}

				if (CHECK_FLAG(cda->l2o.flags, RFAPI_L2O_LNI)) {
					if (cda->l2o.o.logical_net_id
					    != adb->l2o.logical_net_id) {
#if DEBUG_L2_EXTRA
						vnc_zlog_debug_verbose(
							"%s: adb=%p, LNI doesn't match, skipping",
							__func__, adb);
#endif
						continue;
					}
				}

#if DEBUG_L2_EXTRA
				vnc_zlog_debug_verbose(
					"%s: ipN adding adb %p to delete list",
					__func__, adb);
#endif

				listnode_add(adb_delete_list, adb);
			}

			struct listnode *node;

			for (ALL_LIST_ELEMENTS_RO(adb_delete_list, node, adb)) {
				int this_advertisement_prefix_count;
				struct rfapi_vn_option optary[3];
				struct rfapi_vn_option *opt = NULL;
				int cur_opt = 0;

				this_advertisement_prefix_count = 1;

				rfapiQprefix2Rprefix(&adb->u.s.prefix_ip, &rp);

				memset(optary, 0, sizeof(optary));

				/* if mac addr present in advert,  make l2o vn
				 * option */
				if (adb->u.s.prefix_eth.family == AF_ETHERNET) {
					if (opt != NULL)
						opt->next = &optary[cur_opt];
					opt = &optary[cur_opt++];
					opt->type = RFAPI_VN_OPTION_TYPE_L2ADDR;
					opt->v.l2addr.macaddr =
						adb->u.s.prefix_eth.u
							.prefix_eth;
					++this_advertisement_prefix_count;
				}
				/*
				 * use saved RD value instead of trying to
				 * invert
				 * complex RD computation in rfapi_register()
				 */
				if (opt != NULL)
					opt->next = &optary[cur_opt];
				opt = &optary[cur_opt++];
				opt->type = RFAPI_VN_OPTION_TYPE_INTERNAL_RD;
				opt->v.internal_rd = adb->u.s.prd;

#if DEBUG_L2_EXTRA
				vnc_zlog_debug_verbose(
					"%s: ipN killing reg from adb %p ",
					__func__, adb);
#endif

				rc = rfapi_register(rfd, &rp, 0, NULL,
						    (cur_opt ? optary : NULL),
						    RFAPI_REGISTER_KILL);
				if (!rc) {
					cda->pfx_count +=
						this_advertisement_prefix_count;
					cda->reg_count += 1;
					deleted_from_this_nve = 1;
				}
				if (h->rfp_methods.local_cb) {
					rfapiAddDeleteLocalRfpPrefix(
						&rfd->un_addr, &rfd->vn_addr,
						&rp, 0, 0, NULL, &head, &tail);
				}
			}
			list_delete_all_node(adb_delete_list);

			if (!(pPrefix && !RFAPI_0_PREFIX(pPrefix))) {
				/*
				 * Caller didn't specify a prefix, or specified
				 * (0/32 or 0/128)
				 */

				/*
				 * Advertised 0/32 and 0/128 (indexed by
				 * ethernet address)
				 */
				sl = rfd->advertised.ip0_by_ether;

				for (cursor = NULL,
				    rc = skiplist_next(sl, NULL, (void **)&adb,
						       &cursor);
				     !rc;
				     rc = skiplist_next(sl, NULL, (void **)&adb,
							&cursor)) {

					if (CHECK_FLAG(cda->l2o.flags,
						       RFAPI_L2O_MACADDR)) {
						if (memcmp(cda->l2o.o.macaddr
								   .octet,
							   adb->u.s.prefix_eth.u
								   .prefix_eth
								   .octet,
							   ETH_ALEN)) {

							continue;
						}
					}
					if (CHECK_FLAG(cda->l2o.flags,
						       RFAPI_L2O_LNI)) {
						if (cda->l2o.o.logical_net_id
						    != adb->l2o.logical_net_id) {
							continue;
						}
					}
#if DEBUG_L2_EXTRA
					vnc_zlog_debug_verbose(
						"%s: ip0 adding adb %p to delete list",
						__func__, adb);
#endif
					listnode_add(adb_delete_list, adb);
				}


				for (ALL_LIST_ELEMENTS_RO(adb_delete_list, node,
							  adb)) {

					struct rfapi_vn_option vn;

					rfapiQprefix2Rprefix(
						&adb->u.s.prefix_ip, &rp);

					memset(&vn, 0, sizeof(vn));
					vn.type = RFAPI_VN_OPTION_TYPE_L2ADDR;
					vn.v.l2addr = adb->l2o;

#if DEBUG_L2_EXTRA
					vnc_zlog_debug_verbose(
						"%s: ip0 killing reg from adb %p ",
						__func__, adb);
#endif

					rc = rfapi_register(
						rfd, &rp, 0, NULL, &vn,
						RFAPI_REGISTER_KILL);
					if (!rc) {
						cda->pfx_count += 1;
						cda->reg_count += 1;
						deleted_from_this_nve = 1;
					}
					if (h->rfp_methods.local_cb) {
						struct rfapi_vn_option
							*vn_opt_new;

						vn_opt_new =
							rfapi_vn_options_dup(
								&vn);
						rfapiAddDeleteLocalRfpPrefix(
							&rfd->un_addr,
							&rfd->vn_addr, &rp, 0,
							0, vn_opt_new, &head,
							&tail);
					}
				}
				list_delete_all_node(adb_delete_list);
			}
			list_delete(&adb_delete_list);
		}


		if (head) { /* should not be set if (NULL ==
			       rfapi_cfg->local_cb) */
			h->flags |= RFAPI_INCALLBACK;
			(*h->rfp_methods.local_cb)(head, rfd->cookie);
			h->flags &= ~RFAPI_INCALLBACK;
			head = tail = NULL;
		}

		if (deleted_from_this_nve) {
			/*
			 * track unique NVEs seen
			 */
			memset(&ha, 0, sizeof(ha));
			ha.un = rfd->un_addr;
			ha.vn = rfd->vn_addr;

			if (!cda->nves)
				cda->nves = skiplist_new(0, nve_addr_cmp,
							 nve_addr_free);
			if (skiplist_search(cda->nves, &ha, (void **)&hap)) {
				hap = XCALLOC(MTYPE_RFAPI_NVE_ADDR,
					      sizeof(struct nve_addr));
				assert(hap);
				ha.cda = cda;
				*hap = ha;
				skiplist_insert(cda->nves, hap, hap);
			}
		}
	} while (0); /*  to preserve old code structure */

	return 0;
}

static int rfapiDeleteLocalPrefixes(struct rfapi_local_reg_delete_arg *cda)
{
	int rc = 0;

	if (cda->rfg) {
		if (cda->rfg->rfd) /* if not open, nothing to delete */
			rc = rfapiDeleteLocalPrefixesByRFD(cda, cda->rfg->rfd);
	} else {
		struct bgp *bgp = cda->bgp;
		struct rfapi *h;
		struct rfapi_cfg *rfapi_cfg;

		struct listnode *node;
		struct rfapi_descriptor *rfd;
		if (!bgp)
			return ENXIO;
		h = bgp->rfapi;
		rfapi_cfg = bgp->rfapi_cfg;
		if (!h || !rfapi_cfg)
			return ENXIO;
		vnc_zlog_debug_verbose("%s: starting descriptor loop",
				       __func__);
		for (ALL_LIST_ELEMENTS_RO(&h->descriptors, node, rfd)) {
			rc = rfapiDeleteLocalPrefixesByRFD(cda, rfd);
		}
	}
	return rc;
}

/*
 * clear_vnc_prefix
 *
 * Deletes local and remote prefixes that match
 */
static void clear_vnc_prefix(struct rfapi_local_reg_delete_arg *cda)
{
	struct prefix pfx_un;
	struct prefix pfx_vn;

	struct prefix *pUN = NULL;
	struct prefix *pVN = NULL;
	struct prefix *pPrefix = NULL;

	struct rfapi_import_table *it = NULL;

	/*
	 * Delete matching remote prefixes in holddown
	 */
	if (cda->vn_address.addr_family) {
		if (!rfapiRaddr2Qprefix(&cda->vn_address, &pfx_vn))
			pVN = &pfx_vn;
	}
	if (cda->un_address.addr_family) {
		if (!rfapiRaddr2Qprefix(&cda->un_address, &pfx_un))
			pUN = &pfx_un;
	}
	if (cda->prefix.family) {
		pPrefix = &cda->prefix;
	}
	if (cda->rfg) {
		it = cda->rfg->rfapi_import_table;
	}
	rfapiDeleteRemotePrefixes(
		pUN, pVN, pPrefix, it, 0, 1, &cda->remote_active_pfx_count,
		&cda->remote_active_nve_count, &cda->remote_holddown_pfx_count,
		&cda->remote_holddown_nve_count);

	/*
	 * Now do local prefixes
	 */
	rfapiDeleteLocalPrefixes(cda);
}

static void print_cleared_stats(struct rfapi_local_reg_delete_arg *cda)
{
	struct vty *vty = cda->vty; /* for benefit of VTYNL */

	/* Our special element-deleting function counts nves */
	if (cda->nves) {
		skiplist_free(cda->nves);
		cda->nves = NULL;
	}
	if (cda->failed_pfx_count)
		vty_out(vty, "Failed to delete %d prefixes\n",
			cda->failed_pfx_count);

	/* left as "prefixes" even in single case for ease of machine parsing */
	vty_out(vty,
		"[Local] Cleared %u registrations, %u prefixes, %u responses from %d NVEs\n",
		cda->reg_count, cda->pfx_count, cda->query_count,
		cda->nve_count);

	/*
	 * We don't currently allow deletion of active remote prefixes from
	 * the command line
	 */

	vty_out(vty, "[Holddown] Cleared %u prefixes from %u NVEs\n",
		cda->remote_holddown_pfx_count, cda->remote_holddown_nve_count);
}

/*
 * Caller has already deleted registrations and queries for this/these
 * NVEs. Now we just have to close their descriptors.
 */
static void clear_vnc_nve_closer(struct rfapi_local_reg_delete_arg *cda)
{
	struct skiplist *sl = cda->nves; /* contains affected NVEs */
	struct nve_addr *pKey;
	struct nve_addr *pValue;
	void *cursor = NULL;
	int rc;

	if (!sl)
		return;

	for (rc = skiplist_next(sl, (void **)&pKey, (void **)&pValue, &cursor);
	     !rc; rc = skiplist_next(sl, (void **)&pKey, (void **)&pValue,
				     &cursor)) {

		if (pValue->rfd) {
			((struct rfapi_descriptor *)pValue->rfd)->flags |=
				RFAPI_HD_FLAG_CLOSING_ADMINISTRATIVELY;
			rfapi_close(pValue->rfd);
		}
	}
}

DEFUN (clear_vnc_nve_all,
       clear_vnc_nve_all_cmd,
       "clear vnc nve *",
       "clear\n"
       "VNC Information\n"
       "Clear per NVE information\n"
       "For all NVEs\n")
{

	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_args(vty, NULL, NULL, NULL, NULL, NULL, NULL,
				     NULL, NULL, &cda)))
		return rc;

	cda.vty = vty;

	clear_vnc_responses(&cda);
	clear_vnc_prefix(&cda);
	clear_vnc_nve_closer(&cda);

	print_cleared_stats(&cda);

	return 0;
}

DEFUN (clear_vnc_nve_vn_un,
       clear_vnc_nve_vn_un_cmd,
       "clear vnc nve vn <*|A.B.C.D|X:X::X:X> un <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear prefix registration information\n"
       "VN address of NVE\n"
       "For all NVEs\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "For all UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_tokens(vty, NULL, NULL, argv[4], argv[6], NULL,
				       NULL, NULL, NULL, &cda)))
		return rc;

	cda.vty = vty;

	clear_vnc_responses(&cda);
	clear_vnc_prefix(&cda);
	clear_vnc_nve_closer(&cda);

	print_cleared_stats(&cda);

	return 0;
}

DEFUN (clear_vnc_nve_un_vn,
       clear_vnc_nve_un_vn_cmd,
       "clear vnc nve un <*|A.B.C.D|X:X::X:X> vn <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear prefix registration information\n"
       "UN address of NVE\n"
       "For all un NVEs\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "VN address of NVE\n"
       "For all vn NVEs\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_tokens(vty, NULL, NULL, argv[6], argv[4], NULL,
				       NULL, NULL, NULL, &cda)))
		return rc;

	cda.vty = vty;

	clear_vnc_responses(&cda);
	clear_vnc_prefix(&cda);
	clear_vnc_nve_closer(&cda);

	print_cleared_stats(&cda);

	return 0;
}

DEFUN (clear_vnc_nve_vn,
       clear_vnc_nve_vn_cmd,
       "clear vnc nve vn <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear prefix registration information\n"
       "VN address of NVE\n"
       "All addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_tokens(vty, NULL, NULL, argv[4], NULL, NULL,
				       NULL, NULL, NULL, &cda)))
		return rc;

	cda.vty = vty;

	clear_vnc_responses(&cda);
	clear_vnc_prefix(&cda);
	clear_vnc_nve_closer(&cda);

	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_nve_un,
       clear_vnc_nve_un_cmd,
       "clear vnc nve un <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear prefix registration information\n"
       "UN address of NVE\n"
       "All un nves\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_tokens(vty, NULL, NULL, NULL, argv[4], NULL,
				       NULL, NULL, NULL, &cda)))
		return rc;

	cda.vty = vty;

	clear_vnc_responses(&cda);
	clear_vnc_prefix(&cda);
	clear_vnc_nve_closer(&cda);

	print_cleared_stats(&cda);
	return 0;
}

/*-------------------------------------------------
 *		Clear VNC Prefix
 *-------------------------------------------------*/

/*
 * This function is defined in this file (rather than in rfp_registration.c)
 * because here we have access to all the task handles.
 */
DEFUN (clear_vnc_prefix_vn_un,
       clear_vnc_prefix_vn_un_cmd,
       "clear vnc prefix <*|A.B.C.D/M|X:X::X:X/M> vn <*|A.B.C.D|X:X::X:X> un <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "VN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "All UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_tokens(vty, NULL, argv[3], argv[5], argv[7],
				       NULL, NULL, NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_prefix_un_vn,
       clear_vnc_prefix_un_vn_cmd,
       "clear vnc prefix <*|A.B.C.D/M|X:X::X:X/M> un <*|A.B.C.D|X:X::X:X> vn <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "UN address of NVE\n"
       "All UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "VN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_tokens(vty, NULL, argv[3], argv[7], argv[5],
				       NULL, NULL, NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_prefix_un,
       clear_vnc_prefix_un_cmd,
       "clear vnc prefix <*|A.B.C.D/M|X:X::X:X/M> un <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "UN address of NVE\n"
       "All UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_tokens(vty, NULL, argv[3], NULL, argv[5], NULL,
				       NULL, NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_prefix_vn,
       clear_vnc_prefix_vn_cmd,
       "clear vnc prefix <*|A.B.C.D/M|X:X::X:X/M> vn <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "UN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_tokens(vty, NULL, argv[3], argv[5], NULL, NULL,
				       NULL, NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_prefix_all,
       clear_vnc_prefix_all_cmd,
       "clear vnc prefix <*|A.B.C.D/M|X:X::X:X/M> *",
       "clear\n"
       "VNC Information\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "From any NVE\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	if ((rc = parse_deleter_tokens(vty, NULL, argv[3], NULL, NULL, NULL,
				       NULL, NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

/*-------------------------------------------------
 *		Clear VNC MAC
 *-------------------------------------------------*/

/*
 * This function is defined in this file (rather than in rfp_registration.c)
 * because here we have access to all the task handles.
 */
DEFUN (clear_vnc_mac_vn_un,
       clear_vnc_mac_vn_un_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> vn <*|A.B.C.D|X:X::X:X> un <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "VN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "All UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, NULL, argv[7], argv[9],
				       argv[3], argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_mac_un_vn,
       clear_vnc_mac_un_vn_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> un <*|A.B.C.D|X:X::X:X> vn <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "UN address of NVE\n"
       "All UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "VN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, NULL, argv[9], argv[7],
				       argv[3], argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_mac_un,
       clear_vnc_mac_un_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> un <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "UN address of NVE\n"
       "All UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, NULL, NULL, argv[7], argv[3],
				       argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_mac_vn,
       clear_vnc_mac_vn_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> vn <*|A.B.C.D|X:X::X:X>",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "UN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, NULL, argv[7], NULL, argv[3],
				       argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_mac_all,
       clear_vnc_mac_all_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> *",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "From any NVE\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, NULL, NULL, NULL, argv[3],
				       argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

/*-------------------------------------------------
 *		Clear VNC MAC PREFIX
 *-------------------------------------------------*/

DEFUN (clear_vnc_mac_vn_un_prefix,
       clear_vnc_mac_vn_un_prefix_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> vn <*|A.B.C.D|X:X::X:X> un <*|A.B.C.D|X:X::X:X> prefix <*|A.B.C.D/M|X:X::X:X/M>",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "VN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "UN address of NVE\n"
       "All UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, argv[11], argv[7], argv[9],
				       argv[3], argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_mac_un_vn_prefix,
       clear_vnc_mac_un_vn_prefix_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> un <*|A.B.C.D|X:X::X:X> vn <*|A.B.C.D|X:X::X:X> prefix <*|A.B.C.D/M|X:X::X:X/M> prefix <*|A.B.C.D/M|X:X::X:X/M>",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "UN address of NVE\n"
       "All UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "VN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, argv[11], argv[9], argv[7],
				       argv[3], argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_mac_un_prefix,
       clear_vnc_mac_un_prefix_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> un <*|A.B.C.D|X:X::X:X> prefix <*|A.B.C.D/M|X:X::X:X/M>",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "UN address of NVE\n"
       "All UN addresses\n"
       "UN IPv4 interface address\n"
       "UN IPv6 interface address\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 Prefix\n"
       "IPv6 Prefix\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, argv[9], NULL, argv[7],
				       argv[3], argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_mac_vn_prefix,
       clear_vnc_mac_vn_prefix_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> vn <*|A.B.C.D|X:X::X:X> prefix <*|A.B.C.D/M|X:X::X:X/M>",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "UN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n"
       "Clear prefix registration information\n"
       "All prefixes\n"
       "IPv4 Prefix\n"
       "IPv6 Prefix\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, argv[9], argv[7], NULL,
				       argv[3], argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

DEFUN (clear_vnc_mac_all_prefix,
       clear_vnc_mac_all_prefix_cmd,
       "clear vnc mac <*|YY:YY:YY:YY:YY:YY> virtual-network-identifier <*|(1-4294967295)> prefix <*|A.B.C.D/M|X:X::X:X/M>",
       "clear\n"
       "VNC Information\n"
       "Clear mac registration information\n"
       "All macs\n"
       "MAC address\n"
       "VNI keyword\n"
       "Any virtual network identifier\n"
       "Virtual network identifier\n"
       "UN address of NVE\n"
       "All VN addresses\n"
       "VN IPv4 interface address\n"
       "VN IPv6 interface address\n")
{
	struct rfapi_local_reg_delete_arg cda;
	int rc;

	/* pfx vn un L2 VNI */
	if ((rc = parse_deleter_tokens(vty, NULL, argv[7], NULL, NULL, argv[3],
				       argv[5], NULL, NULL, &cda)))
		return rc;
	cda.vty = vty;
	clear_vnc_prefix(&cda);
	print_cleared_stats(&cda);
	return 0;
}

/************************************************************************
 *			Show commands
 ************************************************************************/


/* copied from rfp_vty.c */
static int check_and_display_is_vnc_running(struct vty *vty)
{
	if (bgp_rfapi_is_vnc_configured(NULL) == 0)
		return 1; /* is running */

	if (vty) {
		vty_out(vty, "VNC is not configured.\n");
	}
	return 0; /* not running */
}

static int rfapi_vty_show_nve_summary(struct vty *vty,
				      show_nve_summary_t show_type)
{
	struct bgp *bgp_default = bgp_get_default();
	struct rfapi *h;
	int is_vnc_running = (bgp_rfapi_is_vnc_configured(bgp_default) == 0);

	int active_local_routes;
	int active_remote_routes;
	int holddown_remote_routes;
	int imported_remote_routes;

	if (!bgp_default)
		goto notcfg;

	h = bgp_default->rfapi;

	if (!h)
		goto notcfg;

	/* don't show local info if not running RFP */
	if (is_vnc_running || show_type == SHOW_NVE_SUMMARY_REGISTERED) {

		switch (show_type) {

		case SHOW_NVE_SUMMARY_ACTIVE_NVES:
			vty_out(vty, "%-24s ", "NVEs:");
			vty_out(vty, "%-8s %-8u ",
				"Active:", h->descriptors.count);
			vty_out(vty, "%-8s %-8u ",
				"Maximum:", h->stat.max_descriptors);
			vty_out(vty, "%-8s %-8u",
				"Unknown:", h->stat.count_unknown_nves);
			break;

		case SHOW_NVE_SUMMARY_REGISTERED:
			/*
			 * NB: With the introduction of L2 route support, we no
			 * longer have a one-to-one correspondence between
			 * locally-originated route advertisements and routes in
			 * the import tables that have local origin. This
			 * discrepancy arises because a single advertisement
			 * may contain both an IP prefix and a MAC address.
			 * Such an advertisement results in two import table
			 * entries: one indexed by IP prefix, the other indexed
			 * by MAC address.
			 *
			 * TBD: update computation and display of registration
			 * statistics to reflect the underlying semantics.
			 */
			if (is_vnc_running) {
				vty_out(vty, "%-24s ", "Registrations:");
				vty_out(vty, "%-8s %-8u ", "Active:",
					rfapiApCountAll(bgp_default));
				vty_out(vty, "%-8s %-8u ", "Failed:",
					h->stat.count_registrations_failed);
				vty_out(vty, "%-8s %-8u",
					"Total:", h->stat.count_registrations);
				vty_out(vty, "\n");
			}
			vty_out(vty, "%-24s ", "Prefixes registered:");
			vty_out(vty, "\n");

			rfapiCountAllItRoutes(&active_local_routes,
					      &active_remote_routes,
					      &holddown_remote_routes,
					      &imported_remote_routes);

			/* local */
			if (is_vnc_running) {
				vty_out(vty, "    %-20s ", "Locally:");
				vty_out(vty, "%-8s %-8u ",
					"Active:", active_local_routes);
				vty_out(vty, "\n");
			}


			vty_out(vty, "    %-20s ", "Remotely:");
			vty_out(vty, "%-8s %-8u",
				"Active:", active_remote_routes);
			vty_out(vty, "\n");
			vty_out(vty, "    %-20s ", "In Holddown:");
			vty_out(vty, "%-8s %-8u",
				"Active:", holddown_remote_routes);
			vty_out(vty, "\n");
			vty_out(vty, "    %-20s ", "Imported:");
			vty_out(vty, "%-8s %-8u",
				"Active:", imported_remote_routes);
			break;

		case SHOW_NVE_SUMMARY_QUERIES:
			vty_out(vty, "%-24s ", "Queries:");
			vty_out(vty, "%-8s %-8u ",
				"Active:", rfapi_monitor_count(NULL));
			vty_out(vty, "%-8s %-8u ",
				"Failed:", h->stat.count_queries_failed);
			vty_out(vty, "%-8s %-8u",
				"Total:", h->stat.count_queries);
			break;

		case SHOW_NVE_SUMMARY_RESPONSES:
			rfapiRibShowResponsesSummary(vty);

		default:
			break;
		}
		vty_out(vty, "\n");
	}
	return 0;

notcfg:
	vty_out(vty, "VNC is not configured.\n");
	return CMD_WARNING;
}

static int rfapi_show_nves(struct vty *vty, struct prefix *vn_prefix,
			   struct prefix *un_prefix)
{
	// struct hash                      *rfds;
	// struct rfp_rfapi_descriptor_param param;

	struct bgp *bgp_default = bgp_get_default();
	struct rfapi *h;
	struct listnode *node;
	struct rfapi_descriptor *rfd;

	int total = 0;
	int printed = 0;
	int rc;

	if (!bgp_default)
		goto notcfg;

	h = bgp_default->rfapi;

	if (!h)
		goto notcfg;

	rc = rfapi_vty_show_nve_summary(vty, SHOW_NVE_SUMMARY_ACTIVE_NVES);
	if (rc)
		return rc;

	for (ALL_LIST_ELEMENTS_RO(&h->descriptors, node, rfd)) {
		struct prefix pfx;
		char vn_addr_buf[INET6_ADDRSTRLEN] = {
			0,
		};
		char un_addr_buf[INET6_ADDRSTRLEN] = {
			0,
		};
		char age[10];

		++total;

		if (vn_prefix) {
			assert(!rfapiRaddr2Qprefix(&rfd->vn_addr, &pfx));
			if (!prefix_match(vn_prefix, &pfx))
				continue;
		}

		if (un_prefix) {
			assert(!rfapiRaddr2Qprefix(&rfd->un_addr, &pfx));
			if (!prefix_match(un_prefix, &pfx))
				continue;
		}

		rfapiRfapiIpAddr2Str(&rfd->vn_addr, vn_addr_buf,
				     INET6_ADDRSTRLEN);
		rfapiRfapiIpAddr2Str(&rfd->un_addr, un_addr_buf,
				     INET6_ADDRSTRLEN);

		if (!printed) {
			/* print out a header */
			vty_out(vty,
				"                                Active      Next Hops\n");
			vty_out(vty, "%-15s %-15s %-5s %-5s %-6s %-6s %s\n",
				"VN Address", "UN Address", "Regis", "Resps",
				"Reach", "Remove", "Age");
		}

		++printed;

		vty_out(vty, "%-15s %-15s %-5u %-5u %-6u %-6u %s\n",
			vn_addr_buf, un_addr_buf, rfapiApCount(rfd),
			rfapi_monitor_count(rfd), rfd->stat_count_nh_reachable,
			rfd->stat_count_nh_removal,
			rfapiFormatAge(rfd->open_time, age, 10));
	}

	if (printed > 0 || vn_prefix || un_prefix)
		vty_out(vty, "Displayed %d out of %d active NVEs\n", printed,
			total);

	return 0;

notcfg:
	vty_out(vty, "VNC is not configured.\n");
	return CMD_WARNING;
}


DEFUN (vnc_show_summary,
       vnc_show_summary_cmd,
       "show vnc summary",
       SHOW_STR
       VNC_SHOW_STR
       "Display VNC status summary\n")
{
	if (!check_and_display_is_vnc_running(vty))
		return CMD_SUCCESS;
	bgp_rfapi_show_summary(bgp_get_default(), vty);
	vty_out(vty, "\n");
	rfapi_vty_show_nve_summary(vty, SHOW_NVE_SUMMARY_ACTIVE_NVES);
	rfapi_vty_show_nve_summary(vty, SHOW_NVE_SUMMARY_QUERIES);
	rfapi_vty_show_nve_summary(vty, SHOW_NVE_SUMMARY_RESPONSES);
	rfapi_vty_show_nve_summary(vty, SHOW_NVE_SUMMARY_REGISTERED);
	return CMD_SUCCESS;
}

DEFUN (vnc_show_nves,
       vnc_show_nves_cmd,
       "show vnc nves",
       SHOW_STR
       VNC_SHOW_STR
       "List known NVEs\n")
{
	rfapi_show_nves(vty, NULL, NULL);
	return CMD_SUCCESS;
}

DEFUN (vnc_show_nves_ptct,
       vnc_show_nves_ptct_cmd,
       "show vnc nves <vn|un> <A.B.C.D|X:X::X:X>",
       SHOW_STR
       VNC_SHOW_STR
       "List known NVEs\n"
       "VN address of NVE\n"
       "UN address of NVE\n"
       "IPv4 interface address\n"
       "IPv6 interface address\n")
{
	struct prefix pfx;

	if (!check_and_display_is_vnc_running(vty))
		return CMD_SUCCESS;

	if (!str2prefix(argv[4]->arg, &pfx)) {
		vty_out(vty, "Malformed address \"%s\"\n", argv[4]->arg);
		return CMD_WARNING;
	}
	if (pfx.family != AF_INET && pfx.family != AF_INET6) {
		vty_out(vty, "Invalid address \"%s\"\n", argv[4]->arg);
		return CMD_WARNING;
	}

	if (argv[3]->arg[0] == 'u') {
		rfapi_show_nves(vty, NULL, &pfx);
	} else {
		rfapi_show_nves(vty, &pfx, NULL);
	}

	return CMD_SUCCESS;
}

/* adapted from rfp_registration_cache_log() */
static void rfapi_show_registrations(struct vty *vty,
				     struct prefix *restrict_to, int show_local,
				     int show_remote, int show_holddown,
				     int show_imported)
{
	int printed = 0;

	if (!vty)
		return;

	rfapi_vty_show_nve_summary(vty, SHOW_NVE_SUMMARY_REGISTERED);

	if (show_local) {
		/* non-expiring, local */
		printed += rfapiShowRemoteRegistrations(vty, restrict_to, 0, 1,
							0, 0);
	}
	if (show_remote) {
		/* non-expiring, non-local */
		printed += rfapiShowRemoteRegistrations(vty, restrict_to, 0, 0,
							1, 0);
	}
	if (show_holddown) {
		/* expiring, including local */
		printed += rfapiShowRemoteRegistrations(vty, restrict_to, 1, 1,
							1, 0);
	}
	if (show_imported) {
		/* non-expiring, non-local */
		printed += rfapiShowRemoteRegistrations(vty, restrict_to, 0, 0,
							1, 1);
	}
	if (!printed) {
		vty_out(vty, "\n");
	}
}

DEFUN (vnc_show_registrations_pfx,
       vnc_show_registrations_pfx_cmd,
       "show vnc registrations [<A.B.C.D/M|X:X::X:X/M|YY:YY:YY:YY:YY:YY>]",
       SHOW_STR
       VNC_SHOW_STR
       "List active prefix registrations\n"
       "Limit output to a particular IPv4 prefix\n"
       "Limit output to a particular IPv6 prefix\n"
       "Limit output to a particular IPv6 address\n")
{
	struct prefix p;
	struct prefix *p_addr = NULL;

	if (argc > 3) {
		if (!str2prefix(argv[3]->arg, &p)) {
			vty_out(vty, "Invalid prefix: %s\n", argv[3]->arg);
			return CMD_SUCCESS;
		} else {
			p_addr = &p;
		}
	}

	rfapi_show_registrations(vty, p_addr, 1, 1, 1, 1);
	return CMD_SUCCESS;
}

DEFUN (vnc_show_registrations_some_pfx,
         vnc_show_registrations_some_pfx_cmd,
         "show vnc registrations <all|holddown|imported|local|remote> [<A.B.C.D/M|X:X::X:X/M|YY:YY:YY:YY:YY:YY>]",
         SHOW_STR
         VNC_SHOW_STR
         "List active prefix registrations\n"
         "show all registrations\n"
         "show only registrations in holddown\n"
         "show only imported prefixes\n"
         "show only local registrations\n"
         "show only remote registrations\n"
         "Limit output to a particular prefix or address\n"
         "Limit output to a particular prefix or address\n"
         "Limit output to a particular prefix or address\n")
{
	struct prefix p;
	struct prefix *p_addr = NULL;

	int show_local = 0;
	int show_remote = 0;
	int show_holddown = 0;
	int show_imported = 0;

	if (argc > 4) {
		if (!str2prefix(argv[4]->arg, &p)) {
			vty_out(vty, "Invalid prefix: %s\n", argv[4]->arg);
			return CMD_SUCCESS;
		} else {
			p_addr = &p;
		}
	}
	switch (argv[3]->arg[0]) {
	case 'a':
		show_local = 1;
		show_remote = 1;
		show_holddown = 1;
		show_imported = 1;
		break;

	case 'h':
		show_holddown = 1;
		break;

	case 'i':
		show_imported = 1;
		break;

	case 'l':
		show_local = 1;
		break;

	case 'r':
		show_remote = 1;
		break;
	}

	rfapi_show_registrations(vty, p_addr, show_local, show_remote,
				 show_holddown, show_imported);
	return CMD_SUCCESS;
}

DEFUN (vnc_show_responses_pfx,
       vnc_show_responses_pfx_cmd,
       "show vnc responses [<A.B.C.D/M|X:X::X:X/M|YY:YY:YY:YY:YY:YY>]",
       SHOW_STR
       VNC_SHOW_STR
       "List recent query responses\n"
       "Limit output to a particular IPv4 prefix\n"
       "Limit output to a particular IPv6 prefix\n"
       "Limit output to a particular IPv6 address\n" )
{
	struct prefix p;
	struct prefix *p_addr = NULL;

	if (argc > 3) {
		if (!str2prefix(argv[3]->arg, &p)) {
			vty_out(vty, "Invalid prefix: %s\n", argv[3]->arg);
			return CMD_SUCCESS;
		} else {
			p_addr = &p;
		}
	}
	rfapi_vty_show_nve_summary(vty, SHOW_NVE_SUMMARY_QUERIES);

	rfapiRibShowResponsesSummary(vty);

	rfapiRibShowResponses(vty, p_addr, 0);
	rfapiRibShowResponses(vty, p_addr, 1);

	return CMD_SUCCESS;
}

DEFUN (vnc_show_responses_some_pfx,
       vnc_show_responses_some_pfx_cmd,
       "show vnc responses <active|removed> [<A.B.C.D/M|X:X::X:X/M|YY:YY:YY:YY:YY:YY>]",
       SHOW_STR
       VNC_SHOW_STR
       "List recent query responses\n"
       "show only active query responses\n"
       "show only removed query responses\n"
       "Limit output to a particular IPv4 prefix\n"
       "Limit output to a particular IPv6 prefix\n"
       "Limit output to a particular IPV6 address\n")
{
	struct prefix p;
	struct prefix *p_addr = NULL;

	int show_active = 0;
	int show_removed = 0;

	if (!check_and_display_is_vnc_running(vty))
		return CMD_SUCCESS;

	if (argc > 4) {
		if (!str2prefix(argv[4]->arg, &p)) {
			vty_out(vty, "Invalid prefix: %s\n", argv[4]->arg);
			return CMD_SUCCESS;
		} else {
			p_addr = &p;
		}
	}

	switch (argv[3]->arg[0]) {
	case 'a':
		show_active = 1;
		break;

	case 'r':
		show_removed = 1;
		break;
	}

	rfapi_vty_show_nve_summary(vty, SHOW_NVE_SUMMARY_QUERIES);

	rfapiRibShowResponsesSummary(vty);

	if (show_active)
		rfapiRibShowResponses(vty, p_addr, 0);
	if (show_removed)
		rfapiRibShowResponses(vty, p_addr, 1);

	return CMD_SUCCESS;
}

DEFUN (show_vnc_queries_pfx,
       show_vnc_queries_pfx_cmd,
       "show vnc queries [<A.B.C.D/M|X:X::X:X/M|YY:YY:YY:YY:YY:YY>]",
       SHOW_STR
       VNC_SHOW_STR
       "List active queries\n"
       "Limit output to a particular IPv4 prefix or address\n"
       "Limit output to a particular IPv6 prefix\n"
       "Limit output to a particualr IPV6 address\n")
{
	struct prefix pfx;
	struct prefix *p = NULL;

	if (argc > 3) {
		if (!str2prefix(argv[3]->arg, &pfx)) {
			vty_out(vty, "Invalid prefix: %s\n", argv[3]->arg);
			return CMD_WARNING;
		}
		p = &pfx;
	}

	rfapi_vty_show_nve_summary(vty, SHOW_NVE_SUMMARY_QUERIES);

	return rfapiShowVncQueries(vty, p);
}

DEFUN (vnc_clear_counters,
       vnc_clear_counters_cmd,
       "clear vnc counters",
       CLEAR_STR
       VNC_SHOW_STR
       "Reset VNC counters\n")
{
	struct bgp *bgp_default = bgp_get_default();
	struct rfapi *h;
	struct listnode *node;
	struct rfapi_descriptor *rfd;

	if (!bgp_default)
		goto notcfg;

	h = bgp_default->rfapi;

	if (!h)
		goto notcfg;

	/* per-rfd */
	for (ALL_LIST_ELEMENTS_RO(&h->descriptors, node, rfd)) {
		rfd->stat_count_nh_reachable = 0;
		rfd->stat_count_nh_removal = 0;
	}

	/* global */
	memset(&h->stat, 0, sizeof(h->stat));

	/*
	 * 151122 per bug 103, set count_registrations = number active.
	 * Do same for queries
	 */
	h->stat.count_registrations = rfapiApCountAll(bgp_default);
	h->stat.count_queries = rfapi_monitor_count(NULL);

	rfapiRibShowResponsesSummaryClear();

	return CMD_SUCCESS;

notcfg:
	vty_out(vty, "VNC is not configured.\n");
	return CMD_WARNING;
}

/************************************************************************
 *		Add prefix with vrf
 *
 * add [vrf <vrf-name>] prefix <prefix>
 *     [rd <value>] [label <value>] [local-preference <0-4294967295>]
 ************************************************************************/
void vnc_add_vrf_opener(struct bgp *bgp, struct rfapi_nve_group_cfg *rfg)
{
	if (rfg->rfd == NULL) { /* need new rfapi_handle */
		/* based on rfapi_open */
		struct rfapi_descriptor *rfd;

		rfd = XCALLOC(MTYPE_RFAPI_DESC,
			      sizeof(struct rfapi_descriptor));
		rfd->bgp = bgp;
		rfg->rfd = rfd;
		/* leave most fields empty as will get from (dynamic) config
		 * when needed */
		rfd->default_tunneltype_option.type = BGP_ENCAP_TYPE_MPLS;
		rfd->cookie = rfg;
		if (rfg->vn_prefix.family
		    && !CHECK_FLAG(rfg->flags, RFAPI_RFG_VPN_NH_SELF)) {
			rfapiQprefix2Raddr(&rfg->vn_prefix, &rfd->vn_addr);
		} else {
			memset(&rfd->vn_addr, 0, sizeof(struct rfapi_ip_addr));
			rfd->vn_addr.addr_family = AF_INET;
			rfd->vn_addr.addr.v4 = bgp->router_id;
		}
		rfd->un_addr = rfd->vn_addr; /* sigh, need something in UN for
						lookups */
		vnc_zlog_debug_verbose("%s: Opening RFD for VRF %s", __func__,
				       rfg->name);
		rfapi_init_and_open(bgp, rfd, rfg);
	}
}

/* NOTE: this functions parallels vnc_direct_add_rn_group_rd */
static int vnc_add_vrf_prefix(struct vty *vty, const char *arg_vrf,
			      const char *arg_prefix,
			      const char *arg_rd,    /* optional */
			      const char *arg_label, /* optional */
			      const char *arg_pref)  /* optional */
{
	struct bgp *bgp;
	struct rfapi_nve_group_cfg *rfg;
	struct prefix pfx;
	struct rfapi_ip_prefix rpfx;
	uint32_t pref = 0;
	struct rfapi_vn_option optary[3];
	struct rfapi_vn_option *opt = NULL;
	int cur_opt = 0;

	bgp = bgp_get_default(); /* assume main instance for now */
	if (!bgp) {
		vty_out(vty, "No BGP process is configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!bgp->rfapi || !bgp->rfapi_cfg) {
		vty_out(vty, "VRF support not configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rfg = bgp_rfapi_cfg_match_byname(bgp, arg_vrf, RFAPI_GROUP_CFG_VRF);
	/* arg checks */
	if (!rfg) {
		vty_out(vty, "VRF \"%s\" appears not to be configured.\n",
			arg_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!rfg->rt_export_list || !rfg->rfapi_import_table) {
		vty_out(vty,
			"VRF \"%s\" is missing RT import/export RT configuration.\n",
			arg_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!rfg->rd.prefixlen && !arg_rd) {
		vty_out(vty,
			"VRF \"%s\" isn't configured with an RD, so RD must be provided.\n",
			arg_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (rfg->label > MPLS_LABEL_MAX && !arg_label) {
		vty_out(vty,
			"VRF \"%s\" isn't configured with a default labels, so a label must be provided.\n",
			arg_vrf);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!str2prefix(arg_prefix, &pfx)) {
		vty_out(vty, "Malformed prefix \"%s\"\n", arg_prefix);
		return CMD_WARNING_CONFIG_FAILED;
	}
	rfapiQprefix2Rprefix(&pfx, &rpfx);
	memset(optary, 0, sizeof(optary));
	if (arg_rd) {
		opt = &optary[cur_opt++];
		opt->type = RFAPI_VN_OPTION_TYPE_INTERNAL_RD;
		if (!str2prefix_rd(arg_rd, &opt->v.internal_rd)) {
			vty_out(vty, "Malformed RD \"%s\"\n", arg_rd);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	if (rfg->label <= MPLS_LABEL_MAX || arg_label) {
		struct rfapi_l2address_option *l2o;
		if (opt != NULL)
			opt->next = &optary[cur_opt];
		opt = &optary[cur_opt++];
		opt->type = RFAPI_VN_OPTION_TYPE_L2ADDR;
		l2o = &opt->v.l2addr;
		if (arg_label) {
			int32_t label;
			label = strtoul(arg_label, NULL, 10);
			l2o->label = label;
		} else
			l2o->label = rfg->label;
	}
	if (arg_pref) {
		char *endptr = NULL;
		pref = strtoul(arg_pref, &endptr, 10);
		if (*endptr != '\0') {
			vty_out(vty,
				"%% Invalid local-preference value \"%s\"\n",
				arg_pref);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	rpfx.cost = 255 - (pref & 255);
	vnc_add_vrf_opener(bgp, rfg);

	if (!rfapi_register(rfg->rfd, &rpfx, RFAPI_INFINITE_LIFETIME, NULL,
			    (cur_opt ? optary : NULL), RFAPI_REGISTER_ADD)) {
		struct rfapi_next_hop_entry *head = NULL;
		struct rfapi_next_hop_entry *tail = NULL;
		struct rfapi_vn_option *vn_opt_new;

		vnc_zlog_debug_verbose("%s: rfapi_register succeeded",
				       __func__);

		if (bgp->rfapi->rfp_methods.local_cb) {
			struct rfapi_descriptor *r =
				(struct rfapi_descriptor *)rfg->rfd;
			vn_opt_new = rfapi_vn_options_dup(opt);

			rfapiAddDeleteLocalRfpPrefix(&r->un_addr, &r->vn_addr,
						     &rpfx, 1,
						     RFAPI_INFINITE_LIFETIME,
						     vn_opt_new, &head, &tail);
			if (head) {
				bgp->rfapi->flags |= RFAPI_INCALLBACK;
				(*bgp->rfapi->rfp_methods.local_cb)(head,
								    r->cookie);
				bgp->rfapi->flags &= ~RFAPI_INCALLBACK;
			}
			head = tail = NULL;
		}
		vnc_zlog_debug_verbose(
			"%s completed, count=%d/%d", __func__,
			rfg->rfapi_import_table->local_count[AFI_IP],
			rfg->rfapi_import_table->local_count[AFI_IP6]);
		return CMD_SUCCESS;
	}

	vnc_zlog_debug_verbose("%s: rfapi_register failed", __func__);
	vty_out(vty, "Add failed.\n");
	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (add_vrf_prefix_rd_label_pref,
       add_vrf_prefix_rd_label_pref_cmd,
      "add vrf NAME prefix <A.B.C.D/M|X:X::X:X/M> [{rd ASN:NN_OR_IP-ADDRESS|label (0-1048575)|preference (0-4294967295)}]",
       "Add\n"
       "To a VRF\n"
       "VRF name\n"
       "Add/modify prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "Override configured VRF Route Distinguisher\n"
       "<as-number>:<number> or <ip-address>:<number>\n"
       "Override configured VRF label\n"
       "Label Value <0-1048575>\n"
       "Set advertised local preference\n"
       "local preference (higher=more preferred)\n")
{
	char *arg_vrf = argv[2]->arg;
	char *arg_prefix = argv[4]->arg;
	char *arg_rd = NULL;    /* optional */
	char *arg_label = NULL; /* optional */
	char *arg_pref = NULL;  /* optional */
	int pargc = 5;
	argc--; /* don't parse argument */
	while (pargc < argc) {
		switch (argv[pargc++]->arg[0]) {
		case 'r':
			arg_rd = argv[pargc]->arg;
			break;
		case 'l':
			arg_label = argv[pargc]->arg;
			break;
		case 'p':
			arg_pref = argv[pargc]->arg;
			break;
		default:
			break;
		}
		pargc++;
	}

	return vnc_add_vrf_prefix(vty, arg_vrf, arg_prefix, arg_rd, arg_label,
				  arg_pref);
}

/************************************************************************
 *		del prefix with vrf
 *
 * clear [vrf <vrf-name>] prefix <prefix> [rd <value>]
 ************************************************************************/
static int rfapi_cfg_group_it_count(struct rfapi_nve_group_cfg *rfg)
{
	int count = 0;

	if (rfg->rfapi_import_table == NULL)
		return 0;

	afi_t afi = AFI_MAX;
	while (afi-- > 0) {
		count += rfg->rfapi_import_table->local_count[afi];
	}
	return count;
}

void clear_vnc_vrf_closer(struct rfapi_nve_group_cfg *rfg)
{
	struct rfapi_descriptor *rfd = rfg->rfd;
	afi_t afi;

	if (rfd == NULL)
		return;
	/* check if IT is empty */
	for (afi = 0;
	     afi < AFI_MAX && rfg->rfapi_import_table->local_count[afi] == 0;
	     afi++)
		;

	if (afi == AFI_MAX) {
		vnc_zlog_debug_verbose("%s: closing RFD for VRF %s", __func__,
				       rfg->name);
		rfg->rfd = NULL;
		rfapi_close(rfd);
	} else {
		vnc_zlog_debug_verbose(
			"%s: VRF %s afi=%d count=%d", __func__, rfg->name, afi,
			rfg->rfapi_import_table->local_count[afi]);
	}
}

static int vnc_clear_vrf(struct vty *vty, struct bgp *bgp, const char *arg_vrf,
			 const char *arg_prefix, /* NULL = all */
			 const char *arg_rd)     /* optional */
{
	struct rfapi_nve_group_cfg *rfg;
	struct rfapi_local_reg_delete_arg cda;
	int rc;
	int start_count;

	if (bgp == NULL)
		bgp = bgp_get_default(); /* assume main instance for now */
	if (!bgp) {
		vty_out(vty, "No BGP process is configured\n");
		return CMD_WARNING;
	}
	if (!bgp->rfapi || !bgp->rfapi_cfg) {
		vty_out(vty, "VRF support not configured\n");
		return CMD_WARNING;
	}
	rfg = bgp_rfapi_cfg_match_byname(bgp, arg_vrf, RFAPI_GROUP_CFG_VRF);
	/* arg checks */
	if (!rfg) {
		vty_out(vty, "VRF \"%s\" appears not to be configured.\n",
			arg_vrf);
		return CMD_WARNING;
	}
	rc = parse_deleter_args(vty, bgp, arg_prefix, NULL, NULL, NULL, NULL,
				arg_rd, rfg, &cda);
	if (rc != CMD_SUCCESS) /* parse error */
		return rc;

	start_count = rfapi_cfg_group_it_count(rfg);
	clear_vnc_prefix(&cda);
	vty_out(vty, "Cleared %u out of %d prefixes.\n", cda.pfx_count,
		start_count);
	return CMD_SUCCESS;
}

DEFUN (clear_vrf_prefix_rd,
       clear_vrf_prefix_rd_cmd,
       "clear vrf NAME [prefix <A.B.C.D/M|X:X::X:X/M>] [rd ASN:NN_OR_IP-ADDRESS]",
       "Clear stored data\n"
       "From a VRF\n"
       "VRF name\n"
       "Prefix related information\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "Specific VRF Route Distinguisher\n"
       "<as-number>:<number> or <ip-address>:<number>\n")
{
	char *arg_vrf = argv[2]->arg;
	char *arg_prefix = NULL; /* optional */
	char *arg_rd = NULL;     /* optional */
	int pargc = 3;
	argc--; /* don't check parameter */
	while (pargc < argc) {
		switch (argv[pargc++]->arg[0]) {
		case 'r':
			arg_rd = argv[pargc]->arg;
			break;
		case 'p':
			arg_prefix = argv[pargc]->arg;
			break;
		default:
			break;
		}
		pargc++;
	}
	return vnc_clear_vrf(vty, NULL, arg_vrf, arg_prefix, arg_rd);
}

DEFUN (clear_vrf_all,
       clear_vrf_all_cmd,
       "clear vrf NAME all",
       "Clear stored data\n"
       "From a VRF\n"
       "VRF name\n"
       "All prefixes\n")
{
	char *arg_vrf = argv[2]->arg;
	return vnc_clear_vrf(vty, NULL, arg_vrf, NULL, NULL);
}

void rfapi_vty_init(void)
{
	install_element(ENABLE_NODE, &add_vnc_prefix_cost_life_lnh_cmd);
	install_element(ENABLE_NODE, &add_vnc_prefix_life_cost_lnh_cmd);
	install_element(ENABLE_NODE, &add_vnc_prefix_cost_lnh_cmd);
	install_element(ENABLE_NODE, &add_vnc_prefix_life_lnh_cmd);
	install_element(ENABLE_NODE, &add_vnc_prefix_lnh_cmd);

	install_element(ENABLE_NODE, &add_vnc_prefix_cost_life_cmd);
	install_element(ENABLE_NODE, &add_vnc_prefix_life_cost_cmd);
	install_element(ENABLE_NODE, &add_vnc_prefix_cost_cmd);
	install_element(ENABLE_NODE, &add_vnc_prefix_life_cmd);
	install_element(ENABLE_NODE, &add_vnc_prefix_cmd);

	install_element(ENABLE_NODE, &add_vnc_mac_vni_prefix_cost_life_cmd);
	install_element(ENABLE_NODE, &add_vnc_mac_vni_prefix_life_cmd);
	install_element(ENABLE_NODE, &add_vnc_mac_vni_prefix_cost_cmd);
	install_element(ENABLE_NODE, &add_vnc_mac_vni_prefix_cmd);
	install_element(ENABLE_NODE, &add_vnc_mac_vni_cost_life_cmd);
	install_element(ENABLE_NODE, &add_vnc_mac_vni_cost_cmd);
	install_element(ENABLE_NODE, &add_vnc_mac_vni_life_cmd);
	install_element(ENABLE_NODE, &add_vnc_mac_vni_cmd);

	install_element(ENABLE_NODE, &add_vrf_prefix_rd_label_pref_cmd);

	install_element(ENABLE_NODE, &clear_vnc_nve_all_cmd);
	install_element(ENABLE_NODE, &clear_vnc_nve_vn_un_cmd);
	install_element(ENABLE_NODE, &clear_vnc_nve_un_vn_cmd);
	install_element(ENABLE_NODE, &clear_vnc_nve_vn_cmd);
	install_element(ENABLE_NODE, &clear_vnc_nve_un_cmd);

	install_element(ENABLE_NODE, &clear_vnc_prefix_vn_un_cmd);
	install_element(ENABLE_NODE, &clear_vnc_prefix_un_vn_cmd);
	install_element(ENABLE_NODE, &clear_vnc_prefix_un_cmd);
	install_element(ENABLE_NODE, &clear_vnc_prefix_vn_cmd);
	install_element(ENABLE_NODE, &clear_vnc_prefix_all_cmd);

	install_element(ENABLE_NODE, &clear_vnc_mac_vn_un_cmd);
	install_element(ENABLE_NODE, &clear_vnc_mac_un_vn_cmd);
	install_element(ENABLE_NODE, &clear_vnc_mac_un_cmd);
	install_element(ENABLE_NODE, &clear_vnc_mac_vn_cmd);
	install_element(ENABLE_NODE, &clear_vnc_mac_all_cmd);

	install_element(ENABLE_NODE, &clear_vnc_mac_vn_un_prefix_cmd);
	install_element(ENABLE_NODE, &clear_vnc_mac_un_vn_prefix_cmd);
	install_element(ENABLE_NODE, &clear_vnc_mac_un_prefix_cmd);
	install_element(ENABLE_NODE, &clear_vnc_mac_vn_prefix_cmd);
	install_element(ENABLE_NODE, &clear_vnc_mac_all_prefix_cmd);

	install_element(ENABLE_NODE, &clear_vrf_prefix_rd_cmd);
	install_element(ENABLE_NODE, &clear_vrf_all_cmd);

	install_element(ENABLE_NODE, &vnc_clear_counters_cmd);

	install_element(VIEW_NODE, &vnc_show_summary_cmd);
	install_element(VIEW_NODE, &vnc_show_nves_cmd);
	install_element(VIEW_NODE, &vnc_show_nves_ptct_cmd);

	install_element(VIEW_NODE, &vnc_show_registrations_pfx_cmd);
	install_element(VIEW_NODE, &vnc_show_registrations_some_pfx_cmd);
	install_element(VIEW_NODE, &vnc_show_responses_pfx_cmd);
	install_element(VIEW_NODE, &vnc_show_responses_some_pfx_cmd);
	install_element(VIEW_NODE, &show_vnc_queries_pfx_cmd);
}
