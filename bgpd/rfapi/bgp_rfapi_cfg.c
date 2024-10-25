// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */
#include "lib/zebra.h"

#include "lib/command.h"
#include "lib/prefix.h"
#include "lib/memory.h"
#include "lib/linklist.h"
#include "lib/agg_table.h"
#include "lib/plist.h"
#include "lib/routemap.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"

#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi_backend.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_monitor.h"
#include "bgpd/rfapi/vnc_zebra.h"
#include "bgpd/rfapi/vnc_export_bgp.h"
#include "bgpd/rfapi/vnc_export_bgp_p.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/vnc_debug.h"

#ifdef ENABLE_BGP_VNC

#undef BGP_VNC_DEBUG_MATCH_GROUP


DEFINE_MGROUP(RFAPI, "rfapi");
DEFINE_MTYPE(RFAPI, RFAPI_CFG, "NVE Configuration");
DEFINE_MTYPE(RFAPI, RFAPI_GROUP_CFG, "NVE Group Configuration");
DEFINE_MTYPE(RFAPI, RFAPI_L2_CFG, "RFAPI L2 Group Configuration");
DEFINE_MTYPE(RFAPI, RFAPI_RFP_GROUP_CFG, "RFAPI RFP Group Configuration");
DEFINE_MTYPE(RFAPI, RFAPI, "RFAPI Generic");
DEFINE_MTYPE(RFAPI, RFAPI_DESC, "RFAPI Descriptor");
DEFINE_MTYPE(RFAPI, RFAPI_IMPORTTABLE, "RFAPI Import Table");
DEFINE_MTYPE(RFAPI, RFAPI_MONITOR, "RFAPI Monitor VPN");
DEFINE_MTYPE(RFAPI, RFAPI_MONITOR_ENCAP, "RFAPI Monitor Encap");
DEFINE_MTYPE(RFAPI, RFAPI_NEXTHOP, "RFAPI Next Hop");
DEFINE_MTYPE(RFAPI, RFAPI_VN_OPTION, "RFAPI VN Option");
DEFINE_MTYPE(RFAPI, RFAPI_UN_OPTION, "RFAPI UN Option");
DEFINE_MTYPE(RFAPI, RFAPI_WITHDRAW, "RFAPI Withdraw");
DEFINE_MTYPE(RFAPI, RFAPI_RFG_NAME, "RFAPI RFGName");
DEFINE_MTYPE(RFAPI, RFAPI_ADB, "RFAPI Advertisement Data");
DEFINE_MTYPE(RFAPI, RFAPI_ETI, "RFAPI Export Table Info");
DEFINE_MTYPE(RFAPI, RFAPI_NVE_ADDR, "RFAPI NVE Address");
DEFINE_MTYPE(RFAPI, RFAPI_PREFIX_BAG, "RFAPI Prefix Bag");
DEFINE_MTYPE(RFAPI, RFAPI_IT_EXTRA, "RFAPI IT Extra");
DEFINE_MTYPE(RFAPI, RFAPI_INFO, "RFAPI Info");
DEFINE_MTYPE(RFAPI, RFAPI_ADDR, "RFAPI Addr");
DEFINE_MTYPE(RFAPI, RFAPI_UPDATED_RESPONSE_QUEUE, "RFAPI Updated Rsp Queue");
DEFINE_MTYPE(RFAPI, RFAPI_RECENT_DELETE, "RFAPI Recently Deleted Route");
DEFINE_MTYPE(RFAPI, RFAPI_L2ADDR_OPT, "RFAPI L2 Address Option");
DEFINE_MTYPE(RFAPI, RFAPI_AP, "RFAPI Advertised Prefix");
DEFINE_MTYPE(RFAPI, RFAPI_MONITOR_ETH, "RFAPI Monitor Ethernet");

DEFINE_QOBJ_TYPE(rfapi_nve_group_cfg);
DEFINE_QOBJ_TYPE(rfapi_l2_group_cfg);
/***********************************************************************
 *			RFAPI Support
 ***********************************************************************/


/*
 * compaitibility to old quagga_time call
 * time_t value in terms of stabilised absolute time.
 * replacement for POSIX time()
 */
time_t rfapi_time(time_t *t)
{
	time_t clock = monotime(NULL);
	if (t)
		*t = clock;
	return clock;
}

void nve_group_to_nve_list(struct rfapi_nve_group_cfg *rfg, struct list **nves,
			   uint8_t family) /* AF_INET, AF_INET6 */
{
	struct listnode *hln;
	struct rfapi_descriptor *rfd;

	/*
	 * loop over nves in this grp, add to list
	 */
	for (ALL_LIST_ELEMENTS_RO(rfg->nves, hln, rfd)) {
		if (rfd->vn_addr.addr_family == family) {
			if (!*nves)
				*nves = list_new();
			listnode_add(*nves, rfd);
		}
	}
}


struct rfapi_nve_group_cfg *bgp_rfapi_cfg_match_group(struct rfapi_cfg *hc,
						      struct prefix *vn,
						      struct prefix *un)
{
	struct rfapi_nve_group_cfg *rfg_vn = NULL;
	struct rfapi_nve_group_cfg *rfg_un = NULL;

	struct agg_table *rt_vn;
	struct agg_table *rt_un;
	struct agg_node *rn_vn;
	struct agg_node *rn_un;

	struct rfapi_nve_group_cfg *rfg;
	struct listnode *node, *nnode;

	switch (vn->family) {
	case AF_INET:
		rt_vn = hc->nve_groups_vn[AFI_IP];
		break;
	case AF_INET6:
		rt_vn = hc->nve_groups_vn[AFI_IP6];
		break;
	default:
		return NULL;
	}

	switch (un->family) {
	case AF_INET:
		rt_un = hc->nve_groups_un[AFI_IP];
		break;
	case AF_INET6:
		rt_un = hc->nve_groups_un[AFI_IP6];
		break;
	default:
		return NULL;
	}

	rn_vn = agg_node_match(rt_vn, vn); /* NB locks node */
	if (rn_vn) {
		rfg_vn = rn_vn->info;
		agg_unlock_node(rn_vn);
	}

	rn_un = agg_node_match(rt_un, un); /* NB locks node */
	if (rn_un) {
		rfg_un = rn_un->info;
		agg_unlock_node(rn_un);
	}

#ifdef BGP_VNC_DEBUG_MATCH_GROUP
	{
		vnc_zlog_debug_verbose("%s: vn prefix: %pFX", __func__, vn);
		vnc_zlog_debug_verbose("%s: un prefix: %pFX", __func__, un);
		vnc_zlog_debug_verbose(
			"%s: rn_vn=%p, rn_un=%p, rfg_vn=%p, rfg_un=%p",
			__func__, rn_vn, rn_un, rfg_vn, rfg_un);
	}
#endif


	if (rfg_un == rfg_vn) /* same group */
		return rfg_un;
	if (!rfg_un) /* un doesn't match, return vn-matched grp */
		return rfg_vn;
	if (!rfg_vn) /* vn doesn't match, return un-matched grp */
		return rfg_un;

	/*
	 * Two different nve groups match: the group configured earlier wins.
	 * For now, just walk the sequential list and pick the first one.
	 * If this approach is too slow, then store serial numbers in the
	 * nve group structures as they are defined and just compare
	 * serial numbers.
	 */
	for (ALL_LIST_ELEMENTS(hc->nve_groups_sequential, node, nnode, rfg)) {
		if ((rfg == rfg_un) || (rfg == rfg_vn)) {
			return rfg;
		}
	}
	vnc_zlog_debug_verbose(
		"%s: shouldn't happen, returning NULL when un and vn match",
		__func__);
	return NULL; /* shouldn't happen */
}

/*------------------------------------------
 * rfapi_get_rfp_start_val
 *
 * Returns value passed to rfapi on rfp_start
 *
 * input:
 *	void *		bgp structure
 *
 * returns:
 *	void *
 *------------------------------------------*/
void *rfapi_get_rfp_start_val(void *bgpv)
{
	struct bgp *bgp = bgpv;
	if (bgp == NULL || bgp->rfapi == NULL)
		return NULL;
	return bgp->rfapi->rfp;
}

/*------------------------------------------
 * bgp_rfapi_is_vnc_configured
 *
 * Returns if VNC is configured
 *
 * input:
 *    bgp        NULL (=use default instance)
 *
 * output:
 *
 * return value: If VNC is configured for the bgpd instance
 *	0		Success
 *      EPERM		Not Default instance (VNC operations not allowed)
 *	ENXIO		VNC not configured
 --------------------------------------------*/
int bgp_rfapi_is_vnc_configured(struct bgp *bgp)
{
	if (bgp == NULL)
		bgp = bgp_get_default();

	if (bgp && bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return EPERM;

	if (bgp && bgp->rfapi_cfg)
		return 0;
	return ENXIO;
}

/***********************************************************************
 *			VNC Configuration/CLI
 ***********************************************************************/
#define VNC_VTY_CONFIG_CHECK(bgp)                                                            \
	{                                                                                    \
		switch (bgp_rfapi_is_vnc_configured(bgp)) {                                  \
		case EPERM:                                                                  \
			vty_out(vty,                                                         \
				"VNC operations only permitted on default BGP instance.\n"); \
			return CMD_WARNING_CONFIG_FAILED;                                    \
			break;                                                               \
		case ENXIO:                                                                  \
			vty_out(vty, "VNC not configured.\n");                               \
			return CMD_WARNING_CONFIG_FAILED;                                    \
			break;                                                               \
		default:                                                                     \
			break;                                                               \
		}                                                                            \
	}

DEFUN (vnc_advertise_un_method,
       vnc_advertise_un_method_cmd,
       "vnc advertise-un-method encap-attr",
       VNC_CONFIG_STR
       "Method of advertising UN addresses\n"
       "Via Tunnel Encap attribute (in VPN SAFI)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VNC_VTY_CONFIG_CHECK(bgp);

	if (!strncmp(argv[2]->arg, "encap-safi", 7)) {
		bgp->rfapi_cfg->flags |= BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP;
	} else {
		bgp->rfapi_cfg->flags &= ~BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP;
	}

	return CMD_SUCCESS;
}

/*-------------------------------------------------------------------------
 *			RFG defaults
 *-----------------------------------------------------------------------*/


DEFUN_NOSH (vnc_defaults,
	    vnc_defaults_cmd,
	    "vnc defaults", VNC_CONFIG_STR "Configure default NVE group\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VNC_VTY_CONFIG_CHECK(bgp);
	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT) {
		vty_out(vty, "Malformed community-list value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	vty->node = BGP_VNC_DEFAULTS_NODE;
	return CMD_SUCCESS;
}

static int set_ecom_list(struct vty *vty, int argc, struct cmd_token **argv,
			 struct ecommunity **list)
{
	struct ecommunity *ecom = NULL;
	struct ecommunity *ecomadd;

	for (; argc; --argc, ++argv) {

		ecomadd = ecommunity_str2com(argv[0]->arg,
					     ECOMMUNITY_ROUTE_TARGET, 0);
		if (!ecomadd) {
			vty_out(vty, "Malformed community-list value\n");
			if (ecom)
				ecommunity_free(&ecom);
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (ecom) {
			ecommunity_merge(ecom, ecomadd);
			ecommunity_free(&ecomadd);
		} else {
			ecom = ecomadd;
		}
	}

	if (*list) {
		ecommunity_free(&*list);
	}
	*list = ecom;

	return CMD_SUCCESS;
}

DEFUN (vnc_defaults_rt_import,
       vnc_defaults_rt_import_cmd,
       "rt import RTLIST...",
       "Specify default route targets\n"
       "Import filter\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	return set_ecom_list(vty, argc - 2, argv + 2,
			     &bgp->rfapi_cfg->default_rt_import_list);
}

DEFUN (vnc_defaults_rt_export,
       vnc_defaults_rt_export_cmd,
       "rt export RTLIST...",
       "Configure default route targets\n"
       "Export filter\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	return set_ecom_list(vty, argc - 2, argv + 2,
			     &bgp->rfapi_cfg->default_rt_export_list);
}

DEFUN (vnc_defaults_rt_both,
       vnc_defaults_rt_both_cmd,
       "rt both RTLIST...",
       "Configure default route targets\n"
       "Export+import filters\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int rc;

	rc = set_ecom_list(vty, argc - 2, argv + 2,
			   &bgp->rfapi_cfg->default_rt_import_list);
	if (rc != CMD_SUCCESS)
		return rc;
	return set_ecom_list(vty, argc - 2, argv + 2,
			     &bgp->rfapi_cfg->default_rt_export_list);
}

DEFUN (vnc_defaults_rd,
       vnc_defaults_rd_cmd,
       "rd ASN:NN_OR_IP-ADDRESS:NN",
       "Specify default route distinguisher\n"
       "Route Distinguisher (<as-number>:<number> | <ip-address>:<number> | auto:vn:<number> )\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct prefix_rd prd;

	if (!strncmp(argv[1]->arg, "auto:vn:", 8)) {
		/*
		 * use AF_UNIX to designate automatically-assigned RD
		 * auto:vn:nn where nn is a 2-octet quantity
		 */
		char *end = NULL;
		uint32_t value32 = strtoul(argv[1]->arg + 8, &end, 10);
		uint16_t value = value32 & 0xffff;

		if (!argv[1]->arg[8] || *end) {
			vty_out(vty, "%% Malformed rd\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (value32 > 0xffff) {
			vty_out(vty, "%% Malformed rd (must be less than %u\n",
				0x0ffff);
			return CMD_WARNING_CONFIG_FAILED;
		}

		memset(&prd, 0, sizeof(prd));
		prd.family = AF_UNIX;
		prd.prefixlen = 64;
		prd.val[0] = (RD_TYPE_IP >> 8) & 0x0ff;
		prd.val[1] = RD_TYPE_IP & 0x0ff;
		prd.val[6] = (value >> 8) & 0x0ff;
		prd.val[7] = value & 0x0ff;

	} else {

		/* TODO: save RD format */
		ret = str2prefix_rd(argv[1]->arg, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed rd\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	bgp->rfapi_cfg->default_rd = prd;
	return CMD_SUCCESS;
}

DEFUN (vnc_defaults_l2rd,
       vnc_defaults_l2rd_cmd,
       "l2rd <(1-255)|auto-vn>",
       "Specify default Local Nve ID value to use in RD for L2 routes\n"
       "Fixed value 1-255\n"
       "use the low-order octet of the NVE's VN address\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint8_t value = 0;

	if (strmatch(argv[1]->text, "auto-vn")) {
		value = 0;
	} else {
		char *end = NULL;
		unsigned long value_l = strtoul(argv[1]->arg, &end, 10);

		value = value_l & 0xff;
		if (!argv[1]->arg[0] || *end) {
			vty_out(vty, "%% Malformed l2 nve ID \"%s\"\n",
				argv[1]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if ((value_l < 1) || (value_l > 0xff)) {
			vty_out(vty,
				"%% Malformed l2 nve id (must be greater than 0 and less than %u\n",
				0x100);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	bgp->rfapi_cfg->flags |= BGP_VNC_CONFIG_L2RD;
	bgp->rfapi_cfg->default_l2rd = value;

	return CMD_SUCCESS;
}

DEFUN (vnc_defaults_no_l2rd,
       vnc_defaults_no_l2rd_cmd,
       "no l2rd",
       NO_STR
       "Specify default Local Nve ID value to use in RD for L2 routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->rfapi_cfg->default_l2rd = 0;
	bgp->rfapi_cfg->flags &= ~BGP_VNC_CONFIG_L2RD;

	return CMD_SUCCESS;
}

DEFUN (vnc_defaults_responselifetime,
       vnc_defaults_responselifetime_cmd,
       "response-lifetime <LIFETIME|infinite>",
       "Specify default response lifetime\n"
       "Response lifetime in seconds\n" "Infinite response lifetime\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint32_t rspint;
	struct rfapi *h = NULL;
	struct listnode *hdnode;
	struct rfapi_descriptor *rfd;

	h = bgp->rfapi;
	if (!h)
		return CMD_WARNING_CONFIG_FAILED;

	if (strmatch(argv[1]->text, "infinite")) {
		rspint = RFAPI_INFINITE_LIFETIME;
	} else {
		rspint = strtoul(argv[1]->arg, NULL, 10);
		if (rspint > INT32_MAX)
			rspint = INT32_MAX; /* is really an int, not an unsigned
					       int */
	}

	bgp->rfapi_cfg->default_response_lifetime = rspint;

	for (ALL_LIST_ELEMENTS_RO(&h->descriptors, hdnode, rfd))
		if (rfd->rfg
		    && !(rfd->rfg->flags & RFAPI_RFG_RESPONSE_LIFETIME))
			rfd->response_lifetime = rfd->rfg->response_lifetime =
				rspint;

	return CMD_SUCCESS;
}

struct rfapi_nve_group_cfg *
bgp_rfapi_cfg_match_byname(struct bgp *bgp, const char *name,
			   rfapi_group_cfg_type_t type) /* _MAX = any */
{
	struct rfapi_nve_group_cfg *rfg;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->nve_groups_sequential, node,
			       nnode, rfg)) {
		if ((type == RFAPI_GROUP_CFG_MAX || type == rfg->type)
		    && !strcmp(rfg->name, name))
			return rfg;
	}
	return NULL;
}

static struct rfapi_nve_group_cfg *
rfapi_group_new(struct bgp *bgp, rfapi_group_cfg_type_t type, const char *name)
{
	struct rfapi_nve_group_cfg *rfg;

	rfg = XCALLOC(MTYPE_RFAPI_GROUP_CFG,
		      sizeof(struct rfapi_nve_group_cfg));
	rfg->type = type;
	rfg->name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
	/* add to tail of list */
	listnode_add(bgp->rfapi_cfg->nve_groups_sequential, rfg);
	rfg->label = MPLS_LABEL_NONE;

	QOBJ_REG(rfg, rfapi_nve_group_cfg);

	return rfg;
}

static struct rfapi_l2_group_cfg *rfapi_l2_group_lookup_byname(struct bgp *bgp,
							       const char *name)
{
	struct rfapi_l2_group_cfg *rfg;
	struct listnode *node, *nnode;

	if (bgp->rfapi_cfg->l2_groups == NULL) /* not the best place for this */
		bgp->rfapi_cfg->l2_groups = list_new();

	for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->l2_groups, node, nnode, rfg)) {
		if (!strcmp(rfg->name, name))
			return rfg;
	}
	return NULL;
}

static struct rfapi_l2_group_cfg *rfapi_l2_group_new(void)
{
	struct rfapi_l2_group_cfg *rfg;

	rfg = XCALLOC(MTYPE_RFAPI_L2_CFG, sizeof(struct rfapi_l2_group_cfg));
	QOBJ_REG(rfg, rfapi_l2_group_cfg);

	return rfg;
}

static void rfapi_l2_group_del(struct rfapi_l2_group_cfg *rfg)
{
	QOBJ_UNREG(rfg);
	XFREE(MTYPE_RFAPI_L2_CFG, rfg);
}

static int rfapi_str2route_type(const char *l3str, const char *pstr, afi_t *afi,
				int *type)
{
	if (!l3str || !pstr)
		return EINVAL;

	if (!strcmp(l3str, "ipv4")) {
		*afi = AFI_IP;
	} else {
		if (!strcmp(l3str, "ipv6"))
			*afi = AFI_IP6;
		else
			return ENOENT;
	}

	if (!strcmp(pstr, "connected"))
		*type = ZEBRA_ROUTE_CONNECT;
	if (!strcmp(pstr, "kernel"))
		*type = ZEBRA_ROUTE_KERNEL;
	if (!strcmp(pstr, "static"))
		*type = ZEBRA_ROUTE_STATIC;
	if (!strcmp(pstr, "bgp"))
		*type = ZEBRA_ROUTE_BGP;
	if (!strcmp(pstr, "bgp-direct"))
		*type = ZEBRA_ROUTE_BGP_DIRECT;
	if (!strcmp(pstr, "bgp-direct-to-nve-groups"))
		*type = ZEBRA_ROUTE_BGP_DIRECT_EXT;

	if (!strcmp(pstr, "rip")) {
		if (*afi == AFI_IP)
			*type = ZEBRA_ROUTE_RIP;
		else
			*type = ZEBRA_ROUTE_RIPNG;
	}

	if (!strcmp(pstr, "ripng")) {
		if (*afi == AFI_IP)
			return EAFNOSUPPORT;
		*type = ZEBRA_ROUTE_RIPNG;
	}

	if (!strcmp(pstr, "ospf")) {
		if (*afi == AFI_IP)
			*type = ZEBRA_ROUTE_OSPF;
		else
			*type = ZEBRA_ROUTE_OSPF6;
	}

	if (!strcmp(pstr, "ospf6")) {
		if (*afi == AFI_IP)
			return EAFNOSUPPORT;
		*type = ZEBRA_ROUTE_OSPF6;
	}

	return 0;
}

/*-------------------------------------------------------------------------
 *			redistribute
 *-----------------------------------------------------------------------*/

#define VNC_REDIST_ENABLE(bgp, afi, type)                                      \
	do {                                                                   \
		switch (type) {                                                \
		case ZEBRA_ROUTE_BGP_DIRECT:                                   \
			vnc_import_bgp_redist_enable((bgp), (afi));            \
			break;                                                 \
		case ZEBRA_ROUTE_BGP_DIRECT_EXT:                               \
			vnc_import_bgp_exterior_redist_enable((bgp), (afi));   \
			break;                                                 \
		default:                                                       \
			if ((type) < ZEBRA_ROUTE_MAX)			       \
				vnc_redistribute_set((bgp), (afi), (type));    \
			break;                                                 \
		}                                                              \
	} while (0)

#define VNC_REDIST_DISABLE(bgp, afi, type)                                     \
	do {                                                                   \
		switch (type) {                                                \
		case ZEBRA_ROUTE_BGP_DIRECT:                                   \
			vnc_import_bgp_redist_disable((bgp), (afi));           \
			break;                                                 \
		case ZEBRA_ROUTE_BGP_DIRECT_EXT:                               \
			vnc_import_bgp_exterior_redist_disable((bgp), (afi));  \
			break;                                                 \
		default:                                                       \
			if ((type) < ZEBRA_ROUTE_MAX)			       \
				vnc_redistribute_unset((bgp), (afi), (type));  \
			break;                                                 \
		}                                                              \
	} while (0)

static uint8_t redist_was_enabled[AFI_MAX][ZEBRA_ROUTE_MAX];

static void vnc_redistribute_prechange(struct bgp *bgp)
{
	afi_t afi;
	int type;

	vnc_zlog_debug_verbose("%s: entry", __func__);
	memset(redist_was_enabled, 0, sizeof(redist_was_enabled));

	/*
	 * Look to see if we have any redistribution enabled. If so, flush
	 * the corresponding routes and turn off redistribution temporarily.
	 * We need to do it because the RD's used for the redistributed
	 * routes depend on the nve group.
	 */
	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		for (type = 0; type < ZEBRA_ROUTE_MAX; ++type) {
			if (bgp->rfapi_cfg->redist[afi][type]) {
				redist_was_enabled[afi][type] = 1;
				VNC_REDIST_DISABLE(bgp, afi, type);
			}
		}
	}
	vnc_zlog_debug_verbose("%s: return", __func__);
}

static void vnc_redistribute_postchange(struct bgp *bgp)
{
	afi_t afi;
	int type;

	vnc_zlog_debug_verbose("%s: entry", __func__);
	/*
	 * If we turned off redistribution above, turn it back on. Doing so
	 * will tell zebra to resend the routes to us
	 */
	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		for (type = 0; type < ZEBRA_ROUTE_MAX; ++type) {
			if (redist_was_enabled[afi][type]) {
				VNC_REDIST_ENABLE(bgp, afi, type);
			}
		}
	}
	vnc_zlog_debug_verbose("%s: return", __func__);
}

DEFUN (vnc_redistribute_rh_roo_localadmin,
       vnc_redistribute_rh_roo_localadmin_cmd,
       "vnc redistribute resolve-nve roo-ec-local-admin (0-65535)",
       VNC_CONFIG_STR
       "Redistribute routes into VNC\n"
       "Resolve-NVE mode\n"
       "Route Origin Extended Community Local Admin Field\n" "Field value\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint32_t localadmin;
	char *endptr;

	VNC_VTY_CONFIG_CHECK(bgp);

	localadmin = strtoul(argv[4]->arg, &endptr, 0);
	if (!argv[4]->arg[0] || *endptr) {
		vty_out(vty, "%% Malformed value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (localadmin > 0xffff) {
		vty_out(vty, "%% Value out of range (0-%d)\n", 0xffff);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bgp->rfapi_cfg->resolve_nve_roo_local_admin == localadmin)
		return CMD_SUCCESS;

	if ((bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS)
	    == BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE) {

		vnc_export_bgp_prechange(bgp);
	}
	vnc_redistribute_prechange(bgp);

	bgp->rfapi_cfg->resolve_nve_roo_local_admin = localadmin;

	if ((bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS)
	    == BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE) {

		vnc_export_bgp_postchange(bgp);
	}
	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}


DEFUN (vnc_redistribute_mode,
       vnc_redistribute_mode_cmd,
       "vnc redistribute mode <nve-group|plain|resolve-nve>",
       VNC_CONFIG_STR
       "Redistribute routes into VNC\n"
       "Redistribution mode\n"
       "Based on redistribute nve-group\n"
       "Unmodified\n" "Resolve each nexthop to connected NVEs\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	vnc_redist_mode_t newmode;

	VNC_VTY_CONFIG_CHECK(bgp);

	switch (argv[3]->arg[0]) {
	case 'n':
		newmode = VNC_REDIST_MODE_RFG;
		break;

	case 'p':
		newmode = VNC_REDIST_MODE_PLAIN;
		break;

	case 'r':
		newmode = VNC_REDIST_MODE_RESOLVE_NVE;
		break;

	default:
		vty_out(vty, "unknown redistribute mode\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (newmode != bgp->rfapi_cfg->redist_mode) {
		vnc_redistribute_prechange(bgp);
		bgp->rfapi_cfg->redist_mode = newmode;
		vnc_redistribute_postchange(bgp);
	}

	return CMD_SUCCESS;
}

DEFUN (vnc_redistribute_protocol,
       vnc_redistribute_protocol_cmd,
       "vnc redistribute <ipv4|ipv6> <bgp|bgp-direct|bgp-direct-to-nve-groups|connected|kernel|ospf|rip|static>",
       VNC_CONFIG_STR
       "Redistribute routes into VNC\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "From BGP\n"
       "From BGP without Zebra\n"
       "From BGP without Zebra, only to configured NVE groups\n"
       "Connected interfaces\n"
       "From kernel routes\n"
       "From Open Shortest Path First (OSPF)\n"
       "From Routing Information Protocol (RIP)\n" "From Static routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int type = ZEBRA_ROUTE_MAX; /* init to bogus value */
	afi_t afi;

	VNC_VTY_CONFIG_CHECK(bgp);

	if (rfapi_str2route_type(argv[2]->arg, argv[3]->arg, &afi, &type)) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (type == ZEBRA_ROUTE_BGP_DIRECT_EXT) {
		if (bgp->rfapi_cfg->redist_bgp_exterior_view_name) {
			VNC_REDIST_DISABLE(bgp, afi,
					   type); /* disabled view implicitly */
			XFREE(MTYPE_RFAPI_GROUP_CFG,
			      bgp->rfapi_cfg->redist_bgp_exterior_view_name);
		}
		bgp->rfapi_cfg->redist_bgp_exterior_view = bgp;
	}

	VNC_REDIST_ENABLE(bgp, afi, type);

	return CMD_SUCCESS;
}

DEFUN (vnc_no_redistribute_protocol,
       vnc_no_redistribute_protocol_cmd,
       "no vnc redistribute <ipv4|ipv6> <bgp|bgp-direct|bgp-direct-to-nve-groups|connected|kernel|ospf|rip|static>",
       NO_STR
       VNC_CONFIG_STR
       "Redistribute from other protocol\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "From BGP\n"
       "From BGP without Zebra\n"
       "From BGP without Zebra, only to configured NVE groups\n"
       "Connected interfaces\n"
       "From kernel routes\n"
       "From Open Shortest Path First (OSPF)\n"
       "From Routing Information Protocol (RIP)\n" "From Static routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int type;
	afi_t afi;

	VNC_VTY_CONFIG_CHECK(bgp);

	if (rfapi_str2route_type(argv[3]->arg, argv[4]->arg, &afi, &type)) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	VNC_REDIST_DISABLE(bgp, afi, type);

	if (type == ZEBRA_ROUTE_BGP_DIRECT_EXT) {
		XFREE(MTYPE_RFAPI_GROUP_CFG,
		      bgp->rfapi_cfg->redist_bgp_exterior_view_name);
		bgp->rfapi_cfg->redist_bgp_exterior_view = NULL;
	}

	return CMD_SUCCESS;
}

DEFUN (vnc_redistribute_bgp_exterior,
       vnc_redistribute_bgp_exterior_cmd,
       "vnc redistribute <ipv4|ipv6> bgp-direct-to-nve-groups view NAME",
       VNC_CONFIG_STR
       "Redistribute routes into VNC\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "From BGP without Zebra, only to configured NVE groups\n"
       "From BGP view\n" "BGP view name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int type;
	afi_t afi;

	VNC_VTY_CONFIG_CHECK(bgp);

	if (rfapi_str2route_type(argv[2]->arg, "bgp-direct-to-nve-groups", &afi,
				 &type)) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	XFREE(MTYPE_RFAPI_GROUP_CFG,
	      bgp->rfapi_cfg->redist_bgp_exterior_view_name);
	bgp->rfapi_cfg->redist_bgp_exterior_view_name =
		XSTRDUP(MTYPE_RFAPI_GROUP_CFG, argv[5]->arg);
	/* could be NULL if name is not defined yet */
	bgp->rfapi_cfg->redist_bgp_exterior_view =
		bgp_lookup_by_name(argv[5]->arg);

	VNC_REDIST_ENABLE(bgp, afi, type);

	return CMD_SUCCESS;
}

DEFUN (vnc_redistribute_nvegroup,
       vnc_redistribute_nvegroup_cmd,
       "vnc redistribute nve-group NAME",
       VNC_CONFIG_STR
       "Assign a NVE group to routes redistributed from another routing protocol\n"
       "NVE group\n" "Group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VNC_VTY_CONFIG_CHECK(bgp);

	vnc_redistribute_prechange(bgp);

	/*
	 * OK if nve group doesn't exist yet; we'll set the pointer
	 * when the group is defined later
	 */
	bgp->rfapi_cfg->rfg_redist = bgp_rfapi_cfg_match_byname(
		bgp, argv[3]->arg, RFAPI_GROUP_CFG_NVE);
	XFREE(MTYPE_RFAPI_GROUP_CFG, bgp->rfapi_cfg->rfg_redist_name);
	bgp->rfapi_cfg->rfg_redist_name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG,
						  argv[3]->arg);

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

DEFUN (vnc_redistribute_no_nvegroup,
       vnc_redistribute_no_nvegroup_cmd,
       "no vnc redistribute nve-group",
       NO_STR
       VNC_CONFIG_STR
       "Redistribute from other protocol\n"
       "Assign a NVE group to routes redistributed from another routing protocol\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	VNC_VTY_CONFIG_CHECK(bgp);

	vnc_redistribute_prechange(bgp);

	bgp->rfapi_cfg->rfg_redist = NULL;
	XFREE(MTYPE_RFAPI_GROUP_CFG, bgp->rfapi_cfg->rfg_redist_name);

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}


DEFUN (vnc_redistribute_lifetime,
       vnc_redistribute_lifetime_cmd,
       "vnc redistribute lifetime <LIFETIME|infinite>",
       VNC_CONFIG_STR
       "Redistribute\n"
       "Assign a lifetime to routes redistributed from another routing protocol\n"
       "lifetime value (32 bit)\n"
       "Allow lifetime to never expire\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VNC_VTY_CONFIG_CHECK(bgp);

	vnc_redistribute_prechange(bgp);

	if (strmatch(argv[3]->text, "infinite")) {
		bgp->rfapi_cfg->redist_lifetime = RFAPI_INFINITE_LIFETIME;
	} else {
		bgp->rfapi_cfg->redist_lifetime =
			strtoul(argv[3]->arg, NULL, 10);
	}

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

/*-- redist policy, non-nvegroup start --*/

DEFUN (vnc_redist_bgpdirect_no_prefixlist,
       vnc_redist_bgpdirect_no_prefixlist_cmd,
       "no vnc redistribute <bgp-direct|bgp-direct-to-nve-groups> <ipv4|ipv6> prefix-list",
       NO_STR
       VNC_CONFIG_STR
       "Redistribute from other protocol\n"
       "Redistribute from BGP directly\n"
       "Redistribute from BGP without Zebra, only to configured NVE groups\n"
       "IPv4 routes\n"
       "IPv6 routes\n" "Prefix-list for filtering redistributed routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi;
	struct rfapi_cfg *hc;
	uint8_t route_type = 0;

	VNC_VTY_CONFIG_CHECK(bgp);
	hc = bgp->rfapi_cfg;

	if (strmatch(argv[3]->text, "bgp-direct")) {
		route_type = ZEBRA_ROUTE_BGP_DIRECT;
	} else {
		route_type = ZEBRA_ROUTE_BGP_DIRECT_EXT;
	}

	if (strmatch(argv[4]->text, "ipv4")) {
		afi = AFI_IP;
	} else {
		afi = AFI_IP6;
	}

	vnc_redistribute_prechange(bgp);

	XFREE(MTYPE_RFAPI_GROUP_CFG, hc->plist_redist_name[route_type][afi]);
	hc->plist_redist[route_type][afi] = NULL;

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

DEFUN (vnc_redist_bgpdirect_prefixlist,
       vnc_redist_bgpdirect_prefixlist_cmd,
       "vnc redistribute <bgp-direct|bgp-direct-to-nve-groups> <ipv4|ipv6> prefix-list NAME",
       VNC_CONFIG_STR
       "Redistribute from other protocol\n"
       "Redistribute from BGP directly\n"
       "Redistribute from BGP without Zebra, only to configured NVE groups\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "Prefix-list for filtering redistributed routes\n"
       "prefix list name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct rfapi_cfg *hc;
	afi_t afi;
	uint8_t route_type = 0;

	VNC_VTY_CONFIG_CHECK(bgp);
	hc = bgp->rfapi_cfg;

	if (strmatch(argv[2]->text, "bgp-direct")) {
		route_type = ZEBRA_ROUTE_BGP_DIRECT;
	} else {
		route_type = ZEBRA_ROUTE_BGP_DIRECT_EXT;
	}

	if (strmatch(argv[3]->text, "ipv4")) {
		afi = AFI_IP;
	} else {
		afi = AFI_IP6;
	}

	vnc_redistribute_prechange(bgp);

	XFREE(MTYPE_RFAPI_GROUP_CFG, hc->plist_redist_name[route_type][afi]);
	hc->plist_redist_name[route_type][afi] = XSTRDUP(MTYPE_RFAPI_GROUP_CFG,
							 argv[5]->arg);
	hc->plist_redist[route_type][afi] =
		prefix_list_lookup(afi, argv[5]->arg);

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

DEFUN (vnc_redist_bgpdirect_no_routemap,
       vnc_redist_bgpdirect_no_routemap_cmd,
       "no vnc redistribute <bgp-direct|bgp-direct-to-nve-groups> route-map",
       NO_STR
       VNC_CONFIG_STR
       "Redistribute from other protocols\n"
       "Redistribute from BGP directly\n"
       "Redistribute from BGP without Zebra, only to configured NVE groups\n"
       "Route-map for filtering redistributed routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct rfapi_cfg *hc;
	uint8_t route_type = 0;

	VNC_VTY_CONFIG_CHECK(bgp);
	hc = bgp->rfapi_cfg;

	if (strmatch(argv[3]->text, "bgp-direct")) {
		route_type = ZEBRA_ROUTE_BGP_DIRECT;
	} else {
		route_type = ZEBRA_ROUTE_BGP_DIRECT_EXT;
	}

	vnc_redistribute_prechange(bgp);

	XFREE(MTYPE_RFAPI_GROUP_CFG, hc->routemap_redist_name[route_type]);
	hc->routemap_redist[route_type] = NULL;

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

DEFUN (vnc_redist_bgpdirect_routemap,
       vnc_redist_bgpdirect_routemap_cmd,
       "vnc redistribute <bgp-direct|bgp-direct-to-nve-groups> route-map NAME",
       VNC_CONFIG_STR
       "Redistribute from other protocols\n"
       "Redistribute from BGP directly\n"
       "Redistribute from BGP without Zebra, only to configured NVE groups\n"
       "Route-map for filtering exported routes\n" "route map name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct rfapi_cfg *hc;
	uint8_t route_type = 0;

	VNC_VTY_CONFIG_CHECK(bgp);
	hc = bgp->rfapi_cfg;

	if (strmatch(argv[2]->text, "bgp-direct")) {
		route_type = ZEBRA_ROUTE_BGP_DIRECT;
	} else {
		route_type = ZEBRA_ROUTE_BGP_DIRECT_EXT;
	}

	vnc_redistribute_prechange(bgp);

	XFREE(MTYPE_RFAPI_GROUP_CFG, hc->routemap_redist_name[route_type]);

	/* If the old route map config overwrite with new
	 * route map config , old routemap counter have to be
	 * reduced.
	 */
	route_map_counter_decrement(hc->routemap_redist[route_type]);
	hc->routemap_redist_name[route_type] = XSTRDUP(MTYPE_RFAPI_GROUP_CFG,
						       argv[4]->arg);

	hc->routemap_redist[route_type] =
		route_map_lookup_by_name(argv[4]->arg);
	route_map_counter_increment(hc->routemap_redist[route_type]);

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

/*-- redist policy, non-nvegroup end --*/

/*-- redist policy, nvegroup start --*/

DEFUN (vnc_nve_group_redist_bgpdirect_no_prefixlist,
       vnc_nve_group_redist_bgpdirect_no_prefixlist_cmd,
       "no redistribute bgp-direct <ipv4|ipv6> prefix-list",
       NO_STR
       "Redistribute from other protocol\n"
       "Redistribute from BGP directly\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "Prefix-list for filtering redistributed routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg)
	afi_t afi;

	VNC_VTY_CONFIG_CHECK(bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (strmatch(argv[3]->text, "ipv4")) {
		afi = AFI_IP;
	} else {
		afi = AFI_IP6;
	}

	vnc_redistribute_prechange(bgp);

	XFREE(MTYPE_RFAPI_GROUP_CFG,
	      rfg->plist_redist_name[ZEBRA_ROUTE_BGP_DIRECT][afi]);
	rfg->plist_redist[ZEBRA_ROUTE_BGP_DIRECT][afi] = NULL;

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

DEFUN (vnc_nve_group_redist_bgpdirect_prefixlist,
       vnc_nve_group_redist_bgpdirect_prefixlist_cmd,
       "redistribute bgp-direct <ipv4|ipv6> prefix-list NAME",
       "Redistribute from other protocol\n"
       "Redistribute from BGP directly\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "Prefix-list for filtering redistributed routes\n"
       "prefix list name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	afi_t afi;

	VNC_VTY_CONFIG_CHECK(bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (strmatch(argv[2]->text, "ipv4")) {
		afi = AFI_IP;
	} else {
		afi = AFI_IP6;
	}

	vnc_redistribute_prechange(bgp);

	XFREE(MTYPE_RFAPI_GROUP_CFG,
	      rfg->plist_redist_name[ZEBRA_ROUTE_BGP_DIRECT][afi]);
	rfg->plist_redist_name[ZEBRA_ROUTE_BGP_DIRECT][afi] =
		XSTRDUP(MTYPE_RFAPI_GROUP_CFG, argv[4]->arg);
	rfg->plist_redist[ZEBRA_ROUTE_BGP_DIRECT][afi] =
		prefix_list_lookup(afi, argv[4]->arg);

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

DEFUN (vnc_nve_group_redist_bgpdirect_no_routemap,
       vnc_nve_group_redist_bgpdirect_no_routemap_cmd,
       "no redistribute bgp-direct route-map",
       NO_STR
       "Redistribute from other protocols\n"
       "Redistribute from BGP directly\n"
       "Route-map for filtering redistributed routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);

	VNC_VTY_CONFIG_CHECK(bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	vnc_redistribute_prechange(bgp);

	XFREE(MTYPE_RFAPI_GROUP_CFG,
	      rfg->routemap_redist_name[ZEBRA_ROUTE_BGP_DIRECT]);
	route_map_counter_decrement(
		rfg->routemap_redist[ZEBRA_ROUTE_BGP_DIRECT]);
	rfg->routemap_redist[ZEBRA_ROUTE_BGP_DIRECT] = NULL;

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

DEFUN (vnc_nve_group_redist_bgpdirect_routemap,
       vnc_nve_group_redist_bgpdirect_routemap_cmd,
       "redistribute bgp-direct route-map NAME",
       "Redistribute from other protocols\n"
       "Redistribute from BGP directly\n"
       "Route-map for filtering exported routes\n" "route map name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);

	VNC_VTY_CONFIG_CHECK(bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	vnc_redistribute_prechange(bgp);

	XFREE(MTYPE_RFAPI_GROUP_CFG,
	      rfg->routemap_redist_name[ZEBRA_ROUTE_BGP_DIRECT]);
	route_map_counter_decrement(
		rfg->routemap_redist[ZEBRA_ROUTE_BGP_DIRECT]);
	rfg->routemap_redist_name[ZEBRA_ROUTE_BGP_DIRECT] =
		XSTRDUP(MTYPE_RFAPI_GROUP_CFG, argv[3]->arg);
	rfg->routemap_redist[ZEBRA_ROUTE_BGP_DIRECT] =
		route_map_lookup_by_name(argv[3]->arg);
	route_map_counter_increment(
		rfg->routemap_redist[ZEBRA_ROUTE_BGP_DIRECT]);

	vnc_redistribute_postchange(bgp);

	return CMD_SUCCESS;
}

/*-- redist policy, nvegroup end --*/

/*-------------------------------------------------------------------------
 *			export
 *-----------------------------------------------------------------------*/

DEFUN (vnc_export_mode,
       vnc_export_mode_cmd,
       "vnc export <bgp|zebra> mode <group-nve|ce|none|registering-nve>",
       VNC_CONFIG_STR
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "Select export mode\n"
       "Export routes with nve-group next-hops\n"
       "Export routes with NVE connected router next-hops\n"
       "Disable export\n" "Export routes with registering NVE as next-hop\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint32_t oldmode = 0;
	uint32_t newmode = 0;

	VNC_VTY_CONFIG_CHECK(bgp);

	if (argv[2]->arg[0] == 'b') {
		oldmode = bgp->rfapi_cfg->flags
			  & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS;
		switch (argv[4]->arg[0]) {
		case 'g':
			newmode = BGP_VNC_CONFIG_EXPORT_BGP_MODE_GRP;
			break;
		case 'c':
			newmode = BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE;
			break;
		case 'n':
			newmode = 0;
			break;
		case 'r':
			newmode = BGP_VNC_CONFIG_EXPORT_BGP_MODE_RH;
			break;
		default:
			vty_out(vty, "Invalid mode specified\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (newmode == oldmode) {
			vty_out(vty, "Mode unchanged\n");
			return CMD_SUCCESS;
		}

		vnc_export_bgp_prechange(bgp);

		bgp->rfapi_cfg->flags &= ~BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS;
		bgp->rfapi_cfg->flags |= newmode;

		vnc_export_bgp_postchange(bgp);


	} else {
		/*
		 * export to zebra with RH mode is not yet implemented
		 */
		vty_out(vty,
			"Changing modes for zebra export not implemented yet\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

static struct rfapi_rfg_name *rfgn_new(void)
{
	return XCALLOC(MTYPE_RFAPI_RFG_NAME, sizeof(struct rfapi_rfg_name));
}

static void rfgn_free(struct rfapi_rfg_name *rfgn)
{
	XFREE(MTYPE_RFAPI_RFG_NAME, rfgn);
}

DEFUN (vnc_export_nvegroup,
       vnc_export_nvegroup_cmd,
       "vnc export <bgp|zebra> group-nve group NAME",
       VNC_CONFIG_STR
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "NVE group, used in 'group-nve' export mode\n"
       "NVE group\n" "Group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct rfapi_nve_group_cfg *rfg_new;

	VNC_VTY_CONFIG_CHECK(bgp);

	rfg_new = bgp_rfapi_cfg_match_byname(bgp, argv[5]->arg,
					     RFAPI_GROUP_CFG_NVE);
	if (rfg_new == NULL) {
		rfg_new = bgp_rfapi_cfg_match_byname(bgp, argv[5]->arg,
						     RFAPI_GROUP_CFG_VRF);
		if (rfg_new)
			vnc_add_vrf_opener(bgp, rfg_new);
	}

	if (rfg_new == NULL) {
		vty_out(vty, "Can't find group named \"%s\".\n", argv[5]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv[2]->arg[0] == 'b') {

		struct listnode *node;
		struct rfapi_rfg_name *rfgn;

		/*
		 * Set group for export to BGP Direct
		 */

		/* see if group is already included in export list */
		for (ALL_LIST_ELEMENTS_RO(
			     bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
			     rfgn)) {

			if (!strcmp(rfgn->name, argv[5]->arg)) {
				/* already in the list: we're done */
				return CMD_SUCCESS;
			}
		}

		rfgn = rfgn_new();
		rfgn->name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, argv[5]->arg);
		rfgn->rfg = rfg_new; /* OK if not set yet */

		listnode_add(bgp->rfapi_cfg->rfg_export_direct_bgp_l, rfgn);

		vnc_zlog_debug_verbose("%s: testing rfg_new", __func__);
		if (rfg_new) {
			vnc_zlog_debug_verbose(
				"%s: testing bgp grp mode enabled", __func__);
			if (VNC_EXPORT_BGP_GRP_ENABLED(bgp->rfapi_cfg))
				vnc_zlog_debug_verbose(
					"%s: calling vnc_direct_bgp_add_group",
					__func__);
			vnc_direct_bgp_add_group(bgp, rfg_new);
		}

	} else {

		struct listnode *node;
		struct rfapi_rfg_name *rfgn;

		/*
		 * Set group for export to Zebra
		 */

		/* see if group is already included in export list */
		for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_zebra_l,
					  node, rfgn)) {

			if (!strcmp(rfgn->name, argv[5]->arg)) {
				/* already in the list: we're done */
				return CMD_SUCCESS;
			}
		}

		rfgn = rfgn_new();
		rfgn->name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, argv[5]->arg);
		rfgn->rfg = rfg_new; /* OK if not set yet */

		listnode_add(bgp->rfapi_cfg->rfg_export_zebra_l, rfgn);

		if (rfg_new) {
			if (VNC_EXPORT_ZEBRA_GRP_ENABLED(bgp->rfapi_cfg))
				vnc_zebra_add_group(bgp, rfg_new);
		}
	}

	return CMD_SUCCESS;
}

/*
 * This command applies to routes exported from VNC to BGP directly
 * without going though zebra
 */
DEFUN (vnc_no_export_nvegroup,
       vnc_no_export_nvegroup_cmd,
       "vnc export <bgp|zebra> group-nve no group NAME",
       VNC_CONFIG_STR
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "NVE group, used in 'group-nve' export mode\n"
       "Disable export of VNC routes\n" "NVE group\n" "Group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct listnode *node, *nnode;
	struct rfapi_rfg_name *rfgn;

	VNC_VTY_CONFIG_CHECK(bgp);

	if (argv[2]->arg[0] == 'b') {
		for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_direct_bgp_l,
				       node, nnode, rfgn)) {

			if (rfgn->name && !strcmp(rfgn->name, argv[6]->arg)) {
				vnc_zlog_debug_verbose("%s: matched \"%s\"",
						       __func__, rfgn->name);
				if (rfgn->rfg)
					vnc_direct_bgp_del_group(bgp,
								 rfgn->rfg);
				XFREE(MTYPE_RFAPI_GROUP_CFG, rfgn->name);
				list_delete_node(
					bgp->rfapi_cfg->rfg_export_direct_bgp_l,
					node);
				rfgn_free(rfgn);
				break;
			}
		}
	} else {
		for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_zebra_l, node,
				       nnode, rfgn)) {

			vnc_zlog_debug_verbose("does rfg \"%s\" match?",
					       rfgn->name);
			if (rfgn->name && !strcmp(rfgn->name, argv[6]->arg)) {
				if (rfgn->rfg)
					vnc_zebra_del_group(bgp, rfgn->rfg);
				XFREE(MTYPE_RFAPI_GROUP_CFG, rfgn->name);
				list_delete_node(
					bgp->rfapi_cfg->rfg_export_zebra_l,
					node);
				rfgn_free(rfgn);
				break;
			}
		}
	}
	return CMD_SUCCESS;
}

DEFUN (vnc_nve_group_export_no_prefixlist,
       vnc_nve_group_export_no_prefixlist_cmd,
       "no export <bgp|zebra> <ipv4|ipv6> prefix-list [NAME]",
       NO_STR
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "Prefix-list for filtering exported routes\n" "prefix list name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	int idx = 0;
	int is_bgp = 1;
	afi_t afi;

	VNC_VTY_CONFIG_CHECK(bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		vty_out(vty, "%% Malformed Address Family\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv[idx - 1]->text[0] == 'z')
		is_bgp = 0;
	idx += 2; /* skip afi and keyword */

	if (is_bgp) {
		if (idx == argc
		    || (rfg->plist_export_bgp_name[afi]
			&& strmatch(argv[idx]->arg,
				    rfg->plist_export_bgp_name[afi]))) {
			if (rfg->plist_export_bgp_name[afi])
				free(rfg->plist_export_bgp_name[afi]);
			rfg->plist_export_bgp_name[afi] = NULL;
			rfg->plist_export_bgp[afi] = NULL;

			vnc_direct_bgp_reexport_group_afi(bgp, rfg, afi);
		}
	} else {
		if (idx == argc
		    || (rfg->plist_export_zebra_name[afi]
			&& strmatch(argv[idx]->arg,
				    rfg->plist_export_zebra_name[afi]))) {
			XFREE(MTYPE_RFAPI_GROUP_CFG,
			      rfg->plist_export_zebra_name[afi]);
			rfg->plist_export_zebra[afi] = NULL;

			vnc_zebra_reexport_group_afi(bgp, rfg, afi);
		}
	}
	return CMD_SUCCESS;
}

ALIAS (vnc_nve_group_export_no_prefixlist,
       vnc_vrf_policy_export_no_prefixlist_cmd,
       "no export <ipv4|ipv6> prefix-list [NAME]",
       NO_STR
       "Export to VRF\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "Prefix-list for filtering exported routes\n" "prefix list name\n")

DEFUN (vnc_nve_group_export_prefixlist,
       vnc_nve_group_export_prefixlist_cmd,
       "export <bgp|zebra> <ipv4|ipv6> prefix-list NAME",
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "Prefix-list for filtering exported routes\n" "prefix list name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	int idx = 0;
	int is_bgp = 1;
	afi_t afi;

	VNC_VTY_CONFIG_CHECK(bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		vty_out(vty, "%% Malformed Address Family\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv[idx - 1]->text[0] == 'z')
		is_bgp = 0;
	idx = argc - 1;

	if (is_bgp) {
		XFREE(MTYPE_RFAPI_GROUP_CFG, rfg->plist_export_bgp_name[afi]);
		rfg->plist_export_bgp_name[afi] = XSTRDUP(MTYPE_RFAPI_GROUP_CFG,
							  argv[idx]->arg);
		rfg->plist_export_bgp[afi] =
			prefix_list_lookup(afi, argv[idx]->arg);

		vnc_direct_bgp_reexport_group_afi(bgp, rfg, afi);

	} else {
		XFREE(MTYPE_RFAPI_GROUP_CFG, rfg->plist_export_zebra_name[afi]);
		rfg->plist_export_zebra_name[afi] =
			XSTRDUP(MTYPE_RFAPI_GROUP_CFG, argv[idx]->arg);
		rfg->plist_export_zebra[afi] =
			prefix_list_lookup(afi, argv[idx]->arg);

		vnc_zebra_reexport_group_afi(bgp, rfg, afi);
	}
	return CMD_SUCCESS;
}

ALIAS (vnc_nve_group_export_prefixlist,
       vnc_vrf_policy_export_prefixlist_cmd,
       "export <ipv4|ipv6> prefix-list NAME",
       "Export to VRF\n"
       "IPv4 routes\n"
       "IPv6 routes\n"
       "Prefix-list for filtering exported routes\n" "prefix list name\n")

DEFUN (vnc_nve_group_export_no_routemap,
       vnc_nve_group_export_no_routemap_cmd,
       "no export <bgp|zebra> route-map [NAME]",
       NO_STR
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "Route-map for filtering exported routes\n" "route map name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	int idx = 2;
	int is_bgp = 1;

	VNC_VTY_CONFIG_CHECK(bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	switch (argv[idx]->text[0]) {
	case 'z':
		is_bgp = 0;
		idx += 2;
		break;
	case 'b':
		idx += 2;
		break;
	default: /* route-map */
		idx++;
		break;
	}

	if (is_bgp) {
		if (idx == argc
		    || (rfg->routemap_export_bgp_name
			&& strmatch(argv[idx]->arg,
				    rfg->routemap_export_bgp_name))) {
			XFREE(MTYPE_RFAPI_GROUP_CFG,
			      rfg->routemap_export_bgp_name);
			route_map_counter_decrement(rfg->routemap_export_bgp);
			rfg->routemap_export_bgp = NULL;

			vnc_direct_bgp_reexport_group_afi(bgp, rfg, AFI_IP);
			vnc_direct_bgp_reexport_group_afi(bgp, rfg, AFI_IP6);
		}
	} else {
		if (idx == argc
		    || (rfg->routemap_export_zebra_name
			&& strmatch(argv[idx]->arg,
				    rfg->routemap_export_zebra_name))) {
			XFREE(MTYPE_RFAPI_GROUP_CFG, rfg->routemap_export_zebra_name);
			route_map_counter_decrement(rfg->routemap_export_zebra);
			rfg->routemap_export_zebra = NULL;

			vnc_zebra_reexport_group_afi(bgp, rfg, AFI_IP);
			vnc_zebra_reexport_group_afi(bgp, rfg, AFI_IP6);
		}
	}
	return CMD_SUCCESS;
}

ALIAS (vnc_nve_group_export_no_routemap,
       vnc_vrf_policy_export_no_routemap_cmd,
       "no export route-map [NAME]",
       NO_STR
       "Export to VRF\n"
       "Route-map for filtering exported routes\n" "route map name\n")

DEFUN (vnc_nve_group_export_routemap,
       vnc_nve_group_export_routemap_cmd,
       "export <bgp|zebra> route-map NAME",
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "Route-map for filtering exported routes\n" "route map name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	int idx = 0;
	int is_bgp = 1;

	VNC_VTY_CONFIG_CHECK(bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv[1]->text[0] == 'z')
		is_bgp = 0;
	idx = argc - 1;

	if (is_bgp) {
		XFREE(MTYPE_RFAPI_GROUP_CFG, rfg->routemap_export_bgp_name);
		route_map_counter_decrement(rfg->routemap_export_bgp);
		rfg->routemap_export_bgp_name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG,
							argv[idx]->arg);
		rfg->routemap_export_bgp =
			route_map_lookup_by_name(argv[idx]->arg);
		route_map_counter_increment(rfg->routemap_export_bgp);
		vnc_direct_bgp_reexport_group_afi(bgp, rfg, AFI_IP);
		vnc_direct_bgp_reexport_group_afi(bgp, rfg, AFI_IP6);
	} else {
		XFREE(MTYPE_RFAPI_GROUP_CFG, rfg->routemap_export_zebra_name);
		route_map_counter_decrement(rfg->routemap_export_zebra);
		rfg->routemap_export_zebra_name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG,
							  argv[idx]->arg);
		rfg->routemap_export_zebra =
			route_map_lookup_by_name(argv[idx]->arg);
		route_map_counter_increment(rfg->routemap_export_zebra);
		vnc_zebra_reexport_group_afi(bgp, rfg, AFI_IP);
		vnc_zebra_reexport_group_afi(bgp, rfg, AFI_IP6);
	}
	return CMD_SUCCESS;
}

ALIAS (vnc_nve_group_export_routemap,
       vnc_vrf_policy_export_routemap_cmd,
       "export route-map NAME",
       "Export to VRF\n"
       "Route-map for filtering exported routes\n" "route map name\n")

DEFUN (vnc_nve_export_no_prefixlist,
       vnc_nve_export_no_prefixlist_cmd,
       "no vnc export <bgp|zebra> <ipv4|ipv6> prefix-list [NAME]",
       NO_STR
       VNC_CONFIG_STR
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "IPv4 prefixes\n"
       "IPv6 prefixes\n"
       "Prefix-list for filtering exported routes\n" "Prefix list name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct rfapi_cfg *hc;
	afi_t afi;

	VNC_VTY_CONFIG_CHECK(bgp);
	hc = bgp->rfapi_cfg;

	if (strmatch(argv[4]->text, "ipv4")) {
		afi = AFI_IP;
	} else {
		afi = AFI_IP6;
	}

	if (argv[3]->arg[0] == 'b') {
		if (((argc > 6) && hc->plist_export_bgp_name[afi]
		     && strmatch(argv[6]->text, hc->plist_export_bgp_name[afi]))
		    || (argc <= 6)) {
			XFREE(MTYPE_RFAPI_GROUP_CFG,
			      hc->plist_export_bgp_name[afi]);
			hc->plist_export_bgp[afi] = NULL;
			vnc_direct_bgp_reexport(bgp, afi);
		}
	} else {
		if (((argc > 6) && hc->plist_export_zebra_name[afi]
		     && strmatch(argv[6]->text,
				 hc->plist_export_zebra_name[afi]))
		    || (argc <= 6)) {
			XFREE(MTYPE_RFAPI_GROUP_CFG,
			      hc->plist_export_zebra_name[afi]);
			hc->plist_export_zebra[afi] = NULL;
			/* TBD vnc_zebra_rh_reexport(bgp, afi); */
		}
	}
	return CMD_SUCCESS;
}

DEFUN (vnc_nve_export_prefixlist,
       vnc_nve_export_prefixlist_cmd,
       "vnc export <bgp|zebra> <ipv4|ipv6> prefix-list NAME",
       VNC_CONFIG_STR
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "IPv4 prefixes\n"
       "IPv6 prefixes\n"
       "Prefix-list for filtering exported routes\n" "Prefix list name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct rfapi_cfg *hc;
	afi_t afi;

	VNC_VTY_CONFIG_CHECK(bgp);
	hc = bgp->rfapi_cfg;

	if (strmatch(argv[3]->text, "ipv4")) {
		afi = AFI_IP;
	} else {
		afi = AFI_IP6;
	}

	if (argv[2]->arg[0] == 'b') {
		XFREE(MTYPE_RFAPI_GROUP_CFG, hc->plist_export_bgp_name[afi]);
		hc->plist_export_bgp_name[afi] = XSTRDUP(MTYPE_RFAPI_GROUP_CFG,
							 argv[5]->arg);
		hc->plist_export_bgp[afi] =
			prefix_list_lookup(afi, argv[5]->arg);
		vnc_direct_bgp_reexport(bgp, afi);
	} else {
		XFREE(MTYPE_RFAPI_GROUP_CFG, hc->plist_export_zebra_name[afi]);
		hc->plist_export_zebra_name[afi] =
			XSTRDUP(MTYPE_RFAPI_GROUP_CFG, argv[5]->arg);
		hc->plist_export_zebra[afi] =
			prefix_list_lookup(afi, argv[5]->arg);
		/* TBD vnc_zebra_rh_reexport(bgp, afi); */
	}
	return CMD_SUCCESS;
}

DEFUN (vnc_nve_export_no_routemap,
       vnc_nve_export_no_routemap_cmd,
       "no vnc export <bgp|zebra> route-map [NAME]",
       NO_STR
       VNC_CONFIG_STR
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "Route-map for filtering exported routes\n" "Route map name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct rfapi_cfg *hc;

	VNC_VTY_CONFIG_CHECK(bgp);
	hc = bgp->rfapi_cfg;

	if (argv[3]->arg[0] == 'b') {
		if (((argc > 5) && hc->routemap_export_bgp_name
		     && strmatch(argv[5]->text, hc->routemap_export_bgp_name))
		    || (argc <= 5)) {
			XFREE(MTYPE_RFAPI_GROUP_CFG,
			      hc->routemap_export_bgp_name);
			route_map_counter_decrement(hc->routemap_export_bgp);
			hc->routemap_export_bgp = NULL;
			vnc_direct_bgp_reexport(bgp, AFI_IP);
			vnc_direct_bgp_reexport(bgp, AFI_IP6);
		}
	} else {
		if (((argc > 5) && hc->routemap_export_zebra_name
		     && strmatch(argv[5]->text, hc->routemap_export_zebra_name))
		    || (argc <= 5)) {

			XFREE(MTYPE_RFAPI_GROUP_CFG, hc->routemap_export_zebra_name);
			route_map_counter_decrement(hc->routemap_export_zebra);
			hc->routemap_export_zebra = NULL;
			/* TBD vnc_zebra_rh_reexport(bgp, AFI_IP); */
			/* TBD vnc_zebra_rh_reexport(bgp, AFI_IP6); */
		}
	}
	return CMD_SUCCESS;
}

DEFUN (vnc_nve_export_routemap,
       vnc_nve_export_routemap_cmd,
       "vnc export <bgp|zebra> route-map NAME",
       VNC_CONFIG_STR
       "Export to other protocols\n"
       "Export to BGP\n"
       "Export to Zebra (experimental)\n"
       "Route-map for filtering exported routes\n" "Route map name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct rfapi_cfg *hc;

	VNC_VTY_CONFIG_CHECK(bgp);
	hc = bgp->rfapi_cfg;

	if (argv[2]->arg[0] == 'b') {
		XFREE(MTYPE_RFAPI_GROUP_CFG, hc->routemap_export_bgp_name);
		route_map_counter_decrement(hc->routemap_export_bgp);
		hc->routemap_export_bgp_name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG,
						       argv[4]->arg);
		hc->routemap_export_bgp =
			route_map_lookup_by_name(argv[4]->arg);
		route_map_counter_increment(hc->routemap_export_bgp);
		vnc_direct_bgp_reexport(bgp, AFI_IP);
		vnc_direct_bgp_reexport(bgp, AFI_IP6);
	} else {
		XFREE(MTYPE_RFAPI_GROUP_CFG, hc->routemap_export_zebra_name);
		route_map_counter_decrement(hc->routemap_export_zebra);
		hc->routemap_export_zebra_name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG,
							 argv[4]->arg);
		hc->routemap_export_zebra =
			route_map_lookup_by_name(argv[4]->arg);
		route_map_counter_increment(hc->routemap_export_zebra);
		/* TBD vnc_zebra_rh_reexport(bgp, AFI_IP); */
		/* TBD vnc_zebra_rh_reexport(bgp, AFI_IP6); */
	}
	return CMD_SUCCESS;
}


/*
 * respond to changes in the global prefix list configuration
 */
void vnc_prefix_list_update(struct bgp *bgp)
{
	afi_t afi;
	struct listnode *n;
	struct rfapi_nve_group_cfg *rfg;
	struct rfapi_cfg *hc;
	int i;

	if (!bgp) {
		vnc_zlog_debug_verbose("%s: No BGP process is configured",
				       __func__);
		return;
	}

	if (!(hc = bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose("%s: rfapi not configured", __func__);
		return;
	}

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		/*
		 * Loop over nve groups
		 */
		for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->nve_groups_sequential,
					  n, rfg)) {

			if (rfg->plist_export_bgp_name[afi]) {
				rfg->plist_export_bgp[afi] = prefix_list_lookup(
					afi, rfg->plist_export_bgp_name[afi]);
			}
			if (rfg->plist_export_zebra_name[afi]) {
				rfg->plist_export_zebra
					[afi] = prefix_list_lookup(
					afi, rfg->plist_export_zebra_name[afi]);
			}
			for (i = 0; i < ZEBRA_ROUTE_MAX; ++i) {
				if (rfg->plist_redist_name[i][afi]) {
					rfg->plist_redist
						[i][afi] = prefix_list_lookup(
						afi,
						rfg->plist_redist_name[i][afi]);
				}
			}

			vnc_direct_bgp_reexport_group_afi(bgp, rfg, afi);
			/* TBD vnc_zebra_reexport_group_afi(bgp, rfg, afi); */
		}

		/*
		 * RH config, too
		 */
		if (hc->plist_export_bgp_name[afi]) {
			hc->plist_export_bgp[afi] = prefix_list_lookup(
				afi, hc->plist_export_bgp_name[afi]);
		}
		if (hc->plist_export_zebra_name[afi]) {
			hc->plist_export_zebra[afi] = prefix_list_lookup(
				afi, hc->plist_export_zebra_name[afi]);
		}

		for (i = 0; i < ZEBRA_ROUTE_MAX; ++i) {
			if (hc->plist_redist_name[i][afi]) {
				hc->plist_redist[i][afi] = prefix_list_lookup(
					afi, hc->plist_redist_name[i][afi]);
			}
		}
	}

	vnc_direct_bgp_reexport(bgp, AFI_IP);
	vnc_direct_bgp_reexport(bgp, AFI_IP6);

	/* TBD vnc_zebra_rh_reexport(bgp, AFI_IP); */
	/* TBD vnc_zebra_rh_reexport(bgp, AFI_IP6); */

	vnc_redistribute_prechange(bgp);
	vnc_redistribute_postchange(bgp);
}

/*
 * respond to changes in the global route map configuration
 */
void vnc_routemap_update(struct bgp *bgp, const char *unused)
{
	struct listnode *n;
	struct rfapi_nve_group_cfg *rfg;
	struct rfapi_cfg *hc;
	int i;
	struct route_map *old = NULL;

	vnc_zlog_debug_verbose("%s(arg=%s)", __func__, unused);

	if (!bgp) {
		vnc_zlog_debug_verbose("%s: No BGP process is configured",
				       __func__);
		return;
	}

	if (!(hc = bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose("%s: rfapi not configured", __func__);
		return;
	}

	/*
	 * Loop over nve groups
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->nve_groups_sequential, n,
				  rfg)) {

		if (rfg->routemap_export_bgp_name) {
			old = rfg->routemap_export_bgp;
			rfg->routemap_export_bgp = route_map_lookup_by_name(
				rfg->routemap_export_bgp_name);
			/* old is NULL. i.e Route map creation event.
			 * So update applied_counter.
			 * If Old is not NULL, i.e It may be routemap
			 * updation or deletion.
			 * So no need to update the counter.
			 */
			if (!old)
				route_map_counter_increment(
					rfg->routemap_export_bgp);
		}
		if (rfg->routemap_export_zebra_name) {
			old = rfg->routemap_export_bgp;
			rfg->routemap_export_bgp = route_map_lookup_by_name(
				rfg->routemap_export_zebra_name);
			if (!old)
				route_map_counter_increment(
					rfg->routemap_export_bgp);
		}
		for (i = 0; i < ZEBRA_ROUTE_MAX; ++i) {
			if (rfg->routemap_redist_name[i]) {
				old = rfg->routemap_redist[i];
				rfg->routemap_redist[i] =
					route_map_lookup_by_name(
						rfg->routemap_redist_name[i]);
				if (!old)
					route_map_counter_increment(
						rfg->routemap_redist[i]);
			}
		}

		vnc_direct_bgp_reexport_group_afi(bgp, rfg, AFI_IP);
		vnc_direct_bgp_reexport_group_afi(bgp, rfg, AFI_IP6);
		/* TBD vnc_zebra_reexport_group_afi(bgp, rfg, afi); */
	}

	/*
	 * RH config, too
	 */
	if (hc->routemap_export_bgp_name) {
		old = hc->routemap_export_bgp;
		hc->routemap_export_bgp =
			route_map_lookup_by_name(hc->routemap_export_bgp_name);
		if (!old)
			route_map_counter_increment(hc->routemap_export_bgp);
	}
	if (hc->routemap_export_zebra_name) {
		old  = hc->routemap_export_bgp;
		hc->routemap_export_bgp = route_map_lookup_by_name(
			hc->routemap_export_zebra_name);
		if (!old)
			route_map_counter_increment(hc->routemap_export_bgp);
	}
	for (i = 0; i < ZEBRA_ROUTE_MAX; ++i) {
		if (hc->routemap_redist_name[i]) {
			old = hc->routemap_redist[i];
			hc->routemap_redist[i] = route_map_lookup_by_name(
				hc->routemap_redist_name[i]);
			if (!old)
				route_map_counter_increment(
					hc->routemap_redist[i]);
		}
	}

	vnc_direct_bgp_reexport(bgp, AFI_IP);
	vnc_direct_bgp_reexport(bgp, AFI_IP6);

	/* TBD vnc_zebra_rh_reexport(bgp, AFI_IP); */
	/* TBD vnc_zebra_rh_reexport(bgp, AFI_IP6); */

	vnc_redistribute_prechange(bgp);
	vnc_redistribute_postchange(bgp);

	vnc_zlog_debug_verbose("%s done", __func__);
}

/*-------------------------------------------------------------------------
 *			nve-group
 *-----------------------------------------------------------------------*/


DEFUN_NOSH (vnc_nve_group,
       vnc_nve_group_cmd,
       "vnc nve-group NAME",
       VNC_CONFIG_STR "Configure a NVE group\n" "Group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct rfapi_nve_group_cfg *rfg;
	struct listnode *node, *nnode;
	struct rfapi_rfg_name *rfgn;

	VNC_VTY_CONFIG_CHECK(bgp);

	/* Search for name */
	rfg = bgp_rfapi_cfg_match_byname(bgp, argv[2]->arg,
					 RFAPI_GROUP_CFG_NVE);

	if (!rfg) {
		rfg = rfapi_group_new(bgp, RFAPI_GROUP_CFG_NVE, argv[2]->arg);
		if (!rfg) {
			/* Error out of memory */
			vty_out(vty, "Can't allocate memory for NVE group\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* Copy defaults from struct rfapi_cfg */
		rfg->rd = bgp->rfapi_cfg->default_rd;
		if (bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_L2RD) {
			rfg->l2rd = bgp->rfapi_cfg->default_l2rd;
			rfg->flags |= RFAPI_RFG_L2RD;
		}
		rfg->rd = bgp->rfapi_cfg->default_rd;
		rfg->response_lifetime =
			bgp->rfapi_cfg->default_response_lifetime;

		if (bgp->rfapi_cfg->default_rt_export_list) {
			rfg->rt_export_list = ecommunity_dup(
				bgp->rfapi_cfg->default_rt_export_list);
		}

		if (bgp->rfapi_cfg->default_rt_import_list) {
			rfg->rt_import_list = ecommunity_dup(
				bgp->rfapi_cfg->default_rt_import_list);
			rfg->rfapi_import_table = rfapiImportTableRefAdd(
				bgp, rfg->rt_import_list, rfg);
		}

		/*
		 * If a redist nve group was named but the group was not
		 * defined,
		 * make the linkage now
		 */
		if (!bgp->rfapi_cfg->rfg_redist) {
			if (bgp->rfapi_cfg->rfg_redist_name
			    && !strcmp(bgp->rfapi_cfg->rfg_redist_name,
				       rfg->name)) {

				vnc_redistribute_prechange(bgp);
				bgp->rfapi_cfg->rfg_redist = rfg;
				vnc_redistribute_postchange(bgp);
			}
		}

		/*
		 * Same treatment for bgp-direct export group
		 */
		for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_direct_bgp_l,
				       node, nnode, rfgn)) {

			if (!strcmp(rfgn->name, rfg->name)) {
				rfgn->rfg = rfg;
				vnc_direct_bgp_add_group(bgp, rfg);
				break;
			}
		}

		/*
		 * Same treatment for zebra export group
		 */
		for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_zebra_l, node,
				       nnode, rfgn)) {

			vnc_zlog_debug_verbose(
				"%s: ezport zebra: checking if \"%s\" == \"%s\"",
				__func__, rfgn->name, rfg->name);
			if (!strcmp(rfgn->name, rfg->name)) {
				rfgn->rfg = rfg;
				vnc_zebra_add_group(bgp, rfg);
				break;
			}
		}
	}

	/*
	 * XXX subsequent calls will need to make sure this item is still
	 * in the linked list and has the same name
	 */
	VTY_PUSH_CONTEXT_SUB(BGP_VNC_NVE_GROUP_NODE, rfg);

	return CMD_SUCCESS;
}

static void bgp_rfapi_delete_nve_group(struct vty *vty, /* NULL = no output */
				       struct bgp *bgp,
				       struct rfapi_nve_group_cfg *rfg)
{
	struct list *orphaned_nves = NULL;
	struct listnode *node, *nnode;

	/*
	 * If there are currently-open NVEs that belong to this group,
	 * zero out their references to this group structure.
	 */
	if (rfg->nves) {
		struct rfapi_descriptor *rfd;
		orphaned_nves = list_new();
		while ((rfd = listnode_head(rfg->nves))) {
			rfd->rfg = NULL;
			listnode_delete(rfg->nves, rfd);
			listnode_add(orphaned_nves, rfd);
		}
		list_delete(&rfg->nves);
	}

	/* delete it */
	XFREE(MTYPE_RFAPI_GROUP_CFG, rfg->name);
	if (rfg->rfapi_import_table)
		rfapiImportTableRefDelByIt(bgp, rfg->rfapi_import_table);
	if (rfg->rt_import_list)
		ecommunity_free(&rfg->rt_import_list);
	if (rfg->rt_export_list)
		ecommunity_free(&rfg->rt_export_list);

	if (rfg->vn_node) {
		rfg->vn_node->info = NULL;
		agg_unlock_node(rfg->vn_node); /* frees */
	}
	if (rfg->un_node) {
		rfg->un_node->info = NULL;
		agg_unlock_node(rfg->un_node); /* frees */
	}
	if (rfg->rfp_cfg)
		XFREE(MTYPE_RFAPI_RFP_GROUP_CFG, rfg->rfp_cfg);
	listnode_delete(bgp->rfapi_cfg->nve_groups_sequential, rfg);

	QOBJ_UNREG(rfg);
	XFREE(MTYPE_RFAPI_GROUP_CFG, rfg);

	/*
	 * Attempt to reassign the orphaned nves to a new group. If
	 * a NVE can not be reassigned, its rfd->rfg will remain NULL
	 * and it will become a zombie until released by rfapi_close().
	 */
	if (orphaned_nves) {
		struct rfapi_descriptor *rfd;

		for (ALL_LIST_ELEMENTS(orphaned_nves, node, nnode, rfd)) {
			/*
			 * 1. rfapi_close() equivalent except:
			 *          a. don't free original descriptor
			 *          b. remember query list
			 *          c. remember advertised route list
			 * 2. rfapi_open() equivalent except:
			 *          a. reuse original descriptor
			 * 3. rfapi_register() on remembered advertised route
			 * list
			 * 4. rfapi_query on rememebred query list
			 */

			int rc;

			rc = rfapi_reopen(rfd, bgp);

			if (!rc) {
				list_delete_node(orphaned_nves, node);
				if (vty)
					vty_out(vty,
						"WARNING: reassigned NVE vn=");
				rfapiPrintRfapiIpAddr(vty, &rfd->vn_addr);
				if (vty)
					vty_out(vty, " un=");
				rfapiPrintRfapiIpAddr(vty, &rfd->un_addr);
				if (vty)
					vty_out(vty, " to new group \"%s\"\n",
						rfd->rfg->name);
			}
		}

		for (ALL_LIST_ELEMENTS_RO(orphaned_nves, node, rfd)) {
			if (vty)
				vty_out(vty, "WARNING: orphaned NVE vn=");
			rfapiPrintRfapiIpAddr(vty, &rfd->vn_addr);
			if (vty)
				vty_out(vty, " un=");
			rfapiPrintRfapiIpAddr(vty, &rfd->un_addr);
			if (vty)
				vty_out(vty, "\n");
		}
		list_delete(&orphaned_nves);
	}
}

static int
bgp_rfapi_delete_named_nve_group(struct vty *vty, /* NULL = no output */
				 struct bgp *bgp,
				 const char *rfg_name,	/* NULL = any */
				 rfapi_group_cfg_type_t type) /* _MAX = any */
{
	struct rfapi_nve_group_cfg *rfg = NULL;
	struct listnode *node, *nnode;
	struct rfapi_rfg_name *rfgn;

	/* Search for name */
	if (rfg_name) {
		rfg = bgp_rfapi_cfg_match_byname(bgp, rfg_name, type);
		if (!rfg) {
			if (vty)
				vty_out(vty, "No NVE group named \"%s\"\n",
					rfg_name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/*
	 * If this group is the redist nve group, unlink it
	 */
	if (rfg_name == NULL || bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
		bgp->rfapi_cfg->rfg_redist = NULL;
		vnc_redistribute_postchange(bgp);
	}


	/*
	 * remove reference from bgp direct export list
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
				  rfgn)) {
		if (rfgn->rfg == rfg) {
			rfgn->rfg = NULL;
			/* remove exported routes from this group */
			vnc_direct_bgp_del_group(bgp, rfg);
			break;
		}
	}

	/*
	 * remove reference from zebra export list
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_zebra_l, node,
				  rfgn)) {
		if (rfgn->rfg == rfg) {
			rfgn->rfg = NULL;
			/* remove exported routes from this group */
			vnc_zebra_del_group(bgp, rfg);
			break;
		}
	}
	if (rfg) {
		if (rfg->rfd)
			clear_vnc_vrf_closer(rfg);
		bgp_rfapi_delete_nve_group(vty, bgp, rfg);
	} else /* must be delete all */
		for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->nve_groups_sequential,
				       node, nnode, rfg)) {
			if (rfg->rfd)
				clear_vnc_vrf_closer(rfg);
			bgp_rfapi_delete_nve_group(vty, bgp, rfg);
		}
	return CMD_SUCCESS;
}

DEFUN (vnc_no_nve_group,
       vnc_no_nve_group_cmd,
       "no vnc nve-group NAME",
       NO_STR
       VNC_CONFIG_STR
       "Configure a NVE group\n"
       "Group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	return bgp_rfapi_delete_named_nve_group(vty, bgp, argv[3]->arg,
						RFAPI_GROUP_CFG_NVE);
}

DEFUN (vnc_nve_group_prefix,
       vnc_nve_group_prefix_cmd,
       "prefix <vn|un> <A.B.C.D/M|X:X::X:X/M>",
       "Specify prefixes matching NVE VN or UN interfaces\n"
       "VN prefix\n"
       "UN prefix\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	struct prefix p;
	afi_t afi;
	struct agg_table *rt;
	struct agg_node *rn;
	int is_un_prefix = 0;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!str2prefix(argv[2]->arg, &p)) {
		vty_out(vty, "Malformed prefix \"%s\"\n", argv[2]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	afi = family2afi(p.family);
	if (!afi) {
		vty_out(vty, "Unsupported address family\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv[1]->arg[0] == 'u') {
		rt = bgp->rfapi_cfg->nve_groups_un[afi];
		is_un_prefix = 1;
	} else {
		rt = bgp->rfapi_cfg->nve_groups_vn[afi];
	}

	rn = agg_node_get(rt, &p); /* NB locks node */
	if (rn->info) {
		/*
		 * There is already a group with this prefix
		 */
		agg_unlock_node(rn);
		if (rn->info != rfg) {
			/*
			 * different group name: fail
			 */
			vty_out(vty,
				"nve group \"%s\" already has \"%s\" prefix %s\n",
				((struct rfapi_nve_group_cfg *)(rn->info))
					->name,
				argv[1]->arg, argv[2]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		} else {
			/*
			 * same group name: it's already in the correct place
			 * in the table, so we're done.
			 *
			 * Implies rfg->(vn|un)_prefix is already correct.
			 */
			return CMD_SUCCESS;
		}
	}

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	/* New prefix, new node */

	if (is_un_prefix) {

		/* detach rfg from previous route table location */
		if (rfg->un_node) {
			rfg->un_node->info = NULL;
			agg_unlock_node(rfg->un_node); /* frees */
		}
		rfg->un_node = rn; /* back ref */
		rfg->un_prefix = p;

	} else {

		/* detach rfg from previous route table location */
		if (rfg->vn_node) {
			rfg->vn_node->info = NULL;
			agg_unlock_node(rfg->vn_node); /* frees */
		}
		rfg->vn_node = rn; /* back ref */
		rfg->vn_prefix = p;
	}

	/* attach */
	rn->info = rfg;

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}

	return CMD_SUCCESS;
}

DEFUN (vnc_nve_group_rt_import,
       vnc_nve_group_rt_import_cmd,
       "rt import RTLIST...",
       "Specify route targets\n"
       "Import filter\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	int rc;
	struct listnode *node;
	struct rfapi_rfg_name *rfgn;
	int is_export_bgp = 0;
	int is_export_zebra = 0;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rc = set_ecom_list(vty, argc - 2, argv + 2, &rfg->rt_import_list);
	if (rc != CMD_SUCCESS)
		return rc;

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
				  rfgn)) {

		if (rfgn->rfg == rfg) {
			is_export_bgp = 1;
			break;
		}
	}

	if (is_export_bgp)
		vnc_direct_bgp_del_group(bgp, rfg);

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_zebra_l, node,
				  rfgn)) {

		if (rfgn->rfg == rfg) {
			is_export_zebra = 1;
			break;
		}
	}

	if (is_export_zebra)
		vnc_zebra_del_group(bgp, rfg);

	/*
	 * stop referencing old import table, now reference new one
	 */
	if (rfg->rfapi_import_table)
		rfapiImportTableRefDelByIt(bgp, rfg->rfapi_import_table);
	rfg->rfapi_import_table =
		rfapiImportTableRefAdd(bgp, rfg->rt_import_list, rfg);

	if (is_export_bgp)
		vnc_direct_bgp_add_group(bgp, rfg);

	if (is_export_zebra)
		vnc_zebra_add_group(bgp, rfg);

	return CMD_SUCCESS;
}

DEFUN (vnc_nve_group_rt_export,
       vnc_nve_group_rt_export_cmd,
       "rt export RTLIST...",
       "Specify route targets\n"
       "Export filter\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	int rc;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	rc = set_ecom_list(vty, argc - 2, argv + 2, &rfg->rt_export_list);

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}

	return rc;
}

DEFUN (vnc_nve_group_rt_both,
       vnc_nve_group_rt_both_cmd,
       "rt both RTLIST...",
       "Specify route targets\n"
       "Export+import filters\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	int rc;
	int is_export_bgp = 0;
	int is_export_zebra = 0;
	struct listnode *node;
	struct rfapi_rfg_name *rfgn;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rc = set_ecom_list(vty, argc - 2, argv + 2, &rfg->rt_import_list);
	if (rc != CMD_SUCCESS)
		return rc;

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
				  rfgn)) {

		if (rfgn->rfg == rfg) {
			is_export_bgp = 1;
			break;
		}
	}

	if (is_export_bgp)
		vnc_direct_bgp_del_group(bgp, rfg);

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_zebra_l, node,
				  rfgn)) {

		if (rfgn->rfg == rfg) {
			is_export_zebra = 1;
			break;
		}
	}

	if (is_export_zebra) {
		vnc_zlog_debug_verbose("%s: is_export_zebra", __func__);
		vnc_zebra_del_group(bgp, rfg);
	}

	/*
	 * stop referencing old import table, now reference new one
	 */
	if (rfg->rfapi_import_table)
		rfapiImportTableRefDelByIt(bgp, rfg->rfapi_import_table);
	rfg->rfapi_import_table =
		rfapiImportTableRefAdd(bgp, rfg->rt_import_list, rfg);

	if (is_export_bgp)
		vnc_direct_bgp_add_group(bgp, rfg);

	if (is_export_zebra)
		vnc_zebra_add_group(bgp, rfg);

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	rc = set_ecom_list(vty, argc - 2, argv + 2, &rfg->rt_export_list);

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}

	return rc;
}

DEFUN (vnc_nve_group_l2rd,
       vnc_nve_group_l2rd_cmd,
       "l2rd <(1-255)|auto-vn>",
       "Specify default Local Nve ID value to use in RD for L2 routes\n"
       "Fixed value 1-255\n"
       "use the low-order octet of the NVE's VN address\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (strmatch(argv[1]->text, "auto:vn")) {
		rfg->l2rd = 0;
	} else {
		char *end = NULL;
		unsigned long value_l = strtoul(argv[1]->arg, &end, 10);
		uint8_t value = value_l & 0xff;

		if (!argv[1]->arg[0] || *end) {
			vty_out(vty, "%% Malformed l2 nve ID \"%s\"\n",
				argv[1]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if ((value_l < 1) || (value_l > 0xff)) {
			vty_out(vty,
				"%% Malformed l2 nve id (must be greater than 0 and less than %u\n",
				0x100);
			return CMD_WARNING_CONFIG_FAILED;
		}

		rfg->l2rd = value;
	}
	rfg->flags |= RFAPI_RFG_L2RD;

	return CMD_SUCCESS;
}

DEFUN (vnc_nve_group_no_l2rd,
       vnc_nve_group_no_l2rd_cmd,
       "no l2rd",
       NO_STR
       "Specify default Local Nve ID value to use in RD for L2 routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rfg->l2rd = 0;
	rfg->flags &= ~RFAPI_RFG_L2RD;

	return CMD_SUCCESS;
}

DEFUN (vnc_nve_group_rd,
       vnc_nve_group_rd_cmd,
       "rd ASN:NN_OR_IP-ADDRESS:NN",
       "Specify route distinguisher\n"
       "Route Distinguisher (<as-number>:<number> | <ip-address>:<number> | auto:vn:<number> )\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct prefix_rd prd;
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!strncmp(argv[1]->arg, "auto:vn:", 8)) {
		/*
		 * use AF_UNIX to designate automatically-assigned RD
		 * auto:vn:nn where nn is a 2-octet quantity
		 */
		char *end = NULL;
		uint32_t value32 = strtoul(argv[1]->arg + 8, &end, 10);
		uint16_t value = value32 & 0xffff;

		if (!argv[1]->arg[8] || *end) {
			vty_out(vty, "%% Malformed rd\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (value32 > 0xffff) {
			vty_out(vty, "%% Malformed rd (must be less than %u\n",
				0x0ffff);
			return CMD_WARNING_CONFIG_FAILED;
		}

		memset(&prd, 0, sizeof(prd));
		prd.family = AF_UNIX;
		prd.prefixlen = 64;
		prd.val[0] = (RD_TYPE_IP >> 8) & 0x0ff;
		prd.val[1] = RD_TYPE_IP & 0x0ff;
		prd.val[6] = (value >> 8) & 0x0ff;
		prd.val[7] = value & 0x0ff;

	} else {

		/* TODO: save RD format */
		ret = str2prefix_rd(argv[1]->arg, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed rd\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	rfg->rd = prd;

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}
	return CMD_SUCCESS;
}

DEFUN (vnc_nve_group_responselifetime,
       vnc_nve_group_responselifetime_cmd,
       "response-lifetime <LIFETIME|infinite>",
       "Specify response lifetime\n"
       "Response lifetime in seconds\n" "Infinite response lifetime\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	unsigned int rspint;
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	struct rfapi_descriptor *rfd;
	struct listnode *hdnode;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (strmatch(argv[1]->text, "infinite")) {
		rspint = RFAPI_INFINITE_LIFETIME;
	} else {
		rspint = strtoul(argv[1]->arg, NULL, 10);
	}

	rfg->response_lifetime = rspint;
	rfg->flags |= RFAPI_RFG_RESPONSE_LIFETIME;
	if (rfg->nves)
		for (ALL_LIST_ELEMENTS_RO(rfg->nves, hdnode, rfd))
			rfd->response_lifetime = rspint;
	return CMD_SUCCESS;
}

/*
 * Sigh. This command, like exit-address-family, is a hack to deal
 * with the lack of rigorous level control in the command handler.
 * TBD fix command handler.
 */
DEFUN_NOSH (exit_vnc,
       exit_vnc_cmd,
       "exit-vnc",
       "Exit VNC configuration mode\n")
{
	if (vty->node == BGP_VNC_DEFAULTS_NODE
	    || vty->node == BGP_VNC_NVE_GROUP_NODE
	    || vty->node == BGP_VNC_L2_GROUP_NODE) {

		vty->node = BGP_NODE;
	}
	return CMD_SUCCESS;
}

static struct cmd_node bgp_vnc_defaults_node = {
	.name = "bgp vnc defaults",
	.node = BGP_VNC_DEFAULTS_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-vnc-defaults)# ",
};

static struct cmd_node bgp_vnc_nve_group_node = {
	.name = "bgp vnc nve",
	.node = BGP_VNC_NVE_GROUP_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-vnc-nve-group)# ",
};

/*-------------------------------------------------------------------------
 *			VNC nve-group
 * Note there are two types of NVEs, one for VPNs one for RFP NVEs
 *-----------------------------------------------------------------------*/

DEFUN_NOSH (vnc_vrf_policy,
       vnc_vrf_policy_cmd,
       "vrf-policy NAME",
       "Configure a VRF policy group\n"
       "VRF name\n")
{
	struct rfapi_nve_group_cfg *rfg;
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF) {
		vty_out(vty,
			"Can't configure vrf-policy within a BGP VRF instance\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Search for name */
	rfg = bgp_rfapi_cfg_match_byname(bgp, argv[1]->arg,
					 RFAPI_GROUP_CFG_VRF);

	if (!rfg) {
		rfg = rfapi_group_new(bgp, RFAPI_GROUP_CFG_VRF, argv[1]->arg);
		if (!rfg) {
			/* Error out of memory */
			vty_out(vty, "Can't allocate memory for NVE group\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	/*
	 * XXX subsequent calls will need to make sure this item is still
	 * in the linked list and has the same name
	 */
	VTY_PUSH_CONTEXT_SUB(BGP_VRF_POLICY_NODE, rfg);

	return CMD_SUCCESS;
}

DEFUN (vnc_no_vrf_policy,
       vnc_no_vrf_policy_cmd,
       "no vrf-policy NAME",
       NO_STR
       "Remove a VRF policy group\n"
       "VRF name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* silently return */
	if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
		return CMD_SUCCESS;

	return bgp_rfapi_delete_named_nve_group(vty, bgp, argv[2]->arg,
						RFAPI_GROUP_CFG_VRF);
}

DEFUN (vnc_vrf_policy_label,
       vnc_vrf_policy_label_cmd,
       "label (0-1048575)",
       "Default label value for VRF\n"
       "Label Value <0-1048575>\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);

	uint32_t label;
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	label = strtoul(argv[1]->arg, NULL, 10);

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	rfg->label = label;

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}
	return CMD_SUCCESS;
}

DEFUN (vnc_vrf_policy_no_label,
       vnc_vrf_policy_no_label_cmd,
       "no label",
       NO_STR
       "Remove VRF default label\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current VRF group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	rfg->label = MPLS_LABEL_NONE;

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}
	return CMD_SUCCESS;
}

DEFUN (vnc_vrf_policy_nexthop,
       vnc_vrf_policy_nexthop_cmd,
       "nexthop <A.B.C.D|X:X::X:X|self>",
       "Specify next hop to use for VRF advertised prefixes\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "Use configured router-id (default)\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	struct prefix p;

	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current VRF no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	if (!str2prefix(argv[1]->arg, &p) && p.family) {
		// vty_out (vty, "Nexthop set to self\n");
		SET_FLAG(rfg->flags, RFAPI_RFG_VPN_NH_SELF);
		memset(&rfg->vn_prefix, 0, sizeof(struct prefix));
	} else {
		UNSET_FLAG(rfg->flags, RFAPI_RFG_VPN_NH_SELF);
		rfg->vn_prefix = p;
		rfg->un_prefix = p;
	}

	/* TBD handle router-id/ nexthop changes when have advertised prefixes
	 */

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}

	return CMD_SUCCESS;
}

/* The RT code should be refactored/simplified with above... */
DEFUN (vnc_vrf_policy_rt_import,
       vnc_vrf_policy_rt_import_cmd,
       "rt import RTLIST...",
       "Specify route targets\n"
       "Import filter\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int rc;
	struct listnode *node;
	struct rfapi_rfg_name *rfgn;
	int is_export_bgp = 0;
	int is_export_zebra = 0;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rc = set_ecom_list(vty, argc - 2, argv + 2, &rfg->rt_import_list);
	if (rc != CMD_SUCCESS)
		return rc;

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
				  rfgn)) {

		if (rfgn->rfg == rfg) {
			is_export_bgp = 1;
			break;
		}
	}

	if (is_export_bgp)
		vnc_direct_bgp_del_group(bgp, rfg);

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_zebra_l, node,
				  rfgn)) {

		if (rfgn->rfg == rfg) {
			is_export_zebra = 1;
			break;
		}
	}

	if (is_export_zebra)
		vnc_zebra_del_group(bgp, rfg);

	/*
	 * stop referencing old import table, now reference new one
	 */
	if (rfg->rfapi_import_table)
		rfapiImportTableRefDelByIt(bgp, rfg->rfapi_import_table);
	rfg->rfapi_import_table =
		rfapiImportTableRefAdd(bgp, rfg->rt_import_list, rfg);

	if (is_export_bgp)
		vnc_direct_bgp_add_group(bgp, rfg);

	if (is_export_zebra)
		vnc_zebra_add_group(bgp, rfg);

	return CMD_SUCCESS;
}

DEFUN (vnc_vrf_policy_rt_export,
       vnc_vrf_policy_rt_export_cmd,
       "rt export RTLIST...",
       "Specify route targets\n"
       "Export filter\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int rc;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	rc = set_ecom_list(vty, argc - 2, argv + 2, &rfg->rt_export_list);

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}

	return rc;
}

DEFUN (vnc_vrf_policy_rt_both,
       vnc_vrf_policy_rt_both_cmd,
       "rt both RTLIST...",
       "Specify route targets\n"
       "Export+import filters\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int rc;
	int is_export_bgp = 0;
	int is_export_zebra = 0;
	struct listnode *node;
	struct rfapi_rfg_name *rfgn;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rc = set_ecom_list(vty, argc - 2, argv + 2, &rfg->rt_import_list);
	if (rc != CMD_SUCCESS)
		return rc;

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
				  rfgn)) {

		if (rfgn->rfg == rfg) {
			is_export_bgp = 1;
			break;
		}
	}

	if (is_export_bgp)
		vnc_direct_bgp_del_group(bgp, rfg);

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_zebra_l, node,
				  rfgn)) {

		if (rfgn->rfg == rfg) {
			is_export_zebra = 1;
			break;
		}
	}

	if (is_export_zebra) {
		vnc_zlog_debug_verbose("%s: is_export_zebra", __func__);
		vnc_zebra_del_group(bgp, rfg);
	}

	/*
	 * stop referencing old import table, now reference new one
	 */
	if (rfg->rfapi_import_table)
		rfapiImportTableRefDelByIt(bgp, rfg->rfapi_import_table);
	rfg->rfapi_import_table =
		rfapiImportTableRefAdd(bgp, rfg->rt_import_list, rfg);

	if (is_export_bgp)
		vnc_direct_bgp_add_group(bgp, rfg);

	if (is_export_zebra)
		vnc_zebra_add_group(bgp, rfg);

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	rc = set_ecom_list(vty, argc - 2, argv + 2, &rfg->rt_export_list);

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}

	return rc;
}

DEFUN (vnc_vrf_policy_rd,
       vnc_vrf_policy_rd_cmd,
       "rd ASN:NN_OR_IP-ADDRESS:NN",
       "Specify default VRF route distinguisher\n"
       "Route Distinguisher (<as-number>:<number> | <ip-address>:<number> | auto:nh:<number> )\n")
{
	int ret;
	struct prefix_rd prd;
	VTY_DECLVAR_CONTEXT_SUB(rfapi_nve_group_cfg, rfg);
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->nve_groups_sequential, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current NVE group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!strncmp(argv[1]->arg, "auto:nh:", 8)) {
		/*
		 * use AF_UNIX to designate automatically-assigned RD
		 * auto:vn:nn where nn is a 2-octet quantity
		 */
		char *end = NULL;
		uint32_t value32 = strtoul(argv[1]->arg + 8, &end, 10);
		uint16_t value = value32 & 0xffff;

		if (!*(argv[1]->arg + 5) || *end) {
			vty_out(vty, "%% Malformed rd\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (value32 > 0xffff) {
			vty_out(vty, "%% Malformed rd (must be less than %u\n",
				0x0ffff);
			return CMD_WARNING_CONFIG_FAILED;
		}

		memset(&prd, 0, sizeof(prd));
		prd.family = AF_UNIX;
		prd.prefixlen = 64;
		prd.val[0] = (RD_TYPE_IP >> 8) & 0x0ff;
		prd.val[1] = RD_TYPE_IP & 0x0ff;
		prd.val[6] = (value >> 8) & 0x0ff;
		prd.val[7] = value & 0x0ff;

	} else {

		/* TODO: save RD format */
		ret = str2prefix_rd(argv[1]->arg, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed rd\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_prechange(bgp);
	}

	rfg->rd = prd;

	if (bgp->rfapi_cfg->rfg_redist == rfg) {
		vnc_redistribute_postchange(bgp);
	}
	return CMD_SUCCESS;
}

DEFUN_NOSH (exit_vrf_policy,
       exit_vrf_policy_cmd,
       "exit-vrf-policy",
       "Exit VRF policy configuration mode\n")
{
	if (vty->node == BGP_VRF_POLICY_NODE) {
		vty->node = BGP_NODE;
	}
	return CMD_SUCCESS;
}

static struct cmd_node bgp_vrf_policy_node = {
	.name = "bgp vrf policy",
	.node = BGP_VRF_POLICY_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-vrf-policy)# ",
};

/*-------------------------------------------------------------------------
 *			vnc-l2-group
 *-----------------------------------------------------------------------*/


DEFUN_NOSH (vnc_l2_group,
       vnc_l2_group_cmd,
       "vnc l2-group NAME",
       VNC_CONFIG_STR "Configure a L2 group\n" "Group name\n")
{
	struct rfapi_l2_group_cfg *rfg;
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	VNC_VTY_CONFIG_CHECK(bgp);

	/* Search for name */
	rfg = rfapi_l2_group_lookup_byname(bgp, argv[2]->arg);

	if (!rfg) {
		rfg = rfapi_l2_group_new();
		if (!rfg) {
			/* Error out of memory */
			vty_out(vty, "Can't allocate memory for L2 group\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		rfg->name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, argv[2]->arg);
		/* add to tail of list */
		listnode_add(bgp->rfapi_cfg->l2_groups, rfg);
	}

	/*
	 * XXX subsequent calls will need to make sure this item is still
	 * in the linked list and has the same name
	 */
	VTY_PUSH_CONTEXT_SUB(BGP_VNC_L2_GROUP_NODE, rfg);
	return CMD_SUCCESS;
}

static void bgp_rfapi_delete_l2_group(struct vty *vty, /* NULL = no output */
				      struct bgp *bgp,
				      struct rfapi_l2_group_cfg *rfg)
{
	/* delete it */
	XFREE(MTYPE_RFAPI_GROUP_CFG, rfg->name);
	if (rfg->rt_import_list)
		ecommunity_free(&rfg->rt_import_list);
	if (rfg->rt_export_list)
		ecommunity_free(&rfg->rt_export_list);
	if (rfg->labels)
		list_delete(&rfg->labels);
	XFREE(MTYPE_RFAPI_RFP_GROUP_CFG, rfg->rfp_cfg);
	listnode_delete(bgp->rfapi_cfg->l2_groups, rfg);

	rfapi_l2_group_del(rfg);
}

static int
bgp_rfapi_delete_named_l2_group(struct vty *vty, /* NULL = no output */
				struct bgp *bgp,
				const char *rfg_name) /* NULL = any */
{
	struct rfapi_l2_group_cfg *rfg = NULL;
	struct listnode *node, *nnode;

	/* Search for name */
	if (rfg_name) {
		rfg = rfapi_l2_group_lookup_byname(bgp, rfg_name);
		if (!rfg) {
			if (vty)
				vty_out(vty, "No L2 group named \"%s\"\n",
					rfg_name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (rfg)
		bgp_rfapi_delete_l2_group(vty, bgp, rfg);
	else /* must be delete all */
		for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->l2_groups, node, nnode,
				       rfg))
			bgp_rfapi_delete_l2_group(vty, bgp, rfg);
	return CMD_SUCCESS;
}

DEFUN (vnc_no_l2_group,
       vnc_no_l2_group_cmd,
       "no vnc l2-group NAME",
       NO_STR
       VNC_CONFIG_STR
       "Configure a L2 group\n"
       "Group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	return bgp_rfapi_delete_named_l2_group(vty, bgp, argv[3]->arg);
}


DEFUN (vnc_l2_group_lni,
       vnc_l2_group_lni_cmd,
       "logical-network-id (0-4294967295)",
       "Specify Logical Network ID associated with group\n"
       "value\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_l2_group_cfg, rfg);
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->l2_groups, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current L2 group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rfg->logical_net_id = strtoul(argv[1]->arg, NULL, 10);

	return CMD_SUCCESS;
}

DEFUN (vnc_l2_group_labels,
       vnc_l2_group_labels_cmd,
       "labels (0-1048575)...",
       "Specify label values associated with group\n"
       "Space separated list of label values <0-1048575>\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_l2_group_cfg, rfg);
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct list *ll;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->l2_groups, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current L2 group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ll = rfg->labels;
	if (ll == NULL) {
		ll = list_new();
		rfg->labels = ll;
	}
	argc--;
	argv++;
	for (; argc; --argc, ++argv) {
		uint32_t label;
		label = strtoul(argv[0]->arg, NULL, 10);
		if (!listnode_lookup(ll, (void *)(uintptr_t)label))
			listnode_add(ll, (void *)(uintptr_t)label);
	}

	return CMD_SUCCESS;
}

DEFUN (vnc_l2_group_no_labels,
       vnc_l2_group_no_labels_cmd,
       "no labels (0-1048575)...",
       NO_STR
       "Specify label values associated with L2 group\n"
       "Space separated list of label values <0-1048575>\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_l2_group_cfg, rfg);
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct list *ll;

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->l2_groups, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current L2 group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ll = rfg->labels;
	if (ll == NULL) {
		vty_out(vty, "Label no longer associated with group\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	argc -= 2;
	argv += 2;
	for (; argc; --argc, ++argv) {
		uint32_t label;
		label = strtoul(argv[0]->arg, NULL, 10);
		listnode_delete(ll, (void *)(uintptr_t)label);
	}

	return CMD_SUCCESS;
}

DEFUN (vnc_l2_group_rt,
       vnc_l2_group_rt_cmd,
       "rt <both|export|import> ASN:NN_OR_IP-ADDRESS:NN",
       "Specify route targets\n"
       "Export+import filters\n"
       "Export filters\n"
       "Import filters\n"
       "A route target\n")
{
	VTY_DECLVAR_CONTEXT_SUB(rfapi_l2_group_cfg, rfg);
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int rc = CMD_SUCCESS;
	int do_import = 0;
	int do_export = 0;

	switch (argv[1]->arg[0]) {
	case 'b':
		do_export = 1;
		do_import = 1;
		break;
	case 'i':
		do_import = 1;
		break;
	case 'e':
		do_export = 1;
		break;
	default:
		vty_out(vty, "Unknown option, %s\n", argv[1]->arg);
		return CMD_ERR_NO_MATCH;
	}

	/* make sure it's still in list */
	if (!listnode_lookup(bgp->rfapi_cfg->l2_groups, rfg)) {
		/* Not in list anymore */
		vty_out(vty, "Current L2 group no longer exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (do_import)
		rc = set_ecom_list(vty, argc - 2, argv + 2,
				   &rfg->rt_import_list);
	if (rc == CMD_SUCCESS && do_export)
		rc = set_ecom_list(vty, argc - 2, argv + 2,
				   &rfg->rt_export_list);
	return rc;
}


static struct cmd_node bgp_vnc_l2_group_node = {
	.name = "bgp vnc l2",
	.node = BGP_VNC_L2_GROUP_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-vnc-l2-group)# ",
};

struct rfapi_l2_group_cfg *
bgp_rfapi_get_group_by_lni_label(struct bgp *bgp, uint32_t logical_net_id,
				 uint32_t label)
{
	struct rfapi_l2_group_cfg *rfg;
	struct listnode *node;

	if (bgp->rfapi_cfg->l2_groups == NULL) /* not the best place for this */
		return NULL;

	label = label & 0xfffff; /* label is 20 bits! */

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->l2_groups, node, rfg)) {
		if (rfg->logical_net_id == logical_net_id) {
			struct listnode *lnode;
			void *data;
			for (ALL_LIST_ELEMENTS_RO(rfg->labels, lnode, data))
				if (((uint32_t)((uintptr_t)data))
				    == label) { /* match! */
					return rfg;
				}
		}
	}
	return NULL;
}

struct list *bgp_rfapi_get_labellist_by_lni_label(struct bgp *bgp,
						  uint32_t logical_net_id,
						  uint32_t label)
{
	struct rfapi_l2_group_cfg *rfg;
	rfg = bgp_rfapi_get_group_by_lni_label(bgp, logical_net_id, label);
	if (rfg) {
		return rfg->labels;
	}
	return NULL;
}

struct ecommunity *
bgp_rfapi_get_ecommunity_by_lni_label(struct bgp *bgp, uint32_t is_import,
				      uint32_t logical_net_id, uint32_t label)
{
	struct rfapi_l2_group_cfg *rfg;
	rfg = bgp_rfapi_get_group_by_lni_label(bgp, logical_net_id, label);
	if (rfg) {
		if (is_import)
			return rfg->rt_import_list;
		else
			return rfg->rt_export_list;
	}
	return NULL;
}

void bgp_rfapi_cfg_init(void)
{
	install_node(&bgp_vnc_defaults_node);
	install_node(&bgp_vnc_nve_group_node);
	install_node(&bgp_vrf_policy_node);
	install_node(&bgp_vnc_l2_group_node);
	install_default(BGP_VRF_POLICY_NODE);
	install_default(BGP_VNC_DEFAULTS_NODE);
	install_default(BGP_VNC_NVE_GROUP_NODE);
	install_default(BGP_VNC_L2_GROUP_NODE);

	/*
	 * Add commands
	 */
	install_element(BGP_NODE, &vnc_defaults_cmd);
	install_element(BGP_NODE, &vnc_nve_group_cmd);
	install_element(BGP_NODE, &vnc_no_nve_group_cmd);
	install_element(BGP_NODE, &vnc_vrf_policy_cmd);
	install_element(BGP_NODE, &vnc_no_vrf_policy_cmd);
	install_element(BGP_NODE, &vnc_l2_group_cmd);
	install_element(BGP_NODE, &vnc_no_l2_group_cmd);
	install_element(BGP_NODE, &vnc_advertise_un_method_cmd);
	install_element(BGP_NODE, &vnc_export_mode_cmd);

	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_defaults_rt_import_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_defaults_rt_export_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_defaults_rt_both_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_defaults_rd_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_defaults_l2rd_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_defaults_no_l2rd_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE,
			&vnc_defaults_responselifetime_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &exit_vnc_cmd);

	install_element(BGP_NODE, &vnc_redistribute_protocol_cmd);
	install_element(BGP_NODE, &vnc_no_redistribute_protocol_cmd);
	install_element(BGP_NODE, &vnc_redistribute_nvegroup_cmd);
	install_element(BGP_NODE, &vnc_redistribute_no_nvegroup_cmd);
	install_element(BGP_NODE, &vnc_redistribute_lifetime_cmd);
	install_element(BGP_NODE, &vnc_redistribute_rh_roo_localadmin_cmd);
	install_element(BGP_NODE, &vnc_redistribute_mode_cmd);
	install_element(BGP_NODE, &vnc_redistribute_bgp_exterior_cmd);

	install_element(BGP_NODE, &vnc_redist_bgpdirect_no_prefixlist_cmd);
	install_element(BGP_NODE, &vnc_redist_bgpdirect_prefixlist_cmd);
	install_element(BGP_NODE, &vnc_redist_bgpdirect_no_routemap_cmd);
	install_element(BGP_NODE, &vnc_redist_bgpdirect_routemap_cmd);

	install_element(BGP_VNC_NVE_GROUP_NODE,
			&vnc_nve_group_redist_bgpdirect_no_prefixlist_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE,
			&vnc_nve_group_redist_bgpdirect_prefixlist_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE,
			&vnc_nve_group_redist_bgpdirect_no_routemap_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE,
			&vnc_nve_group_redist_bgpdirect_routemap_cmd);

	install_element(BGP_NODE, &vnc_export_nvegroup_cmd);
	install_element(BGP_NODE, &vnc_no_export_nvegroup_cmd);
	install_element(BGP_NODE, &vnc_nve_export_prefixlist_cmd);
	install_element(BGP_NODE, &vnc_nve_export_routemap_cmd);
	install_element(BGP_NODE, &vnc_nve_export_no_prefixlist_cmd);
	install_element(BGP_NODE, &vnc_nve_export_no_routemap_cmd);

	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_l2rd_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_no_l2rd_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_prefix_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_rt_import_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_rt_export_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_rt_both_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_rd_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE,
			&vnc_nve_group_responselifetime_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE,
			&vnc_nve_group_export_prefixlist_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE,
			&vnc_nve_group_export_routemap_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE,
			&vnc_nve_group_export_no_prefixlist_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE,
			&vnc_nve_group_export_no_routemap_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &exit_vnc_cmd);

	install_element(BGP_VRF_POLICY_NODE, &vnc_vrf_policy_label_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vnc_vrf_policy_no_label_cmd);
	// Reenable to support VRF controller use case and testing
	install_element(BGP_VRF_POLICY_NODE, &vnc_vrf_policy_nexthop_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vnc_vrf_policy_rt_import_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vnc_vrf_policy_rt_export_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vnc_vrf_policy_rt_both_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vnc_vrf_policy_rd_cmd);
	install_element(BGP_VRF_POLICY_NODE,
			&vnc_vrf_policy_export_prefixlist_cmd);
	install_element(BGP_VRF_POLICY_NODE,
			&vnc_vrf_policy_export_routemap_cmd);
	install_element(BGP_VRF_POLICY_NODE,
			&vnc_vrf_policy_export_no_prefixlist_cmd);
	install_element(BGP_VRF_POLICY_NODE,
			&vnc_vrf_policy_export_no_routemap_cmd);
	install_element(BGP_VRF_POLICY_NODE, &exit_vrf_policy_cmd);

	install_element(BGP_VNC_L2_GROUP_NODE, &vnc_l2_group_lni_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &vnc_l2_group_labels_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &vnc_l2_group_no_labels_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &vnc_l2_group_rt_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &exit_vnc_cmd);
}

struct rfapi_cfg *bgp_rfapi_cfg_new(struct rfapi_rfp_cfg *cfg)
{
	struct rfapi_cfg *h;
	afi_t afi;

	h = XCALLOC(MTYPE_RFAPI_CFG, sizeof(struct rfapi_cfg));
	assert(h);

	h->nve_groups_sequential = list_new();
	assert(h->nve_groups_sequential);
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		h->nve_groups_vn[afi] = agg_table_init();
		h->nve_groups_un[afi] = agg_table_init();
	}
	h->default_response_lifetime =
		BGP_VNC_DEFAULT_RESPONSE_LIFETIME_DEFAULT;
	h->rfg_export_direct_bgp_l = list_new();
	h->rfg_export_zebra_l = list_new();
	h->resolve_nve_roo_local_admin =
		BGP_VNC_CONFIG_RESOLVE_NVE_ROO_LOCAL_ADMIN_DEFAULT;

	SET_FLAG(h->flags, BGP_VNC_CONFIG_FLAGS_DEFAULT);

	if (cfg == NULL) {
		h->rfp_cfg.download_type = RFAPI_RFP_DOWNLOAD_PARTIAL;
		h->rfp_cfg.ftd_advertisement_interval =
			RFAPI_RFP_CFG_DEFAULT_FTD_ADVERTISEMENT_INTERVAL;
		h->rfp_cfg.holddown_factor =
			RFAPI_RFP_CFG_DEFAULT_HOLDDOWN_FACTOR;
		h->rfp_cfg.use_updated_response = 0;
		h->rfp_cfg.use_removes = 0;
	} else {
		h->rfp_cfg.download_type = cfg->download_type;
		h->rfp_cfg.ftd_advertisement_interval =
			cfg->ftd_advertisement_interval;
		h->rfp_cfg.holddown_factor = cfg->holddown_factor;
		h->rfp_cfg.use_updated_response = cfg->use_updated_response;
		h->rfp_cfg.use_removes = cfg->use_removes;
		if (cfg->use_updated_response)
			h->flags &= ~BGP_VNC_CONFIG_CALLBACK_DISABLE;
		else
			h->flags |= BGP_VNC_CONFIG_CALLBACK_DISABLE;
		if (cfg->use_removes)
			h->flags &= ~BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE;
		else
			h->flags |= BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE;
	}
	return h;
}

static void bgp_rfapi_rfgn_list_delete(void *data)
{
	struct rfapi_rfg_name *rfgn = data;

	XFREE(MTYPE_RFAPI_GROUP_CFG, rfgn->name);
	rfgn_free(rfgn);
}

void bgp_rfapi_cfg_destroy(struct bgp *bgp, struct rfapi_cfg *h)
{
	afi_t afi;
	if (h == NULL)
		return;

	bgp_rfapi_delete_named_nve_group(NULL, bgp, NULL, RFAPI_GROUP_CFG_MAX);
	bgp_rfapi_delete_named_l2_group(NULL, bgp, NULL);
	if (h->l2_groups != NULL)
		list_delete(&h->l2_groups);
	list_delete(&h->nve_groups_sequential);

	h->rfg_export_direct_bgp_l->del = bgp_rfapi_rfgn_list_delete;
	list_delete(&h->rfg_export_direct_bgp_l);

	h->rfg_export_zebra_l->del = bgp_rfapi_rfgn_list_delete;
	list_delete(&h->rfg_export_zebra_l);

	if (h->default_rt_export_list)
		ecommunity_free(&h->default_rt_export_list);
	if (h->default_rt_import_list)
		ecommunity_free(&h->default_rt_import_list);
	XFREE(MTYPE_RFAPI_RFP_GROUP_CFG, h->default_rfp_cfg);
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		agg_table_finish(h->nve_groups_vn[afi]);
		agg_table_finish(h->nve_groups_un[afi]);
	}
	XFREE(MTYPE_RFAPI_CFG, h);
}

int bgp_rfapi_cfg_write(struct vty *vty, struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct rfapi_nve_group_cfg *rfg;
	struct rfapi_cfg *hc = bgp->rfapi_cfg;
	struct rfapi_rfg_name *rfgn;
	int write = 0;
	afi_t afi;
	int type;
	if (bgp->rfapi == NULL || hc == NULL)
		return write;

	vty_out(vty, "!\n");
	for (ALL_LIST_ELEMENTS(hc->nve_groups_sequential, node, nnode, rfg))
		if (rfg->type == RFAPI_GROUP_CFG_VRF) {
			++write;
			vty_out(vty, " vrf-policy %s\n", rfg->name);
			if (rfg->label <= MPLS_LABEL_MAX) {
				vty_out(vty, "  label %u\n", rfg->label);
			}
			if (CHECK_FLAG(rfg->flags, RFAPI_RFG_VPN_NH_SELF)) {
				vty_out(vty, "  nexthop self\n");

			} else {
				if (rfg->vn_prefix.family) {
					char buf[BUFSIZ];
					buf[0] = buf[BUFSIZ - 1] = 0;
					inet_ntop(rfg->vn_prefix.family,
						  &rfg->vn_prefix.u.prefix, buf,
						  sizeof(buf));
					if (!buf[0] || buf[BUFSIZ - 1]) {
						// vty_out (vty, "nexthop
						// self\n");
					} else {
						vty_out(vty, "  nexthop %s\n",
							buf);
					}
				}
			}

			if (rfg->rd.prefixlen) {
				if (AF_UNIX == rfg->rd.family) {

					uint16_t value = 0;

					value = ((rfg->rd.val[6] << 8)
						 & 0x0ff00)
						| (rfg->rd.val[7] & 0x0ff);

					vty_out(vty, "  rd auto:nh:%d\n",
						value);

				} else
					vty_out(vty, "  rd %pRDP\n", &rfg->rd);
			}

			if (rfg->rt_import_list && rfg->rt_export_list
			    && ecommunity_cmp(rfg->rt_import_list,
					      rfg->rt_export_list)) {
				char *b = ecommunity_ecom2str(
					rfg->rt_import_list,
					ECOMMUNITY_FORMAT_ROUTE_MAP,
					ECOMMUNITY_ROUTE_TARGET);
				vty_out(vty, "  rt both %s\n", b);
				XFREE(MTYPE_ECOMMUNITY_STR, b);
			} else {
				if (rfg->rt_import_list) {
					char *b = ecommunity_ecom2str(
						rfg->rt_import_list,
						ECOMMUNITY_FORMAT_ROUTE_MAP,
						ECOMMUNITY_ROUTE_TARGET);
					vty_out(vty, "  rt import %s\n", b);
					XFREE(MTYPE_ECOMMUNITY_STR, b);
				}
				if (rfg->rt_export_list) {
					char *b = ecommunity_ecom2str(
						rfg->rt_export_list,
						ECOMMUNITY_FORMAT_ROUTE_MAP,
						ECOMMUNITY_ROUTE_TARGET);
					vty_out(vty, "  rt export %s\n", b);
					XFREE(MTYPE_ECOMMUNITY_STR, b);
				}
			}

			/*
			 * route filtering: prefix-lists and route-maps
			 */
			for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

				const char *afistr =
					(afi == AFI_IP) ? "ipv4" : "ipv6";

				if (rfg->plist_export_bgp_name[afi]) {
					vty_out(vty,
						"  export %s%s prefix-list %s\n",
						(rfg->type == RFAPI_GROUP_CFG_VRF
							 ? ""
							 : "bgp "),
						afistr,
						rfg->plist_export_bgp_name
							[afi]);
				}
				if (rfg->plist_export_zebra_name[afi]) {
					vty_out(vty,
						"  export %s%s prefix-list %s\n",
						(rfg->type == RFAPI_GROUP_CFG_VRF
							 ? ""
							 : "zebra "),
						afistr,
						rfg->plist_export_zebra_name
							[afi]);
				}
				/*
				 * currently we only support redist plists for
				 * bgp-direct.
				 * If we later add plist support for
				 * redistributing other
				 * protocols, we'll need to loop over protocols
				 * here
				 */
				if (rfg->plist_redist_name
					    [ZEBRA_ROUTE_BGP_DIRECT][afi]) {
					vty_out(vty,
						"  redistribute bgp-direct %s prefix-list %s\n",
						afistr,
						rfg->plist_redist_name
							[ZEBRA_ROUTE_BGP_DIRECT]
							[afi]);
				}
				if (rfg->plist_redist_name
					    [ZEBRA_ROUTE_BGP_DIRECT_EXT][afi]) {
					vty_out(vty,
						"  redistribute bgp-direct-to-nve-groups %s prefix-list %s\n",
						afistr,
						rfg->plist_redist_name
							[ZEBRA_ROUTE_BGP_DIRECT_EXT]
							[afi]);
				}
			}

			if (rfg->routemap_export_bgp_name) {
				vty_out(vty, "  export %sroute-map %s\n",
					(rfg->type == RFAPI_GROUP_CFG_VRF
						 ? ""
						 : "bgp "),
					rfg->routemap_export_bgp_name);
			}
			if (rfg->routemap_export_zebra_name) {
				vty_out(vty, "  export %sroute-map %s\n",
					(rfg->type == RFAPI_GROUP_CFG_VRF
						 ? ""
						 : "zebra "),
					rfg->routemap_export_zebra_name);
			}
			if (rfg->routemap_redist_name[ZEBRA_ROUTE_BGP_DIRECT]) {
				vty_out(vty,
					"  redistribute bgp-direct route-map %s\n",
					rfg->routemap_redist_name
						[ZEBRA_ROUTE_BGP_DIRECT]);
			}
			if (rfg->routemap_redist_name
				    [ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
				vty_out(vty,
					"  redistribute bgp-direct-to-nve-groups route-map %s\n",
					rfg->routemap_redist_name
						[ZEBRA_ROUTE_BGP_DIRECT_EXT]);
			}
			vty_out(vty, " exit-vrf-policy\n");
			vty_out(vty, "!\n");
		}
	if (hc->flags & BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP) {
		vty_out(vty, " vnc advertise-un-method encap-safi\n");
		write++;
	}

	{ /* was based on listen ports */
		/* for now allow both old and new */
		if (bgp->rfapi->rfp_methods.cfg_cb)
			write += (bgp->rfapi->rfp_methods.cfg_cb)(
				vty, bgp->rfapi->rfp);

		if (write)
			vty_out(vty, "!\n");

		if (hc->l2_groups) {
			struct rfapi_l2_group_cfg *rfgc = NULL;
			struct listnode *gnode;
			for (ALL_LIST_ELEMENTS_RO(hc->l2_groups, gnode, rfgc)) {
				struct listnode *lnode;
				void *data;
				++write;
				vty_out(vty, " vnc l2-group %s\n", rfgc->name);
				if (rfgc->logical_net_id != 0)
					vty_out(vty,
						"   logical-network-id %u\n",
						rfgc->logical_net_id);
				if (rfgc->labels != NULL
				    && listhead(rfgc->labels) != NULL) {
					vty_out(vty, "   labels ");
					for (ALL_LIST_ELEMENTS_RO(rfgc->labels,
								  lnode,
								  data)) {
						vty_out(vty, "%hu ",
							(uint16_t)(
								(uintptr_t)
									data));
					}
					vty_out(vty, "\n");
				}

				if (rfgc->rt_import_list && rfgc->rt_export_list
				    && ecommunity_cmp(rfgc->rt_import_list,
						      rfgc->rt_export_list)) {
					char *b = ecommunity_ecom2str(
						rfgc->rt_import_list,
						ECOMMUNITY_FORMAT_ROUTE_MAP,
						ECOMMUNITY_ROUTE_TARGET);
					vty_out(vty, "   rt both %s\n", b);
					XFREE(MTYPE_ECOMMUNITY_STR, b);
				} else {
					if (rfgc->rt_import_list) {
						char *b = ecommunity_ecom2str(
							rfgc->rt_import_list,
							ECOMMUNITY_FORMAT_ROUTE_MAP,
							ECOMMUNITY_ROUTE_TARGET);
						vty_out(vty, "  rt import %s\n",
							b);
						XFREE(MTYPE_ECOMMUNITY_STR, b);
					}
					if (rfgc->rt_export_list) {
						char *b = ecommunity_ecom2str(
							rfgc->rt_export_list,
							ECOMMUNITY_FORMAT_ROUTE_MAP,
							ECOMMUNITY_ROUTE_TARGET);
						vty_out(vty, "  rt export %s\n",
							b);
						XFREE(MTYPE_ECOMMUNITY_STR, b);
					}
				}
				if (bgp->rfapi->rfp_methods.cfg_group_cb)
					write += (bgp->rfapi->rfp_methods
							  .cfg_group_cb)(
						vty, bgp->rfapi->rfp,
						RFAPI_RFP_CFG_GROUP_L2,
						rfgc->name, rfgc->rfp_cfg);
				vty_out(vty, " exit-vnc\n");
				vty_out(vty, "!\n");
			}
		}

		if (hc->default_rd.prefixlen
		    || hc->default_response_lifetime
			       != BGP_VNC_DEFAULT_RESPONSE_LIFETIME_DEFAULT
		    || hc->default_rt_import_list || hc->default_rt_export_list
		    || hc->nve_groups_sequential->count) {


			++write;
			vty_out(vty, " vnc defaults\n");

			if (hc->default_rd.prefixlen) {
				if (AF_UNIX == hc->default_rd.family) {
					uint16_t value = 0;

					value = ((hc->default_rd.val[6] << 8)
						 & 0x0ff00)
						| (hc->default_rd.val[7]
						   & 0x0ff);

					vty_out(vty, "  rd auto:vn:%d\n",
						value);

				} else
					vty_out(vty, "  rd %pRDP\n",
						&hc->default_rd);
			}
			if (hc->default_response_lifetime
			    != BGP_VNC_DEFAULT_RESPONSE_LIFETIME_DEFAULT) {
				vty_out(vty, "  response-lifetime ");
				if (hc->default_response_lifetime != UINT32_MAX)
					vty_out(vty, "%d",
						hc->default_response_lifetime);
				else
					vty_out(vty, "infinite");
				vty_out(vty, "\n");
			}
			if (hc->default_rt_import_list
			    && hc->default_rt_export_list
			    && ecommunity_cmp(hc->default_rt_import_list,
					      hc->default_rt_export_list)) {
				char *b = ecommunity_ecom2str(
					hc->default_rt_import_list,
					ECOMMUNITY_FORMAT_ROUTE_MAP,
					ECOMMUNITY_ROUTE_TARGET);
				vty_out(vty, "  rt both %s\n", b);
				XFREE(MTYPE_ECOMMUNITY_STR, b);
			} else {
				if (hc->default_rt_import_list) {
					char *b = ecommunity_ecom2str(
						hc->default_rt_import_list,
						ECOMMUNITY_FORMAT_ROUTE_MAP,
						ECOMMUNITY_ROUTE_TARGET);
					vty_out(vty, "  rt import %s\n", b);
					XFREE(MTYPE_ECOMMUNITY_STR, b);
				}
				if (hc->default_rt_export_list) {
					char *b = ecommunity_ecom2str(
						hc->default_rt_export_list,
						ECOMMUNITY_FORMAT_ROUTE_MAP,
						ECOMMUNITY_ROUTE_TARGET);
					vty_out(vty, "  rt export %s\n", b);
					XFREE(MTYPE_ECOMMUNITY_STR, b);
				}
			}
			if (bgp->rfapi->rfp_methods.cfg_group_cb)
				write += (bgp->rfapi->rfp_methods.cfg_group_cb)(
					vty, bgp->rfapi->rfp,
					RFAPI_RFP_CFG_GROUP_DEFAULT, NULL,
					bgp->rfapi_cfg->default_rfp_cfg);
			vty_out(vty, " exit-vnc\n");
			vty_out(vty, "!\n");
		}

		for (ALL_LIST_ELEMENTS(hc->nve_groups_sequential, node, nnode,
				       rfg))
			if (rfg->type == RFAPI_GROUP_CFG_NVE) {
				++write;
				vty_out(vty, " vnc nve-group %s\n", rfg->name);

				if (rfg->vn_prefix.family && rfg->vn_node)
					vty_out(vty, "  prefix %s %pFX\n", "vn",
						&rfg->vn_prefix);

				if (rfg->un_prefix.family && rfg->un_node)
					vty_out(vty, "  prefix %s %pFX\n", "un",
						&rfg->un_prefix);


				if (rfg->rd.prefixlen) {
					if (AF_UNIX == rfg->rd.family) {

						uint16_t value = 0;

						value = ((rfg->rd.val[6] << 8)
							 & 0x0ff00)
							| (rfg->rd.val[7]
							   & 0x0ff);

						vty_out(vty,
							"  rd auto:vn:%d\n",
							value);

					} else
						vty_out(vty, "  rd %pRDP\n",
							&rfg->rd);
				}
				if (rfg->flags & RFAPI_RFG_RESPONSE_LIFETIME) {
					vty_out(vty, "  response-lifetime ");
					if (rfg->response_lifetime
					    != UINT32_MAX)
						vty_out(vty, "%d",
							rfg->response_lifetime);
					else
						vty_out(vty, "infinite");
					vty_out(vty, "\n");
				}

				if (rfg->rt_import_list && rfg->rt_export_list
				    && ecommunity_cmp(rfg->rt_import_list,
						      rfg->rt_export_list)) {
					char *b = ecommunity_ecom2str(
						rfg->rt_import_list,
						ECOMMUNITY_FORMAT_ROUTE_MAP,
						ECOMMUNITY_ROUTE_TARGET);
					vty_out(vty, "  rt both %s\n", b);
					XFREE(MTYPE_ECOMMUNITY_STR, b);
				} else {
					if (rfg->rt_import_list) {
						char *b = ecommunity_ecom2str(
							rfg->rt_import_list,
							ECOMMUNITY_FORMAT_ROUTE_MAP,
							ECOMMUNITY_ROUTE_TARGET);
						vty_out(vty, "  rt import %s\n",
							b);
						XFREE(MTYPE_ECOMMUNITY_STR, b);
					}
					if (rfg->rt_export_list) {
						char *b = ecommunity_ecom2str(
							rfg->rt_export_list,
							ECOMMUNITY_FORMAT_ROUTE_MAP,
							ECOMMUNITY_ROUTE_TARGET);
						vty_out(vty, "  rt export %s\n",
							b);
						XFREE(MTYPE_ECOMMUNITY_STR, b);
					}
				}

				/*
				 * route filtering: prefix-lists and route-maps
				 */
				for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

					const char *afistr = (afi == AFI_IP)
								     ? "ipv4"
								     : "ipv6";

					if (rfg->plist_export_bgp_name[afi]) {
						vty_out(vty,
							"  export bgp %s prefix-list %s\n",
							afistr,
							rfg->plist_export_bgp_name
								[afi]);
					}
					if (rfg->plist_export_zebra_name[afi]) {
						vty_out(vty,
							"  export zebra %s prefix-list %s\n",
							afistr,
							rfg->plist_export_zebra_name
								[afi]);
					}
					/*
					 * currently we only support redist
					 * plists for bgp-direct.
					 * If we later add plist support for
					 * redistributing other
					 * protocols, we'll need to loop over
					 * protocols here
					 */
					if (rfg->plist_redist_name
						    [ZEBRA_ROUTE_BGP_DIRECT]
						    [afi]) {
						vty_out(vty,
							"  redistribute bgp-direct %s prefix-list %s\n",
							afistr,
							rfg->plist_redist_name
								[ZEBRA_ROUTE_BGP_DIRECT]
								[afi]);
					}
					if (rfg->plist_redist_name
						    [ZEBRA_ROUTE_BGP_DIRECT_EXT]
						    [afi]) {
						vty_out(vty,
							"  redistribute bgp-direct-to-nve-groups %s prefix-list %s\n",
							afistr,
							rfg->plist_redist_name
								[ZEBRA_ROUTE_BGP_DIRECT_EXT]
								[afi]);
					}
				}

				if (rfg->routemap_export_bgp_name) {
					vty_out(vty,
						"  export bgp route-map %s\n",
						rfg->routemap_export_bgp_name);
				}
				if (rfg->routemap_export_zebra_name) {
					vty_out(vty,
						"  export zebra route-map %s\n",
						rfg->routemap_export_zebra_name);
				}
				if (rfg->routemap_redist_name
					    [ZEBRA_ROUTE_BGP_DIRECT]) {
					vty_out(vty,
						"  redistribute bgp-direct route-map %s\n",
						rfg->routemap_redist_name
							[ZEBRA_ROUTE_BGP_DIRECT]);
				}
				if (rfg->routemap_redist_name
					    [ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
					vty_out(vty,
						"  redistribute bgp-direct-to-nve-groups route-map %s\n",
						rfg->routemap_redist_name
							[ZEBRA_ROUTE_BGP_DIRECT_EXT]);
				}
				if (bgp->rfapi->rfp_methods.cfg_group_cb)
					write += (bgp->rfapi->rfp_methods
							  .cfg_group_cb)(
						vty, bgp->rfapi->rfp,
						RFAPI_RFP_CFG_GROUP_NVE,
						rfg->name, rfg->rfp_cfg);
				vty_out(vty, " exit-vnc\n");
				vty_out(vty, "!\n");
			}
	} /* have listen ports */

	/*
	 * route export to other protocols
	 */
	if (VNC_EXPORT_BGP_GRP_ENABLED(hc)) {
		vty_out(vty, " vnc export bgp mode group-nve\n");
	} else if (VNC_EXPORT_BGP_RH_ENABLED(hc)) {
		vty_out(vty, " vnc export bgp mode registering-nve\n");
	} else if (VNC_EXPORT_BGP_CE_ENABLED(hc)) {
		vty_out(vty, " vnc export bgp mode ce\n");
	}

	if (VNC_EXPORT_ZEBRA_GRP_ENABLED(hc)) {
		vty_out(vty, " vnc export zebra mode group-nve\n");
	} else if (VNC_EXPORT_ZEBRA_RH_ENABLED(hc)) {
		vty_out(vty, " vnc export zebra mode registering-nve\n");
	}

	if (hc->rfg_export_direct_bgp_l) {
		for (ALL_LIST_ELEMENTS(hc->rfg_export_direct_bgp_l, node, nnode,
				       rfgn)) {

			vty_out(vty, " vnc export bgp group-nve group %s\n",
				rfgn->name);
		}
	}

	if (hc->rfg_export_zebra_l) {
		for (ALL_LIST_ELEMENTS(hc->rfg_export_zebra_l, node, nnode,
				       rfgn)) {

			vty_out(vty, " vnc export zebra group-nve group %s\n",
				rfgn->name);
		}
	}


	if (hc->rfg_redist_name) {
		vty_out(vty, " vnc redistribute nve-group %s\n",
			hc->rfg_redist_name);
	}
	if (hc->redist_lifetime) {
		vty_out(vty, " vnc redistribute lifetime %d\n",
			hc->redist_lifetime);
	}
	if (hc->resolve_nve_roo_local_admin
	    != BGP_VNC_CONFIG_RESOLVE_NVE_ROO_LOCAL_ADMIN_DEFAULT) {

		vty_out(vty,
			" vnc redistribute resolve-nve roo-ec-local-admin %d\n",
			hc->resolve_nve_roo_local_admin);
	}

	if (hc->redist_mode) /* ! default */
	{
		const char *s = "";

		(void)s; /* clang-SA */
		switch (hc->redist_mode) {
		case VNC_REDIST_MODE_PLAIN:
			s = "plain";
			break;
		case VNC_REDIST_MODE_RFG:
			s = "nve-group";
			break;
		case VNC_REDIST_MODE_RESOLVE_NVE:
			s = "resolve-nve";
			break;
		}
		if (s) {
			vty_out(vty, " vnc redistribute mode %s\n", s);
		}
	}

	/*
	 * route filtering: prefix-lists and route-maps
	 */
	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

		const char *afistr = (afi == AFI_IP) ? "ipv4" : "ipv6";

		if (hc->plist_export_bgp_name[afi]) {
			vty_out(vty, " vnc export bgp %s prefix-list %s\n",
				afistr, hc->plist_export_bgp_name[afi]);
		}
		if (hc->plist_export_zebra_name[afi]) {
			vty_out(vty, " vnc export zebra %s prefix-list %s\n",
				afistr, hc->plist_export_zebra_name[afi]);
		}
		if (hc->plist_redist_name[ZEBRA_ROUTE_BGP_DIRECT][afi]) {
			vty_out(vty,
				" vnc redistribute bgp-direct %s prefix-list %s\n",
				afistr,
				hc->plist_redist_name[ZEBRA_ROUTE_BGP_DIRECT]
						     [afi]);
		}
	}

	if (hc->routemap_export_bgp_name) {
		vty_out(vty, " vnc export bgp route-map %s\n",
			hc->routemap_export_bgp_name);
	}
	if (hc->routemap_export_zebra_name) {
		vty_out(vty, " vnc export zebra route-map %s\n",
			hc->routemap_export_zebra_name);
	}
	if (hc->routemap_redist_name[ZEBRA_ROUTE_BGP_DIRECT]) {
		vty_out(vty, " vnc redistribute bgp-direct route-map %s\n",
			hc->routemap_redist_name[ZEBRA_ROUTE_BGP_DIRECT]);
	}

	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		for (type = 0; type < ZEBRA_ROUTE_MAX; ++type) {
			if (hc->redist[afi][type]) {
				if (type == ZEBRA_ROUTE_BGP_DIRECT_EXT
				    && hc->redist_bgp_exterior_view_name) {
					vty_out(vty,
						" vnc redistribute %s %s view %s\n",
						((afi == AFI_IP) ? "ipv4"
								 : "ipv6"),
						zebra_route_string(type),
						hc->redist_bgp_exterior_view_name);
				} else {
					vty_out(vty,
						" vnc redistribute %s %s\n",
						((afi == AFI_IP) ? "ipv4"
								 : "ipv6"),
						zebra_route_string(type));
				}
			}
		}
	}
	return write;
}

void bgp_rfapi_show_summary(struct bgp *bgp, struct vty *vty)
{
	struct rfapi_cfg *hc = bgp->rfapi_cfg;
	afi_t afi;
	int type, redist = 0;
	char tmp[40];
	if (hc == NULL)
		return;

	vty_out(vty, "%-39s %-19s %s\n", "VNC Advertise method:",
		(hc->flags & BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP
			 ? "Encapsulation SAFI"
			 : "Tunnel Encap attribute"),
		((hc->flags & BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP)
				 == (BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP
				     & BGP_VNC_CONFIG_FLAGS_DEFAULT)
			 ? "(default)"
			 : ""));
	/* export */
	vty_out(vty, "%-39s ", "Export from VNC:");
	/*
	 * route export to other protocols
	 */
	if (VNC_EXPORT_BGP_GRP_ENABLED(hc)) {
		redist++;
		vty_out(vty, "ToBGP Groups={");
		if (hc->rfg_export_direct_bgp_l) {
			int cnt = 0;
			struct listnode *node, *nnode;
			struct rfapi_rfg_name *rfgn;
			for (ALL_LIST_ELEMENTS(hc->rfg_export_direct_bgp_l,
					       node, nnode, rfgn)) {
				if (cnt++ != 0)
					vty_out(vty, ",");

				vty_out(vty, "%s", rfgn->name);
			}
		}
		vty_out(vty, "}");
	} else if (VNC_EXPORT_BGP_RH_ENABLED(hc)) {
		redist++;
		vty_out(vty, "ToBGP {Registering NVE}");
		/* note filters, route-maps not shown */
	} else if (VNC_EXPORT_BGP_CE_ENABLED(hc)) {
		redist++;
		vty_out(vty, "ToBGP {NVE connected router:%d}",
			hc->resolve_nve_roo_local_admin);
		/* note filters, route-maps not shown */
	}

	if (VNC_EXPORT_ZEBRA_GRP_ENABLED(hc)) {
		redist++;
		vty_out(vty, "%sToZebra Groups={", (redist == 1 ? "" : " "));
		if (hc->rfg_export_zebra_l) {
			int cnt = 0;
			struct listnode *node, *nnode;
			struct rfapi_rfg_name *rfgn;
			for (ALL_LIST_ELEMENTS(hc->rfg_export_zebra_l, node,
					       nnode, rfgn)) {
				if (cnt++ != 0)
					vty_out(vty, ",");
				vty_out(vty, "%s", rfgn->name);
			}
		}
		vty_out(vty, "}");
	} else if (VNC_EXPORT_ZEBRA_RH_ENABLED(hc)) {
		redist++;
		vty_out(vty, "%sToZebra {Registering NVE}",
			(redist == 1 ? "" : " "));
		/* note filters, route-maps not shown */
	}
	vty_out(vty, "%-19s %s\n", (redist ? "" : "Off"),
		(redist ? "" : "(default)"));

	/* Redistribution */
	redist = 0;
	vty_out(vty, "%-39s ", "Redistribution into VNC:");
	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		for (type = 0; type < ZEBRA_ROUTE_MAX; ++type) {
			if (hc->redist[afi][type]) {
				vty_out(vty, "{%s,%s} ",
					((afi == AFI_IP) ? "ipv4" : "ipv6"),
					zebra_route_string(type));
				redist++;
			}
		}
	}
	vty_out(vty, "%-19s %s\n", (redist ? "" : "Off"),
		(redist ? "" : "(default)"));

	vty_out(vty, "%-39s %3u%-16s %s\n",
		"RFP Registration Hold-Down Factor:",
		hc->rfp_cfg.holddown_factor, "%",
		(hc->rfp_cfg.holddown_factor
				 == RFAPI_RFP_CFG_DEFAULT_HOLDDOWN_FACTOR
			 ? "(default)"
			 : ""));
	vty_out(vty, "%-39s %-19s %s\n", "RFP Updated responses:",
		(hc->rfp_cfg.use_updated_response == 0 ? "Off" : "On"),
		(hc->rfp_cfg.use_updated_response == 0 ? "(default)" : ""));
	vty_out(vty, "%-39s %-19s %s\n", "RFP Removal responses:",
		(hc->rfp_cfg.use_removes == 0 ? "Off" : "On"),
		(hc->rfp_cfg.use_removes == 0 ? "(default)" : ""));
	vty_out(vty, "%-39s %-19s %s\n", "RFP Full table download:",
		(hc->rfp_cfg.download_type == RFAPI_RFP_DOWNLOAD_FULL ? "On"
								      : "Off"),
		(hc->rfp_cfg.download_type == RFAPI_RFP_DOWNLOAD_PARTIAL
			 ? "(default)"
			 : ""));
	snprintf(tmp, sizeof(tmp), "%u seconds",
		 hc->rfp_cfg.ftd_advertisement_interval);
	vty_out(vty, "%-39s %-19s %s\n", "    Advertisement Interval:", tmp,
		(hc->rfp_cfg.ftd_advertisement_interval
				 == RFAPI_RFP_CFG_DEFAULT_FTD_ADVERTISEMENT_INTERVAL
			 ? "(default)"
			 : ""));
	vty_out(vty, "%-39s %d seconds\n", "Default RFP response lifetime:",
		hc->default_response_lifetime);
	vty_out(vty, "\n");
	return;
}

struct rfapi_cfg *bgp_rfapi_get_config(struct bgp *bgp)
{
	struct rfapi_cfg *hc = NULL;
	if (bgp == NULL)
		bgp = bgp_get_default();
	if (bgp != NULL)
		hc = bgp->rfapi_cfg;
	return hc;
}

#endif /* ENABLE_BGP_VNC */
