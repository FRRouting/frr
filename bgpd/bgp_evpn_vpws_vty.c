// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * bgp_evpn_vpws_vty.c: CLI for `vpws-instance NAME` under
 * `address-family l2vpn evpn` plus the matching show command.
 *
 * CLI tree:
 *
 *     ! NEW:
 *     vpws-instance NAME
 *      vpws-id source N target N
 *      vpws-evi N
 *      rd RD
 *      route-target {import|export|both} RT
 *     exit-vpws-instance
 *    exit-address-family
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/vty.h"
#include "lib/prefix.h"
#include "lib/memory.h"

#include "bgpd/bgp_rd.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_evpn_vpws.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_evpn_vpws_vty_clippy.c"

/* BGP_EVPN_VPWS_NODE is defined as a real enum value in
 * lib/command.h (added there as part of this feature). No local
 * #define needed.
 */

static struct cmd_node bgp_evpn_vpws_node = {
	.name = "bgp-evpn-vpws",
	.node = BGP_EVPN_VPWS_NODE,
	.parent_node = BGP_EVPN_NODE,
	.prompt = "%s(config-router-af-vpws)# ",
	.no_xpath = true,
};

/* Sub-context accessor - uses the qobj-based sub-context machinery
 * (lib/vty.h), keyed by the vpws struct's QOBJ_FIELDS.
 */
#define vpws_get_ctx() VTY_GET_CONTEXT_SUB(bgp_evpn_vpws)

/* ---------- entry / exit ---------- */

DEFUN_NOSH (bgp_evpn_vpws_instance,
	    bgp_evpn_vpws_instance_cmd,
	    "vpws-instance WORD",
	    "EVPN-VPWS service\n"
	    "Service instance name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	const char *name = argv[1]->arg;
	struct bgp_evpn_vpws *vpws;

	if (!bgp)
		return CMD_WARNING_CONFIG_FAILED;

	vpws = bgp_evpn_vpws_find(bgp, name);
	if (!vpws) {
		vpws = bgp_evpn_vpws_create(bgp, name);
		if (!vpws) {
			vty_out(vty, "%% Cannot create vpws-instance %s\n", name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	VTY_PUSH_CONTEXT_SUB(BGP_EVPN_VPWS_NODE, vpws);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vpws_instance,
       no_bgp_evpn_vpws_instance_cmd,
       "no vpws-instance WORD",
       NO_STR
       "EVPN-VPWS service\n"
       "Service instance name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	const char *name = argv[2]->arg;
	struct bgp_evpn_vpws *vpws;

	if (!bgp)
		return CMD_WARNING_CONFIG_FAILED;

	vpws = bgp_evpn_vpws_find(bgp, name);
	if (vpws)
		bgp_evpn_vpws_delete(vpws);
	return CMD_SUCCESS;
}

DEFUN_NOSH (bgp_evpn_vpws_exit,
	    bgp_evpn_vpws_exit_cmd,
	    "exit-vpws-instance",
	    "Exit vpws-instance configuration mode\n")
{
	vty->node = BGP_EVPN_NODE;
	vty->qobj_index_sub = 0;
	return CMD_SUCCESS;
}

/* ---------- vpws-id source N target N ---------- */

DEFUN (bgp_evpn_vpws_id,
       bgp_evpn_vpws_id_cmd,
       "vpws-id source (1-4294967295) target (1-4294967295)",
       "VPWS Service Instance Identifier (AC-ID)\n"
       "Local AC-ID (advertised in EAD-EVI Ethernet Tag)\n"
       "Identifier value\n"
       "Remote AC-ID (matched on imported EAD-EVI Ethernet Tag)\n"
       "Identifier value\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bgp_evpn_vpws, ctx);
	uint32_t source = strtoul(argv[2]->arg, NULL, 10);
	uint32_t target = strtoul(argv[4]->arg, NULL, 10);

	if (bgp_evpn_vpws_set_ac_ids(ctx, source, target) < 0) {
		vty_out(vty, "%% Invalid source/target values\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

/* ---------- vpws-evi N ---------- */

DEFUN (bgp_evpn_vpws_evi,
       bgp_evpn_vpws_evi_cmd,
       "vpws-evi (1-16777215)",
       "EVPN Instance identifier for this VPWS service\n"
       "EVI value (1..2^24-1)\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bgp_evpn_vpws, ctx);
	uint32_t evi = strtoul(argv[1]->arg, NULL, 10);

	if (bgp_evpn_vpws_set_evi(ctx, evi) < 0) {
		vty_out(vty, "%% Invalid EVI %u\n", evi);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

/* ---------- rd RD ---------- */

DEFUN (bgp_evpn_vpws_rd,
       bgp_evpn_vpws_rd_cmd,
       "rd ASN:NN_OR_IP-ADDRESS:NN",
       "Route Distinguisher\n"
       "ASN:nn or IP:nn format\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bgp_evpn_vpws, ctx);
	struct prefix_rd prd;

	if (str2prefix_rd(argv[1]->arg, &prd) == 0) {
		vty_out(vty, "%% Malformed RD\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	bgp_evpn_vpws_set_rd(ctx, &prd);
	return CMD_SUCCESS;
}

/* ---------- route-target {import|export|both} RT ---------- */

DEFUN (bgp_evpn_vpws_rt,
       bgp_evpn_vpws_rt_cmd,
       "route-target <import|export|both> RTLIST...",
       "Route Target\n"
       "Import direction\n"
       "Export direction\n"
       "Both import and export\n"
       "Route target (ASN:nn or IP:nn)\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bgp_evpn_vpws, ctx);
	const char *dir = argv[1]->arg;
	struct ecommunity *ecom;
	int direction = 0;
	char *rtstr;
	int rv = CMD_SUCCESS;

	if (!strcmp(dir, "import"))
		direction = 1;
	else if (!strcmp(dir, "export"))
		direction = 2;
	else
		direction = 3;

	rtstr = argv_concat(argv, argc, 2);
	if (!rtstr)
		return CMD_WARNING_CONFIG_FAILED;

	ecom = ecommunity_str2com(rtstr, ECOMMUNITY_ROUTE_TARGET, 0);
	XFREE(MTYPE_TMP, rtstr);

	if (!ecom) {
		vty_out(vty, "%% Malformed route-target\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bgp_evpn_vpws_set_rt(ctx, ecom, direction) < 0)
		rv = CMD_WARNING_CONFIG_FAILED;

	ecommunity_free(&ecom);
	return rv;
}

DEFUN (no_bgp_evpn_vpws_rt,
       no_bgp_evpn_vpws_rt_cmd,
       "no route-target <import|export|both>",
       NO_STR
       "Route Target\n"
       "Import direction\n"
       "Export direction\n"
       "Both import and export\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bgp_evpn_vpws, ctx);
	const char *dir = argv[2]->arg;
	int direction;

	if (!strcmp(dir, "import"))
		direction = 1;
	else if (!strcmp(dir, "export"))
		direction = 2;
	else
		direction = 3;

	bgp_evpn_vpws_clear_rt(ctx, direction);
	return CMD_SUCCESS;
}

/* ---------- interface IFNAME [sid auto] ---------- */

DEFPY (bgp_evpn_vpws_interface_sid,
       bgp_evpn_vpws_interface_sid_cmd,
       "interface IFNAME$ifname [sid auto$sid_auto]",
       "Bind attachment circuit interface\n"
       "Interface name\n"
       "SRv6 SID allocation\n"
       "Auto allocate from BGP-bound locator\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bgp_evpn_vpws, ctx);

	if (bgp_evpn_vpws_set_interface(ctx, ifname, !!sid_auto) < 0) {
		vty_out(vty, "%% Cannot bind interface %s\n", ifname);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFPY (no_bgp_evpn_vpws_interface,
       no_bgp_evpn_vpws_interface_cmd,
       "no interface [IFNAME$ifname]",
       NO_STR
       "Bind attachment circuit interface\n"
       "Interface name\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bgp_evpn_vpws, ctx);
	bgp_evpn_vpws_clear_interface(ctx);
	return CMD_SUCCESS;
}

/* ---------- locator NAME (per-instance SRv6 locator) ---------- */

DEFPY (bgp_evpn_vpws_locator,
       bgp_evpn_vpws_locator_cmd,
       "locator WORD$locname",
       "Bind a per-instance SRv6 locator for this VPWS End.DX2 SID\n"
       "SRv6 locator name\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bgp_evpn_vpws, ctx);

	bgp_evpn_vpws_set_locator(ctx, locname);
	return CMD_SUCCESS;
}

DEFPY (no_bgp_evpn_vpws_locator,
       no_bgp_evpn_vpws_locator_cmd,
       "no locator [WORD$locname]",
       NO_STR
       "Bind a per-instance SRv6 locator for this VPWS End.DX2 SID\n"
       "SRv6 locator name\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bgp_evpn_vpws, ctx);

	bgp_evpn_vpws_set_locator(ctx, NULL);
	return CMD_SUCCESS;
}

/* ---------- show bgp l2vpn evpn vpws [NAME] ---------- */

static void vpws_show_one(struct vty *vty, const struct bgp_evpn_vpws *vpws)
{
	char rd_buf[RD_ADDRSTRLEN];
	char peer_buf[INET6_ADDRSTRLEN] = "-";
	char *import_str = NULL, *export_str = NULL;

	prefix_rd2str(&vpws->prd, rd_buf, sizeof(rd_buf),
		      vpws->bgp ? vpws->bgp->asnotation : ASNOTATION_PLAIN);

	if (vpws->import_rtl)
		import_str = ecommunity_ecom2str(vpws->import_rtl, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
	if (vpws->export_rtl)
		export_str = ecommunity_ecom2str(vpws->export_rtl, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
	if (vpws->peer_present)
		inet_ntop(AF_INET6, &vpws->peer_sid, peer_buf, sizeof(peer_buf));


	char local_sid_buf[INET6_ADDRSTRLEN] = "-";

	if (vpws->sid_allocated)
		inet_ntop(AF_INET6, &vpws->local_sid, local_sid_buf, sizeof(local_sid_buf));

	vty_out(vty, "VPWS instance %s\n", vpws->name);
	vty_out(vty, "  EVI            : %u\n", vpws->evi);
	vty_out(vty, "  AC interface   : %s%s (ifindex=%u)\n",
		vpws->ac_ifname[0] ? vpws->ac_ifname : "(unbound)",
		vpws->ac_ifindex_valid ? "" : " [not operational]", vpws->ac_ifindex);
	vty_out(vty, "  Local SID      : %s%s\n", local_sid_buf,
		vpws->sid_requested && !vpws->sid_allocated ? " (alloc pending)" : "");
	vty_out(vty, "  SRv6 locator   : %s\n",
		vpws->locator_name[0] ? vpws->locator_name : "(BGP instance-wide)");
	vty_out(vty, "  Source AC-ID   : %u\n", vpws->source_ac_id);
	vty_out(vty, "  Target AC-ID   : %u\n", vpws->target_ac_id);
	vty_out(vty, "  RD             : %s%s\n", vpws->prd_set ? rd_buf : "(unset)",
		vpws->prd_set ? "" : "");
	vty_out(vty, "  Import RT      : %s\n", import_str ?: "(unset)");
	vty_out(vty, "  Export RT      : %s\n", export_str ?: "(unset)");
	vty_out(vty, "  EAD-EVI status : %s\n", vpws->advertised ? "advertised" : "not advertised");
	vty_out(vty, "  Peer SID       : %s\n", peer_buf);

	if (import_str)
		ecommunity_strfree(&import_str);
	if (export_str)
		ecommunity_strfree(&export_str);
}

DEFPY (show_bgp_l2vpn_evpn_vpws,
       show_bgp_l2vpn_evpn_vpws_cmd,
       "show bgp l2vpn evpn vpws [WORD$name]",
       SHOW_STR
       BGP_STR
       L2VPN_HELP_STR
       EVPN_HELP_STR
       "VPWS service instances\n"
       "Instance name (omit for all)\n")
{
	struct bgp *bgp = bgp_get_default();
	struct bgp_evpn_vpws *vpws;

	if (!bgp || !bgp->evpn_vpws_inited) {
		vty_out(vty, "No VPWS instances configured.\n");
		return CMD_SUCCESS;
	}

	if (name) {
		vpws = bgp_evpn_vpws_find(bgp, name);
		if (!vpws) {
			vty_out(vty, "%% No such VPWS instance: %s\n", name);
			return CMD_WARNING;
		}
		vpws_show_one(vty, vpws);
		return CMD_SUCCESS;
	}

	frr_each (evpn_vpws_list, &bgp->evpn_vpws_list, vpws) {
		vpws_show_one(vty, vpws);
		vty_out(vty, "\n");
	}
	return CMD_SUCCESS;
}

/* ---------- init ---------- */

void bgp_evpn_vpws_vty_init(void)
{
	install_node(&bgp_evpn_vpws_node);
	install_default(BGP_EVPN_VPWS_NODE);

	install_element(BGP_EVPN_NODE, &bgp_evpn_vpws_instance_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vpws_instance_cmd);

	install_element(BGP_EVPN_VPWS_NODE, &bgp_evpn_vpws_id_cmd);
	install_element(BGP_EVPN_VPWS_NODE, &bgp_evpn_vpws_evi_cmd);
	install_element(BGP_EVPN_VPWS_NODE, &bgp_evpn_vpws_rd_cmd);
	install_element(BGP_EVPN_VPWS_NODE, &bgp_evpn_vpws_rt_cmd);
	install_element(BGP_EVPN_VPWS_NODE, &no_bgp_evpn_vpws_rt_cmd);
	install_element(BGP_EVPN_VPWS_NODE, &bgp_evpn_vpws_interface_sid_cmd);
	install_element(BGP_EVPN_VPWS_NODE, &no_bgp_evpn_vpws_interface_cmd);
	install_element(BGP_EVPN_VPWS_NODE, &bgp_evpn_vpws_locator_cmd);
	install_element(BGP_EVPN_VPWS_NODE, &no_bgp_evpn_vpws_locator_cmd);
	install_element(BGP_EVPN_VPWS_NODE, &bgp_evpn_vpws_exit_cmd);

	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_vpws_cmd);
}
