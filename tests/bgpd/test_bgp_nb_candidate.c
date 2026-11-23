// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit tests for bgpd/bgp_nb_candidate.c helpers (P0-01 .. P0-07).
 * Exercises each helper with:
 *  (a) object only in candidate
 *  (b) object only in running
 *  (c) both candidate and running
 *  (d) same-transaction swap
 */

#include <zebra.h>
#include <assert.h>
#include <stdio.h>

#include "lib/command.h"
#include "lib/debug.h"
#include "lib/filter.h"
#include "lib/frrevent.h"
#include "lib/if.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/routemap.h"
#include "lib/routing_nb.h"
#include "lib/vrf.h"
#include "lib/yang.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_nb_candidate.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_filter_nb.h"
#include "bgpd/bgp_routemap_nb.h"
#include "bgpd/bgp_rpki_nb.h"
#ifdef ENABLE_BGP_VNC
#include "bgpd/bgp_vnc_nb.h"
#endif

struct event_loop *master;
struct zebra_privs_t bgpd_privs = {};

static const struct frr_yang_module_info *const test_yang_modules[] = {
	&frr_filter_info,	 &frr_interface_info,  &frr_route_map_info,
	&frr_vrf_info,		 &frr_routing_info,    &frr_bgp_info,
	&frr_bgp_route_map_info, &frr_bgp_filter_info, &frr_bgp_rpki_info,
#ifdef ENABLE_BGP_VNC
	&frr_bgp_vnc_info,
#endif
};

static int failed;

#define CHECK(cond, fmt, ...)                                                                     \
	do {                                                                                      \
		if (!(cond)) {                                                                    \
			fprintf(stderr, "FAIL (%s:%d): " fmt "\n", __func__, __LINE__,            \
				##__VA_ARGS__);                                                   \
			failed++;                                                                 \
			return;                                                                   \
		}                                                                                 \
	} while (0)

static struct lyd_node *new_tree(void)
{
	struct lyd_node *root = NULL;
	LY_ERR err;

	err = lyd_new_path(NULL, ly_native_ctx, "/frr-routing:routing", NULL, 0, &root);
	assert(err == LY_SUCCESS && root != NULL);
	return root;
}

static void add_path(struct lyd_node *root, const char *path, const char *val)
{
	LY_ERR err;

	err = lyd_new_path(root, ly_native_ctx, path, val, LYD_NEW_PATH_UPDATE, NULL);
	if (err != LY_SUCCESS) {
		fprintf(stderr, "lyd_new_path failed for %s = %s (err %d)\n", path,
			val ? val : "<null>", err);
		assert(err == LY_SUCCESS);
	}
}

static const char *bgp_path(char *buf, size_t len, const char *name, const char *vrf,
			    const char *suffix)
{
	snprintf(buf, len,
		 "/frr-routing:routing/control-plane-protocols/"
		 "control-plane-protocol[type='frr-bgp:bgp'][name='%s'][vrf='%s']"
		 "/frr-bgp:bgp%s",
		 name, vrf, suffix ? suffix : "");
	return buf;
}

static void add_bgp_instance(struct lyd_node *root, const char *name, const char *vrf,
			     const char *as, bool is_view)
{
	char p[XPATH_MAXLEN];

	add_path(root, bgp_path(p, sizeof(p), name, vrf, "/global/local-as"), as);
	if (is_view)
		add_path(root, bgp_path(p, sizeof(p), name, vrf, "/global/instance-type-view"),
			 "true");
}

/* --- P0-01: bgp_nb_cand_instance_key --- */
static void test_p0_01_instance_key(void)
{
	struct lyd_node *tree = new_tree();
	char p[XPATH_MAXLEN];
	const struct lyd_node *n;
	enum bgp_instance_type itype;
	const char *iname = NULL, *vrf = NULL;

	add_bgp_instance(tree, "default", "default", "65001", false);
	add_bgp_instance(tree, "vrf1", "vrf1", "65002", false);
	add_bgp_instance(tree, "myview", "view", "65003", true);

	/* Query from deep leaf under default */
	n = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default", "/global/local-as"));
	CHECK(bgp_nb_cand_instance_key(n, &itype, &iname, &vrf), "default key lookup failed");
	CHECK(itype == BGP_INSTANCE_TYPE_DEFAULT && iname == NULL && strmatch(vrf, "default"),
	      "default key mismatch");

	/* Query from VRF bgp node */
	n = yang_dnode_get(tree, bgp_path(p, sizeof(p), "vrf1", "vrf1", ""));
	CHECK(bgp_nb_cand_instance_key(n, &itype, &iname, &vrf), "vrf key lookup failed");
	CHECK(itype == BGP_INSTANCE_TYPE_VRF && strmatch(iname, "vrf1") && strmatch(vrf, "vrf1"),
	      "vrf key mismatch");

	/* Query from VIEW bgp node */
	n = yang_dnode_get(tree, bgp_path(p, sizeof(p), "myview", "view", ""));
	CHECK(bgp_nb_cand_instance_key(n, &itype, &iname, &vrf), "view key lookup failed");
	CHECK(itype == BGP_INSTANCE_TYPE_VIEW && strmatch(iname, "myview") && strmatch(vrf, "view"),
	      "view key mismatch");

	/* NULL safety */
	CHECK(!bgp_nb_cand_instance_key(NULL, &itype, &iname, &vrf), "NULL should fail");

	lyd_free_all(tree);
	printf("P0-01 instance_key: OK\n");
}

/* --- P0-02 & P0-03: each_instance & evpn_underlay --- */
struct count_ctx {
	int count;
	bool has_default;
	bool has_vrf1;
	bool has_vrf2;
};

static bool count_inst_cb(const struct lyd_node *bgp_dnode, void *arg)
{
	struct count_ctx *ctx = arg;
	enum bgp_instance_type itype;
	const char *iname = NULL;

	ctx->count++;
	if (bgp_nb_cand_instance_key(bgp_dnode, &itype, &iname, NULL)) {
		if (itype == BGP_INSTANCE_TYPE_DEFAULT)
			ctx->has_default = true;
		else if (iname && strmatch(iname, "vrf1"))
			ctx->has_vrf1 = true;
		else if (iname && strmatch(iname, "vrf2"))
			ctx->has_vrf2 = true;
	}
	return true;
}

static bool stop_after_one_cb(const struct lyd_node *bgp_dnode, void *arg)
{
	int *n = arg;

	(*n)++;
	return false;
}

static void test_p0_02_03_each_and_evpn_underlay(void)
{
	struct lyd_node *tree = new_tree();
	char p[XPATH_MAXLEN];
	struct count_ctx cctx = {};
	int stop_n = 0;
	const struct lyd_node *underlay;
	enum bgp_instance_type itype;
	const char *iname = NULL;

	/* (a) Only in candidate tree (running_config empty) */
	add_bgp_instance(tree, "default", "default", "65001", false);
	add_bgp_instance(tree, "vrf1", "vrf1", "65002", false);
	CHECK(bgp_nb_cand_each_instance_in_tree(tree, count_inst_cb, &cctx),
	      "each_instance returned false");
	CHECK(cctx.count == 2 && cctx.has_default && cctx.has_vrf1, "expected 2 instances, got %d",
	      cctx.count);

	CHECK(!bgp_nb_cand_each_instance_in_tree(tree, stop_after_one_cb, &stop_n) && stop_n == 1,
	      "early stop failed");

	/* Without advertise-all-vni, underlay falls back to default */
	underlay = bgp_nb_cand_evpn_underlay(tree);
	CHECK(underlay != NULL && bgp_nb_cand_instance_key(underlay, &itype, &iname, NULL) &&
		      itype == BGP_INSTANCE_TYPE_DEFAULT,
	      "expected default as fallback EVPN underlay");
	CHECK(!bgp_nb_cand_evpn_enabled(underlay), "evpn should not be enabled");

	/* Enable advertise-all-vni on vrf1 -> vrf1 becomes underlay */
	add_path(tree,
		 bgp_path(p, sizeof(p), "vrf1", "vrf1",
			  "/global/afi-safis/afi-safi"
			  "[afi-safi-name='frr-routing:l2vpn-evpn']"
			  "/l2vpn-evpn/advertise-all-vni"),
		 "true");
	underlay = bgp_nb_cand_evpn_underlay(tree);
	CHECK(underlay != NULL && bgp_nb_cand_instance_key(underlay, &itype, &iname, NULL) &&
		      itype == BGP_INSTANCE_TYPE_VRF && strmatch(iname, "vrf1"),
	      "expected vrf1 as EVPN underlay");
	CHECK(bgp_nb_cand_evpn_enabled(underlay), "vrf1 evpn should be enabled");

	/* (d) Swap: move advertise-all-vni to vrf2 and disable on vrf1 */
	add_bgp_instance(tree, "vrf2", "vrf2", "65003", false);
	add_path(tree,
		 bgp_path(p, sizeof(p), "vrf1", "vrf1",
			  "/global/afi-safis/afi-safi"
			  "[afi-safi-name='frr-routing:l2vpn-evpn']"
			  "/l2vpn-evpn/advertise-all-vni"),
		 "false");
	add_path(tree,
		 bgp_path(p, sizeof(p), "vrf2", "vrf2",
			  "/global/afi-safis/afi-safi"
			  "[afi-safi-name='frr-routing:l2vpn-evpn']"
			  "/l2vpn-evpn/advertise-all-vni"),
		 "true");
	underlay = bgp_nb_cand_evpn_underlay(tree);
	CHECK(underlay != NULL && bgp_nb_cand_instance_key(underlay, &itype, &iname, NULL) &&
		      itype == BGP_INSTANCE_TYPE_VRF && strmatch(iname, "vrf2"),
	      "expected vrf2 after swap");

	/* (b) Only in running_config when no transaction is active */
	struct nb_config *saved_running = running_config;
	struct nb_config fake_running = { .dnode = tree };

	running_config = &fake_running;
	memset(&cctx, 0, sizeof(cctx));
	CHECK(bgp_nb_cand_each_instance(count_inst_cb, &cctx) && cctx.count == 3 && cctx.has_vrf2,
	      "running fallback failed (count=%d)", cctx.count);
	underlay = bgp_nb_cand_evpn_underlay(NULL);
	CHECK(underlay != NULL && bgp_nb_cand_instance_key(underlay, &itype, &iname, NULL) &&
		      strmatch(iname, "vrf2"),
	      "running underlay fallback failed");
	running_config = saved_running;

	lyd_free_all(tree);
	printf("P0-02/P0-03 each_instance & evpn_underlay: OK\n");
}

/* --- P0-04 & P0-05: group_members, peer_group, peer_sort --- */
static bool count_members_cb(const struct lyd_node *member, void *arg)
{
	int *cnt = arg;

	(*cnt)++;
	return true;
}

static void test_p0_04_05_group_and_sort(void)
{
	struct lyd_node *tree = new_tree();
	char p[XPATH_MAXLEN];
	const struct lyd_node *g1, *g2, *n1, *n2, *n3, *n4, *n5;
	int cnt = 0;

	add_bgp_instance(tree, "default", "default", "65001", false);
	/* Confederation setup */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default", "/global/confederation/identifier"),
		 "100");
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default", "/global/confederation/member-as"),
		 "65002");

	/* Peer-group G1: remote-as external */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/peer-groups/peer-group[peer-group-name='G1']"
			  "/neighbor-remote-as/remote-as-type"),
		 "external");
	/* Peer-group G2: untyped */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/peer-groups/peer-group[peer-group-name='G2']"),
		 NULL);

	/* n1: member of G1 inheriting external */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.1']"
			  "/peer-group"),
		 "G1");
	/* n2: unnumbered member of G1 overriding to iBGP */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/unnumbered-neighbor[interface='eth0']"
			  "/peer-group"),
		 "G1");
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/unnumbered-neighbor[interface='eth0']"
			  "/neighbor-remote-as/remote-as-type"),
		 "internal");
	/* n3: confederation member-AS peer */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.3']"
			  "/neighbor-remote-as/remote-as-type"),
		 "as-specified");
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.3']"
			  "/neighbor-remote-as/remote-as"),
		 "65002");
	/* n4: remote-as auto in G2 */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.4']"
			  "/peer-group"),
		 "G2");
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.4']"
			  "/neighbor-remote-as/remote-as-type"),
		 "auto");
	/* n5: standalone iBGP via as-specified == local-as */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.5']"
			  "/neighbor-remote-as/remote-as-type"),
		 "as-specified");
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.5']"
			  "/neighbor-remote-as/remote-as"),
		 "65001");

	g1 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/peer-groups/peer-group[peer-group-name='G1']"));
	g2 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/peer-groups/peer-group[peer-group-name='G2']"));
	n1 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/neighbors/neighbor[remote-address='10.0.0.1']"));
	n2 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/neighbors/unnumbered-neighbor[interface='eth0']"));
	n3 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/neighbors/neighbor[remote-address='10.0.0.3']"));
	n4 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/neighbors/neighbor[remote-address='10.0.0.4']"));
	n5 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/neighbors/neighbor[remote-address='10.0.0.5']"));

	CHECK(bgp_nb_cand_peer_group(n1) == g1, "n1 group mismatch");
	CHECK(bgp_nb_cand_peer_group(n2) == g1, "n2 group mismatch");
	CHECK(bgp_nb_cand_peer_group(n3) == NULL, "n3 should have no group");

	bgp_nb_cand_group_members(g1, count_members_cb, &cnt);
	CHECK(cnt == 2, "G1 should have 2 members, got %d", cnt);

	/* Sorts */
	CHECK(bgp_nb_cand_peer_sort(g1) == BGP_PEER_EBGP, "G1 sort");
	CHECK(bgp_nb_cand_peer_sort(n1) == BGP_PEER_EBGP, "n1 inherited sort");
	CHECK(bgp_nb_cand_peer_sort(n2) == BGP_PEER_IBGP, "n2 override sort");
	CHECK(bgp_nb_cand_peer_sort(n3) == BGP_PEER_CONFED, "n3 confed sort");
	CHECK(bgp_nb_cand_peer_sort(n4) == BGP_PEER_EBGP, "n4 auto sort");
	CHECK(bgp_nb_cand_peer_sort(g2) == BGP_PEER_INTERNAL, "G2 untyped w/ auto member sort");
	CHECK(bgp_nb_cand_peer_sort(n5) == BGP_PEER_IBGP, "n5 iBGP sort");

	/* Group member sort checks: G1 has one EBGP and one IBGP */
	CHECK(!bgp_nb_cand_group_members_match_sort(g1, BGP_PEER_EBGP, true),
	      "G1 members are not all EBGP");
	CHECK(!bgp_nb_cand_group_members_match_sort(g1, BGP_PEER_IBGP, false),
	      "G1 has an IBGP member");

	/* (d) Same-transaction swap: move n2 from G1 to G2 */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/unnumbered-neighbor[interface='eth0']"
			  "/peer-group"),
		 "G2");
	CHECK(bgp_nb_cand_peer_group(n2) == g2, "n2 swap to G2 failed");
	CHECK(bgp_nb_cand_group_members_match_sort(g1, BGP_PEER_EBGP, true),
	      "G1 members should now all be EBGP");

	lyd_free_all(tree);
	printf("P0-04/P0-05 group_members & peer_sort: OK\n");
}

/* --- P0-06: enabled_afs --- */
static void test_p0_06_enabled_afs(void)
{
	struct lyd_node *tree = new_tree();
	char p[XPATH_MAXLEN];
	const struct lyd_node *n1, *n2, *g1;
	bool afs[AFI_MAX][SAFI_MAX];

	add_bgp_instance(tree, "default", "default", "65001", false);
	add_path(tree, bgp_path(p, sizeof(p), "default", "default", "/global/default-afi-safi"),
		 "ipv4-unicast");
	add_path(tree, bgp_path(p, sizeof(p), "default", "default", "/global/default-afi-safi"),
		 "ipv6-unicast");

	/* G1: explicitly disables ipv4-unicast, enables l2vpn-evpn */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/peer-groups/peer-group[peer-group-name='G1']"
			  "/afi-safis/afi-safi[afi-safi-name='frr-routing:ipv4-unicast']"
			  "/enabled"),
		 "false");
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/peer-groups/peer-group[peer-group-name='G1']"
			  "/afi-safis/afi-safi[afi-safi-name='frr-routing:l2vpn-evpn']"
			  "/enabled"),
		 "true");

	/* n1: standalone neighbor (inherits defaults only) */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.1']"
			  "/neighbor-remote-as/remote-as-type"),
		 "external");

	/* n2: member of G1, explicitly overrides ipv4-unicast back to true */
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.2']"
			  "/peer-group"),
		 "G1");
	add_path(tree,
		 bgp_path(p, sizeof(p), "default", "default",
			  "/neighbors/neighbor[remote-address='10.0.0.2']"
			  "/afi-safis/afi-safi[afi-safi-name='frr-routing:ipv4-unicast']"
			  "/enabled"),
		 "true");

	g1 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/peer-groups/peer-group[peer-group-name='G1']"));
	n1 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/neighbors/neighbor[remote-address='10.0.0.1']"));
	n2 = yang_dnode_get(tree, bgp_path(p, sizeof(p), "default", "default",
					   "/neighbors/neighbor[remote-address='10.0.0.2']"));

	bgp_nb_cand_enabled_afs(n1, afs);
	CHECK(afs[AFI_IP][SAFI_UNICAST] && afs[AFI_IP6][SAFI_UNICAST] && !afs[AFI_L2VPN][SAFI_EVPN],
	      "n1 default AFs mismatch");

	CHECK(!bgp_nb_cand_peer_af_enabled(g1, AFI_IP, SAFI_UNICAST), "G1 v4 should be disabled");
	CHECK(bgp_nb_cand_peer_af_enabled(g1, AFI_IP6, SAFI_UNICAST),
	      "G1 v6 should inherit default");
	CHECK(bgp_nb_cand_peer_af_enabled(g1, AFI_L2VPN, SAFI_EVPN), "G1 evpn should be enabled");

	bgp_nb_cand_enabled_afs(n2, afs);
	CHECK(afs[AFI_IP][SAFI_UNICAST] && afs[AFI_IP6][SAFI_UNICAST] && afs[AFI_L2VPN][SAFI_EVPN],
	      "n2 effective AFs mismatch");

	lyd_free_all(tree);
	printf("P0-06 enabled_afs: OK\n");
}

/* --- P0-07: bgp_nb_assert_applied --- */
static void test_p0_07_assert_applied(void)
{
	int dummy = 1;

	CHECK(bgp_nb_assert_applied(&dummy, "dummy"), "non-NULL should pass");
	CHECK(!bgp_nb_assert_applied(NULL, "missing-obj"), "NULL should return false");
	printf("P0-07 assert_applied: OK\n");
}

/* --- (c)/(d) Real NB transaction: candidate vs running & same-tx swap --- */
static void test_nb_transaction_candidate_vs_running(void)
{
	struct nb_config *cand = nb_config_dup(running_config);
	struct nb_config_cbs changes;
	char errmsg[BUFSIZ] = {};
	char p[XPATH_MAXLEN];
	int ret;

	/* Commit default instance into running */
	add_bgp_instance(cand->dnode, "default", "default", "65001", false);
	add_path(cand->dnode,
		 bgp_path(p, sizeof(p), "default", "default", "/global/default-afi-safi"),
		 "ipv4-unicast");
	ret = nb_candidate_commit((struct nb_context){ .client = NB_CLIENT_NONE }, cand, true,
				  "seed default", NULL, errmsg, sizeof(errmsg));
	CHECK(ret == NB_OK, "commit default failed: %s", errmsg);

	/* Both candidate and running have default; add vrf1 only in candidate */
	add_bgp_instance(cand->dnode, "vrf1", "vrf1", "65002", false);
	struct count_ctx rctx = {}, cctx = {};

	bgp_nb_cand_each_instance(count_inst_cb, &rctx);
	bgp_nb_cand_each_instance_in_tree(cand->dnode, count_inst_cb, &cctx);
	CHECK(rctx.count == 1 && rctx.has_default && !rctx.has_vrf1,
	      "running should have 1 instance, got %d", rctx.count);
	CHECK(cctx.count == 2 && cctx.has_default && cctx.has_vrf1,
	      "candidate should have 2 instances, got %d", cctx.count);

	/* Same-transaction swap: delete default, commit vrf1 */
	struct lyd_node *dflt_cpp =
		yang_dnode_get(cand->dnode,
			       "/frr-routing:routing/control-plane-protocols/"
			       "control-plane-protocol[type='frr-bgp:bgp'][name='default'][vrf='default']");
	CHECK(dflt_cpp != NULL, "default cpp not found");
	lyd_free_tree(dflt_cpp);

	RB_INIT(nb_config_cbs, &changes);
	ret = nb_candidate_commit((struct nb_context){ .client = NB_CLIENT_NONE }, cand, true,
				  "swap default -> vrf1", NULL, errmsg, sizeof(errmsg));
	CHECK(ret == NB_OK, "swap commit failed: %s", errmsg);

	memset(&rctx, 0, sizeof(rctx));
	bgp_nb_cand_each_instance(count_inst_cb, &rctx);
	CHECK(rctx.count == 1 && !rctx.has_default && rctx.has_vrf1,
	      "after swap expected only vrf1, got count=%d", rctx.count);

	nb_config_free(cand);
	printf("P0 nb_transaction candidate_vs_running_and_swap: OK\n");
}

int main(int argc, char **argv)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;

	cmd_init(1);
	debug_init();
	zlog_aux_init("NONE: ", LOG_DEBUG);
	zprivs_preinit(&bgpd_privs);
	zprivs_init(&bgpd_privs);

	master = event_master_create(NULL);
	nb_init(master, test_yang_modules, array_size(test_yang_modules), false, false);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	hook_register(routing_destroy, bgp_nb_routing_destroy);
	hook_register(routing_destroy_validate, bgp_nb_routing_destroy);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	vrf_init(NULL, NULL, NULL, NULL);
	frr_pthread_init();
	bgp_init(0);
	bgp_pthreads_run();

	test_p0_01_instance_key();
	test_p0_02_03_each_and_evpn_underlay();
	test_p0_04_05_group_and_sort();
	test_p0_06_enabled_afs();
	test_p0_07_assert_applied();
	test_nb_transaction_candidate_vs_running();

	bgp_terminate();
	bgp_close();
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_delete(bgp);
	bgp_dump_finish();
	bgp_route_finish();
	bgp_route_map_terminate();
	bgp_attr_finish();
	bgp_labels_finish();
	bgp_lp_finish();
	bgp_evpn_mh_finish();
	bgp_pthreads_finish();

	return failed ? 1 : 0;
}
