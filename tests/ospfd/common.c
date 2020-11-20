#include <zebra.h>

#include "lib/stream.h"
#include "lib/vty.h"
#include "lib/mpls.h"
#include "lib/if.h"
#include "lib/table.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_sr.h"

#include "common.h"

struct thread_master *master;
struct zebra_privs_t ospfd_privs;


struct ospf_topology *test_find_topology(const char *name)
{
	if (strmatch(name, "topo1"))
		return &topo1;
	else if (strmatch(name, "topo2"))
		return &topo2;
	else if (strmatch(name, "topo3"))
		return &topo3;
	else if (strmatch(name, "topo4"))
		return &topo4;
	else if (strmatch(name, "topo5"))
		return &topo5;

	return NULL;
}

int sort_paths(const void **path1, const void **path2)
{
	const struct ospf_path *p1 = *path1;
	const struct ospf_path *p2 = *path2;

	return (p1->nexthop.s_addr - p2->nexthop.s_addr);
}

void print_route_table(struct vty *vty, struct route_table *rt)
{
	struct route_node *rn;
	struct ospf_route * or ;
	struct listnode *pnode;
	struct ospf_path *path;
	struct mpls_label_stack *label_stack;
	char buf[MPLS_LABEL_STRLEN];

	for (rn = route_top(rt); rn; rn = route_next(rn)) {
		if ((or = rn->info) == NULL)
			continue;

		vty_out(vty, "N %-18pFX %-15pI4 %d\n", &rn->p,
			& or->u.std.area_id, or->cost);

		list_sort(or->paths, sort_paths);

		for (ALL_LIST_ELEMENTS_RO(or->paths, pnode, path)) {
			if (path->nexthop.s_addr == 0)
				continue;

			vty_out(vty, "  -> %pI4 with adv router %pI4",
				&path->nexthop, &path->adv_router);

			if (path->srni.backup_label_stack) {
				label_stack = path->srni.backup_label_stack;
				mpls_label2str(label_stack->num_labels,
					       label_stack->label, buf,
					       MPLS_LABEL_STRLEN, true);
				vty_out(vty, " and backup path %s", buf);
			}
			vty_out(vty, "\n");
		}
	}
}

struct ospf_test_node *test_find_node(struct ospf_topology *topology,
				      const char *hostname)
{
	for (int i = 0; topology->nodes[i].hostname[0]; i++)
		if (strmatch(hostname, topology->nodes[i].hostname))
			return &topology->nodes[i];

	return NULL;
}

static void inject_router_lsa(struct vty *vty, struct ospf *ospf,
			      struct ospf_topology *topology,
			      struct ospf_test_node *root,
			      struct ospf_test_node *tnode)
{
	struct ospf_area *area;
	struct in_addr router_id;
	struct in_addr adj_router_id;
	struct prefix_ipv4 prefix;
	struct in_addr data;
	struct stream *s;
	struct lsa_header *lsah;
	struct ospf_lsa *new;
	int length;
	unsigned long putp;
	uint16_t link_count;
	struct ospf_test_node *tfound_adj_node;
	struct ospf_test_adj *tadj;
	bool is_self_lsa = false;

	area = ospf->backbone;
	inet_aton(tnode->router_id, &router_id);

	if (strncmp(root->router_id, tnode->router_id, 256) == 0)
		is_self_lsa = true;

	s = stream_new(OSPF_MAX_LSA_SIZE);
	lsa_header_set(s, LSA_OPTIONS_GET(area) | LSA_OPTIONS_NSSA_GET(area),
		       OSPF_ROUTER_LSA, router_id, router_id);

	stream_putc(s, router_lsa_flags(area));
	stream_putc(s, 0);

	putp = stream_get_endp(s);
	stream_putw(s, 0);

	for (link_count = 0; tnode->adjacencies[link_count].hostname[0];
	     link_count++) {
		tadj = &tnode->adjacencies[link_count];
		tfound_adj_node = test_find_node(topology, tadj->hostname);
		str2prefix_ipv4(tnode->adjacencies[link_count].network,
				&prefix);

		inet_aton(tfound_adj_node->router_id, &adj_router_id);
		data.s_addr = prefix.prefix.s_addr;
		link_info_set(&s, adj_router_id, data,
			      LSA_LINK_TYPE_POINTOPOINT, 0, tadj->metric);

		masklen2ip(prefix.prefixlen, &data);
		link_info_set(&s, prefix.prefix, data, LSA_LINK_TYPE_STUB, 0,
			      tadj->metric);
	}

	/* Don't forget the node itself (just a stub) */
	str2prefix_ipv4(tnode->router_id, &prefix);
	data.s_addr = 0xffffffff;
	link_info_set(&s, prefix.prefix, data, LSA_LINK_TYPE_STUB, 0, 0);

	/* Take twice the link count (for P2P and stub) plus the local stub */
	stream_putw_at(s, putp, (2 * link_count) + 1);

	length = stream_get_endp(s);
	lsah = (struct lsa_header *)STREAM_DATA(s);
	lsah->length = htons(length);

	new = ospf_lsa_new_and_data(length);
	new->area = area;
	new->vrf_id = area->ospf->vrf_id;

	if (is_self_lsa)
		SET_FLAG(new->flags, OSPF_LSA_SELF | OSPF_LSA_SELF_CHECKED);

	memcpy(new->data, lsah, length);
	stream_free(s);

	ospf_lsdb_add(area->lsdb, new);

	if (is_self_lsa) {
		ospf_lsa_unlock(&area->router_lsa_self);
		area->router_lsa_self = ospf_lsa_lock(new);
	}
}

static void inject_sr_db_entry(struct vty *vty, struct ospf_test_node *tnode,
			       struct ospf_topology *topology)
{
	struct ospf_test_node *tfound_adj_node;
	struct ospf_test_adj *tadj;
	struct in_addr router_id;
	struct in_addr remote_id;
	struct sr_node *srn;
	struct sr_prefix *srp;
	struct sr_link *srl;
	int link_count;

	inet_aton(tnode->router_id, &router_id);

	srn = ospf_sr_node_create(&router_id);

	srn->srgb.range_size = 8000;
	srn->srgb.lower_bound = 16000;
	srn->msd = 16;

	srn->srlb.range_size = 1000;
	srn->srlb.lower_bound = 15000;

	/* Prefix SID */
	srp = XCALLOC(MTYPE_OSPF_SR_PARAMS, sizeof(struct sr_prefix));
	srp->adv_router = router_id;
	srp->sid = tnode->label;
	srp->srn = srn;

	listnode_add(srn->ext_prefix, srp);

	/* Adjacency SIDs for all adjacencies */
	for (link_count = 0; tnode->adjacencies[link_count].hostname[0];
	     link_count++) {
		tadj = &tnode->adjacencies[link_count];
		tfound_adj_node = test_find_node(topology, tadj->hostname);

		srl = XCALLOC(MTYPE_OSPF_SR_PARAMS, sizeof(struct sr_link));
		srl->adv_router = router_id;

		inet_aton(tfound_adj_node->router_id, &remote_id);
		srl->remote_id = remote_id;

		srl->type = ADJ_SID;
		srl->sid[0] = srn->srlb.lower_bound + tadj->label;
		srl->srn = srn;

		listnode_add(srn->ext_link, srl);
	}
}

int topology_load(struct vty *vty, struct ospf_topology *topology,
		  struct ospf_test_node *root, struct ospf *ospf)
{
	struct ospf_test_node *tnode;

	for (int i = 0; topology->nodes[i].hostname[0]; i++) {
		tnode = &topology->nodes[i];

		/* Inject a router LSA for each node, used for SPF */
		inject_router_lsa(vty, ospf, topology, root, tnode);

		/*
		 * SR information could also be inected via LSAs, but directly
		 * filling the SR DB with labels is just easier.
		 */
		inject_sr_db_entry(vty, tnode, topology);
	}

	return 0;
}
