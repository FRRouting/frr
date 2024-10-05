// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra MPLS Data structures and definitions
 * Copyright (C) 2015 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_MPLS_H
#define _ZEBRA_MPLS_H

#include "prefix.h"
#include "table.h"
#include "queue.h"
#include "hash.h"
#include "jhash.h"
#include "nexthop.h"
#include "vty.h"
#include "memory.h"
#include "mpls.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "hook.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Definitions and macros. */

#define NHLFE_FAMILY(nhlfe)                                                    \
	(((nhlfe)->nexthop->type == NEXTHOP_TYPE_IPV6                          \
	  || (nhlfe)->nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX)              \
		 ? AF_INET6                                                    \
		 : AF_INET)

/* Declare LSP nexthop list types */
PREDECL_DLIST(nhlfe_list);

/*
 * (Outgoing) nexthop label forwarding entry
 */
struct zebra_nhlfe {
	/* Type of entry - static etc. */
	enum lsp_types_t type;

	/* Nexthop information (with outgoing label) */
	struct nexthop *nexthop;

	/* Backpointer to base entry. */
	struct zebra_lsp *lsp;

	/* Runtime info - flags, pointers etc. */
	uint32_t flags;
#define NHLFE_FLAG_CHANGED     (1 << 0)
#define NHLFE_FLAG_SELECTED    (1 << 1)
#define NHLFE_FLAG_MULTIPATH   (1 << 2)
#define NHLFE_FLAG_DELETED     (1 << 3)
#define NHLFE_FLAG_INSTALLED   (1 << 4)
#define NHLFE_FLAG_IS_BACKUP   (1 << 5)

	uint8_t distance;

	/* Linkage for LSPs' lists */
	struct nhlfe_list_item list;
};

/*
 * Incoming label entry
 */
struct zebra_ile {
	mpls_label_t in_label;
};

/*
 * Label swap entry (ile -> list of nhlfes)
 */
struct zebra_lsp {
	/* Incoming label */
	struct zebra_ile ile;

	/* List of NHLFEs, pointer to best, and num equal-cost. */
	struct nhlfe_list_head nhlfe_list;

	struct zebra_nhlfe *best_nhlfe;
	uint32_t num_ecmp;

	/* Backup nhlfes, if present. The nexthop in a primary/active nhlfe
	 * refers to its backup (if any) by index, so the order of this list
	 * is significant.
	 */
	struct nhlfe_list_head backup_nhlfe_list;

	/* Flags */
	uint32_t flags;
#define LSP_FLAG_SCHEDULED        (1 << 0)
#define LSP_FLAG_INSTALLED        (1 << 1)
#define LSP_FLAG_CHANGED          (1 << 2)
#define LSP_FLAG_FPM              (1 << 3)

	/* Address-family of NHLFE - saved here for delete. All NHLFEs */
	/* have to be of the same AF */
	uint8_t addr_family;
};

/*
 * FEC to label binding.
 */
struct zebra_fec {
	/* FEC (prefix) */
	struct route_node *rn;

	/* In-label - either statically bound or derived from label block. */
	mpls_label_t label;

	/* Label index (into global label block), if valid */
	uint32_t label_index;

	/* Flags. */
	uint32_t flags;
#define FEC_FLAG_CONFIGURED       (1 << 0)

	/* Clients interested in this FEC. */
	struct list *client_list;
};

/* Declare typesafe list apis/macros */
DECLARE_DLIST(nhlfe_list, struct zebra_nhlfe, list);

/* Function declarations. */

/*
 * Add/update global label block.
 */
int zebra_mpls_label_block_add(struct zebra_vrf *zvrf, uint32_t start_label,
			       uint32_t end_label);

/*
 * Delete global label block.
 */
int zebra_mpls_label_block_del(struct zebra_vrf *vrf);

/*
 * Display MPLS global label block configuration (VTY command handler).
 */
int zebra_mpls_write_label_block_config(struct vty *vty, struct zebra_vrf *vrf);

/*
 * Install dynamic LSP entry.
 */
void zebra_mpls_lsp_install(struct zebra_vrf *zvrf, struct route_node *rn,
			   struct route_entry *re);

/*
 * Uninstall dynamic LSP entry, if any.
 */
int zebra_mpls_lsp_uninstall(struct zebra_vrf *zvrf, struct route_node *rn,
			     struct route_entry *re);

/* Add an NHLFE to an LSP, return the newly-added object */
struct zebra_nhlfe *
zebra_mpls_lsp_add_nhlfe(struct zebra_lsp *lsp, enum lsp_types_t lsp_type,
			 enum nexthop_types_t gtype, const union g_addr *gate,
			 ifindex_t ifindex, uint8_t num_labels,
			 const mpls_label_t *out_labels);

/* Add or update a backup NHLFE for an LSP; return the object */
struct zebra_nhlfe *zebra_mpls_lsp_add_backup_nhlfe(
	struct zebra_lsp *lsp, enum lsp_types_t lsp_type,
	enum nexthop_types_t gtype, const union g_addr *gate, ifindex_t ifindex,
	uint8_t num_labels, const mpls_label_t *out_labels);

/*
 * Add NHLFE or backup NHLFE to an LSP based on a nexthop. These just maintain
 * the LSP and NHLFE objects; nothing is scheduled for processing.
 * Return: the newly-added object
 */
struct zebra_nhlfe *zebra_mpls_lsp_add_nh(struct zebra_lsp *lsp,
					  enum lsp_types_t lsp_type,
					  const struct nexthop *nh);
struct zebra_nhlfe *zebra_mpls_lsp_add_backup_nh(struct zebra_lsp *lsp,
						 enum lsp_types_t lsp_type,
						 const struct nexthop *nh);

/* Free an allocated NHLFE */
void zebra_mpls_nhlfe_free(struct zebra_nhlfe *nhlfe);

int zebra_mpls_fec_register(struct zebra_vrf *zvrf, struct prefix *p,
			    uint32_t label, uint32_t label_index,
			    struct zserv *client);

/*
 * Deregistration from a client for the label binding for a FEC. The FEC
 * itself is deleted if no other registered clients exist and there is no
 * label bound to the FEC.
 */
int zebra_mpls_fec_unregister(struct zebra_vrf *zvrf, struct prefix *p,
			      struct zserv *client);

/*
 * Return FEC (if any) to which this label is bound.
 * Note: Only works for per-prefix binding and when the label is not
 * implicit-null.
 * TODO: Currently walks entire table, can optimize later with another
 * hash..
 */
struct zebra_fec *zebra_mpls_fec_for_label(struct zebra_vrf *zvrf,
					   struct prefix *p, mpls_label_t label);

/*
 * Inform if specified label is currently bound to a FEC or not.
 */
int zebra_mpls_label_already_bound(struct zebra_vrf *zvrf, struct prefix *p,
				   mpls_label_t label);

/*
 * Add static FEC to label binding. If there are clients registered for this
 * FEC, notify them. If there are labeled routes for this FEC, install the
 * label forwarding entry.
 */
int zebra_mpls_static_fec_add(struct zebra_vrf *zvrf, struct prefix *p,
			      mpls_label_t in_label);

/*
 * Remove static FEC to label binding. If there are no clients registered
 * for this FEC, delete the FEC; else notify clients.
 * Note: Upon delete of static binding, if label index exists for this FEC,
 * client may need to be updated with derived label.
 */
int zebra_mpls_static_fec_del(struct zebra_vrf *zvrf, struct prefix *p);

/*
 * Display MPLS FEC to label binding configuration (VTY command handler).
 */
int zebra_mpls_write_fec_config(struct vty *vty, struct zebra_vrf *zvrf);

/*
 * Display MPLS FEC to label binding (VTY command handler).
 */
void zebra_mpls_print_fec_table(struct vty *vty, struct zebra_vrf *zvrf);

/*
 * Display MPLS FEC to label binding for a specific FEC (VTY command handler).
 */
void zebra_mpls_print_fec(struct vty *vty, struct zebra_vrf *zvrf,
			  struct prefix *p);

/*
 * Handle zapi request to install/uninstall LSP and
 * (optionally) FEC-To-NHLFE (FTN) bindings.
 *
 * mpls_zapi_labels_process -> Installs for future processing
 *                             in the meta-q
 * zebra_mpls_labels_process -> called by the meta-q
 */
void mpls_zapi_labels_process(bool add_p, struct zebra_vrf *zvrf,
			      const struct zapi_labels *zl);
void zebra_mpls_zapi_labels_process(bool add_p, struct zebra_vrf *zvrf,
				    const struct zapi_labels *zl);

/*
 * Upon reconfiguring nexthop-resolution updates, update the
 * lsp entries accordingly.
 */
void zebra_mpls_fec_nexthop_resolution_update(struct zebra_vrf *zvrf);

/*
 * Uninstall all NHLFEs bound to a single FEC.
 *
 * mpls_ftn_uninstall -> Called to enqueue into early label processing
 *                       via the metaq
 * zebra_mpls_ftn_uninstall -> Called when we process the meta q
 *                             for this item
 */
void mpls_ftn_uninstall(struct zebra_vrf *zvrf, enum lsp_types_t type,
			struct prefix *prefix, uint8_t route_type,
			uint8_t route_instance);
void zebra_mpls_ftn_uninstall(struct zebra_vrf *zvrf, enum lsp_types_t type,
			      struct prefix *prefix, uint8_t route_type,
			      uint8_t route_instance);
/*
 * Install/update a NHLFE for an LSP in the forwarding table. This may be
 * a new LSP entry or a new NHLFE for an existing in-label or an update of
 * the out-label(s) for an existing NHLFE (update case).
 */
int mpls_lsp_install(struct zebra_vrf *zvrf, enum lsp_types_t type,
		     mpls_label_t in_label, uint8_t num_out_labels,
		     const mpls_label_t *out_labels, enum nexthop_types_t gtype,
		     const union g_addr *gate, ifindex_t ifindex);

/*
 * Lookup LSP by its input label.
 */
struct zebra_lsp *mpls_lsp_find(struct zebra_vrf *zvrf, mpls_label_t in_label);

/*
 * Uninstall a particular NHLFE in the forwarding table. If this is
 * the only NHLFE, the entire LSP forwarding entry has to be deleted.
 */
int mpls_lsp_uninstall(struct zebra_vrf *zvrf, enum lsp_types_t type,
		       mpls_label_t in_label, enum nexthop_types_t gtype,
		       const union g_addr *gate, ifindex_t ifindex,
		       bool backup_p);

/*
 * Uninstall all NHLFEs for a particular LSP forwarding entry.
 */
int mpls_lsp_uninstall_all_vrf(struct zebra_vrf *zvrf, enum lsp_types_t type,
			       mpls_label_t in_label);

#if defined(HAVE_CUMULUS)
/*
 * Check that the label values used in LSP creation are consistent. The
 * main criteria is that if there is ECMP, the label operation must still
 * be consistent - i.e., all paths either do a swap or do PHP. This is due
 * to current HW restrictions.
 */
int zebra_mpls_lsp_label_consistent(struct zebra_vrf *zvrf,
				    mpls_label_t in_label,
				    mpls_label_t out_label,
				    enum nexthop_types_t gtype,
				    union g_addr *gate, ifindex_t ifindex);
#endif /* HAVE_CUMULUS */

/*
 * Add static LSP entry. This may be the first entry for this incoming label
 * or an additional nexthop; an existing entry may also have outgoing label
 * changed.
 * Note: The label operation (swap or PHP) is common for the LSP entry (all
 * NHLFEs).
 */
int zebra_mpls_static_lsp_add(struct zebra_vrf *zvrf, mpls_label_t in_label,
			      mpls_label_t out_label,
			      enum nexthop_types_t gtype, union g_addr *gate,
			      ifindex_t ifindex);

/*
 * Delete static LSP entry. This may be the delete of one particular
 * NHLFE for this incoming label or the delete of the entire entry (i.e.,
 * all NHLFEs).
 * NOTE: Delete of the only NHLFE will also end up deleting the entire
 * LSP configuration.
 */
int zebra_mpls_static_lsp_del(struct zebra_vrf *zvrf, mpls_label_t in_label,
			      enum nexthop_types_t gtype, union g_addr *gate,
			      ifindex_t ifindex);

/*
 * Process LSP update results from zebra dataplane.
 */
/* Forward ref of dplane update context type */
struct zebra_dplane_ctx;

void zebra_mpls_lsp_dplane_result(struct zebra_dplane_ctx *ctx);

/* Process async dplane notifications. */
void zebra_mpls_process_dplane_notify(struct zebra_dplane_ctx *ctx);

/*
 * Schedule all MPLS label forwarding entries for processing.
 * Called upon changes that may affect one or more of them such as
 * interface or nexthop state changes.
 */
void zebra_mpls_lsp_schedule(struct zebra_vrf *zvrf);

/*
 * Display MPLS label forwarding table for a specific LSP
 * (VTY command handler).
 */
void zebra_mpls_print_lsp(struct vty *vty, struct zebra_vrf *zvrf,
			  mpls_label_t label, bool use_json);

/*
 * Display MPLS label forwarding table (VTY command handler).
 */
void zebra_mpls_print_lsp_table(struct vty *vty, struct zebra_vrf *zvrf,
				bool use_json);

/*
 * Display MPLS LSP configuration of all static LSPs (VTY command handler).
 */
int zebra_mpls_write_lsp_config(struct vty *vty, struct zebra_vrf *zvrf);

/*
 * Called when VRF becomes inactive, cleans up information but keeps
 * the table itself.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_mpls_cleanup_tables(struct zebra_vrf *zvrf);

/*
 * Called upon process exiting, need to delete LSP forwarding
 * entries from the kernel.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_mpls_close_tables(struct zebra_vrf *zvrf);

/*
 * Allocate MPLS tables for this VRF.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_mpls_init_tables(struct zebra_vrf *zvrf);

/*
 * If mpls is turned on *after* FRR is brought
 * up let's actually notice this and turn on
 * the relevant bits to make it work.
 */
void zebra_mpls_turned_on(void);

/*
 * Global MPLS initialization/termination.
 */
void zebra_mpls_init(void);
void zebra_mpls_terminate(void);

/*
 * MPLS VTY.
 */
void zebra_mpls_vty_init(void);

/*
 * When cleaning up a client connection ensure that there are no
 * vrf labels that need cleaning up too
 */
void zebra_mpls_client_cleanup_vrf_label(uint8_t proto);

/* Inline functions. */

/*
 * Distance (priority) definition for LSP NHLFE.
 */
static inline uint8_t lsp_distance(enum lsp_types_t type)
{
	switch (type) {
	case ZEBRA_LSP_STATIC:
		return (route_distance(ZEBRA_ROUTE_STATIC));
	case ZEBRA_LSP_LDP:
		return (route_distance(ZEBRA_ROUTE_LDP));
	case ZEBRA_LSP_BGP:
		return (route_distance(ZEBRA_ROUTE_BGP));
	case ZEBRA_LSP_NONE:
	case ZEBRA_LSP_SHARP:
	case ZEBRA_LSP_EVPN:
	case ZEBRA_LSP_OSPF_SR:
	case ZEBRA_LSP_ISIS_SR:
	case ZEBRA_LSP_SRTE:
		return 150;
	}

	/*
	 * For some reason certain compilers do not believe
	 * that all the cases have been handled.  And
	 * WTF does this work differently than when I removed
	 * the default case????
	 */
	return 150;
}

/*
 * Map RIB type to LSP type. Used when labeled-routes from BGP
 * are converted into LSPs.
 */
static inline enum lsp_types_t lsp_type_from_re_type(int re_type)
{
	switch (re_type) {
	case ZEBRA_ROUTE_STATIC:
		return ZEBRA_LSP_STATIC;
	case ZEBRA_ROUTE_LDP:
		return ZEBRA_LSP_LDP;
	case ZEBRA_ROUTE_BGP:
		return ZEBRA_LSP_BGP;
	case ZEBRA_ROUTE_OSPF:
		return ZEBRA_LSP_OSPF_SR;
	case ZEBRA_ROUTE_ISIS:
		return ZEBRA_LSP_ISIS_SR;
	case ZEBRA_ROUTE_SHARP:
		return ZEBRA_LSP_SHARP;
	case ZEBRA_ROUTE_SRTE:
		return ZEBRA_LSP_SRTE;
	default:
		return ZEBRA_LSP_NONE;
	}
}

/*
 * Map LSP type to RIB type.
 */
static inline int re_type_from_lsp_type(enum lsp_types_t lsp_type)
{
	switch (lsp_type) {
	case ZEBRA_LSP_STATIC:
		return ZEBRA_ROUTE_STATIC;
	case ZEBRA_LSP_LDP:
		return ZEBRA_ROUTE_LDP;
	case ZEBRA_LSP_BGP:
	case ZEBRA_LSP_EVPN:
		return ZEBRA_ROUTE_BGP;
	case ZEBRA_LSP_OSPF_SR:
		return ZEBRA_ROUTE_OSPF;
	case ZEBRA_LSP_ISIS_SR:
		return ZEBRA_ROUTE_ISIS;
	case ZEBRA_LSP_NONE:
		return ZEBRA_ROUTE_KERNEL;
	case ZEBRA_LSP_SHARP:
		return ZEBRA_ROUTE_SHARP;
	case ZEBRA_LSP_SRTE:
		return ZEBRA_ROUTE_SRTE;
	}

	/*
	 * For some reason certain compilers do not believe
	 * that all the cases have been handled.  And
	 * WTF does this work differently than when I removed
	 * the default case????
	 */
	return ZEBRA_ROUTE_KERNEL;
}

/* NHLFE type as printable string. */
static inline const char *nhlfe_type2str(enum lsp_types_t lsp_type)
{
	switch (lsp_type) {
	case ZEBRA_LSP_STATIC:
		return "Static";
	case ZEBRA_LSP_LDP:
		return "LDP";
	case ZEBRA_LSP_BGP:
		return "BGP";
	case ZEBRA_LSP_OSPF_SR:
		return "SR (OSPF)";
	case ZEBRA_LSP_ISIS_SR:
		return "SR (IS-IS)";
	case ZEBRA_LSP_SHARP:
		return "SHARP";
	case ZEBRA_LSP_SRTE:
		return "SR-TE";
	case ZEBRA_LSP_EVPN:
		return "EVPN";
	case ZEBRA_LSP_NONE:
		return "Unknown";
	}

	/*
	 * For some reason certain compilers do not believe
	 * that all the cases have been handled.  And
	 * WTF does this work differently than when I removed
	 * the default case????
	 */
	return "Unknown";
}

static inline void mpls_mark_lsps_for_processing(struct zebra_vrf *zvrf,
						 struct prefix *p)
{
	struct route_table *table;
	struct route_node *rn;
	rib_dest_t *dest;

	if (!zvrf)
		return;

	table = zvrf->table[family2afi(p->family)][SAFI_UNICAST];
	if (!table)
		return;

	rn = route_node_match(table, p);
	if (!rn)
		return;


	dest = rib_dest_from_rnode(rn);
	SET_FLAG(dest->flags, RIB_DEST_UPDATE_LSPS);
}

static inline void mpls_unmark_lsps_for_processing(struct route_node *rn)
{
	rib_dest_t *dest = rib_dest_from_rnode(rn);

	UNSET_FLAG(dest->flags, RIB_DEST_UPDATE_LSPS);
}

static inline int mpls_should_lsps_be_processed(struct route_node *rn)
{
	rib_dest_t *dest = rib_dest_from_rnode(rn);

	return !!CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_LSPS);
}

/* Global variables. */
extern bool mpls_enabled;
extern bool mpls_pw_reach_strict; /* Strict pseudowire reachability checking */

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_MPLS_H */
