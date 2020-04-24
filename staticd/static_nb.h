#ifndef _FRR_STATIC_NB_H_
#define _FRR_STATIC_NB_H_

/* prototypes */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy(
	enum nb_event event, const struct lyd_node *dnode);

/* route-list */
#define FRR_STATIC_ROUTE_KEY_XPATH                                             \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']"

#define FRR_STATIC_ROUTE_INFO_KEY_XPATH                                        \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"path-list[distance='%d'][tag='%d'][table-id='%d']"

/* route-list/frr-nexthops */
#define FRR_STATIC_ROUTE_NH_KEY_XPATH                                          \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']"

#define FRR_STATIC_ROUTE_NH_ONLINK_XPATH                                       \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']/onlink"

#define FRR_STATIC_ROUTE_NH_BH_XPATH                                           \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']/"       \
	"bh-type"

#define FRR_STATIC_ROUTE_NHLB_KEY_XPATH                                        \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']/"       \
	"mpls-label-stack/entry[id='%d']/label"

#define FRR_STATIC_ROUTE_NH_LABEL_XPATH                                        \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']/"       \
	"mpls-label-stack"

/* route-list/srclist */
#define FRR_S_ROUTE_SRC_KEY_XPATH                                              \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"src-list[src-prefix='%s']"

#define FRR_S_ROUTE_SRC_INFO_KEY_XPATH                                         \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"src-list[src-prefix='%s']/"                                           \
	"path-list[distance='%d'][tag='%d'][table-id='%d']"

/* route-list/src-list/frr-nexthops*/
#define FRR_S_ROUTE_SRC_NH_KEY_XPATH                                           \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"src-list[src-prefix='%s']/"                                           \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']"

#define FRR_S_ROUTE_SRC_NH_ONLINK_XPATH                                        \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"src-list[src-prefix='%s']/"                                           \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']/onlink"

#define FRR_S_ROUTE_SRC_NH_BH_XPATH                                            \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"src-list[src-prefix='%s']/"                                           \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']/"       \
	"bh-type"

#define FRR_S_ROUTE_SRC_NHLB_KEY_XPATH                                         \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"src-list[src-prefix='%s']/"                                           \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']/"       \
	"mpls-label-stack/entry[id='%d']/label"

#define FRR_S_ROUTE_SRC_NH_LABEL_XPATH                                         \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[destination-prefix='%s']/"             \
	"src-list[src-prefix='%s']/"                                           \
	"path-list[distance='%d'][tag='%d'][table-id='%d']/"                   \
	"frr-staticd-next-hop/"                                                \
	"frr-nexthops/"                                                        \
	"nexthop[nh-type='%s'][gateway='%s'][interface='%s'][vrf='%s']/"       \
	"mpls-label-stack"

extern const struct frr_yang_module_info frr_staticd_info;

#endif
