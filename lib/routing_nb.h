#ifndef _FRR_ROUTING_NB_H_
#define _FRR_ROUTING_NB_H_

int routing_control_plane_protocols_control_plane_protocol_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_destroy(
	enum nb_event event, const struct lyd_node *dnode);

#define FRR_ROUTING_XPATH                                                      \
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol"

#define FRR_ROUTING_KEY_XPATH                                                  \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']"

extern const struct frr_yang_module_info frr_routing_info;

/* Mandatory callbacks. */

#endif /* _FRR_ROUTING_NB_H_ */
