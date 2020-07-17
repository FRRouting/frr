#ifndef _FRR_ROUTING_NB_H_
#define _FRR_ROUTING_NB_H_

extern const struct frr_yang_module_info frr_routing_info;

/* Mandatory callbacks. */
int routing_control_plane_protocols_control_plane_protocol_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_destroy(
	struct nb_cb_destroy_args *args);

#define FRR_ROUTING_XPATH                                                      \
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol"

#define FRR_ROUTING_KEY_XPATH                                                  \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']"
/*
 * callbacks for routing to handle configuration events
 * based on the control plane protocol
 */
DECLARE_HOOK(routing_conf_event, (struct nb_cb_create_args *args), (args))

#endif /* _FRR_ROUTING_NB_H_ */
