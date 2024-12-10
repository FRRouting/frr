<<<<<<< HEAD
=======
// SPDX-License-Identifier: GPL-2.0-or-later

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
#ifndef _FRR_ROUTING_NB_H_
#define _FRR_ROUTING_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_routing_info;
<<<<<<< HEAD
=======
extern const struct frr_yang_module_info frr_routing_cli_info;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

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

#define FRR_ROUTING_KEY_XPATH_VRF                                              \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[vrf='%s']"

/*
 * callbacks for routing to handle configuration events
 * based on the control plane protocol
 */
DECLARE_HOOK(routing_conf_event, (struct nb_cb_create_args *args), (args));
<<<<<<< HEAD
=======
DECLARE_HOOK(routing_create, (struct nb_cb_create_args *args), (args));
DECLARE_KOOH(routing_destroy, (struct nb_cb_destroy_args *args), (args));
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

void routing_control_plane_protocols_register_vrf_dependency(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ROUTING_NB_H_ */
