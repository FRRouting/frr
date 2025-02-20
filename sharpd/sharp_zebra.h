// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect library for SHARP
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __SHARP_ZEBRA_H__
#define __SHARP_ZEBRA_H__

extern void sharp_zebra_init(void);
extern void sharp_zebra_terminate(void);

/* Add and delete extra zapi client sessions, for testing */
int sharp_zclient_create(uint32_t session_id);
int sharp_zclient_delete(uint32_t session_id);

extern void vrf_label_add(vrf_id_t vrf_id, afi_t afi, mpls_label_t label);
extern void nhg_add(uint32_t id, const struct nexthop_group *nhg,
		    const struct nexthop_group *backup_nhg);
extern void nhg_del(uint32_t id);
extern void sharp_zebra_nexthop_watch(struct prefix *p, vrf_id_t vrf_id, bool import, bool watch,
				      bool connected, bool mrib);

extern void sharp_install_routes_helper(struct prefix *p, vrf_id_t vrf_id,
					uint8_t instance, uint32_t nhgid,
					const struct nexthop_group *nhg,
					const struct nexthop_group *backup_nhg,
					uint32_t routes, uint32_t flags,
					char *opaque);
extern void sharp_remove_routes_helper(struct prefix *p, vrf_id_t vrf_id,
				       uint8_t instance, uint32_t routes);

int sharp_install_lsps_helper(bool install_p, bool update_p,
			      const struct prefix *p, uint8_t type,
			      int instance, uint32_t in_label,
			      const struct nexthop_group *nhg,
			      const struct nexthop_group *backup_nhg);

/* Send OPAQUE messages, using subtype 'type'. */
void sharp_opaque_send(uint32_t type, uint32_t proto, uint32_t instance,
		       uint32_t session_id, uint32_t count);

/* Send OPAQUE registration or notification registration messages,
 * for opaque subtype 'type'.
 */
void sharp_opaque_reg_send(bool is_reg, uint32_t proto, uint32_t instance,
			   uint32_t session_id, uint32_t type);

/* Register/unregister for opaque notifications from zebra about 'type'. */
void sharp_zebra_opaque_notif_reg(bool is_reg, uint32_t type);

extern void sharp_zebra_send_arp(const struct interface *ifp,
				 const struct prefix *p);

/* Register Link State Opaque messages */
extern void sharp_zebra_register_te(void);

extern void sharp_redistribute_vrf(struct vrf *vrf, int source, bool turn_on);

extern int sharp_zebra_srv6_manager_get_locator_chunk(const char *lname);
extern int sharp_zebra_srv6_manager_release_locator_chunk(const char *lname);
extern void sharp_install_seg6local_route_helper(struct prefix *p,
						 uint8_t instance,
						 enum seg6local_action_t act,
						 struct seg6local_context *ctx);

extern int sharp_zebra_send_interface_protodown(struct interface *ifp,
						bool down);
extern int sharp_zebra_send_tc_filter_rate(struct interface *ifp,
					   const struct prefix *source,
					   const struct prefix *destination,
					   uint8_t ip_proto, uint16_t src_port,
					   uint16_t dst_port, uint64_t rate);

extern void sharp_zebra_register_neigh(vrf_id_t vrf_id, afi_t afi, bool reg);
#endif
