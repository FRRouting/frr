// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */


#ifndef _ZEBRA_PTM_REDISTRIBUTE_H
#define _ZEBRA_PTM_REDISTRIBUTE_H

#ifdef __cplusplus
extern "C" {
#endif

extern void zebra_interface_bfd_update(struct interface *, struct prefix *,
				       struct prefix *, int, vrf_id_t);
extern void zebra_bfd_peer_replay_req(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_PTM_REDISTRIBUTE_H */
