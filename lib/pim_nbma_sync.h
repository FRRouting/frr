// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Wire structs for PIM <-> NHRP NBMA-mode flag synchronisation.
 * Mirrors lib/ldp_sync.h.
 *
 * pimd is authoritative on `ip pim nbma`. When the operator toggles it,
 * pimd sends PIM_NBMA_IF_STATE_UPDATE so nhrpd mirrors the bit on the
 * matching nhrp_interface, removing the need to also configure
 * `ip nhrp nbma-mode` by hand.
 *
 * On nhrpd start or zebra reconnect, nhrpd sends PIM_NBMA_IF_STATE_REQUEST
 * to recover current pimd-side state.
 */

#ifndef _LIBPIM_NBMA_SYNC_H
#define _LIBPIM_NBMA_SYNC_H

#include <stdbool.h>
#include "lib/if.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pim_nbma_if_state {
	ifindex_t ifindex;
	bool enabled;
	char ifname[IFNAMSIZ];
};

/* ifindex == 0 means "send UPDATE for every NBMA-enabled interface". */
struct pim_nbma_if_state_req {
	ifindex_t ifindex;
};

#ifdef __cplusplus
}
#endif

#endif /* _LIBPIM_NBMA_SYNC_H */
