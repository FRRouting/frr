// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM southbound implementation.
 *
 * Copyright (C) 2021-2026 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#ifndef PIM_SOUTHBOUND_COMMON_H
#define PIM_SOUTHBOUND_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "pim_addr.h"

struct interface;
struct pim_instance;

/** Default TCP listening port. */
#if PIM_IPV == 4
#define PIMSB_DEFAULT_PORT 2650
#else
#define PIMSB_DEFAULT_PORT 2651
#endif /* PIM_IPV == 4 */

/** pimreg interface index value for southbound. */
#define PIM_REG_IF_IDX 0x7FFF0000

/** Maximum amount of multicast interfaces supported */
#define PIMSB_MAX_MULTICAST_IFS 4096

/*
 * PIM southbound callbacks
 */
extern void pimsb_mroute_socket_enable(struct pim_instance *pim);
extern void pimsb_mroute_socket_disable(struct pim_instance *pim);
extern void pimsb_interface_join(struct interface *interface);
extern void pimsb_interface_leave(struct interface *interface, const pim_addr *source,
				  const pim_addr *group);
extern ssize_t pimsb_send(const struct interface *interface, const pim_addr *source,
			  const pim_addr *destination, uint8_t protocol, uint8_t ttl,
			  const void *data, size_t data_length);

extern void pimsb_configure(void);

/*
 * PIM southbound connection handling.
 */
extern void pimsb_socket_init(const struct sockaddr_storage *ss, socklen_t sslen, bool client);
extern void pimsb_socket_stop(void);

#endif /* PIM_SOUTHBOUND_COMMON_H */
