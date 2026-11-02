// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra - validation and netlink encoding of link create/delete/master
 * requests.
 */

#ifndef _ZEBRA_LINK_NETLINK_H
#define _ZEBRA_LINK_NETLINK_H

#include <sys/types.h>

#include "zebra/zebra_link_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Validate parameters (platform independent); returns NULL if OK, or a
 * static string describing the first problem found.
 */
extern const char *zebra_link_params_validate(const char *ifname,
					      const struct zebra_link_params *p);

#ifdef HAVE_NETLINK

enum zebra_link_nl_op {
	ZEBRA_LINK_NL_CREATE,	  /* RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL */
	ZEBRA_LINK_NL_DELETE,	  /* RTM_DELLINK */
	ZEBRA_LINK_NL_SET_MASTER, /* RTM_NEWLINK with IFLA_MASTER */
};

struct zebra_link_nl_req {
	enum zebra_link_nl_op op;

	/* Name of the link; required for create */
	const char *ifname;

	/* Existing link: required for delete and set-master */
	int ifindex;

	/* Create only */
	const struct zebra_link_params *params;
	int link_ifindex; /* resolved vlan parent / gre dev, 0 if none */

	/* Set-master only: ifindex of master, 0 to release from any master */
	int master_ifindex;
};

/*
 * Encode a request into 'buf'.  Returns the (aligned) message length, or 0 if
 * the request is invalid or does not fit.  On failure, 'err' (if not NULL)
 * points to a static string describing the problem.
 */
extern ssize_t zebra_link_nl_encode(const struct zebra_link_nl_req *req, void *buf, size_t buflen,
				    const char **err);

#endif /* HAVE_NETLINK */

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_LINK_NETLINK_H */
