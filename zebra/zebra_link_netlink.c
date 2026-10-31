// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra - validation and netlink encoding of link create/delete/master
 * requests.
 *
 * Netlink link types are described by a small table (struct link_kind_ops).
 * To add a new type, add an enum value in zebra_link_cfg.h, a validator and
 * an encoder here, and one table entry; the generic message construction does
 * not change.
 */

#include <zebra.h>

#include "zebra/zebra_link_netlink.h"

/*
 * Parameter validation.  Kept outside HAVE_NETLINK so that configuration
 * can be validated identically on every platform.
 */

static const char *veth_validate(const char *ifname, const struct zebra_link_params *p)
{
	const char *peer = p->u.veth.peer_name;

	if (!peer[0])
		return "veth peer name is required";
	if (memchr(peer, '\0', IFNAMSIZ) == NULL)
		return "veth peer name is not terminated";
	if (strcmp(peer, ifname) == 0)
		return "veth peer name must differ from the interface name";
	return NULL;
}

static const char *vlan_validate(const char *ifname, const struct zebra_link_params *p)
{
	const struct zebra_link_vlan *v = &p->u.vlan;

	if (!v->parent[0])
		return "vlan parent device is required";
	if (strcmp(v->parent, ifname) == 0)
		return "vlan parent must differ from the interface name";
	if (v->vid < 1 || v->vid > 4094)
		return "vlan id must be in the range 1-4094";
	if (v->encap != ZEBRA_LINK_VLAN_DOT1Q && v->encap != ZEBRA_LINK_VLAN_QINQ)
		return "unknown vlan encapsulation";
	return NULL;
}

static const char *gre_validate(const char *ifname, const struct zebra_link_params *p)
{
	const struct zebra_link_gre *g = &p->u.gre;

	if (!g->has_local && !g->dev[0])
		return "gre requires a local address or a dev";
	if (g->dev[0] && strcmp(g->dev, ifname) == 0)
		return "gre dev must differ from the interface name";
	return NULL;
}

const char *zebra_link_params_validate(const char *ifname, const struct zebra_link_params *p)
{
	if (!ifname || !ifname[0])
		return "interface name is required";
	if (strnlen(ifname, IFNAMSIZ) >= IFNAMSIZ)
		return "interface name is too long";

	switch (p->kind) {
	case ZEBRA_LINK_BRIDGE:
		return NULL;
	case ZEBRA_LINK_VETH:
		return veth_validate(ifname, p);
	case ZEBRA_LINK_VLAN:
		return vlan_validate(ifname, p);
	case ZEBRA_LINK_GRE:
		return gre_validate(ifname, p);
	case ZEBRA_LINK_DUMMY:
		return NULL;
	case ZEBRA_LINK_NONE:
	case ZEBRA_LINK_KIND_MAX:
		break;
	}
	return "unsupported link type";
}

#ifdef HAVE_NETLINK

/*
 * Work around the kernel headers redefining types that the C library has
 * already defined (same workaround as if_netlink.c).
 */
#define _LINUX_IN6_H
#define _LINUX_IF_H
#define _LINUX_IP_H

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_tunnel.h>
#include <linux/veth.h>
#include <arpa/inet.h>

#include "lib/netlink_parser.h"

struct link_kind_ops {
	enum zebra_link_kind kind;
	const char *name; /* IFLA_INFO_KIND */

	/*
	 * Optional: attributes that live on the top level RTM_NEWLINK message
	 * rather than inside IFLA_INFO_DATA (e.g. IFLA_LINK).
	 */
	bool (*put_link)(struct nlmsghdr *n, size_t buflen, const struct zebra_link_params *p,
			 int link_ifindex);

	/* Optional: attributes for IFLA_INFO_DATA. */
	bool (*put_data)(struct nlmsghdr *n, size_t buflen, const struct zebra_link_params *p,
			 int link_ifindex);
};

/* ---- veth ---- */

static bool veth_put_data(struct nlmsghdr *n, size_t buflen, const struct zebra_link_params *p,
			  int link_ifindex)
{
	struct rtattr *peer;
	struct ifinfomsg ifi;
	const char *name = p->u.veth.peer_name;

	/*
	 * VETH_INFO_PEER carries a complete (nested) ifinfomsg followed by the
	 * attributes describing the peer end of the pair.
	 */
	peer = nl_attr_nest(n, buflen, VETH_INFO_PEER);
	if (!peer)
		return false;

	memset(&ifi, 0, sizeof(ifi));
	if (!nl_addraw_l(n, buflen, &ifi, sizeof(ifi)))
		return false;

	if (!nl_attr_put(n, buflen, IFLA_IFNAME, name, strlen(name) + 1))
		return false;

	nl_attr_nest_end(n, peer);
	return true;
}

/* ---- vlan ---- */

static bool vlan_put_link(struct nlmsghdr *n, size_t buflen, const struct zebra_link_params *p,
			  int link_ifindex)
{
	/* The parent device is mandatory for a vlan. */
	if (link_ifindex <= 0)
		return false;
	return nl_attr_put32(n, buflen, IFLA_LINK, link_ifindex);
}

static bool vlan_put_data(struct nlmsghdr *n, size_t buflen, const struct zebra_link_params *p,
			  int link_ifindex)
{
	const struct zebra_link_vlan *v = &p->u.vlan;
	uint16_t proto = (v->encap == ZEBRA_LINK_VLAN_QINQ) ? ETH_P_8021AD : ETH_P_8021Q;

	/* IFLA_VLAN_PROTOCOL is big-endian on the wire */
	if (!nl_attr_put16(n, buflen, IFLA_VLAN_PROTOCOL, htons(proto)))
		return false;
	return nl_attr_put16(n, buflen, IFLA_VLAN_ID, v->vid);
}

/* ---- gre (standard, IPv4 L3 GRE; gretap/ip6gre are future kinds) ---- */

static bool gre_put_data(struct nlmsghdr *n, size_t buflen, const struct zebra_link_params *p,
			 int link_ifindex)
{
	const struct zebra_link_gre *g = &p->u.gre;

	if (link_ifindex > 0 && !nl_attr_put32(n, buflen, IFLA_GRE_LINK, link_ifindex))
		return false;

	if (g->has_key) {
		/*
		 * The key is only used by the kernel if the flag is set.  GRE_KEY
		 * is already in network byte order.
		 */
		if (!nl_attr_put16(n, buflen, IFLA_GRE_IFLAGS, GRE_KEY) ||
		    !nl_attr_put16(n, buflen, IFLA_GRE_OFLAGS, GRE_KEY) ||
		    !nl_attr_put32(n, buflen, IFLA_GRE_IKEY, htonl(g->key)) ||
		    !nl_attr_put32(n, buflen, IFLA_GRE_OKEY, htonl(g->key)))
			return false;
	}

	/* in_addr is already in network byte order */
	if (g->has_local && !nl_attr_put(n, buflen, IFLA_GRE_LOCAL, &g->local, sizeof(g->local)))
		return false;

	/* No remote attribute at all means "any" */
	if (g->has_remote &&
	    !nl_attr_put(n, buflen, IFLA_GRE_REMOTE, &g->remote, sizeof(g->remote)))
		return false;

	if (g->has_ttl && !nl_attr_put8(n, buflen, IFLA_GRE_TTL, g->ttl))
		return false;

	if (g->has_tos && !nl_attr_put8(n, buflen, IFLA_GRE_TOS, g->tos))
		return false;

	return true;
}

static const struct link_kind_ops link_kinds[] = {
	{
		.kind = ZEBRA_LINK_DUMMY,
		.name = "dummy",
		/* no parameters */
	},
	{
		.kind = ZEBRA_LINK_BRIDGE,
		.name = "bridge",
		/* plain bridge: no INFO_DATA yet */
	},
	{
		.kind = ZEBRA_LINK_VETH,
		.name = "veth",
		.put_data = veth_put_data,
	},
	{
		.kind = ZEBRA_LINK_VLAN,
		.name = "vlan",
		.put_link = vlan_put_link,
		.put_data = vlan_put_data,
	},
	{
		.kind = ZEBRA_LINK_GRE,
		.name = "gre",
		.put_data = gre_put_data,
	},
};

static const struct link_kind_ops *link_kind_lookup(enum zebra_link_kind kind)
{
	size_t i;

	for (i = 0; i < array_size(link_kinds); i++)
		if (link_kinds[i].kind == kind)
			return &link_kinds[i];
	return NULL;
}

static ssize_t encode_create(const struct zebra_link_nl_req *req, void *buf, size_t buflen,
			     const char **err)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[];
	} *msg = buf;
	const struct link_kind_ops *ops;
	struct rtattr *linkinfo, *data;
	const char *verr;

	if (!req->params || !req->ifname) {
		*err = "missing link parameters";
		return 0;
	}

	verr = zebra_link_params_validate(req->ifname, req->params);
	if (verr) {
		*err = verr;
		return 0;
	}
	ops = link_kind_lookup(req->params->kind);
	if (!ops) {
		*err = "unsupported link type";
		return 0;
	}

	msg->n.nlmsg_type = RTM_NEWLINK;
	/* EXCL: never modify an existing interface of the same name */
	msg->n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	msg->ifi.ifi_family = AF_UNSPEC;

	if (!nl_attr_put(&msg->n, buflen, IFLA_IFNAME, req->ifname, strlen(req->ifname) + 1))
		goto nospace;

	if (ops->put_link && !ops->put_link(&msg->n, buflen, req->params, req->link_ifindex)) {
		*err = "a required parent/link interface is not available";
		return 0;
	}

	linkinfo = nl_attr_nest(&msg->n, buflen, IFLA_LINKINFO);
	if (!linkinfo)
		goto nospace;

	if (!nl_attr_put(&msg->n, buflen, IFLA_INFO_KIND, ops->name, strlen(ops->name)))
		goto nospace;

	if (ops->put_data) {
		data = nl_attr_nest(&msg->n, buflen, IFLA_INFO_DATA);
		if (!data)
			goto nospace;
		if (!ops->put_data(&msg->n, buflen, req->params, req->link_ifindex))
			goto nospace;
		nl_attr_nest_end(&msg->n, data);
	}

	nl_attr_nest_end(&msg->n, linkinfo);

	return NLMSG_ALIGN(msg->n.nlmsg_len);

nospace:
	*err = "netlink message buffer too small";
	return 0;
}

ssize_t zebra_link_nl_encode(const struct zebra_link_nl_req *req, void *buf, size_t buflen,
			     const char **err)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[];
	} *msg = buf;
	const char *dummy;

	if (!err)
		err = &dummy;
	*err = NULL;

	if (buflen < sizeof(*msg)) {
		*err = "netlink message buffer too small";
		return 0;
	}
	memset(buf, 0, sizeof(*msg));
	msg->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

	switch (req->op) {
	case ZEBRA_LINK_NL_CREATE:
		return encode_create(req, buf, buflen, err);

	case ZEBRA_LINK_NL_DELETE:
		if (req->ifindex <= 0) {
			*err = "interface does not exist";
			return 0;
		}
		msg->n.nlmsg_type = RTM_DELLINK;
		msg->n.nlmsg_flags = NLM_F_REQUEST;
		msg->ifi.ifi_family = AF_UNSPEC;
		msg->ifi.ifi_index = req->ifindex;
		return NLMSG_ALIGN(msg->n.nlmsg_len);

	case ZEBRA_LINK_NL_SET_MASTER:
		if (req->ifindex <= 0) {
			*err = "interface does not exist";
			return 0;
		}
		msg->n.nlmsg_type = RTM_NEWLINK;
		msg->n.nlmsg_flags = NLM_F_REQUEST;
		msg->ifi.ifi_family = AF_UNSPEC;
		msg->ifi.ifi_index = req->ifindex;
		/* A master ifindex of 0 releases the interface (nomaster) */
		if (!nl_attr_put32(&msg->n, buflen, IFLA_MASTER,
				   req->master_ifindex > 0 ? (uint32_t)req->master_ifindex : 0)) {
			*err = "netlink message buffer too small";
			return 0;
		}
		return NLMSG_ALIGN(msg->n.nlmsg_len);
	}

	*err = "unknown link request";
	return 0;
}

#endif /* HAVE_NETLINK */
