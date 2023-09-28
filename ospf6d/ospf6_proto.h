// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Common protocol data and data structures.
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_PROTO_H
#define OSPF6_PROTO_H

/* OSPF protocol version */
#define OSPFV3_VERSION           3

/* TOS field normaly null */
#define DEFAULT_TOS_VALUE      0x0

#define ALLSPFROUTERS6 "ff02::5"
#define ALLDROUTERS6   "ff02::6"

#define OSPF6_ROUTER_BIT_W     (1 << 3)
#define OSPF6_ROUTER_BIT_V     (1 << 2)
#define OSPF6_ROUTER_BIT_E     (1 << 1)
#define OSPF6_ROUTER_BIT_B     (1 << 0)
#define OSPF6_ROUTER_BIT_NT    (1 << 4)


/* OSPF options */
/* present in HELLO, DD, LSA */
#define OSPF6_OPT_SET(x, opt) ((x)[2] |= (opt))
#define OSPF6_OPT_ISSET(x, opt) ((x)[2] & (opt))
#define OSPF6_OPT_CLEAR(x, opt) ((x)[2] &= ~(opt))
#define OSPF6_OPT_SET_EXT(x, opt) ((x)[1] |= (opt))
#define OSPF6_OPT_ISSET_EXT(x, opt) ((x)[1] & (opt))
#define OSPF6_OPT_CLEAR_EXT(x, opt) ((x)[1] &= ~(opt))
#define OSPF6_OPT_CLEAR_ALL(x) ((x)[0] = (x)[1] = (x)[2] = 0)

#define OSPF6_OPT_AT (1 << 2) /* Authentication trailer Capability */
#define OSPF6_OPT_L (1 << 1)  /* Link local signalling Capability */
#define OSPF6_OPT_AF (1 << 0) /* Address family Capability */
/* 2 bits reserved for OSPFv2 migrated options */
#define OSPF6_OPT_DC (1 << 5)   /* Demand Circuit handling Capability */
#define OSPF6_OPT_R (1 << 4)    /* Forwarding Capability (Any Protocol) */
#define OSPF6_OPT_N  (1 << 3)   /* Handling Type-7 LSA Capability */
#define OSPF6_OPT_MC (1 << 2)   /* Multicasting Capability */
#define OSPF6_OPT_E  (1 << 1)   /* AS External Capability */
#define OSPF6_OPT_V6 (1 << 0)   /* IPv6 forwarding Capability */

/* OSPF6 Prefix */
#define OSPF6_PREFIX_MIN_SIZE                  4U /* .length == 0 */
struct ospf6_prefix {
	uint8_t prefix_length;
	uint8_t prefix_options;
	union {
		uint16_t _prefix_metric;
		uint16_t _prefix_referenced_lstype;
	} u;
#define prefix_metric        u._prefix_metric
#define prefix_refer_lstype  u._prefix_referenced_lstype
	/* followed by one address_prefix */
	struct in6_addr addr[];
};

#define OSPF6_PREFIX_OPTION_NU (1 << 0)  /* No Unicast */
#define OSPF6_PREFIX_OPTION_LA (1 << 1)  /* Local Address */
#define OSPF6_PREFIX_OPTION_MC (1 << 2)  /* MultiCast */
#define OSPF6_PREFIX_OPTION_P  (1 << 3)  /* Propagate (NSSA) */
#define OSPF6_PREFIX_OPTION_DN                                                 \
	(1 << 4) /* DN bit to prevent loops in VPN environment */

/* caddr_t OSPF6_PREFIX_BODY (struct ospf6_prefix *); */
#define OSPF6_PREFIX_BODY(x) ((caddr_t)(x) + sizeof(struct ospf6_prefix))

/* size_t OSPF6_PREFIX_SPACE (int prefixlength); */
#define OSPF6_PREFIX_SPACE(x) ((((x) + 31) / 32) * 4)

/* size_t OSPF6_PREFIX_SIZE (struct ospf6_prefix *); */
#define OSPF6_PREFIX_SIZE(x)                                                   \
	(OSPF6_PREFIX_SPACE((x)->prefix_length) + sizeof(struct ospf6_prefix))

/* struct ospf6_prefix *OSPF6_PREFIX_NEXT (struct ospf6_prefix *); */
#define OSPF6_PREFIX_NEXT(x)                                                   \
	((struct ospf6_prefix *)((caddr_t)(x) + OSPF6_PREFIX_SIZE(x)))

extern void ospf6_prefix_in6_addr(struct in6_addr *in6, const void *prefix_buf,
				  const struct ospf6_prefix *p);
extern void ospf6_prefix_apply_mask(struct ospf6_prefix *op);
extern void ospf6_prefix_options_printbuf(uint8_t prefix_options, char *buf,
					  int size);
extern void ospf6_capability_printbuf(char capability, char *buf, int size);
extern void ospf6_options_printbuf(uint8_t *options, char *buf, int size);

#endif /* OSPF6_PROTO_H */
