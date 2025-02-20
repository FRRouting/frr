// SPDX-License-Identifier: GPL-2.0-or-later
/* Router advertisement
 * Copyright (C) 2005 6WIND <jean-mickael.guerin@6wind.com>
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_RTADV_H
#define _ZEBRA_RTADV_H

#include "zebra.h"
#include "vty.h"
#include "typesafe.h"

#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct interface;
struct zebra_if;

#if defined(HAVE_RTADV)

PREDECL_SORTLIST_UNIQ(adv_if_list);
/* Structure which hold status of router advertisement. */
struct rtadv {
	int sock;

	struct adv_if_list_head adv_if;
	struct adv_if_list_head adv_msec_if;

	struct event *ra_read;
	struct event *ra_timer;
};

PREDECL_RBTREE_UNIQ(rtadv_prefixes);

/* Router advertisement parameter.  From RFC4861, RFC6275 and RFC4191. */
struct rtadvconf {
	/* A flag indicating whether or not the router sends periodic Router
	   Advertisements and responds to Router Solicitations.
	   Default: false */
	int AdvSendAdvertisements;

	/* The maximum time allowed between sending unsolicited multicast
	   Router Advertisements from the interface, in milliseconds.
	   MUST be no less than 70 ms [RFC6275 7.5] and no greater
	   than 1800000 ms [RFC4861 6.2.1].

	   Default: 600000 milliseconds */
	int MaxRtrAdvInterval;
#define RTADV_MAX_RTR_ADV_INTERVAL 600000

	/* The minimum time allowed between sending unsolicited multicast
	   Router Advertisements from the interface, in milliseconds.
	   MUST be no less than 30 ms [RFC6275 7.5].
	   MUST be no greater than .75 * MaxRtrAdvInterval.

	   Default: 0.33 * MaxRtrAdvInterval */
	int MinRtrAdvInterval; /* This field is currently unused. */
#define RTADV_MIN_RTR_ADV_INTERVAL (0.33 * RTADV_MAX_RTR_ADV_INTERVAL)

	/* Unsolicited Router Advertisements' interval timer. */
	int AdvIntervalTimer;

	/* The true/false value to be placed in the "Managed address
	   configuration" flag field in the Router Advertisement.  See
	   [ADDRCONF].

	   Default: false */
	int AdvManagedFlag;
	struct timeval lastadvmanagedflag;


	/* The true/false value to be placed in the "Other stateful
	   configuration" flag field in the Router Advertisement.  See
	   [ADDRCONF].

	   Default: false */
	int AdvOtherConfigFlag;
	struct timeval lastadvotherconfigflag;

	/* The value to be placed in MTU options sent by the router.  A
	   value of zero indicates that no MTU options are sent.

	   Default: 0 */
	int AdvLinkMTU;


	/* The value to be placed in the Reachable Time field in the Router
	   Advertisement messages sent by the router.  The value zero means
	   unspecified (by this router).  MUST be no greater than 3,600,000
	   milliseconds (1 hour).

	   Default: 0 */
	uint32_t AdvReachableTime;
#define RTADV_MAX_REACHABLE_TIME 3600000
	struct timeval lastadvreachabletime;

	/* The value to be placed in the Retrans Timer field in the Router
	   Advertisement messages sent by the router.  The value zero means
	   unspecified (by this router).

	   Default: 0 */
	int AdvRetransTimer;
	struct timeval lastadvretranstimer;

	/* The default value to be placed in the Cur Hop Limit field in the
	   Router Advertisement messages sent by the router.  The value
	   should be set to that current diameter of the Internet.  The
	   value zero means unspecified (by this router).

	   Default: The value specified in the "Assigned Numbers" RFC
	   [ASSIGNED] that was in effect at the time of implementation. */
	int AdvCurHopLimit;
	struct timeval lastadvcurhoplimit;

#define RTADV_DEFAULT_HOPLIMIT 64 /* 64 hops */

	/* The value to be placed in the Router Lifetime field of Router
	   Advertisements sent from the interface, in seconds.  MUST be
	   either zero or between MaxRtrAdvInterval and 9000 seconds.  A
	   value of zero indicates that the router is not to be used as a
	   default router.

	   Default: 3 * MaxRtrAdvInterval */
	int AdvDefaultLifetime;
#define RTADV_MAX_RTRLIFETIME 9000 /* 2.5 hours */

	/* A list of prefixes to be placed in Prefix Information options in
	   Router Advertisement messages sent from the interface.

	   Default: all prefixes that the router advertises via routing
	   protocols as being on-link for the interface from which the
	   advertisement is sent. The link-local prefix SHOULD NOT be
	   included in the list of advertised prefixes. */
	struct rtadv_prefixes_head prefixes[1];

	/* The true/false value to be placed in the "Home agent"
	   flag field in the Router Advertisement.  See [RFC6275 7.1].

	   Default: false */
	int AdvHomeAgentFlag;
#ifndef ND_RA_FLAG_HOME_AGENT
#define ND_RA_FLAG_HOME_AGENT 0x20
#endif

	/* The value to be placed in Home Agent Information option if Home
	   Flag is set.
	   Default: 0 */
	int HomeAgentPreference;

	/* The value to be placed in Home Agent Information option if Home
	   Flag is set. Lifetime (seconds) MUST not be greater than 18.2
	   hours.
	   The value 0 has special meaning: use of AdvDefaultLifetime value.

	   Default: 0 */
	int HomeAgentLifetime;
#define RTADV_MAX_HALIFETIME 65520 /* 18.2 hours */

	/* The true/false value to insert or not an Advertisement Interval
	   option. See [RFC 6275 7.3]

	   Default: false */
	int AdvIntervalOption;

	/* The value to be placed in the Default Router Preference field of
	   a router advertisement. See [RFC 4191 2.1 & 2.2]

	   Default: 0 (medium) */
	int DefaultPreference;
#define RTADV_PREF_MEDIUM 0x0 /* Per RFC4191. */

	/*
	 * List of recursive DNS servers to include in the RDNSS option.
	 * See [RFC8106 5.1]
	 *
	 * Default: empty list; do not emit RDNSS option
	 */
	struct list *AdvRDNSSList;

	/*
	 * List of DNS search domains to include in the DNSSL option.
	 * See [RFC8106 5.2]
	 *
	 * Default: empty list; do not emit DNSSL option
	 */
	struct list *AdvDNSSLList;

	/*
	 * rfc4861 states RAs must be sent at least 3 seconds apart.
	 * We allow faster retransmits to speed up convergence but can
	 * turn that capability off to meet the rfc if needed.
	 */
	bool UseFastRexmit; /* True if fast rexmits are enabled */

	uint8_t inFastRexmit; /* True if we're rexmits faster than usual */

	/* Track if RA was configured by BGP or by the Operator or both */
	uint8_t ra_configured;	   /* Was RA configured? */
#define BGP_RA_CONFIGURED (1 << 0) /* BGP configured RA? */
#define VTY_RA_CONFIGURED (1 << 1) /* Operator configured RA? */
#define VTY_RA_INTERVAL_CONFIGURED                                             \
	(1 << 2)		  /* Operator configured RA interval */
	int NumFastReXmitsRemain; /* Loaded first with number of fast
				     rexmits to do */

#define RTADV_FAST_REXMIT_PERIOD 1 /* 1 sec */
#define RTADV_NUM_FAST_REXMITS 4   /* Fast Rexmit RA 4 times on certain events \
				    */
};

struct rtadv_rdnss {
	/* Address of recursive DNS server to advertise */
	struct in6_addr addr;

	/*
	 * Lifetime in seconds; all-ones means infinity, zero
	 * stop using it.
	 */
	uint32_t lifetime;

	/* If lifetime not set, use a default of 3*MaxRtrAdvInterval */
	int lifetime_set;
};

/*
 * [RFC1035 2.3.4] sets the maximum length of a domain name (a sequence of
 * labels, each prefixed by a length octet) at 255 octets.
 */
#define RTADV_MAX_ENCODED_DOMAIN_NAME 255

struct rtadv_dnssl {
	/* Domain name without trailing root zone dot (NUL-terminated) */
	char name[RTADV_MAX_ENCODED_DOMAIN_NAME - 1];

	/* Name encoded as in [RFC1035 3.1] */
	uint8_t encoded_name[RTADV_MAX_ENCODED_DOMAIN_NAME];

	/* Actual length of encoded_name */
	size_t encoded_len;

	/* Lifetime as for RDNSS */
	uint32_t lifetime;
	int lifetime_set;
};

/* Router advertisement prefix. */
struct rtadv_prefix {
	struct rtadv_prefixes_item item;

	/* Prefix to be advertised. */
	struct prefix_ipv6 prefix;

	/* The prefix was manually/automatically defined. */
	int AdvPrefixCreate;

	/* The value to be placed in the Valid Lifetime in the Prefix */
	uint32_t AdvValidLifetime;
#define RTADV_VALID_LIFETIME 2592000

	/* The value to be placed in the on-link flag */
	int AdvOnLinkFlag;

	/* The value to be placed in the Preferred Lifetime in the Prefix
	   Information option, in seconds.*/
	uint32_t AdvPreferredLifetime;
#define RTADV_PREFERRED_LIFETIME 604800

	/* The value to be placed in the Autonomous Flag. */
	int AdvAutonomousFlag;

	/* The value to be placed in the Router Address Flag [RFC6275 7.2]. */
	int AdvRouterAddressFlag;
#ifndef ND_OPT_PI_FLAG_RADDR
#define ND_OPT_PI_FLAG_RADDR         0x20
#endif
};

/* RFC4861 minimum delay between RAs  */
#ifndef MIN_DELAY_BETWEEN_RAS
#define MIN_DELAY_BETWEEN_RAS        3000
#endif

/* RFC4584 Extension to Sockets API for Mobile IPv6 */

#ifndef ND_OPT_ADV_INTERVAL
#define ND_OPT_ADV_INTERVAL	7   /* Adv Interval Option */
#endif
#ifndef ND_OPT_HA_INFORMATION
#define ND_OPT_HA_INFORMATION	8   /* HA Information Option */
#endif


#ifndef HAVE_STRUCT_ND_OPT_ADV_INTERVAL
struct nd_opt_adv_interval { /* Advertisement interval option */
	uint8_t nd_opt_ai_type;
	uint8_t nd_opt_ai_len;
	uint16_t nd_opt_ai_reserved;
	uint32_t nd_opt_ai_interval;
} __attribute__((__packed__));
#else
#ifndef HAVE_STRUCT_ND_OPT_ADV_INTERVAL_ND_OPT_AI_TYPE
/* fields may have to be renamed */
#define nd_opt_ai_type		nd_opt_adv_interval_type
#define nd_opt_ai_len		nd_opt_adv_interval_len
#define nd_opt_ai_reserved	nd_opt_adv_interval_reserved
#define nd_opt_ai_interval	nd_opt_adv_interval_ival
#endif
#endif
#ifndef ND_OPT_RTR_ADV_INTERVAL
#define ND_OPT_RTR_ADV_INTERVAL 7
#endif
#ifndef ND_OPT_HOME_AGENT_INFO
#define ND_OPT_HOME_AGENT_INFO 8
#endif

#ifndef HAVE_STRUCT_ND_OPT_HOMEAGENT_INFO
struct nd_opt_homeagent_info { /* Home Agent info */
	uint8_t nd_opt_hai_type;
	uint8_t nd_opt_hai_len;
	uint16_t nd_opt_hai_reserved;
	uint16_t nd_opt_hai_preference;
	uint16_t nd_opt_hai_lifetime;
} __attribute__((__packed__));
#endif

#ifndef ND_OPT_RDNSS
#define ND_OPT_RDNSS 25
#endif
#ifndef ND_OPT_DNSSL
#define ND_OPT_DNSSL 31
#endif

#ifndef HAVE_STRUCT_ND_OPT_RDNSS
struct nd_opt_rdnss { /* Recursive DNS server option [RFC8106 5.1] */
	uint8_t nd_opt_rdnss_type;
	uint8_t nd_opt_rdnss_len;
	uint16_t nd_opt_rdnss_reserved;
	uint32_t nd_opt_rdnss_lifetime;
	/* Followed by one or more IPv6 addresses */
} __attribute__((__packed__));
#endif

#ifndef HAVE_STRUCT_ND_OPT_DNSSL
struct nd_opt_dnssl { /* DNS search list option [RFC8106 5.2] */
	uint8_t nd_opt_dnssl_type;
	uint8_t nd_opt_dnssl_len;
	uint16_t nd_opt_dnssl_reserved;
	uint32_t nd_opt_dnssl_lifetime;
	/*
	 * Followed by one or more domain names encoded as in [RFC1035 3.1].
	 * Multiple domain names are concatenated after encoding. In any case,
	 * the result is zero-padded to a multiple of 8 octets.
	 */
} __attribute__((__packed__));
#endif

/*
 * ipv6 nd prefixes can be manually defined, derived from the kernel interface
 * configs or both.  If both, manual flag/timer settings are used.
 */
enum ipv6_nd_prefix_source {
	PREFIX_SRC_NONE = 0,
	PREFIX_SRC_MANUAL,
	PREFIX_SRC_AUTO,
	PREFIX_SRC_BOTH,
};

enum ipv6_nd_suppress_ra_status {
	RA_ENABLE = 0,
	RA_SUPPRESS,
};

extern void rtadv_vrf_init(struct zebra_vrf *zvrf);
extern void rtadv_vrf_terminate(struct zebra_vrf *zvrf);
extern void rtadv_stop_ra(struct interface *ifp);
extern void rtadv_stop_ra_all(void);
extern void rtadv_cmd_init(void);
extern void rtadv_if_init(struct zebra_if *zif);
extern void rtadv_if_up(struct zebra_if *zif);
extern void rtadv_if_fini(struct zebra_if *zif);
extern void rtadv_add_prefix(struct zebra_if *zif, const struct prefix_ipv6 *p);
extern void rtadv_delete_prefix(struct zebra_if *zif, const struct prefix *p);

/* returns created prefix */
struct rtadv_prefix *rtadv_add_prefix_manual(struct zebra_if *zif,
					     struct rtadv_prefix *rp);
/* rprefix must be the one returned by rtadv_add_prefix_manual */
void rtadv_delete_prefix_manual(struct zebra_if *zif,
				struct rtadv_prefix *rprefix);

/* returns created address */
struct rtadv_rdnss *rtadv_rdnss_set(struct zebra_if *zif,
				    struct rtadv_rdnss *rdnss);
/* p must be the one returned by rtadv_rdnss_set */
void rtadv_rdnss_reset(struct zebra_if *zif, struct rtadv_rdnss *p);

/* returns created domain */
struct rtadv_dnssl *rtadv_dnssl_set(struct zebra_if *zif,
				    struct rtadv_dnssl *dnssl);
/* p must be the one returned by rtadv_dnssl_set */
void rtadv_dnssl_reset(struct zebra_if *zif, struct rtadv_dnssl *p);
int rtadv_dnssl_encode(uint8_t *out, const char *in);

void ipv6_nd_suppress_ra_set(struct interface *ifp,
			     enum ipv6_nd_suppress_ra_status status);
void ipv6_nd_interval_set(struct interface *ifp, uint32_t interval);

#else /* !HAVE_RTADV */
struct rtadv {
	/* empty structs aren't valid ISO C */
	char dummy;
};

struct rtadvconf {
	/* same again, empty structs aren't valid ISO C */
	char dummy;
};

static inline void rtadv_vrf_init(struct zebra_vrf *zvrf)
{
}
static inline void rtadv_vrf_terminate(struct zebra_vrf *zvrf)
{
}
static inline void rtadv_cmd_init(void)
{
}
static inline void rtadv_if_init(struct zebra_if *zif)
{
}
static inline void rtadv_if_up(struct zebra_if *zif)
{
}
static inline void rtadv_if_fini(struct zebra_if *zif)
{
}
static inline void rtadv_add_prefix(struct zebra_if *zif,
				    const struct prefix_ipv6 *p)
{
}
static inline void rtadv_delete_prefix(struct zebra_if *zif,
				       const struct prefix *p)
{
}
static inline void rtadv_stop_ra(struct interface *ifp)
{
}
static inline void rtadv_stop_ra_all(void)
{
}
#endif

extern void zebra_interface_radv_disable(ZAPI_HANDLER_ARGS);
extern void zebra_interface_radv_enable(ZAPI_HANDLER_ARGS);

extern uint32_t rtadv_get_interfaces_configured_from_bgp(void);
extern bool rtadv_compiled_in(void);
extern void rtadv_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_RTADV_H */
