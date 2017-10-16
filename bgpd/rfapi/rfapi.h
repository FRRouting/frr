/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_RFAPI_H
#define _QUAGGA_BGP_RFAPI_H

#if ENABLE_BGP_VNC

#include <stdint.h>
#include <netinet/in.h>
#include "lib/zebra.h"
#include "lib/vty.h"
#include "lib/prefix.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_encap_types.h"

/* probably ought to have a field-specific define in config.h */
#ifndef s6_addr32 /* for solaris/bsd */
#ifdef SOLARIS_IPV6
#   define	s6_addr32	_S6_un._S6_u32
#else
#   define	s6_addr32	__u6_addr.__u6_addr32
#endif
#endif

#define RFAPI_V4_ADDR 0x04
#define RFAPI_V6_ADDR 0x06
#define RFAPI_SHOW_STR "VNC information\n"

struct rfapi_ip_addr {
	uint8_t addr_family; /* AF_INET | AF_INET6 */
	union {
		struct in_addr v4;  /* in network order */
		struct in6_addr v6; /* in network order */
	} addr;
};

struct rfapi_ip_prefix {
	uint8_t length;
	uint8_t cost; /* bgp local pref = 255 - cost */
	struct rfapi_ip_addr prefix;
};

struct rfapi_nexthop {
	struct prefix addr;
	uint8_t cost;
};

struct rfapi_next_hop_entry {
	struct rfapi_next_hop_entry *next;
	struct rfapi_ip_prefix prefix;
	uint32_t lifetime;
	struct rfapi_ip_addr un_address;
	struct rfapi_ip_addr vn_address;
	struct rfapi_vn_option *vn_options;
	struct rfapi_un_option *un_options;
};

#define RFAPI_REMOVE_RESPONSE_LIFETIME  0
#define RFAPI_INFINITE_LIFETIME         0xFFFFFFFF

struct rfapi_l2address_option {
	struct ethaddr macaddr; /* use 0 to assign label to IP prefix */
	uint32_t label;		/* 20bit label in low bits, no TC, S, or TTL  */
	uint32_t logical_net_id; /* ~= EVPN Ethernet Segment Id,
			    must not be zero for mac regis. */
	uint8_t local_nve_id;
	uint16_t tag_id; /* EVPN Ethernet Tag ID, 0 = none */
};

typedef enum {
	RFAPI_UN_OPTION_TYPE_PROVISIONAL, /* internal use only */
	RFAPI_UN_OPTION_TYPE_TUNNELTYPE,
} rfapi_un_option_type;

struct rfapi_tunneltype_option {
	bgp_encap_types type;
	union {
		struct bgp_encap_type_reserved reserved;
		struct bgp_encap_type_l2tpv3_over_ip l2tpv3_ip;
		struct bgp_encap_type_gre gre;
		struct bgp_encap_type_transmit_tunnel_endpoint
			transmit_tunnel_endpoint;
		struct bgp_encap_type_ipsec_in_tunnel_mode ipsec_tunnel;
		struct bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode
			ip_ipsec;
		struct bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode
			mpls_ipsec;
		struct bgp_encap_type_ip_in_ip ip_ip;
		struct bgp_encap_type_vxlan vxlan;
		struct bgp_encap_type_nvgre nvgre;
		struct bgp_encap_type_mpls mpls;
		struct bgp_encap_type_mpls_in_gre mpls_gre;
		struct bgp_encap_type_vxlan_gpe vxlan_gpe;
		struct bgp_encap_type_mpls_in_udp mpls_udp;
		struct bgp_encap_type_pbb pbb;
	} bgpinfo;
};

struct rfapi_un_option {
	struct rfapi_un_option *next;
	rfapi_un_option_type type;
	union {
		struct rfapi_tunneltype_option tunnel;
	} v;
};

typedef enum {
	RFAPI_VN_OPTION_TYPE_L2ADDR =
		3, /* Layer 2 address, 3 for legacy compatibility */
	RFAPI_VN_OPTION_TYPE_LOCAL_NEXTHOP, /* for static routes */
	RFAPI_VN_OPTION_TYPE_INTERNAL_RD,   /* internal use only */
} rfapi_vn_option_type;

struct rfapi_vn_option {
	struct rfapi_vn_option *next;

	rfapi_vn_option_type type;

	union {
		struct rfapi_l2address_option l2addr;

		/*
		 * If this option is present, the next hop is local to the
		 * client NVE (i.e., not via a tunnel).
		 */
		struct rfapi_nexthop local_nexthop;

		/*
		 * For rfapi internal use only
		 */
		struct prefix_rd internal_rd;
	} v;
};

struct rfapi_l2address_option_match {
	struct rfapi_l2address_option o;
	uint32_t flags;

#define RFAPI_L2O_MACADDR		0x00000001
#define RFAPI_L2O_LABEL			0x00000002
#define RFAPI_L2O_LNI			0x00000004
#define RFAPI_L2O_LHI			0x00000008
};

#define VNC_CONFIG_STR "VNC/RFP related configuration\n"

typedef void *rfapi_handle;

/***********************************************************************
 *			RFP Callbacks
 ***********************************************************************/
/*------------------------------------------
 * rfapi_response_cb_t (callback typedef)
 *
 * Callbacks of this type are used to provide asynchronous
 * route updates from RFAPI to the RFP client.
 *
 * response_cb
 *	called to notify the rfp client that a next hop list
 *	that has previously been provided in response to an
 *	rfapi_query call has been updated. Deleted routes are indicated
 *	with lifetime==RFAPI_REMOVE_RESPONSE_LIFETIME.
 *
 *	By default, the routes an NVE receives via this callback include
 *	its own routes (that it has registered). However, these may be
 *	filtered out if the global BGP_VNC_CONFIG_FILTER_SELF_FROM_RSP
 *	flag is set.
 *
 * local_cb
 *	called to notify the rfp client that a local route
 *	has been added or deleted. Deleted routes are indicated
 *	with lifetime==RFAPI_REMOVE_RESPONSE_LIFETIME.
 *
 * input:
 *	next_hops	a list of possible next hops.
 *			This is a linked list allocated within the
 *			rfapi. The response_cb callback function is responsible
 *			for freeing this memory via rfapi_free_next_hop_list()
 *			in order to avoid memory leaks.
 *
 *	userdata	value (cookie) originally specified in call to
 *			rfapi_open()
 *
 *------------------------------------------*/
typedef void(rfapi_response_cb_t)(struct rfapi_next_hop_entry *next_hops,
				  void *userdata);

/*------------------------------------------
 * rfapi_nve_close_cb_t (callback typedef)
 *
 * Callbacks of this type are used to provide asynchronous
 * notification that an rfapi_handle was invalidated
 *
 * input:
 *	pHandle		Firmerly valid rfapi_handle returned to
 *			client via rfapi_open().
 *
 *	reason		EIDRM	handle administratively closed (clear nve ...)
 *			ESTALE	handle invalidated by configuration change
 *
 *------------------------------------------*/
typedef void(rfapi_nve_close_cb_t)(rfapi_handle pHandle, int reason);

/*------------------------------------------
 * rfp_cfg_write_cb_t (callback typedef)
 *
 * This callback is used to generate output for any config parameters
 * that may supported by RFP  via RFP defined vty commands at the bgp
 * level.  See loglevel as an example.
 *
 * input:
 *    vty           -- quagga vty context
 *    rfp_start_val -- value returned by rfp_start
 *
 * output:
 *    to vty, rfp related configuration
 *
 * return value:
 *    lines written
--------------------------------------------*/
typedef int(rfp_cfg_write_cb_t)(struct vty *vty, void *rfp_start_val);

/*------------------------------------------
 * rfp_cfg_group_write_cb_t (callback typedef)
 *
 * This callback is used to generate output for any config parameters
 * that may supported by RFP via RFP defined vty commands at the
 * L2 or NVE level.  See loglevel as an example.
 *
 * input:
 *    vty              quagga vty context
 *    rfp_start_val    value returned by rfp_start
 *    type             group type
 *    name             group name
 *    rfp_cfg_group    Pointer to configuration structure
 *
 * output:
 *    to vty, rfp related configuration
 *
 * return value:
 *    lines written
--------------------------------------------*/
typedef enum {
	RFAPI_RFP_CFG_GROUP_DEFAULT,
	RFAPI_RFP_CFG_GROUP_NVE,
	RFAPI_RFP_CFG_GROUP_L2
} rfapi_rfp_cfg_group_type;

typedef int(rfp_cfg_group_write_cb_t)(struct vty *vty, void *rfp_start_val,
				      rfapi_rfp_cfg_group_type type,
				      const char *name, void *rfp_cfg_group);

/***********************************************************************
 * Configuration related defines and structures
 ***********************************************************************/

struct rfapi_rfp_cb_methods {
	rfp_cfg_write_cb_t *cfg_cb;		/* show top level config */
	rfp_cfg_group_write_cb_t *cfg_group_cb; /* show group level config */
	rfapi_response_cb_t *response_cb;       /* unsolicited responses */
	rfapi_response_cb_t *local_cb;		/* local route add/delete */
	rfapi_nve_close_cb_t *close_cb;		/* handle closed */
};

/*
 * If a route with infinite lifetime is withdrawn, this is
 * how long (in seconds) to wait before expiring it (because
 * RFAPI_LIFETIME_MULTIPLIER_PCT * infinity is too long to wait)
 */
#define RFAPI_LIFETIME_INFINITE_WITHDRAW_DELAY (60*120)

/*
 * the factor that should be applied to a prefix's <lifetime> value
 * before using it to expire a withdrawn prefix, expressed as a percent.
 * Thus, a value of 100 means to use the exact value of <lifetime>,
 * a value of 200 means to use twice the value of <lifetime>, etc.
 */
#define RFAPI_RFP_CFG_DEFAULT_HOLDDOWN_FACTOR	150

/*
 * This is used by rfapi to determine if RFP is using/supports
 * a partial (i.e., cache) or full table download approach for
 * mapping information.  When  full table download approach is
 * used all information is passed to RFP after an initial
 * rfapi_query.  When partial table download is used, only
 * information matching a query is passed.
 */
typedef enum {
	RFAPI_RFP_DOWNLOAD_PARTIAL = 0,
	RFAPI_RFP_DOWNLOAD_FULL
} rfapi_rfp_download_type;

#define RFAPI_RFP_CFG_DEFAULT_FTD_ADVERTISEMENT_INTERVAL 1

struct rfapi_rfp_cfg {
	/* partial or full table download */
	rfapi_rfp_download_type download_type; /* default=partial */
	/*
	 * When full-table-download is enabled, this is the minimum
	 * number of seconds between times a non-queried prefix will
	 * be updated to a particular NVE.
	 * default: RFAPI_RFP_CFG_DEFAULT_FTD_ADVERTISEMENT_INTERVAL
	 */
	uint32_t ftd_advertisement_interval;
	/*
	 * percentage of registration lifetime to continue to use information
	 * post soft-state refresh timeout
	 default: RFAPI_RFP_CFG_DEFAULT_HOLDDOWN_FACTOR
	 */
	uint32_t holddown_factor;
	/* Control generation of updated RFP responses */
	uint8_t use_updated_response; /* default=0/no */
	/* when use_updated_response, also generate remove responses */
	uint8_t use_removes; /* default=0/no */
};

/***********************************************************************
 * Process related functions -- MUST be provided by the RFAPI user <<===
 ***********************************************************************/

/*------------------------------------------
 * rfp_start
 *
 * This function will start the RFP code
 *
 * input:
 *    master    quagga thread_master to tie into bgpd threads
 *
 * output:
 *    cfgp      Pointer to rfapi_rfp_cfg (null = use defaults),
 *              copied by caller, updated via rfp_set_configuration
 *    cbmp      Pointer to rfapi_rfp_cb_methods, may be null
 *              copied by caller, updated via rfapi_rfp_set_cb_methods
 * return value:
 *    rfp_start_val rfp returned value passed on rfp_stop and other rfapi calls
--------------------------------------------*/
extern void *rfp_start(struct thread_master *master,
		       struct rfapi_rfp_cfg **cfgp,
		       struct rfapi_rfp_cb_methods **cbmp);

/*------------------------------------------
 * rfp_stop
 *
 * This function is called on shutdown to trigger RFP cleanup
 *
 * input:
 *    rfp_start_val
 *
 * output:
 *    none
 *
 * return value:
--------------------------------------------*/
extern void rfp_stop(void *rfp_start_val);

/***********************************************************************
 *		 RFP processing behavior configuration
 ***********************************************************************/

/*------------------------------------------
 * rfapi_rfp_set_configuration
 *
 * This is used to change rfapi's processing behavior based on
 * RFP requirements.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    rfapi_rfp_cfg     Pointer to configuration structure
 *
 * output:
 *    none
 *
 * return value:
 *	0		Success
 *	ENXIO		Unabled to locate configured BGP/VNC
--------------------------------------------*/
extern int rfapi_rfp_set_configuration(void *rfp_start_val,
				       struct rfapi_rfp_cfg *rfp_cfg);

/*------------------------------------------
 * rfapi_rfp_set_cb_methods
 *
 * Change registered callback functions for asynchronous notifications
 * from RFAPI to the RFP client.
 *
 * input:
 *    rfp_start_val     value by rfp_start
 *    methods		Pointer to struct rfapi_rfp_cb_methods containing
 *			pointers to callback methods as described above
 *
 * return value:
 *	0		Success
 *	ENXIO		BGP or VNC not configured
 *------------------------------------------*/
extern int rfapi_rfp_set_cb_methods(void *rfp_start_val,
				    struct rfapi_rfp_cb_methods *methods);

/***********************************************************************
 *		 RFP group specific configuration
 ***********************************************************************/

/*------------------------------------------
 * rfapi_rfp_init_group_config_ptr_vty
 *
 * This is used to init or return a previously init'ed group specific
 * configuration pointer. Group is identified by vty context.
 * NOTE: size is ignored when a previously init'ed value is returned.
 * RFAPI frees rfp_cfg_group when group is deleted during reconfig,
 * bgp restart or shutdown.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    type              group type
 *    vty               quagga vty context
 *    size              number of bytes to allocation
 *
 * output:
 *    none
 *
 * return value:
 *    rfp_cfg_group     NULL or Pointer to configuration structure
--------------------------------------------*/
extern void *rfapi_rfp_init_group_config_ptr_vty(void *rfp_start_val,
						 rfapi_rfp_cfg_group_type type,
						 struct vty *vty,
						 uint32_t size);

/*------------------------------------------
 * rfapi_rfp_get_group_config_ptr_vty
 *
 * This is used to get group specific configuration pointer.
 * Group is identified by type and vty context.
 * RFAPI frees rfp_cfg_group when group is deleted during reconfig,
 * bgp restart or shutdown.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    type              group type
 *    vty               quagga vty context
 *
 * output:
 *    none
 *
 * return value:
 *    rfp_cfg_group     Pointer to configuration structure
--------------------------------------------*/
extern void *rfapi_rfp_get_group_config_ptr_vty(void *rfp_start_val,
						rfapi_rfp_cfg_group_type type,
						struct vty *vty);

/*------------------------------------------
 * rfp_group_config_search_cb_t (callback typedef)
 *
 * This callback is used to called from within a
 * rfapi_rfp_get_group_config_ptr to check if the rfp_cfg_group
 * matches the search criteria
 *
 * input:
 *    criteria          RFAPI caller provided serach criteria
 *    rfp_cfg_group     Pointer to configuration structure | NULL
 *
 * output:
 *
 * return value:
 *      0               Match/Success
 *	ENOENT		No matching
--------------------------------------------*/
typedef int(rfp_group_config_search_cb_t)(void *criteria, void *rfp_cfg_group);

/*------------------------------------------
 * rfapi_rfp_get_group_config_ptr_name
 *
 * This is used to get group specific configuration pointer.
 * Group is identified by type and name context.
 * RFAPI frees rfp_cfg_group when group is deleted during reconfig,
 * bgp restart or shutdown.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    type              group type
 *    name              group name
 *    criteria          RFAPI caller provided serach criteria
 *    search_cb         optional rfp_group_config_search_cb_t
 *
 * output:
 *    none
 *
 * return value:
 *    rfp_cfg_group     Pointer to configuration structure
--------------------------------------------*/
extern void *rfapi_rfp_get_group_config_ptr_name(
	void *rfp_start_val, rfapi_rfp_cfg_group_type type, const char *name,
	void *criteria, rfp_group_config_search_cb_t *search_cb);

/*------------------------------------------
 * rfapi_rfp_get_l2_group_config_ptr_lni
 *
 * This is used to get group specific configuration pointer.
 * Group is identified by type and logical network identifier.
 * RFAPI frees rfp_cfg_group when group is deleted during reconfig,
 * bgp restart or shutdown.
 *
 * input:
 *    rfp_start_val     value returned by rfp_start
 *    logical_net_id    group logical network identifier
 *    criteria          RFAPI caller provided serach criteria
 *    search_cb         optional rfp_group_config_search_cb_t
 *
 * output:
 *    none
 *
 * return value:
 *    rfp_cfg_group     Pointer to configuration structure
--------------------------------------------*/
extern void *
rfapi_rfp_get_l2_group_config_ptr_lni(void *rfp_start_val,
				      uint32_t logical_net_id, void *criteria,
				      rfp_group_config_search_cb_t *search_cb);

/***********************************************************************
 *			NVE Sessions
 ***********************************************************************/

/*------------------------------------------
 * rfapi_open
 *
 * This function initializes a NVE record and associates it with
 * the specified VN and underlay network addresses
 *
 * input:
 *      rfp_start_val   value returned by rfp_start
 *	vn		NVE virtual network address
 *
 *	un		NVE underlay network address
 *
 *	default_options	Default options to use on registrations.
 *			For now only tunnel type is supported.
 *			May be overridden per-prefix in rfapi_register().
 *			Caller owns (rfapi_open() does not free)
 *
 *	response_cb	Pointer to next hop list update callback function or
 *			NULL when no callbacks are desired.
 *
 *	userdata	Passed to subsequent response_cb invocations.
 *
 * output:
 *	response_lifetime The length of time that responses sent to this
 *			NVE are valid.
 *
 *	pHandle		pointer to location to store rfapi handle. The
 *			handle must be passed on subsequent rfapi_ calls.
 *
 *
 * return value:
 *	0		Success
 *	EEXIST		NVE with this {vn,un} already open
 *	ENOENT		No matching nve group config
 *	ENOMSG		Matched nve group config was incomplete
 *	ENXIO		BGP or VNC not configured
 *	EAFNOSUPPORT	Matched nve group specifies auto-assignment of RD,
 *			but underlay network address is not IPv4
 *	EDEADLK		Called from within a callback procedure
 *------------------------------------------*/
extern int rfapi_open(void *rfp_start_val, struct rfapi_ip_addr *vn,
		      struct rfapi_ip_addr *un,
		      struct rfapi_un_option *default_options,
		      uint32_t *response_lifetime, void *userdata,
		      rfapi_handle *pHandle);


/*------------------------------------------
 * rfapi_close
 *
 * Shut down NVE session and release associated data. Calling
 * from within a rfapi callback procedure is permitted (the close
 * will be completed asynchronously after the callback finishes).
 *
 * input:
 *    rfd: rfapi descriptor returned by rfapi_open
 *
 * output:
 *
 * return value:
 *	0		Success
 *	EBADF		invalid handle
 *	ENXIO		BGP or VNC not configured
 *------------------------------------------*/
extern int rfapi_close(rfapi_handle rfd);

/*------------------------------------------
 * rfapi_check
 *
 * Test rfapi descriptor
 *
 * input:
 *    rfd: rfapi descriptor returned by rfapi_open
 *
 * output:
 *
 * return value:
 *	0		Success: handle is valid and usable
 *	EINVAL		null argument
 *	ESTALE		formerly valid handle invalidated by config, needs close
 *	EBADF		invalid handle
 *	ENXIO		BGP or VNC not configured
 *	EAFNOSUPPORT	Internal addressing error
 *------------------------------------------*/
extern int rfapi_check(rfapi_handle rfd);

/***********************************************************************
 *			NVE Routes
 ***********************************************************************/

/*------------------------------------------
 * rfapi_query
 *
 * This function queries the RIB for a
 * particular route.  Note that this call may result in subsequent
 * callbacks to response_cb.  Response callbacks can be cancelled
 * by calling rfapi_query_done.  A duplicate query using the same target
 * will result in only one callback per change in next_hops. (i.e.,
 * cancel/replace the prior query results.)
 *
 * input:
 *    rfd:	rfapi descriptor returned by rfapi_open
 *    target:	the destination address
 *    l2o	ptr to L2 Options struct, NULL if not present in query
 *
 * output:
 *	ppNextHopEntry	pointer to a location to store a pointer
 *			to the returned list of nexthops. It is the
 *			caller's responsibility to free this list
 *			via rfapi_free_next_hop_list().
 *
 *
 * return value:
 *	0		Success
 *	EBADF		invalid handle
 *	ENOENT		no valid route
 *	ENXIO		BGP or VNC not configured
 *	ESTALE		descriptor is no longer usable; should be closed
 *	EDEADLK		Called from within a callback procedure
--------------------------------------------*/
extern int rfapi_query(rfapi_handle rfd, struct rfapi_ip_addr *target,
		       struct rfapi_l2address_option *l2o,
		       struct rfapi_next_hop_entry **ppNextHopEntry);

/*------------------------------------------
 * rfapi_query_done
 *
 * Notifies the rfapi that the user is no longer interested
 * in the specified target.
 *
 * input:
 *    rfd:	rfapi descriptor returned by rfapi_open
 *    target:	the destination address
 *
 * output:
 *
 * return value:
 *	0		Success
 *	EBADF		invalid handle
 *	ENOENT		no match found for target
 *	ENXIO		BGP or VNC not configured
 *	ESTALE		descriptor is no longer usable; should be closed
 *	EDEADLK		Called from within a callback procedure
--------------------------------------------*/
extern int rfapi_query_done(rfapi_handle rfd, struct rfapi_ip_addr *target);

/*------------------------------------------
 * rfapi_query_done_all
 *
 * Notifies the rfapi that the user is no longer interested
 * in any target.
 *
 * input:
 *    rfd:	rfapi descriptor returned by rfapi_open
 *
 * output:
 *    count:	number of queries cleared
 *
 * return value:
 *	0		Success
 *	EBADF		invalid handle
 *	ENXIO		BGP or VNC not configured
 *	ESTALE		descriptor is no longer usable; should be closed
 *	EDEADLK		Called from within a callback procedure
--------------------------------------------*/
extern int rfapi_query_done_all(rfapi_handle rfd, int *count);

/*------------------------------------------
 * rfapi_register
 *
 * Requests that reachability to the indicated prefix via this NVE
 * be advertised by BGP. If <unregister> is non-zero, then the previously-
 * advertised prefix should be withdrawn.
 *
 * (This function should NOT be called if the rfapi_open() function
 * returns NULL)
 *
 * input:
 *    rfd:		rfapi descriptor returned by rfapi_open
 *    prefix:           A prefix to be registered or deregistered
 *    lifetime		Prefix lifetime in seconds, host byte order
 *    options_un	underlay netowrk options, may include tunnel-type
 *			Caller owns (rfapi_register() does not free).
 *    options_vn	virtual network options, may include layer 2 address
 *			option and local-nexthop option
 *			Caller owns (rfapi_register() does not free).
 *
 *    action:       	RFAPI_REGISTER_ADD	add the route
 *                      RFAPI_REGISTER_WITHDRAW	withdraw route
 *			RFAPI_REGISTER_KILL	withdraw without holddown
 *
 * return value:
 *	0		Success
 *	EBADF		invalid handle
 *	ENXIO		BGP or VNC not configured
 *	ESTALE		descriptor is no longer usable; should be closed
 *	EDEADLK		Called from within a callback procedure
 --------------------------------------------*/

typedef enum {
	RFAPI_REGISTER_ADD,
	RFAPI_REGISTER_WITHDRAW,
	RFAPI_REGISTER_KILL
} rfapi_register_action;

extern int rfapi_register(rfapi_handle rfd, struct rfapi_ip_prefix *prefix,
			  uint32_t lifetime, struct rfapi_un_option *options_un,
			  struct rfapi_vn_option *options_vn,
			  rfapi_register_action action);

/***********************************************************************
 *			Helper / Utility functions
 ***********************************************************************/

/*------------------------------------------
 * rfapi_get_vn_addr
 *
 * Get the virtual network address used by an NVE based on it's RFD
 *
 * input:
 *    rfd: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *
 * output:
 *
 * return value:
 *	vn		NVE virtual network address
 *------------------------------------------*/
extern struct rfapi_ip_addr *rfapi_get_vn_addr(void *);

/*------------------------------------------
 * rfapi_get_un_addr
 *
 * Get the underlay network address used by an NVE based on it's RFD
 *
 * input:
 *    rfd: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *
 * output:
 *
 * return value:
 *	un		NVE underlay network address
 *------------------------------------------*/
extern struct rfapi_ip_addr *rfapi_get_un_addr(void *);

/*------------------------------------------
 * rfapi_error_str
 *
 * Returns a string describing the rfapi error code.
 *
 * input:
 *
 *	code		Error code returned by rfapi function
 *
 * returns:
 *
 *	const char *	String
 *------------------------------------------*/
extern const char *rfapi_error_str(int code);

/*------------------------------------------
 * rfapi_get_rfp_start_val
 *
 * Returns value passed to rfapi on rfp_start
 *
 * input:
 *	void *		bgp structure
 *
 * returns:
 *	void *
 *------------------------------------------*/
extern void *rfapi_get_rfp_start_val(void *bgpv);

/*------------------------------------------
 * rfapi_compare_rfds
 *
 * Compare two generic rfapi descriptors.
 *
 * input:
 *    rfd1: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *    rfd2: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *
 * output:
 *
 * return value:
 *	0		Mismatch
 *	1		Match
 *------------------------------------------*/
extern int rfapi_compare_rfds(void *rfd1, void *rfd2);

/*------------------------------------------
 * rfapi_free_next_hop_list
 *
 * Frees a next_hop_list returned by a rfapi_query invocation
 *
 * input:
 *    list:   a pointer to a response list (as a
 *            struct rfapi_next_hop_entry) to free.
 *
 * output:
 *
 * return value: None
 --------------------------------------------*/
extern void rfapi_free_next_hop_list(struct rfapi_next_hop_entry *list);

/*------------------------------------------
 * rfapi_get_response_lifetime_default
 *
 * Returns the default lifetime for a response.
 *    rfp_start_val     value returned by rfp_start or
 *                      NULL (=use default instance)
 *
 * input:
 *    None
 *
 * output:
 *
 * return value: The bgp instance default lifetime for a response.
 --------------------------------------------*/
extern int rfapi_get_response_lifetime_default(void *rfp_start_val);

/*------------------------------------------
 * rfapi_is_vnc_configured
 *
 * Returns if VNC is configured
 *
 * input:
 *    rfp_start_val     value returned by rfp_start or
 *                      NULL (=use default instance)
 *
 * output:
 *
 * return value: If VNC is configured for the bgpd instance
 *	0		Success
 *	ENXIO		VNC not configured
 --------------------------------------------*/
extern int rfapi_is_vnc_configured(void *rfp_start_val);

/*------------------------------------------
 * rfapi_bgp_lookup_by_rfp
 *
 * Find bgp instance pointer based on value returned by rfp_start
 *
 * input:
 *      rfp_start_val     value returned by rfp_startor
 *                        NULL (=get default instance)
 *
 * output:
 *	none
 *
 * return value:
 *	bgp             bgp instance pointer
 *      NULL = not found
 *
 --------------------------------------------*/
extern struct bgp *rfapi_bgp_lookup_by_rfp(void *rfp_start_val);

/*------------------------------------------
 * rfapi_get_rfp_start_val_by_bgp
 *
 * Find bgp instance pointer based on value returned by rfp_start
 *
 * input:
 *	bgp             bgp instance pointer
 *
 * output:
 *	none
 *
 * return value:
 *	rfp_start_val
 *      NULL = not found
 *
 --------------------------------------------*/
extern void *rfapi_get_rfp_start_val_by_bgp(struct bgp *bgp);

#endif /* ENABLE_BGP_VNC */

#endif /* _QUAGGA_BGP_RFAPI_H */
