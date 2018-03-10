/*
 * EIGRP Definition of Constants.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_EIGRP_CONST_H_
#define _ZEBRA_EIGRP_CONST_H_

#define FALSE 0

#define EIGRP_NEIGHBOR_DOWN           0
#define EIGRP_NEIGHBOR_PENDING        1
#define EIGRP_NEIGHBOR_UP             2
#define EIGRP_NEIGHBOR_STATE_MAX      3

/*Packet requiring ack will be retransmitted again after this time*/
#define EIGRP_PACKET_RETRANS_TIME        2 /* in seconds */
#define EIGRP_PACKET_RETRANS_MAX         16 /* number of retrans attempts */
#define PLAINTEXT_LENGTH                 81

/*Metric variance multiplier*/
#define EIGRP_VARIANCE_DEFAULT  1
#define EIGRP_MAX_PATHS_DEFAULT 4

/* Return values of functions involved in packet verification */
#define MSG_OK    0
#define MSG_NG    1

#define EIGRP_HEADER_VERSION            2

/* Default protocol, port number. */
#ifndef IPPROTO_EIGRPIGP
#define IPPROTO_EIGRPIGP         88
#endif /* IPPROTO_EIGRPIGP */

#define EIGRP_AUTH_MD5_TLV_SIZE          40
#define EIGRP_AUTH_SHA256_TLV_SIZE          56

/*Cisco routers use only first 44 bytes of basic hello for their MD5
 * calculations*/
#define EIGRP_MD5_BASIC_COMPUTE       44
#define EIGRP_MD5_UPDATE_INIT_COMPUTE       40

#define EIGRP_AUTH_BASIC_HELLO_FLAG       0x01
#define EIGRP_AUTH_TID_HELLO_FLAG       0x02
#define EIGRP_AUTH_UPDATE_INIT_FLAG       0x04
#define EIGRP_AUTH_UPDATE_FLAG            0x08
#define EIGRP_AUTH_EXTRA_SALT_FLAG        0x10

#define EIGRP_NEXT_SEQUENCE_TLV_SIZE     8

/* IP TTL for EIGRP protocol. */
#define EIGRP_IP_TTL             1

/* VTY port number. */
#define EIGRP_VTY_PORT          2613

/* Default configuration file name for eigrp. */
#define EIGRP_DEFAULT_CONFIG   "eigrpd.conf"

#define EIGRP_HELLO_INTERVAL_DEFAULT        5
#define EIGRP_HOLD_INTERVAL_DEFAULT         15
#define EIGRP_BANDWIDTH_DEFAULT             100000
#define EIGRP_DELAY_DEFAULT                 10
#define EIGRP_RELIABILITY_DEFAULT           255
#define EIGRP_LOAD_DEFAULT                  1

#define EIGRP_MULTICAST_ADDRESS            0xe000000A /*224.0.0.10*/

#define EIGRP_MAX_METRIC                   0xffffffffU    /*4294967295*/
enum metric_change { METRIC_DECREASE, METRIC_SAME, METRIC_INCREASE };

#define DEFAULT_ROUTE               ZEBRA_ROUTE_MAX
#define DEFAULT_ROUTE_TYPE(T) ((T) == DEFAULT_ROUTE)

#define INTERFACE_DOWN_BY_ZEBRA       1
#define INTERFACE_DOWN_BY_VTY         2
#define INTERFACE_DOWN_BY_FINAL       3

#define EIGRP_HELLO_NORMAL                    0x00
#define EIGRP_HELLO_GRACEFUL_SHUTDOWN         0x01
#define EIGRP_HELLO_ADD_SEQUENCE              0x02
#define EIGRP_HELLO_GRACEFUL_SHUTDOWN_NBR     0x04

/* EIGRP Network Type. */
#define EIGRP_IFTYPE_NONE 0
#define EIGRP_IFTYPE_POINTOPOINT 1
#define EIGRP_IFTYPE_BROADCAST 2
#define EIGRP_IFTYPE_NBMA 3
#define EIGRP_IFTYPE_POINTOMULTIPOINT 4
#define EIGRP_IFTYPE_LOOPBACK 5
#define EIGRP_IFTYPE_MAX 6

#define EIGRP_IF_ACTIVE                  0
#define EIGRP_IF_PASSIVE                 1

/* EIGRP TT destination type */
#define EIGRP_TOPOLOGY_TYPE_CONNECTED           0 // Connected network
#define EIGRP_TOPOLOGY_TYPE_REMOTE              1 // Remote internal network
#define EIGRP_TOPOLOGY_TYPE_REMOTE_EXTERNAL     2 // Remote external network

/*EIGRP TT entry flags*/
#define EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG     (1 << 0)
#define EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG    (1 << 1)
#define EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG       (1 << 2)
#define EIGRP_NEXTHOP_ENTRY_EXTERNAL_FLAG      (1 << 3)

/*EIGRP FSM state count, event count*/
#define EIGRP_FSM_STATE_MAX                  5
#define EIGRP_FSM_EVENT_MAX                  16

/*EEGRP FSM states*/
enum eigrp_fsm_states {
	EIGRP_FSM_STATE_PASSIVE,
	EIGRP_FSM_STATE_ACTIVE_0,
	EIGRP_FSM_STATE_ACTIVE_1,
	EIGRP_FSM_STATE_ACTIVE_2,
	EIGRP_FSM_STATE_ACTIVE_3,
};

/*EIGRP FSM events return values*/
#define EIGRP_FSM_NEED_UPDATE				1
#define EIGRP_FSM_NEED_QUERY				2

/*EIGRP FSM events*/
enum eigrp_fsm_events {
	/*
	 * Input event other than query from succ,
	 * FC is not satisified
	 */
	EIGRP_FSM_EVENT_NQ_FCN,

	/* last reply, FD is reset */
	EIGRP_FSM_EVENT_LR,

	/* Query from succ, FC not satisfied */
	EIGRP_FSM_EVENT_Q_FCN,

	/* last reply, FC satisifed with current value of FDij */
	EIGRP_FSM_EVENT_LR_FCS,

	/* distance increase while in a active state */
	EIGRP_FSM_EVENT_DINC,

	/* Query from succ while in active state */
	EIGRP_FSM_EVENT_QACT,

	/* last reply, FC not satisified */
	EIGRP_FSM_EVENT_LR_FCN,

	/*
	 * state not changed
	 * usually by receiving not last reply
	 */
	EIGRP_FSM_KEEP_STATE,
};

/**
 * External routes originate from some other protocol - these are them
 */
#define NULL_PROTID		0		/*!< unknown protocol */
#define IGRP_PROTID		1		/*!< IGRP.. whos your daddy! */
#define EIGRP_PROTID		2		/*!< EIGRP - Just flat out the best */
#define STATIC_PROTID		3		/*!< Staticly configured source */
#define RIP_PROTID		4		/*!< Routing Information Protocol */
#define HELLO_PROTID		5		/*!< Hello? RFC-891 you there? */
#define OSPF_PROTID		6		/*!< OSPF - Open Shortest Path First */
#define ISIS_PROTID		7		/*!< Intermediate System To Intermediate System */
#define EGP_PROTID		8		/*!< Exterior Gateway Protocol */
#define BGP_PROTID		9		/*!< Border Gateway Protocol */
#define IDRP_PROTID		10		/*!< InterDomain Routing Protocol */
#define CONN_PROTID		11		/*!< Connected source */

/*
 * metric k-value defaults
 */
#define EIGRP_K1_DEFAULT	1		//!< unweighed inverse bandwidth
#define EIGRP_K2_DEFAULT	0		//!< no loading term
#define EIGRP_K3_DEFAULT	1		//!< unweighted delay
#define EIGRP_K4_DEFAULT	0		//!< no reliability term
#define EIGRP_K5_DEFAULT	0		//!< no reliability term
#define EIGRP_K6_DEFAULT	0		//!< do not add in extended metrics

/*
 * EIGRP Fixed header
 */
#define EIGRP_HEADER_LEN        20U
#define EIGRP_PACKET_MAX_LEN    65535U   /* includes IP Header size. */

#define EIGRP_TLV_HDR_LENGTH    4

/**
 * EIGRP Packet Opcodes
 */
#define EIGRP_OPC_UPDATE        1       /*!< packet containing routing information */
#define EIGRP_OPC_REQUEST       2       /*!< sent to request one or more routes */
#define EIGRP_OPC_QUERY         3       /*!< sent when a routing is in active start */
#define EIGRP_OPC_REPLY         4       /*!< sent in response to a query */
#define EIGRP_OPC_HELLO         5       /*!< sent to maintain a peering session */
#define EIGRP_OPC_IPXSAP        6       /*!< IPX SAP information */
#define EIGRP_OPC_PROBE         7       /*!< for test purposes   */
#define EIGRP_OPC_ACK           8       /*!< acknowledge         */
#define EIGRP_OPC_SIAQUERY      10      /*!< QUERY - with relaxed restrictions */
#define EIGRP_OPC_SIAREPLY      11      /*!< REPLY - may contain old routing information */

/**
 * EIGRP TLV Range definitions
 *      PDM             TLV Range
 *      General         0x0000
 *      IPv4            0x0100                  ** TLVs for one and all
 *      ATALK           0x0200                  ** legacy
 *      IPX             0x0300                  ** discontinued
 *      IPv6            0x0400                  ** legacy
 *      Multiprotocol   0x0600                  ** wide metrics
 *      MultiTopology   0x00f0                  ** deprecated
 */
#define EIGRP_TLV_RANGEMASK     0xfff0          /*!< should be 0xff00 - opps */
#define EIGRP_TLV_GENERAL       0x0000

/**
 * 1.2 TLV Definitions  ** legacy
 * These are considered legacyu and are only used for backward compability with
 * older Cisco Routers.  They should not be your first choice for packet codings
 */
#define EIGRP_TLV_IPv4          0x0100          /*!< Classic IPv4 TLV encoding */
#define EIGRP_TLV_ATALK         0x0200          /*!< Classic Appletalk TLV encoding*/
#define EIGRP_TLV_IPX           0x0300          /*!< Classic IPX TLV encoding */
#define EIGRP_TLV_IPv6          0x0400          /*!< Classic IPv6 TLV encoding */

/**
 * 2.0 Multi-Protocol TLV Definitions
 * These are the current packet formats and should be used for packets
 */
#define EIGRP_TLV_MP            0x0600          /*!< Non-PDM specific encoding */

/**
 * TLV type definitions.  Generic (protocol-independent) TLV types are
 * defined here.  Protocol-specific ones are defined elsewhere.
 */
#define EIGRP_TLV_PARAMETER             (EIGRP_TLV_GENERAL | 0x0001)    /*!< eigrp parameters */
#define EIGRP_TLV_PARAMETER_LEN         (12U)
#define EIGRP_TLV_AUTH                  (EIGRP_TLV_GENERAL | 0x0002)    /*!< authentication */
#define EIGRP_TLV_SEQ                   (EIGRP_TLV_GENERAL | 0x0003)    /*!< sequenced packet */
#define EIGRP_TLV_SEQ_BASE_LEN          (5U)
#define EIGRP_TLV_SW_VERSION            (EIGRP_TLV_GENERAL | 0x0004)    /*!< software version */
#define EIGRP_TLV_SW_VERSION_LEN        (8U)
#define EIGRP_TLV_NEXT_MCAST_SEQ        (EIGRP_TLV_GENERAL | 0x0005)    /*!< sequence number */
#define EIGRP_TLV_PEER_TERMINATION      (EIGRP_TLV_GENERAL | 0x0007)    /*!< peer termination */
#define EIGRP_TLV_PEER_TERMINATION_LEN 	(9U)
#define EIGRP_TLV_PEER_TIDLIST          (EIGRP_TLV_GENERAL | 0x0008)    /*!< peer sub-topology list */

/* Older cisco routers send TIDLIST value wrong, adding for backwards
 * compatabily */
#define EIGRP_TLV_PEER_MTRLIST          (EIGRP_TLV_GENERAL | 0x00f5)

/**
 * Route Based TLVs
 */
#define EIGRP_TLV_REQUEST               0x0001
#define EIGRP_TLV_INTERNAL              0x0002
#define EIGRP_TLV_EXTERNAL              0x0003
#define EIGRP_TLV_COMMUNITY             0x0004
#define EIGRP_TLV_TYPEMASK              0x000f

#define EIGRP_TLV_IPv4_REQ              (EIGRP_TLV_IPv4 | EIGRP_TLV_REQUEST)
#define EIGRP_TLV_IPv4_INT              (EIGRP_TLV_IPv4 | EIGRP_TLV_INTERNAL)
#define EIGRP_TLV_IPv4_EXT              (EIGRP_TLV_IPv4 | EIGRP_TLV_EXTERNAL)
#define EIGRP_TLV_IPv4_COM              (EIGRP_TLV_IPv4 | EIGRP_TLV_COMMUNITY)

#define EIGRP_TLV_IPV4_SIZE_GRT_24_BIT      0x001D
#define EIGRP_TLV_IPV4_SIZE_GRT_16_BIT      0x001C
#define EIGRP_TLV_IPV4_SIZE_GRT_8_BIT       0x001B
#define EIGRP_TLV_IPV4_SIZE_GRT_0_BIT       0x001A
#define EIGRP_TLV_MAX_IPV4_BYTE             EIGRP_TLV_IPV4_SIZE_GRT_24_BIT

/* max number of TLV IPv4 prefixes in packet */
#define EIGRP_TLV_MAX_IPv4				25

/**
 *
 * extdata flag field definitions
 */
#define EIGRP_OPAQUE_EXT        0x01    /*!< Route is external */
#define EIGRP_OPAQUE_CD         0x02    /*!< Candidate default route */

/**
 * Address-Family types are taken from:
 *       http://www.iana.org/assignments/address-family-numbers
 * to provide a standards based exchange of AFI information between
 * EIGRP routers.
 */
#define EIGRP_AF_IPv4           1       /*!< IPv4 (IP version 4) */
#define EIGRP_AF_IPv6           2       /*!< IPv6 (IP version 6) */
#define EIGRP_AF_IPX            11      /*!< IPX */
#define EIGRP_AF_ATALK          12      /*!< Appletalk */
#define EIGRP_SF_COMMON         16384   /*!< Cisco Service Family */
#define EIGRP_SF_IPv4           16385   /*!< Cisco IPv4 Service Family */
#define EIGRP_SF_IPv6           16386   /*!< Cisco IPv6 Service Family */

/**
 * Authentication types supported by EIGRP
 */
#define EIGRP_AUTH_TYPE_NONE            0
#define EIGRP_AUTH_TYPE_TEXT            1
#define EIGRP_AUTH_TYPE_MD5             2
#define EIGRP_AUTH_TYPE_MD5_LEN         16
#define EIGRP_AUTH_TYPE_SHA256          3
#define EIGRP_AUTH_TYPE_SHA256_LEN      32

/**
 * opaque flag field definitions
 */
#define EIGRP_OPAQUE_SRCWD      0x01    /*!< Route Source Withdraw */
#define EIGRP_OPAQUE_ACTIVE     0x04    /*!< Route is currently in active state */
#define EIGRP_OPAQUE_REPL       0x08    /*!< Route is replicated from different tableid */

/**
 * pak flag bit field definitions - 0 (none)-7 source priority
 */
#define EIGRP_PRIV_DEFAULT      0x00    /* 0 (none)-7 source priority */
#define EIGRP_PRIV_LOW          0x01
#define EIGRP_PRIV_MEDIUM       0x04
#define EIGRP_PRIV_HIGH         0x07

/*
 * Init bit definition. First unicast transmitted Update has this
 * bit set in the flags field of the fixed header. It tells the neighbor
 * to down-load his topology table.
 */
#define EIGRP_INIT_FLAG 0x01

/*
 * CR bit (Conditionally Received) definition in flags field on header. Any
 * packets with the CR-bit set can be accepted by an EIGRP speaker if and
 * only if a previous Hello was received with the SEQUENCE_TYPE TLV present.
 *
 * This allows multicasts to be transmitted in order and reliably at the
 * same time as unicasts are transmitted.
 */
#define EIGRP_CR_FLAG 0x02

/*
 * RS bit.  The Restart flag is set in the hello and the init
 * update packets during the nsf signaling period.  A nsf-aware
 * router looks at the RS flag to detect if a peer is restarting
 * and maintain the adjacency. A restarting router looks at
 * this flag to determine if the peer is helping out with the restart.
 */
#define EIGRP_RS_FLAG 0x04

/*
 * EOT bit.  The End-of-Table flag marks the end of the start-up updates
 * sent to a new peer.  A nsf restarting router looks at this flag to
 * determine if it has finished receiving the start-up updates from all
 * peers.  A nsf-aware router waits for this flag before cleaning up
 * the stale routes from the restarting peer.
 */
#define EIGRP_EOT_FLAG 0x08

/**
 * EIGRP Virtual Router ID
 *
 * Define values to deal with EIGRP virtual router ids.  Virtual
 * router IDs are stored in the upper short of the EIGRP fixed packet
 * header.  The lower short of the packet header continues to be used
 * as asystem number.
 *
 * Virtual Router IDs are PDM-independent.  All PDMs will use
 * VRID_BASE to indicate the 'base' or 'legacy' EIGRP instance.
 * All PDMs need to initialize their vrid to VRID_BASE for compatibility
 * with legacy routers.
 * Once IPv6 supports 'MTR Multicast', it will use the same VRID as
 * IPv4.  No current plans to support VRIDs on IPX. :)
 * Initial usage of VRID is to signal usage of Multicast topology for
 * MTR.
 *
 * VRID_MCAST is a well known constant, other VRIDs will be determined
 * programmatic...
 *
 * With the addition of SAF the VRID space has been divided into two
 * segments 0x0000-0x7fff is for EIGRP and vNets, 0x8000-0xffff is
 * for saf and its associated vNets.
 */
#define EIGRP_VRID_MASK         0x8001
#define EIGRP_VRID_AF_BASE      0x0000
#define EIGRP_VRID_MCAST_BASE   0x0001
#define EIGRP_VRID_SF_BASE      0x8000

/* Extended Attributes for a destination */
#define EIGRP_ATTR_HDRLEN (2)
#define EIGRP_ATTR_MAXDATA (512)

#define EIGRP_ATTR_NOOP         0       /*!< No-Op used as offset padding */
#define EIGRP_ATTR_SCALED       1       /*!< Scaled metric values */
#define EIGRP_ATTR_TAG          2       /*!< Tag assigned by Admin for dest */
#define EIGRP_ATTR_COMM         3       /*!< Community attribute for dest */
#define EIGRP_ATTR_JITTER       4       /*!< Variation in path delay */
#define EIGRP_ATTR_QENERGY      5       /*!< Non-Active energy usage along path */
#define EIGRP_ATTR_ENERGY       6       /*!< Active energy usage along path */

/*
 * Begin EIGRP-BGP interoperability communities
 */
#define EIGRP_EXTCOMM_SOO_ASFMT         0x0003 /* Site-of-Origin, BGP AS format */
#define EIGRP_EXTCOMM_SOO_ADRFMT        0x0103 /* Site-of-Origin, BGP/EIGRP addr format */

/*
 * EIGRP Specific communities
 */
#define EIGRP_EXTCOMM_EIGRP             0x8800 /* EIGRP route information appended*/
#define EIGRP_EXTCOMM_DAD               0x8801 /* EIGRP AS + Delay           */
#define EIGRP_EXTCOMM_VRHB              0x8802 /* EIGRP Vector: Reliability + Hop + BW */
#define EIGRP_EXTCOMM_SRLM              0x8803 /* EIGRP System: Reserve +Load + MTU   */
#define EIGRP_EXTCOMM_SAR               0x8804 /* EIGRP System: Remote AS + Remote ID  */
#define EIGRP_EXTCOMM_RPM               0x8805 /* EIGRP Remote: Protocol + Metric    */
#define EIGRP_EXTCOMM_VRR               0x8806 /* EIGRP Vecmet: Rsvd + (internal) Routerid */

/*
 * EIGRP Filter constants
 */
#define EIGRP_FILTER_IN  0
#define EIGRP_FILTER_OUT 1
#define EIGRP_FILTER_MAX 2

/*
 * EIGRP Filter constants
 */
#define EIGRP_HSROLE_DEFAULT  	EIGRP_HSROLE_SPOKE
#define EIGRP_HSROLE_HUB 		0x01
#define EIGRP_HSROLE_SPOKE 		0x02

#endif /* _ZEBRA_EIGRP_CONST_H_ */
