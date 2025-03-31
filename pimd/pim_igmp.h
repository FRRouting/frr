// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_IGMP_H
#define PIM_IGMP_H

#include <netinet/in.h>

#include <zebra.h>
#include "vty.h"
#include "linklist.h"
#include "pim_igmp_stats.h"
#include "pim_str.h"

/*
  The following sizes are likely to support
  any message sent within local MTU.
*/
#define PIM_IGMP_BUFSIZE_READ         (20000)
#define PIM_IGMP_BUFSIZE_WRITE        (20000)

#define PIM_IGMP_MEMBERSHIP_QUERY     (0x11)
#define PIM_IGMP_V1_MEMBERSHIP_REPORT (0x12)
#define PIM_IGMP_V2_MEMBERSHIP_REPORT (0x16)
#define PIM_IGMP_V2_LEAVE_GROUP       (0x17)
#define PIM_IGMP_MTRACE_RESPONSE      (0x1E)
#define PIM_IGMP_MTRACE_QUERY_REQUEST (0x1F)
#define PIM_IGMP_V3_MEMBERSHIP_REPORT (0x22)

#define IGMP_V3_REPORT_HEADER_SIZE    (8)
#define IGMP_V3_GROUP_RECORD_MIN_SIZE (8)
#define IGMP_V3_MSG_MIN_SIZE                                                   \
	(IGMP_V3_REPORT_HEADER_SIZE + IGMP_V3_GROUP_RECORD_MIN_SIZE)
#define IGMP_V12_MSG_SIZE             (8)

#define IGMP_V3_GROUP_RECORD_TYPE_OFFSET       (0)
#define IGMP_V3_GROUP_RECORD_AUXDATALEN_OFFSET (1)
#define IGMP_V3_GROUP_RECORD_NUMSOURCES_OFFSET (2)
#define IGMP_V3_GROUP_RECORD_GROUP_OFFSET      (4)
#define IGMP_V3_GROUP_RECORD_SOURCE_OFFSET     (8)
#define IGMP_CHECKSUM_OFFSET                   (2)

#define IGMP_DEFAULT_VERSION (3)

#define IGMP_GET_INT16(ptr, output)                                            \
	do {                                                                   \
		output = *(ptr) << 8;                                          \
		output |= *((ptr) + 1);                                        \
	} while (0)

enum gm_join_type { GM_JOIN_STATIC = 0, GM_JOIN_PROXY = 1, GM_JOIN_BOTH = 2 };

struct gm_join {
	pim_addr group_addr;
	pim_addr source_addr;
	int sock_fd;
	enum gm_join_type join_type;
	time_t sock_creation;
};

struct static_group {
	pim_addr group_addr;
	pim_addr source_addr;
	struct channel_oil *oilp;
};

struct gm_sock {
	int fd;
	struct interface *interface;
	pim_addr ifaddr;
	time_t sock_creation;

	struct event *t_igmp_read; /* read: IGMP sockets */
	/* timer: issue IGMP general queries */
	struct event *t_igmp_query_timer;
	struct event *t_other_querier_timer;  /* timer: other querier present */
	pim_addr querier_addr;		      /* IP address of the querier */
	int querier_query_interval;	   /* QQI */
	int querier_robustness_variable; /* QRV */
	int startup_query_count;

	bool mtrace_only;

	struct igmp_stats igmp_stats;
};

struct pim_interface;

#if PIM_IPV == 4
void pim_igmp_if_init(struct pim_interface *pim_ifp, struct interface *ifp);
void pim_igmp_if_reset(struct pim_interface *pim_ifp);
void pim_igmp_if_fini(struct pim_interface *pim_ifp);

struct gm_sock *pim_igmp_sock_lookup_ifaddr(struct list *igmp_sock_list,
					    struct in_addr ifaddr);
struct gm_sock *pim_igmp_sock_add(struct list *igmp_sock_list,
				  struct in_addr ifaddr, struct interface *ifp,
				  bool mtrace_only);
void igmp_sock_delete(struct gm_sock *igmp);
void igmp_sock_free(struct gm_sock *igmp);
void igmp_sock_delete_all(struct interface *ifp);
int pim_igmp_packet(struct gm_sock *igmp, char *buf, size_t len);
bool pim_igmp_verify_header(struct ip *ip_hdr, size_t len, size_t *ip_hlen);
void pim_igmp_general_query_on(struct gm_sock *igmp);
void pim_igmp_general_query_off(struct gm_sock *igmp);
void pim_igmp_other_querier_timer_on(struct gm_sock *igmp);
void pim_igmp_other_querier_timer_off(struct gm_sock *igmp);

int igmp_validate_checksum(char *igmp_msg, int igmp_msg_len);

#else /* PIM_IPV != 4 */
static inline void pim_igmp_if_init(struct pim_interface *pim_ifp,
				    struct interface *ifp)
{
}

static inline void pim_igmp_if_fini(struct pim_interface *pim_ifp)
{
}

static inline void pim_igmp_general_query_on(struct gm_sock *igmp)
{
}

static inline void pim_igmp_general_query_off(struct gm_sock *igmp)
{
}

static inline void pim_igmp_other_querier_timer_on(struct gm_sock *igmp)
{
}

static inline void pim_igmp_other_querier_timer_off(struct gm_sock *igmp)
{
}
#endif /* PIM_IPV == 4 */

#define IGMP_SOURCE_MASK_FORWARDING        (1 << 0)
#define IGMP_SOURCE_MASK_DELETE            (1 << 1)
#define IGMP_SOURCE_MASK_SEND              (1 << 2)
#define IGMP_SOURCE_TEST_FORWARDING(flags) ((flags) & IGMP_SOURCE_MASK_FORWARDING)
#define IGMP_SOURCE_TEST_DELETE(flags)     ((flags) & IGMP_SOURCE_MASK_DELETE)
#define IGMP_SOURCE_TEST_SEND(flags)       ((flags) & IGMP_SOURCE_MASK_SEND)
#define IGMP_SOURCE_DO_FORWARDING(flags)   ((flags) |= IGMP_SOURCE_MASK_FORWARDING)
#define IGMP_SOURCE_DO_DELETE(flags)       ((flags) |= IGMP_SOURCE_MASK_DELETE)
#define IGMP_SOURCE_DO_SEND(flags)         ((flags) |= IGMP_SOURCE_MASK_SEND)
#define IGMP_SOURCE_DONT_FORWARDING(flags) ((flags) &= ~IGMP_SOURCE_MASK_FORWARDING)
#define IGMP_SOURCE_DONT_DELETE(flags)     ((flags) &= ~IGMP_SOURCE_MASK_DELETE)
#define IGMP_SOURCE_DONT_SEND(flags)       ((flags) &= ~IGMP_SOURCE_MASK_SEND)

struct gm_source {
	pim_addr source_addr;
	struct event *t_source_timer;
	struct gm_group *source_group; /* back pointer */
	time_t source_creation;
	uint32_t source_flags;
	struct channel_oil *source_channel_oil;

	/*
	  RFC 3376: 6.6.3.2. Building and Sending Group and Source Specific
	  Queries
	*/
	int source_query_retransmit_count;
};

struct gm_group {
	/*
	  RFC 3376: 6.2.2. Definition of Group Timers

	  The group timer is only used when a group is in EXCLUDE mode and it
	  represents the time for the *filter-mode* of the group to expire and
	  switch to INCLUDE mode.
	*/
	struct event *t_group_timer;

	/* Shared between group-specific and
	   group-and-source-specific retransmissions */
	struct event *t_group_query_retransmit_timer;

	/* Counter exclusive for group-specific retransmissions
	   (not used by group-and-source-specific retransmissions,
	   since sources have their counters) */
	int group_specific_query_retransmit_count;

	/* compatibility mode - igmp v1, v2 or v3 */
	int igmp_version;
	pim_addr group_addr;
	int group_filtermode_isexcl;    /* 0=INCLUDE, 1=EXCLUDE */
	struct list *group_source_list; /* list of struct gm_source */
	time_t group_creation;
	struct interface *interface;
	int64_t last_igmp_v1_report_dsec;
	int64_t last_igmp_v2_report_dsec;
};

#if PIM_IPV == 4
struct pim_instance;

void igmp_anysource_forward_start(struct pim_instance *pim,
				  struct gm_group *group);
void igmp_anysource_forward_stop(struct gm_group *group);

void igmp_source_forward_start(struct pim_instance *pim,
			       struct gm_source *source);
void igmp_source_forward_stop(struct gm_source *source);
void igmp_source_forward_reevaluate_all(struct pim_instance *pim);

struct gm_group *find_group_by_addr(struct gm_sock *igmp,
				    struct in_addr group_addr);
struct gm_group *igmp_add_group_by_addr(struct gm_sock *igmp,
					struct in_addr group_addr);

struct gm_source *igmp_get_source_by_addr(struct gm_group *group,
					  struct in_addr src_addr,
					  bool *created);

void igmp_group_delete_empty_include(struct gm_group *group);

void igmp_startup_mode_on(struct gm_sock *igmp);

void igmp_group_timer_on(struct gm_group *group, long interval_msec,
			 const char *ifname);

void igmp_send_query(int igmp_version, struct gm_group *group, char *query_buf,
		     int query_buf_size, int num_sources,
		     struct in_addr dst_addr, struct in_addr group_addr,
		     int query_max_response_time_dsec, uint8_t s_flag,
		     struct gm_sock *igmp);
void igmp_group_delete(struct gm_group *group);

void igmp_send_query_on_intf(struct interface *ifp, int igmp_ver);

#else /* PIM_IPV != 4 */
static inline void igmp_startup_mode_on(struct gm_sock *igmp)
{
}
#endif /* PIM_IPV != 4 */

#endif /* PIM_IGMP_H */
