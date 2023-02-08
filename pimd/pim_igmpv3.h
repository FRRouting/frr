// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_IGMPV3_H
#define PIM_IGMPV3_H

#include <zebra.h>
#include "if.h"

#include "pim_igmp.h"

#define IGMP_V3_CHECKSUM_OFFSET            (2)
#define IGMP_V3_REPORT_NUMGROUPS_OFFSET    (6)
#define IGMP_V3_REPORT_GROUPPRECORD_OFFSET (8)
#define IGMP_V3_NUMSOURCES_OFFSET          (10)
#define IGMP_V3_SOURCES_OFFSET             (12)

#define IGMP_GRP_REC_TYPE_MODE_IS_INCLUDE        (1)
#define IGMP_GRP_REC_TYPE_MODE_IS_EXCLUDE        (2)
#define IGMP_GRP_REC_TYPE_CHANGE_TO_INCLUDE_MODE (3)
#define IGMP_GRP_REC_TYPE_CHANGE_TO_EXCLUDE_MODE (4)
#define IGMP_GRP_REC_TYPE_ALLOW_NEW_SOURCES      (5)
#define IGMP_GRP_REC_TYPE_BLOCK_OLD_SOURCES      (6)

/* GMI: Group Membership Interval */
#define PIM_IGMP_GMI_MSEC(qrv,qqi,qri_dsec) ((qrv) * (1000 * (qqi)) + 100 * (qri_dsec))

/* OQPI: Other Querier Present Interval */
#define PIM_IGMP_OQPI_MSEC(qrv,qqi,qri_dsec) ((qrv) * (1000 * (qqi)) + 100 * ((qri_dsec) >> 1))

/* SQI: Startup Query Interval */
#define PIM_IGMP_SQI(qi) (((qi) < 4) ? 1 : ((qi) >> 2))

/* LMQT: Last Member Query Time */
#define PIM_IGMP_LMQT_MSEC(lmqi_dsec, lmqc) ((lmqc) * (100 * (lmqi_dsec)))

/* OHPI: Older Host Present Interval */
#define PIM_IGMP_OHPI_DSEC(qrv,qqi,qri_dsec) ((qrv) * (10 * (qqi)) + (qri_dsec))

#if PIM_IPV == 4
void igmp_group_reset_gmi(struct gm_group *group);
void igmp_source_reset_gmi(struct gm_group *group, struct gm_source *source);

void igmp_source_free(struct gm_source *source);
void igmp_source_delete(struct gm_source *source);
void igmp_source_delete_expired(struct list *source_list);

void igmpv3_report_isin(struct gm_sock *igmp, struct in_addr from,
			struct in_addr group_addr, int num_sources,
			struct in_addr *sources);
void igmpv3_report_isex(struct gm_sock *igmp, struct in_addr from,
			struct in_addr group_addr, int num_sources,
			struct in_addr *sources, int from_igmp_v2_report);
void igmpv3_report_toin(struct gm_sock *igmp, struct in_addr from,
			struct in_addr group_addr, int num_sources,
			struct in_addr *sources);
void igmpv3_report_toex(struct gm_sock *igmp, struct in_addr from,
			struct in_addr group_addr, int num_sources,
			struct in_addr *sources);
void igmpv3_report_allow(struct gm_sock *igmp, struct in_addr from,
			 struct in_addr group_addr, int num_sources,
			 struct in_addr *sources);
void igmpv3_report_block(struct gm_sock *igmp, struct in_addr from,
			 struct in_addr group_addr, int num_sources,
			 struct in_addr *sources);

void igmp_group_timer_lower_to_lmqt(struct gm_group *group);
void igmp_source_timer_lower_to_lmqt(struct gm_source *source);

struct gm_source *igmp_find_source_by_addr(struct gm_group *group,
					   struct in_addr src_addr);

void igmp_v3_send_query(struct gm_group *group, int fd, const char *ifname,
			char *query_buf, int query_buf_size, int num_sources,
			struct in_addr dst_addr, struct in_addr group_addr,
			int query_max_response_time_dsec, uint8_t s_flag,
			uint8_t querier_robustness_variable,
			uint16_t querier_query_interval);

void igmp_v3_recv_query(struct gm_sock *igmp, const char *from_str,
			char *igmp_msg);

int igmp_v3_recv_report(struct gm_sock *igmp, struct in_addr from,
			const char *from_str, char *igmp_msg, int igmp_msg_len);

#else /* PIM_IPV != 4 */
static inline void igmp_group_reset_gmi(struct gm_group *group)
{
}


static inline void igmp_source_reset_gmi(struct gm_group *group,
					 struct gm_source *source)
{
}
#endif

#endif /* PIM_IGMPV3_H */
