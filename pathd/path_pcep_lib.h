// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#ifndef _PATH_PCEP_LIB_H_
#define _PATH_PCEP_LIB_H_

#include <stdbool.h>
#include "pceplib/pcep_pcc_api.h"
#include "frr_pthread.h"
#include "pathd/path_pcep.h"

int pcep_lib_initialize(struct frr_pthread *fpt);
void pcep_lib_finalize(void);
pcep_session *
pcep_lib_connect(struct ipaddr *src_addr, int src_port, struct ipaddr *dst_addr,
		 int dst_port, short msd,
		 const struct pcep_config_group_opts *pcep_options);
void pcep_lib_disconnect(pcep_session *sess);
struct pcep_message *pcep_lib_format_report(struct pcep_caps *caps,
					    struct path *path);
struct pcep_message *pcep_lib_format_request(struct pcep_caps *caps,
					     struct path *path);
struct pcep_message *pcep_lib_format_request_cancelled(uint32_t reqid);

struct pcep_message *pcep_lib_format_error(int error_type, int error_value,
					   struct path *path);
struct path *pcep_lib_parse_path(struct pcep_message *msg);
void pcep_lib_parse_capabilities(struct pcep_message *msg,
				 struct pcep_caps *caps);
struct counters_group *pcep_lib_copy_counters(pcep_session *sess);
void pcep_lib_free_counters(struct counters_group *counters);
pcep_session *pcep_lib_copy_pcep_session(pcep_session *sess);

#endif // _PATH_PCEP_LIB_H_
