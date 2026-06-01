// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Mgmtd internal API for in-process callers (e.g. gRPC when running in mgmtd).
 * Not for use by external FE clients.
 *
 * Copyright (C) 2026  FRRouting
 */

#ifndef _FRR_MGMTD_GRPC_INTERNAL_H_
#define _FRR_MGMTD_GRPC_INTERNAL_H_

#include "mgmt_defines.h"
#include "mgmt_msg_native.h"

struct mgmt_master;

/*
 * Get config tree from mgmtd datastore (sync, no FE client).
 * For use by gRPC Get when running inside mgmtd.
 *
 * master: mgmt master (use global mm when in mgmtd)
 * ds_id: MGMTD_DS_RUNNING or MGMTD_DS_CANDIDATE
 * xpath: path to fetch (use "/" for full tree)
 * flags: GET_DATA_FLAG_* (only CONFIG is used)
 * wd_options: LYD_PRINT_WD_* for with-defaults
 * result_type: LYD_LYB (only LYB supported for now)
 * out_lyb: on success, allocated buffer (caller frees with XFREE(MTYPE_TMP, *out_lyb))
 * out_len: on success, length of *out_lyb
 *
 * Returns: 0 on success, -1 on error (e.g. unsupported ds_id, xpath resolve failure).
 * Operational (STATE) is not supported; use FE client path or get_dnode_state for that.
 */
int mgmt_grpc_get_tree_internal(struct mgmt_master *master, enum mgmt_ds_id ds_id,
				const char *xpath, uint8_t flags, uint32_t wd_options,
				uint8_t result_type, uint8_t **out_lyb, size_t *out_len);

#endif /* _FRR_MGMTD_GRPC_INTERNAL_H_ */
