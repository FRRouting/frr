// SPDX-License-Identifier: GPL-2.0-or-later
/*
  * Copyright (C) 2021  Vmware, Inc.
  *		       Pushpasis Sarkar <spushpasis@vmware.com>
  * Copyright (c) 2023, LabN Consulting, L.L.C.
  *
  */
#ifndef _FRR_MGMTD_HISTORY_H_
#define _FRR_MGMTD_HISTORY_H_

#include "vrf.h"

PREDECL_DLIST(mgmt_cmt_infos);

struct mgmt_ds_ctx;

/*
 * Rollback specific commit from commit history.
 *
 * vty
 *    VTY context.
 *
 * cmtid_str
 *    Specific commit id from commit history.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_history_rollback_by_id(struct vty *vty, const char *cmtid_str);

/*
 * Rollback n commits from commit history.
 *
 * vty
 *    VTY context.
 *
 * num_cmts
 *    Number of commits to be rolled back.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_history_rollback_n(struct vty *vty, int num_cmts);

extern void mgmt_history_rollback_complete(bool success);

/*
 * Show mgmt commit history.
 */
extern void show_mgmt_cmt_history(struct vty *vty);

extern void mgmt_history_new_record(struct mgmt_ds_ctx *ds_ctx);

extern void mgmt_history_destroy(void);
extern void mgmt_history_init(void);

#endif /* _FRR_MGMTD_HISTORY_H_ */
