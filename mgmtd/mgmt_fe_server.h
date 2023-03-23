// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Frontend Server
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#ifndef _FRR_MGMTD_FE_SERVER_H_
#define _FRR_MGMTD_FE_SERVER_H_

#define MGMTD_FE_MAX_CONN 32

/* Initialise frontend server */
extern int mgmt_fe_server_init(struct thread_master *master);

/* Destroy frontend server */
extern void mgmt_fe_server_destroy(void);

#endif /* _FRR_MGMTD_FE_SERVER_H_ */
