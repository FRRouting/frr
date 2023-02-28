// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Backend Server
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
 */

#ifndef _FRR_MGMTD_BE_SERVER_H_
#define _FRR_MGMTD_BE_SERVER_H_

#define MGMTD_BE_MAX_CONN 32

/* Initialise backend server */
extern int mgmt_be_server_init(struct thread_master *master);

/* Destroy backend server */
extern void mgmt_be_server_destroy(void);

#endif /* _FRR_MGMTD_BE_SERVER_H_ */
