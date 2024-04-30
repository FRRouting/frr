// SPDX-License-Identifier: GPL-2.0-or-later
/* PTM Library
 * Copyright (C) 2015 Cumulus Networks, Inc.
 */
#ifndef __PTM_LIB_H__
#define __PTM_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

#define PTMLIB_MSG_SZ           1024
#define PTMLIB_MSG_HDR_LEN      37
#define PTMLIB_MSG_VERSION      2
#define PTMLIB_MAXNAMELEN       32

#define    PTMLIB_CMD_GET_STATUS        "get-status"
#define    PTMLIB_CMD_GET_BFD_CLIENT    "get-bfd-client"
#define    PTMLIB_CMD_START_BFD_SESS    "start-bfd-sess"
#define    PTMLIB_CMD_STOP_BFD_SESS     "stop-bfd-sess"

typedef enum {
	PTMLIB_MSG_TYPE_NOTIFICATION = 1,
	PTMLIB_MSG_TYPE_CMD,
	PTMLIB_MSG_TYPE_RESPONSE,
} ptmlib_msg_type;

typedef enum {
	MODULE_BFD = 0,
	MODULE_LLDP,
	MODULE_MAX,
} ptmlib_mod_type;

typedef int (*ptm_cmd_cb)(void *data, void *arg);
typedef int (*ptm_notify_cb)(void *data, void *arg);
typedef int (*ptm_response_cb)(void *data, void *arg);
typedef int (*ptm_log_cb)(void *data, void *arg, ...);

typedef struct ptm_lib_handle_s {
	char client_name[PTMLIB_MAXNAMELEN];
	ptm_cmd_cb cmd_cb;
	ptm_notify_cb notify_cb;
	ptm_response_cb response_cb;
} ptm_lib_handle_t;

/* Prototypes */
int ptm_lib_process_msg(ptm_lib_handle_t *, int, char *, int, void *);
ptm_lib_handle_t *ptm_lib_register(char *, ptm_cmd_cb, ptm_notify_cb,
				   ptm_response_cb);
void ptm_lib_deregister(ptm_lib_handle_t *);
int ptm_lib_find_key_in_msg(void *, const char *, char *);
int ptm_lib_init_msg(ptm_lib_handle_t *, int, int, void *, void **);
int ptm_lib_append_msg(ptm_lib_handle_t *, void *, const char *, const char *);
int ptm_lib_complete_msg(ptm_lib_handle_t *, void *, char *, int *);
int ptm_lib_cleanup_msg(ptm_lib_handle_t *, void *);

#ifdef __cplusplus
}
#endif

#endif
