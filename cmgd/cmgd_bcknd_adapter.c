/*
 * CMGD Backend Client Connection Adapter
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "thread.h"
#include "sockunion.h"
#include "prefix.h"
#include "network.h"
#include "lib/libfrr.h"
#include "lib/thread.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_memory.h"
#include "cmgd/cmgd_bcknd_adapter.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_BCKND_ADPTR_DBG(fmt, ...)				\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_BCKND_ADPTR_ERR(fmt, ...)				\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_BCKND_ADPTR_DBG(fmt, ...)				\
	zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_BCKND_ADPTR_ERR(fmt, ...)				\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define FOREACH_ADPTR_IN_LIST(adptr)						\
	for ((adptr) = cmgd_adptr_list_first(&cmgd_bcknd_adptrs); (adptr);	\
		(adptr) = cmgd_adptr_list_next(&cmgd_bcknd_adptrs, (adptr)))

static struct thread_master *cmgd_bcknd_adptr_tm = NULL;

static struct cmgd_adptr_list_head cmgd_bcknd_adptrs = {0};

static void cmgd_bcknd_adptr_register_event(
	cmgd_bcknd_client_adapter_t *adptr, cmgd_bcknd_event_t event);

static void cmgd_bcknd_adapter_disconnect(cmgd_bcknd_client_adapter_t *adptr)
{
	if (adptr->conn_fd) {
		close(adptr->conn_fd);
		adptr->conn_fd = 0;
	}

	THREAD_OFF(adptr->conn_read_ev);

	/* TODO: notify about client disconnect for appropriate cleanup */

	cmgd_adptr_list_del(&cmgd_bcknd_adptrs, adptr);

	cmgd_bcknd_adapter_unlock(&adptr);
}

static int cmgd_bcknd_adapter_process_msg(
	cmgd_bcknd_client_adapter_t *adptr, uint8_t *bkcnd_msg, int bytes_read)
{
	(void) bkcnd_msg;

	CMGD_BCKND_ADPTR_DBG(
		"Got message of %d bytes from CMGD Backend adapter '%s'", 
		bytes_read, adptr->name);

	return 0;
}

static int cmgd_bcknd_adapter_read(struct thread *thread)
{
	cmgd_bcknd_client_adapter_t *adptr;
	uint8_t bcknd_msg[CMGD_BCKND_MSG_MAX_LEN];
	int bytes_read;

	adptr = (cmgd_bcknd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	bytes_read = read(adptr->conn_fd, bcknd_msg, sizeof(bcknd_msg));
	if (bytes_read < 0) {
		CMGD_BCKND_ADPTR_ERR(
			"Got error while reading from CMGD Backend adapter socket. Err: '%s'", 
			safe_strerror(errno));
		cmgd_bcknd_adapter_disconnect(adptr);
	}

	if (!bytes_read)
		return 0;

	return cmgd_bcknd_adapter_process_msg(adptr, bcknd_msg, bytes_read);
}

static int cmgd_bcknd_adapter_write(struct thread *thread)
{
	cmgd_bcknd_client_adapter_t *adptr;
	// uint8_t bkcnd_msg[CMGD_BCKND_MSG_MAX_LEN];
	//int bytes_read;

	adptr = (cmgd_bcknd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	return 0;
}

static void cmgd_bcknd_adptr_register_event(
	cmgd_bcknd_client_adapter_t *adptr, cmgd_bcknd_event_t event)
{
	switch (event) {
	case CMGD_BCKND_CONN_READ:
		adptr->conn_read_ev = 
			thread_add_read(cmgd_bcknd_adptr_tm,
				cmgd_bcknd_adapter_read, adptr, 
				adptr->conn_fd, NULL);
		break;
	case CMGD_BCKND_CONN_WRITE:
		adptr->conn_read_ev = 
			thread_add_write(cmgd_bcknd_adptr_tm,
				cmgd_bcknd_adapter_write, adptr, 
				adptr->conn_fd, NULL);
		break;
	default:
		assert(!"cmgd_bcknd_adptr_post_event() called incorrectly");
	}
}

void cmgd_bcknd_adapter_lock(cmgd_bcknd_client_adapter_t *adptr)
{
	adptr->refcount++;
}

extern void cmgd_bcknd_adapter_unlock(cmgd_bcknd_client_adapter_t **adptr)
{
	assert(*adptr && (*adptr)->refcount);

	(*adptr)->refcount--;
	if (!(*adptr)->refcount) {
		cmgd_adptr_list_del(&cmgd_bcknd_adptrs, *adptr);
		XFREE(MTYPE_CMGD_BCKND_ADPATER, *adptr);
	}

	*adptr = NULL;
}

int cmgd_bcknd_adapter_init(struct thread_master *tm)
{
	if (!cmgd_bcknd_adptr_tm) {
		cmgd_bcknd_adptr_tm = tm;
		cmgd_adptr_list_init(&cmgd_bcknd_adptrs);
	}

	return 0;
}

static cmgd_bcknd_client_adapter_t *cmgd_bcknd_find_adapter_by_fd(int conn_fd)
{
	cmgd_bcknd_client_adapter_t *adptr;

	FOREACH_ADPTR_IN_LIST(adptr) {
		if (adptr->conn_fd == conn_fd) 
			return adptr;
	}

	return NULL;
}

cmgd_bcknd_client_adapter_t *cmgd_bcknd_create_adapter(
	int conn_fd, union sockunion *from)
{
	cmgd_bcknd_client_adapter_t *adptr = NULL;

	adptr = cmgd_bcknd_find_adapter_by_fd(conn_fd);
	if (!adptr) {
		adptr = XMALLOC(MTYPE_CMGD_BCKND_ADPATER, 
				sizeof(cmgd_bcknd_client_adapter_t));
		assert(adptr);

		adptr->conn_fd = conn_fd;
		memcpy(&adptr->conn_su, from, sizeof(adptr->conn_su));
		snprintf(adptr->name, sizeof(adptr->name), "Unknown-FD-%d", adptr->conn_fd);
		cmgd_bcknd_adapter_lock(adptr);

		cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_READ);
		cmgd_adptr_list_add_tail(&cmgd_bcknd_adptrs, adptr);

		CMGD_BCKND_ADPTR_DBG(
			"Added new CMGD Backend adapter '%s'", adptr->name);
	}

	return adptr;
}

cmgd_bcknd_client_adapter_t *cmgd_bcknd_get_adapter(const char *name)
{
	return NULL;
}

int cmgd_bcknd_create_trxn(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id)
{
	return 0;
}

int cmgd_bcknd_destroy_trxn(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id)
{
	return 0;
}

int cmgd_bcknd_send_cfg_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_cfgreq_t *cfg_req)
{
	return 0;
}

int cmgd_bcknd_send_get_data_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_datareq_t *data_req)
{
	return 0;
}

int cmgd_bcknd_send_get_next_data_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_datareq_t *data_req)
{
	return 0;
}
