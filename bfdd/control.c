/*********************************************************************
 * Copyright 2017-2018 Network Device Education Foundation, Inc. ("NetDEF")
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
 *
 * control.c: implements the BFD daemon control socket. It will be used
 * to talk with clients daemon/scripts/consumers.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <zebra.h>

#include <sys/un.h>

#include "bfd.h"

/*
 * Prototypes
 */
static int sock_set_nonblock(int fd);
struct bfd_control_queue *control_queue_new(struct bfd_control_socket *bcs);
static void control_queue_free(struct bfd_control_socket *bcs,
			       struct bfd_control_queue *bcq);
static int control_queue_dequeue(struct bfd_control_socket *bcs);
static int control_queue_enqueue(struct bfd_control_socket *bcs,
				 struct bfd_control_msg *bcm);
static int control_queue_enqueue_first(struct bfd_control_socket *bcs,
				       struct bfd_control_msg *bcm);
struct bfd_notify_peer *control_notifypeer_new(struct bfd_control_socket *bcs,
					       struct bfd_session *bs);
static void control_notifypeer_free(struct bfd_control_socket *bcs,
				    struct bfd_notify_peer *bnp);
struct bfd_notify_peer *control_notifypeer_find(struct bfd_control_socket *bcs,
						struct bfd_session *bs);


struct bfd_control_socket *control_new(int sd);
static void control_free(struct bfd_control_socket *bcs);
static void control_reset_buf(struct bfd_control_buffer *bcb);
static int control_read(struct thread *t);
static int control_write(struct thread *t);

static void control_handle_request_add(struct bfd_control_socket *bcs,
				       struct bfd_control_msg *bcm);
static void control_handle_request_del(struct bfd_control_socket *bcs,
				       struct bfd_control_msg *bcm);
static int notify_add_cb(struct bfd_peer_cfg *bpc, void *arg);
static int notify_del_cb(struct bfd_peer_cfg *bpc, void *arg);
static void control_handle_notify_add(struct bfd_control_socket *bcs,
				      struct bfd_control_msg *bcm);
static void control_handle_notify_del(struct bfd_control_socket *bcs,
				      struct bfd_control_msg *bcm);
static void _control_handle_notify(struct hash_bucket *hb, void *arg);
static void control_handle_notify(struct bfd_control_socket *bcs,
				  struct bfd_control_msg *bcm);
static void control_response(struct bfd_control_socket *bcs, uint16_t id,
			     const char *status, const char *error);

static void _control_notify_config(struct bfd_control_socket *bcs,
				   const char *op, struct bfd_session *bs);
static void _control_notify(struct bfd_control_socket *bcs,
			    struct bfd_session *bs);


/*
 * Functions
 */
static int sock_set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		log_warning("%s: fcntl F_GETFL: %s", __func__, strerror(errno));
		return -1;
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		log_warning("%s: fcntl F_SETFL: %s", __func__, strerror(errno));
		return -1;
	}

	return 0;
}

int control_init(const char *path)
{
	int sd;
	mode_t umval;
	struct sockaddr_un sun_ = {
		.sun_family = AF_UNIX,
		.sun_path = BFDD_CONTROL_SOCKET,
	};

	if (path)
		strlcpy(sun_.sun_path, path, sizeof(sun_.sun_path));

	/* Remove previously created sockets. */
	unlink(sun_.sun_path);

	sd = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	if (sd == -1) {
		log_error("%s: socket: %s", __func__, strerror(errno));
		return -1;
	}

	umval = umask(0);
	if (bind(sd, (struct sockaddr *)&sun_, sizeof(sun_)) == -1) {
		log_error("%s: bind: %s", __func__, strerror(errno));
		close(sd);
		return -1;
	}
	umask(umval);

	if (listen(sd, SOMAXCONN) == -1) {
		log_error("%s: listen: %s", __func__, strerror(errno));
		close(sd);
		return -1;
	}

	sock_set_nonblock(sd);

	bglobal.bg_csock = sd;

	return 0;
}

void control_shutdown(void)
{
	struct bfd_control_socket *bcs;

	if (bglobal.bg_csockev) {
		thread_cancel(bglobal.bg_csockev);
		bglobal.bg_csockev = NULL;
	}

	socket_close(&bglobal.bg_csock);

	while (!TAILQ_EMPTY(&bglobal.bg_bcslist)) {
		bcs = TAILQ_FIRST(&bglobal.bg_bcslist);
		control_free(bcs);
	}
}

int control_accept(struct thread *t)
{
	int csock, sd = THREAD_FD(t);

	csock = accept(sd, NULL, 0);
	if (csock == -1) {
		log_warning("%s: accept: %s", __func__, strerror(errno));
		return 0;
	}

	if (control_new(csock) == NULL)
		close(csock);

	bglobal.bg_csockev = NULL;
	thread_add_read(master, control_accept, NULL, sd, &bglobal.bg_csockev);

	return 0;
}


/*
 * Client handling
 */
struct bfd_control_socket *control_new(int sd)
{
	struct bfd_control_socket *bcs;

	bcs = XCALLOC(MTYPE_BFDD_CONTROL, sizeof(*bcs));

	/* Disable notifications by default. */
	bcs->bcs_notify = 0;

	bcs->bcs_sd = sd;
	thread_add_read(master, control_read, bcs, sd, &bcs->bcs_ev);

	TAILQ_INIT(&bcs->bcs_bcqueue);
	TAILQ_INIT(&bcs->bcs_bnplist);
	TAILQ_INSERT_TAIL(&bglobal.bg_bcslist, bcs, bcs_entry);

	return bcs;
}

static void control_free(struct bfd_control_socket *bcs)
{
	struct bfd_control_queue *bcq;
	struct bfd_notify_peer *bnp;

	if (bcs->bcs_ev) {
		thread_cancel(bcs->bcs_ev);
		bcs->bcs_ev = NULL;
	}

	if (bcs->bcs_outev) {
		thread_cancel(bcs->bcs_outev);
		bcs->bcs_outev = NULL;
	}

	close(bcs->bcs_sd);

	TAILQ_REMOVE(&bglobal.bg_bcslist, bcs, bcs_entry);

	/* Empty output queue. */
	while (!TAILQ_EMPTY(&bcs->bcs_bcqueue)) {
		bcq = TAILQ_FIRST(&bcs->bcs_bcqueue);
		control_queue_free(bcs, bcq);
	}

	/* Empty notification list. */
	while (!TAILQ_EMPTY(&bcs->bcs_bnplist)) {
		bnp = TAILQ_FIRST(&bcs->bcs_bnplist);
		control_notifypeer_free(bcs, bnp);
	}

	control_reset_buf(&bcs->bcs_bin);
	XFREE(MTYPE_BFDD_CONTROL, bcs);
}

struct bfd_notify_peer *control_notifypeer_new(struct bfd_control_socket *bcs,
					       struct bfd_session *bs)
{
	struct bfd_notify_peer *bnp;

	bnp = control_notifypeer_find(bcs, bs);
	if (bnp)
		return bnp;

	bnp = XCALLOC(MTYPE_BFDD_CONTROL, sizeof(*bnp));

	TAILQ_INSERT_TAIL(&bcs->bcs_bnplist, bnp, bnp_entry);
	bnp->bnp_bs = bs;
	bs->refcount++;

	return bnp;
}

static void control_notifypeer_free(struct bfd_control_socket *bcs,
				    struct bfd_notify_peer *bnp)
{
	TAILQ_REMOVE(&bcs->bcs_bnplist, bnp, bnp_entry);
	bnp->bnp_bs->refcount--;
	XFREE(MTYPE_BFDD_CONTROL, bnp);
}

struct bfd_notify_peer *control_notifypeer_find(struct bfd_control_socket *bcs,
						struct bfd_session *bs)
{
	struct bfd_notify_peer *bnp;

	TAILQ_FOREACH (bnp, &bcs->bcs_bnplist, bnp_entry) {
		if (bnp->bnp_bs == bs)
			return bnp;
	}

	return NULL;
}

struct bfd_control_queue *control_queue_new(struct bfd_control_socket *bcs)
{
	struct bfd_control_queue *bcq;

	bcq = XCALLOC(MTYPE_BFDD_NOTIFICATION, sizeof(*bcq));

	control_reset_buf(&bcq->bcq_bcb);
	TAILQ_INSERT_TAIL(&bcs->bcs_bcqueue, bcq, bcq_entry);

	return bcq;
}

static void control_queue_free(struct bfd_control_socket *bcs,
			       struct bfd_control_queue *bcq)
{
	control_reset_buf(&bcq->bcq_bcb);
	TAILQ_REMOVE(&bcs->bcs_bcqueue, bcq, bcq_entry);
	XFREE(MTYPE_BFDD_NOTIFICATION, bcq);
}

static int control_queue_dequeue(struct bfd_control_socket *bcs)
{
	struct bfd_control_queue *bcq;

	/* List is empty, nothing to do. */
	if (TAILQ_EMPTY(&bcs->bcs_bcqueue))
		goto empty_list;

	bcq = TAILQ_FIRST(&bcs->bcs_bcqueue);
	control_queue_free(bcs, bcq);

	/* Get the next buffer to send. */
	if (TAILQ_EMPTY(&bcs->bcs_bcqueue))
		goto empty_list;

	bcq = TAILQ_FIRST(&bcs->bcs_bcqueue);
	bcs->bcs_bout = &bcq->bcq_bcb;

	bcs->bcs_outev = NULL;
	thread_add_write(master, control_write, bcs, bcs->bcs_sd,
			 &bcs->bcs_outev);

	return 1;

empty_list:
	if (bcs->bcs_outev) {
		thread_cancel(bcs->bcs_outev);
		bcs->bcs_outev = NULL;
	}
	bcs->bcs_bout = NULL;
	return 0;
}

static int control_queue_enqueue(struct bfd_control_socket *bcs,
				 struct bfd_control_msg *bcm)
{
	struct bfd_control_queue *bcq;
	struct bfd_control_buffer *bcb;

	bcq = control_queue_new(bcs);
	if (bcq == NULL)
		return -1;

	bcb = &bcq->bcq_bcb;
	bcb->bcb_left = sizeof(struct bfd_control_msg) + ntohl(bcm->bcm_length);
	bcb->bcb_pos = 0;
	bcb->bcb_bcm = bcm;

	/* If this is the first item, then dequeue and start using it. */
	if (bcs->bcs_bout == NULL) {
		bcs->bcs_bout = bcb;

		/* New messages, active write events. */
		thread_add_write(master, control_write, bcs, bcs->bcs_sd,
				 &bcs->bcs_outev);
	}

	return 0;
}

static int control_queue_enqueue_first(struct bfd_control_socket *bcs,
				       struct bfd_control_msg *bcm)
{
	struct bfd_control_queue *bcq, *bcqn;
	struct bfd_control_buffer *bcb;

	/* Enqueue it somewhere. */
	if (control_queue_enqueue(bcs, bcm) == -1)
		return -1;

	/*
	 * The item is either the first or the last. So we must first
	 * check the best case where the item is already the first.
	 */
	bcq = TAILQ_FIRST(&bcs->bcs_bcqueue);
	bcb = &bcq->bcq_bcb;
	if (bcm == bcb->bcb_bcm)
		return 0;

	/*
	 * The item was not the first, so it is the last. We'll try to
	 * assign it to the head of the queue, however if there is a
	 * transfer in progress, then we have to make the item as the
	 * next one.
	 *
	 * Interrupting the transfer of in progress message will cause
	 * the client to lose track of the message position/data.
	 */
	bcqn = TAILQ_LAST(&bcs->bcs_bcqueue, bcqueue);
	TAILQ_REMOVE(&bcs->bcs_bcqueue, bcqn, bcq_entry);
	if (bcb->bcb_pos != 0) {
		/*
		 * First position is already being sent, insert into
		 * second position.
		 */
		TAILQ_INSERT_AFTER(&bcs->bcs_bcqueue, bcq, bcqn, bcq_entry);
	} else {
		/*
		 * Old message didn't start being sent, we still have
		 * time to put this one in the head of the queue.
		 */
		TAILQ_INSERT_HEAD(&bcs->bcs_bcqueue, bcqn, bcq_entry);
		bcb = &bcqn->bcq_bcb;
		bcs->bcs_bout = bcb;
	}

	return 0;
}

static void control_reset_buf(struct bfd_control_buffer *bcb)
{
	/* Get ride of old data. */
	XFREE(MTYPE_BFDD_NOTIFICATION, bcb->bcb_buf);
	bcb->bcb_buf = NULL;
	bcb->bcb_pos = 0;
	bcb->bcb_left = 0;
}

static int control_read(struct thread *t)
{
	struct bfd_control_socket *bcs = THREAD_ARG(t);
	struct bfd_control_buffer *bcb = &bcs->bcs_bin;
	int sd = bcs->bcs_sd;
	struct bfd_control_msg bcm;
	ssize_t bread;
	size_t plen;

	/*
	 * Check if we have already downloaded message content, if so then skip
	 * to
	 * download the rest of it and process.
	 *
	 * Otherwise download a new message header and allocate the necessary
	 * memory.
	 */
	if (bcb->bcb_buf != NULL)
		goto skip_header;

	bread = read(sd, &bcm, sizeof(bcm));
	if (bread == 0) {
		control_free(bcs);
		return 0;
	}
	if (bread < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			goto schedule_next_read;

		log_warning("%s: read: %s", __func__, strerror(errno));
		control_free(bcs);
		return 0;
	}

	/* Validate header fields. */
	plen = ntohl(bcm.bcm_length);
	if (plen < 2) {
		log_debug("%s: client closed due small message length: %d",
			  __func__, bcm.bcm_length);
		control_free(bcs);
		return 0;
	}

	if (bcm.bcm_ver != BMV_VERSION_1) {
		log_debug("%s: client closed due bad version: %d", __func__,
			  bcm.bcm_ver);
		control_free(bcs);
		return 0;
	}

	/* Prepare the buffer to load the message. */
	bcs->bcs_version = bcm.bcm_ver;
	bcs->bcs_type = bcm.bcm_type;

	bcb->bcb_pos = sizeof(bcm);
	bcb->bcb_left = plen;
	bcb->bcb_buf = XMALLOC(MTYPE_BFDD_NOTIFICATION,
			       sizeof(bcm) + bcb->bcb_left + 1);
	if (bcb->bcb_buf == NULL) {
		log_warning("%s: not enough memory for message size: %u",
			    __func__, bcb->bcb_left);
		control_free(bcs);
		return 0;
	}

	memcpy(bcb->bcb_buf, &bcm, sizeof(bcm));

	/* Terminate data string with NULL for later processing. */
	bcb->bcb_buf[sizeof(bcm) + bcb->bcb_left] = 0;

skip_header:
	/* Download the remaining data of the message and process it. */
	bread = read(sd, &bcb->bcb_buf[bcb->bcb_pos], bcb->bcb_left);
	if (bread == 0) {
		control_free(bcs);
		return 0;
	}
	if (bread < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			goto schedule_next_read;

		log_warning("%s: read: %s", __func__, strerror(errno));
		control_free(bcs);
		return 0;
	}

	bcb->bcb_pos += bread;
	bcb->bcb_left -= bread;
	/* We need more data, return to wait more. */
	if (bcb->bcb_left > 0)
		goto schedule_next_read;

	switch (bcb->bcb_bcm->bcm_type) {
	case BMT_REQUEST_ADD:
		control_handle_request_add(bcs, bcb->bcb_bcm);
		break;
	case BMT_REQUEST_DEL:
		control_handle_request_del(bcs, bcb->bcb_bcm);
		break;
	case BMT_NOTIFY:
		control_handle_notify(bcs, bcb->bcb_bcm);
		break;
	case BMT_NOTIFY_ADD:
		control_handle_notify_add(bcs, bcb->bcb_bcm);
		break;
	case BMT_NOTIFY_DEL:
		control_handle_notify_del(bcs, bcb->bcb_bcm);
		break;

	default:
		log_debug("%s: unhandled message type: %d", __func__,
			  bcb->bcb_bcm->bcm_type);
		control_response(bcs, bcb->bcb_bcm->bcm_id, BCM_RESPONSE_ERROR,
				 "invalid message type");
		break;
	}

	bcs->bcs_version = 0;
	bcs->bcs_type = 0;
	control_reset_buf(bcb);

schedule_next_read:
	bcs->bcs_ev = NULL;
	thread_add_read(master, control_read, bcs, sd, &bcs->bcs_ev);

	return 0;
}

static int control_write(struct thread *t)
{
	struct bfd_control_socket *bcs = THREAD_ARG(t);
	struct bfd_control_buffer *bcb = bcs->bcs_bout;
	int sd = bcs->bcs_sd;
	ssize_t bwrite;

	bwrite = write(sd, &bcb->bcb_buf[bcb->bcb_pos], bcb->bcb_left);
	if (bwrite == 0) {
		control_free(bcs);
		return 0;
	}
	if (bwrite < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			bcs->bcs_outev = NULL;
			thread_add_write(master, control_write, bcs,
					 bcs->bcs_sd, &bcs->bcs_outev);
			return 0;
		}

		log_warning("%s: write: %s", __func__, strerror(errno));
		control_free(bcs);
		return 0;
	}

	bcb->bcb_pos += bwrite;
	bcb->bcb_left -= bwrite;
	if (bcb->bcb_left > 0) {
		bcs->bcs_outev = NULL;
		thread_add_write(master, control_write, bcs, bcs->bcs_sd,
				 &bcs->bcs_outev);
		return 0;
	}

	control_queue_dequeue(bcs);

	return 0;
}


/*
 * Message processing
 */
static void control_handle_request_add(struct bfd_control_socket *bcs,
				       struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	if (config_request_add(json) == 0)
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);
	else
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_ERROR,
				 "request add failed");
}

static void control_handle_request_del(struct bfd_control_socket *bcs,
				       struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	if (config_request_del(json) == 0)
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);
	else
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_ERROR,
				 "request del failed");
}

static struct bfd_session *_notify_find_peer(struct bfd_peer_cfg *bpc)
{
	struct peer_label *pl;

	if (bpc->bpc_has_label) {
		pl = pl_find(bpc->bpc_label);
		if (pl)
			return pl->pl_bs;
	}

	return bs_peer_find(bpc);
}

static void _control_handle_notify(struct hash_bucket *hb, void *arg)
{
	struct bfd_control_socket *bcs = arg;
	struct bfd_session *bs = hb->data;

	/* Notify peer configuration. */
	if (bcs->bcs_notify & BCM_NOTIFY_CONFIG)
		_control_notify_config(bcs, BCM_NOTIFY_CONFIG_ADD, bs);

	/* Notify peer status. */
	if (bcs->bcs_notify & BCM_NOTIFY_PEER_STATE)
		_control_notify(bcs, bs);
}

static void control_handle_notify(struct bfd_control_socket *bcs,
				  struct bfd_control_msg *bcm)
{
	memcpy(&bcs->bcs_notify, bcm->bcm_data, sizeof(bcs->bcs_notify));

	control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);

	/*
	 * If peer asked for notification configuration, send everything that
	 * was configured until the moment to sync up.
	 */
	if (bcs->bcs_notify & (BCM_NOTIFY_CONFIG | BCM_NOTIFY_PEER_STATE))
		bfd_id_iterate(_control_handle_notify, bcs);
}

static int notify_add_cb(struct bfd_peer_cfg *bpc, void *arg)
{
	struct bfd_control_socket *bcs = arg;
	struct bfd_session *bs = _notify_find_peer(bpc);

	if (bs == NULL)
		return -1;

	if (control_notifypeer_new(bcs, bs) == NULL)
		return -1;

	/* Notify peer status. */
	_control_notify(bcs, bs);

	return 0;
}

static int notify_del_cb(struct bfd_peer_cfg *bpc, void *arg)
{
	struct bfd_control_socket *bcs = arg;
	struct bfd_session *bs = _notify_find_peer(bpc);
	struct bfd_notify_peer *bnp;

	if (bs == NULL)
		return -1;

	bnp = control_notifypeer_find(bcs, bs);
	if (bnp)
		control_notifypeer_free(bcs, bnp);

	return 0;
}

static void control_handle_notify_add(struct bfd_control_socket *bcs,
				      struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	if (config_notify_request(bcs, json, notify_add_cb) == 0) {
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);
		return;
	}

	control_response(bcs, bcm->bcm_id, BCM_RESPONSE_ERROR,
			 "failed to parse notify data");
}

static void control_handle_notify_del(struct bfd_control_socket *bcs,
				      struct bfd_control_msg *bcm)
{
	const char *json = (const char *)bcm->bcm_data;

	if (config_notify_request(bcs, json, notify_del_cb) == 0) {
		control_response(bcs, bcm->bcm_id, BCM_RESPONSE_OK, NULL);
		return;
	}

	control_response(bcs, bcm->bcm_id, BCM_RESPONSE_ERROR,
			 "failed to parse notify data");
}


/*
 * Internal functions used by the BFD daemon.
 */
static void control_response(struct bfd_control_socket *bcs, uint16_t id,
			     const char *status, const char *error)
{
	struct bfd_control_msg *bcm;
	char *jsonstr;
	size_t jsonstrlen;

	/* Generate JSON response. */
	jsonstr = config_response(status, error);
	if (jsonstr == NULL) {
		log_warning("%s: config_response: failed to get JSON str",
			    __func__);
		return;
	}

	/* Allocate data and answer. */
	jsonstrlen = strlen(jsonstr);
	bcm = XMALLOC(MTYPE_BFDD_NOTIFICATION,
		      sizeof(struct bfd_control_msg) + jsonstrlen);

	bcm->bcm_length = htonl(jsonstrlen);
	bcm->bcm_ver = BMV_VERSION_1;
	bcm->bcm_type = BMT_RESPONSE;
	bcm->bcm_id = id;
	memcpy(bcm->bcm_data, jsonstr, jsonstrlen);
	XFREE(MTYPE_BFDD_NOTIFICATION, jsonstr);

	control_queue_enqueue_first(bcs, bcm);
}

static void _control_notify(struct bfd_control_socket *bcs,
			    struct bfd_session *bs)
{
	struct bfd_control_msg *bcm;
	char *jsonstr;
	size_t jsonstrlen;

	/* Generate JSON response. */
	jsonstr = config_notify(bs);
	if (jsonstr == NULL) {
		log_warning("%s: config_notify: failed to get JSON str",
			    __func__);
		return;
	}

	/* Allocate data and answer. */
	jsonstrlen = strlen(jsonstr);
	bcm = XMALLOC(MTYPE_BFDD_NOTIFICATION,
		      sizeof(struct bfd_control_msg) + jsonstrlen);

	bcm->bcm_length = htonl(jsonstrlen);
	bcm->bcm_ver = BMV_VERSION_1;
	bcm->bcm_type = BMT_NOTIFY;
	bcm->bcm_id = htons(BCM_NOTIFY_ID);
	memcpy(bcm->bcm_data, jsonstr, jsonstrlen);
	XFREE(MTYPE_BFDD_NOTIFICATION, jsonstr);

	control_queue_enqueue(bcs, bcm);
}

int control_notify(struct bfd_session *bs, uint8_t notify_state)
{
	struct bfd_control_socket *bcs;
	struct bfd_notify_peer *bnp;

	/* Notify zebra listeners as well. */
	ptm_bfd_notify(bs, notify_state);

	/*
	 * PERFORMANCE: reuse the bfd_control_msg allocated data for
	 * all control sockets to avoid wasting memory.
	 */
	TAILQ_FOREACH (bcs, &bglobal.bg_bcslist, bcs_entry) {
		/*
		 * Test for all notifications first, then search for
		 * specific peers.
		 */
		if ((bcs->bcs_notify & BCM_NOTIFY_PEER_STATE) == 0) {
			bnp = control_notifypeer_find(bcs, bs);
			/*
			 * If the notification is not configured here,
			 * don't send it.
			 */
			if (bnp == NULL)
				continue;
		}

		_control_notify(bcs, bs);
	}

	return 0;
}

static void _control_notify_config(struct bfd_control_socket *bcs,
				   const char *op, struct bfd_session *bs)
{
	struct bfd_control_msg *bcm;
	char *jsonstr;
	size_t jsonstrlen;

	/* Generate JSON response. */
	jsonstr = config_notify_config(op, bs);
	if (jsonstr == NULL) {
		log_warning("%s: config_notify_config: failed to get JSON str",
			    __func__);
		return;
	}

	/* Allocate data and answer. */
	jsonstrlen = strlen(jsonstr);
	bcm = XMALLOC(MTYPE_BFDD_NOTIFICATION,
		      sizeof(struct bfd_control_msg) + jsonstrlen);

	bcm->bcm_length = htonl(jsonstrlen);
	bcm->bcm_ver = BMV_VERSION_1;
	bcm->bcm_type = BMT_NOTIFY;
	bcm->bcm_id = htons(BCM_NOTIFY_ID);
	memcpy(bcm->bcm_data, jsonstr, jsonstrlen);
	XFREE(MTYPE_BFDD_NOTIFICATION, jsonstr);

	control_queue_enqueue(bcs, bcm);
}

int control_notify_config(const char *op, struct bfd_session *bs)
{
	struct bfd_control_socket *bcs;
	struct bfd_notify_peer *bnp;

	/* Remove the control sockets notification for this peer. */
	if (strcmp(op, BCM_NOTIFY_CONFIG_DELETE) == 0 && bs->refcount > 0) {
		TAILQ_FOREACH (bcs, &bglobal.bg_bcslist, bcs_entry) {
			bnp = control_notifypeer_find(bcs, bs);
			if (bnp)
				control_notifypeer_free(bcs, bnp);
		}
	}

	/*
	 * PERFORMANCE: reuse the bfd_control_msg allocated data for
	 * all control sockets to avoid wasting memory.
	 */
	TAILQ_FOREACH (bcs, &bglobal.bg_bcslist, bcs_entry) {
		/*
		 * Test for all notifications first, then search for
		 * specific peers.
		 */
		if ((bcs->bcs_notify & BCM_NOTIFY_CONFIG) == 0)
			continue;

		_control_notify_config(bcs, op, bs);
	}

	return 0;
}
