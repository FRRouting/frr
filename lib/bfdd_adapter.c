/*
 * BFD daemon adapter code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include <arpa/inet.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "bfdd_adapter.h"

/* Declare bfd_receive_id context structure. */
struct bfd_receive_ctx {
	uint16_t brc_reqid;
	bfd_control_recv_cb brc_dispatch;
	void *brc_dispatch_arg;
};

/*
 * Prototypes
 */
static int bfd_receive_id(struct bfd_control_msg *bcm, bool *repeat, void *arg);


/*
 * Control socket
 */
int bfd_control_init(const char *path)
{
	struct sockaddr_un sun = {.sun_family = AF_UNIX,
				  .sun_path = BFD_CONTROL_SOCK_PATH};
	int sd;

	if (path)
		strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	sd = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	if (sd == -1) {
		zlog_err("%s: socket: %s\n", __func__, strerror(errno));
		return -1;
	}

	if (connect(sd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		zlog_err("%s: connect: %s\n", __func__, strerror(errno));
		return -1;
	}

	return sd;
}

uint16_t bfd_control_send(int sd, enum bc_msg_type bmt, const void *data,
			  size_t datalen)
{
	static uint16_t id;
	const uint8_t *dataptr = data;
	ssize_t sent;
	size_t cur = 0;
	struct bfd_control_msg bcm = {
		.bcm_length = htonl(datalen),
		.bcm_type = bmt,
		.bcm_ver = BMV_VERSION_1,
		.bcm_id = htons(++id),
	};
	/* Don't use special notification ID. */
	if (bcm.bcm_id == ntohs(BCM_NOTIFY_ID))
		bcm.bcm_id = htons(++id);

	sent = write(sd, &bcm, sizeof(bcm));
	if (sent == 0) {
		zlog_err("%s: bfdd closed connection\n", __func__);
		return 0;
	}
	if (sent < 0) {
		zlog_err("%s: write: %s\n", __func__, strerror(errno));
		return 0;
	}

	while (datalen > 0) {
		sent = write(sd, &dataptr[cur], datalen);
		if (sent == 0) {
			zlog_err("%s: bfdd closed connection\n", __func__);
			return 0;
		}
		if (sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK
			    || errno == EINTR)
				continue;

			zlog_err("%s: write: %s\n", __func__, strerror(errno));
			return 0;
		}

		datalen -= sent;
		cur += sent;
	}

	return id;
}

int bfd_control_recv(int sd, bfd_control_recv_cb cb, void *arg)
{
	size_t bufpos, bufremaining, plen;
	ssize_t bread;
	struct bfd_control_msg *bcm, bcmh;
	int ret;
	bool repeat;

read_next:
	repeat = false;

	bread = read(sd, &bcmh, sizeof(bcmh));
	if (bread == 0) {
		zlog_err("%s: bfdd closed connection\n", __func__);
		return -1;
	}
	if (bread < 0) {
		zlog_err("%s: read: %s\n", __func__, strerror(errno));
		return -1;
	}

	if (bcmh.bcm_ver != BMV_VERSION_1) {
		zlog_err("%s: wrong protocol version (%d)\n", __func__,
			 bcmh.bcm_ver);
		return -1;
	}

	plen = ntohl(bcmh.bcm_length);
	if (plen > 0) {
		/* Allocate the space for NULL byte as well. */
		bcm = malloc(sizeof(bcmh) + plen + 1);
		if (bcm == NULL) {
			zlog_err("%s: malloc: %s\n", __func__, strerror(errno));
			return -1;
		}

		*bcm = bcmh;
		bufremaining = plen;
		bufpos = 0;
	} else {
		bcm = &bcmh;
		bufremaining = 0;
		bufpos = 0;
	}

	while (bufremaining > 0) {
		bread = read(sd, &bcm->bcm_data[bufpos], bufremaining);
		if (bread == 0) {
			zlog_err("%s: bfdd closed connection\n", __func__);
			ret = -1;
			repeat = false;
			goto skip_and_return;
		}
		if (bread < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK
			    || errno == EINTR)
				continue;

			zlog_err("%s: read: %s\n", __func__, strerror(errno));
			ret = -1;
			repeat = false;
			goto skip_and_return;
		}

		bufremaining -= bread;
		bufpos += bread;
	}

	/* Terminate possible JSON string with NULL. */
	if (bufpos > 0)
		bcm->bcm_data[bufpos] = 0;

	/* Use the callback, otherwise return success. */
	if (cb != NULL)
		ret = cb(bcm, &repeat, arg);
	else
		ret = 0;

skip_and_return:
	/*
	 * Only try to free() memory that was allocated and not from
	 * heap. Use plen to find if we allocated memory.
	 */
	if (plen > 0)
		free(bcm);

	if (repeat)
		goto read_next;

	return ret;
}

/*
 * bfd_control_call: sends a request and expects a response.
 *
 * This function receives the module adapter with the necessary callbacks to
 * dispatch requests that were not meant to the one made here.
 *
 * Returns 0 on success or -1 on failure.
 */
int bfd_control_call(struct bfdd_adapter_ctx *bac, enum bc_msg_type bmt,
		     const void *data, size_t datalen)
{
	struct bfd_receive_ctx brc;

	/* Always allow configuration when the daemon is not running. */
	if (bac->bac_csock == -1)
		return 0;

	brc.brc_reqid = bfd_control_send(bac->bac_csock, bmt, data, datalen);
	if (brc.brc_reqid == 0)
		return -1;

	brc.brc_dispatch = bac->bac_read;
	brc.brc_dispatch_arg = bac->bac_read_arg;
	if (bfd_control_recv(bac->bac_csock, bfd_receive_id, &brc.brc_reqid)
	    != 0)
		return -1;

	return 0;
}

static int socket_is_valid(int sd)
{
	return fcntl(sd, F_GETFD) == -1 && errno == EBADF;
}

/* Forward reinit function declaration. */
static int bfd_adapter_reinit(struct thread *thread);

static int bfd_adapter_read(struct thread *thread)
{
	struct bfdd_adapter_ctx *bac = THREAD_ARG(thread);

	bac->bac_threcv = NULL;

	/* Receive and handle the current packet. */
	if (bfd_control_recv(bac->bac_csock, bac->bac_read, bac->bac_read_arg)
		    != 0
	    && !socket_is_valid(bac->bac_csock)) {
		close(bac->bac_csock);
		bac->bac_csock = -1;
		thread_add_timer_msec(bac->bac_master, bfd_adapter_reinit, bac,
				      BFDD_ADAPTER_CSOCK_TIMEOUT,
				      &bac->bac_thinit);
		return 0;
	}

	/* Schedule next read. */
	thread_add_read(bac->bac_master, bfd_adapter_read, bac, bac->bac_csock,
			&bac->bac_threcv);

	return 0;
}

static int bfd_adapter_reinit(struct thread *thread)
{
	struct bfdd_adapter_ctx *bac = THREAD_ARG(thread);
	int csock;

	bac->bac_thinit = NULL;

	csock = bfd_control_init(bac->bac_ctlpath);
	if (csock == -1) {
		thread_add_timer_msec(bac->bac_master, bfd_adapter_reinit, bac,
				      BFDD_ADAPTER_CSOCK_TIMEOUT,
				      &bac->bac_thinit);
		return 0;
	}

	bac->bac_csock = csock;
	if (bac->bac_reconfigure(csock, bac->bac_reconfigure_arg) != 0)
		goto close_and_retry;

	thread_add_read(bac->bac_master, bfd_adapter_read, bac, bac->bac_csock,
			&bac->bac_threcv);

	return 0;

close_and_retry:
	bac->bac_csock = -1;
	close(csock);
	thread_add_timer_msec(bac->bac_master, bfd_adapter_reinit, bac,
			      BFDD_ADAPTER_CSOCK_TIMEOUT, &bac->bac_thinit);
	return 0;
}

void bfd_adapter_init(struct bfdd_adapter_ctx *bac)
{
	bac->bac_csock = -1;
	bac->bac_thinit = NULL;
	bac->bac_threcv = NULL;
	thread_add_timer_msec(bac->bac_master, bfd_adapter_reinit, bac,
			      BFDD_ADAPTER_CSOCK_TIMEOUT, &bac->bac_thinit);
}


/*
 * JSON queries build
 */
struct json_object *bfd_ctrl_new_json(void)
{
	struct json_object *jo, *jon;

	/* Create the main object: '{}' */
	jo = json_object_new_object();
	if (jo == NULL)
		return NULL;

	/* Create the IPv4 list: '{ 'ipv4': [] }' */
	jon = json_object_new_array();
	if (jon == NULL) {
		json_object_put(jo);
		return NULL;
	}
	json_object_object_add(jo, "ipv4", jon);

	/* Create the IPv6 list: '{ 'ipv4': [], 'ipv6': [] }' */
	jon = json_object_new_array();
	if (jon == NULL) {
		json_object_put(jo);
		return NULL;
	}
	json_object_object_add(jo, "ipv6", jon);

	/* Create the label list: '{ 'ipv4': [], 'ipv6': [], 'label': [] }' */
	jon = json_object_new_array();
	if (jon == NULL) {
		json_object_put(jo);
		return NULL;
	}
	json_object_object_add(jo, "label", jon);

	return jo;
}

static void _bfd_ctrl_add_peer(struct json_object *msg,
			       struct bfd_peer_cfg *bpc, bool use_label)
{
	struct json_object *peer_jo, *plist;

	peer_jo = json_object_new_object();
	if (peer_jo == NULL)
		return;

	if (bpc->bpc_has_label)
		json_object_add_string(peer_jo, "label", bpc->bpc_label);

	/* If using labels, don't add the keys as they are redundant. */
	if (!use_label || !bpc->bpc_has_label) {
		json_object_add_bool(peer_jo, "multihop", bpc->bpc_mhop);

		if (bpc->bpc_mhop)
			json_object_add_string(peer_jo, "local-address",
					       satostr(&bpc->bpc_local));

		json_object_add_string(peer_jo, "peer-address",
				       satostr(&bpc->bpc_peer));

		if (bpc->bpc_has_localif)
			json_object_add_string(peer_jo, "local-interface",
					       bpc->bpc_localif);
	}

	if (bpc->bpc_has_detectmultiplier)
		json_object_add_int(peer_jo, "detect-multiplier",
				    bpc->bpc_detectmultiplier);

	if (bpc->bpc_has_recvinterval)
		json_object_add_int(peer_jo, "receive-interval",
				    bpc->bpc_recvinterval);

	if (bpc->bpc_has_txinterval)
		json_object_add_int(peer_jo, "transmit-interval",
				    bpc->bpc_txinterval);

	if (bpc->bpc_has_echointerval)
		json_object_add_int(peer_jo, "echo-interval",
				    bpc->bpc_echointerval);

	json_object_add_bool(peer_jo, "echo-mode", bpc->bpc_echo);
	json_object_add_bool(peer_jo, "create-only", bpc->bpc_createonly);
	json_object_add_bool(peer_jo, "shutdown", bpc->bpc_shutdown);

	/* Select the appropriated peer list and add the peer to it. */
	if (use_label && bpc->bpc_has_label)
		json_object_object_get_ex(msg, "label", &plist);
	else if (bpc->bpc_ipv4)
		json_object_object_get_ex(msg, "ipv4", &plist);
	else
		json_object_object_get_ex(msg, "ipv6", &plist);

	json_object_array_add(plist, peer_jo);
}

/*
 * This function tries to use the peer label to save some bytes on the
 * message and to avoid ambiguity.
 */
void bfd_ctrl_add_peer_bylabel(struct json_object *msg,
			       struct bfd_peer_cfg *bpc)
{
	_bfd_ctrl_add_peer(msg, bpc, true);
}

/*
 * This function registers the peer always using addresses.
 */
void bfd_ctrl_add_peer(struct json_object *msg, struct bfd_peer_cfg *bpc)
{
	_bfd_ctrl_add_peer(msg, bpc, false);
}

int bfd_response_parse(const char *json, struct bfdd_response *br)
{
	struct json_object *jo, *status, *message;
	const char *sval;

	memset(br, 0, sizeof(*br));

	jo = json_tokener_parse(json);
	if (jo == NULL)
		return -1;

	if (!json_object_object_get_ex(jo, "status", &status)) {
		json_object_put(jo);
		return -1;
	}

	sval = json_object_get_string(status);
	if (strcmp(sval, BCM_RESPONSE_OK) == 0)
		br->br_status = BRS_OK;
	else if (strcmp(sval, BCM_RESPONSE_ERROR) == 0)
		br->br_status = BRS_ERROR;

	if (json_object_object_get_ex(jo, "error", &message)) {
		sval = json_object_get_string(status);
		strlcpy(br->br_message, sval, sizeof(br->br_message));
	}

	json_object_put(jo);

	return 0;
}


/*
 * JSON helper functions
 */
int json_object_add_string(struct json_object *jo, const char *key,
			   const char *str)
{
	struct json_object *jon;

	jon = json_object_new_string(str);
	if (jon == NULL) {
		json_object_put(jon);
		return -1;
	}

	json_object_object_add(jo, key, jon);
	return 0;
}

int json_object_add_bool(struct json_object *jo, const char *key, bool boolean)
{
	struct json_object *jon;

	jon = json_object_new_boolean(boolean);
	if (jon == NULL) {
		json_object_put(jon);
		return -1;
	}

	json_object_object_add(jo, key, jon);
	return 0;
}

int json_object_add_int(struct json_object *jo, const char *key, int64_t value)
{
	struct json_object *jon;

	jon = json_object_new_int64(value);
	if (jon == NULL) {
		json_object_put(jon);
		return -1;
	}

	json_object_object_add(jo, key, jon);
	return 0;
}


/*
 * Utilities
 */
const char *satostr(struct sockaddr_any *sa)
{
#define INETSTR_BUFCOUNT 8
	static char buf[INETSTR_BUFCOUNT][INET6_ADDRSTRLEN];
	static int bufidx;
	struct sockaddr_in *sin = &sa->sa_sin;
	struct sockaddr_in6 *sin6;

	bufidx += (bufidx + 1) % INETSTR_BUFCOUNT;
	strcpy(buf[bufidx], "unknown");
	buf[bufidx][0] = 0;

	switch (sin->sin_family) {
	case AF_INET:
		inet_ntop(AF_INET, &sin->sin_addr, buf[bufidx],
			  sizeof(buf[bufidx]));
		break;
	case AF_INET6:
		sin6 = &sa->sa_sin6;
		inet_ntop(AF_INET6, &sin6->sin6_addr, buf[bufidx],
			  sizeof(buf[bufidx]));
		break;
	}

	return buf[bufidx];
}

int strtosa(const char *addr, struct sockaddr_any *sa)
{
	memset(sa, 0, sizeof(*sa));

	if (inet_pton(AF_INET, addr, &sa->sa_sin.sin_addr) == 1) {
		sa->sa_sin.sin_family = AF_INET;
		return 0;
	}

	if (inet_pton(AF_INET6, addr, &sa->sa_sin6.sin6_addr) == 1) {
		sa->sa_sin6.sin6_family = AF_INET6;
		return 0;
	}

	return -1;
}

int sa_cmp(const struct sockaddr_any *sa, const struct sockaddr_any *san)
{
	if (sa->sa_sin.sin_family > san->sa_sin.sin_family)
		return -1;
	if (sa->sa_sin.sin_family < san->sa_sin.sin_family)
		return 1;

	switch (sa->sa_sin.sin_family) {
	case AF_INET:
		return memcmp(&sa->sa_sin.sin_addr, &san->sa_sin.sin_addr,
			      sizeof(sa->sa_sin.sin_addr));
	case AF_INET6:
		return memcmp(&sa->sa_sin6.sin6_addr, &san->sa_sin6.sin6_addr,
			      sizeof(sa->sa_sin6.sin6_addr));
	default:
		return sa->sa_sin.sin_family != san->sa_sin.sin_family;
	}

	return 0;
}

void integer2timestr(uint64_t time, char *buf, size_t buflen)
{
	unsigned int year, month, day, hour, minute, second;
	int rv;

	year = month = day = hour = minute = second = 0;

#define MINUTES (60)
#define HOURS (24 * MINUTES)
#define DAYS (30 * HOURS)
#define MONTHS (12 * DAYS)
#define YEARS (MONTHS)
	if (time >= YEARS) {
		year = time / YEARS;
		time -= year * YEARS;

		rv = snprintf(buf, buflen, "%u year(s), ", year);
		buf += rv;
		buflen -= rv;
	}
	if (time >= MONTHS) {
		month = time / MONTHS;
		time -= month * MONTHS;

		rv = snprintf(buf, buflen, "%u month(s), ", month);
		buf += rv;
		buflen -= rv;
	}
	if (time >= DAYS) {
		day = time / DAYS;
		time -= day * DAYS;

		rv = snprintf(buf, buflen, "%u day(s), ", day);
		buf += rv;
		buflen -= rv;
	}
	if (time >= HOURS) {
		hour = time / HOURS;
		time -= hour * HOURS;

		rv = snprintf(buf, buflen, "%u hour(s), ", hour);
		buf += rv;
		buflen -= rv;
	}
	if (time >= MINUTES) {
		minute = time / MINUTES;
		time -= minute * MINUTES;

		rv = snprintf(buf, buflen, "%u minute(s), ", minute);
		buf += rv;
		buflen -= rv;
	}
	second = time % MINUTES;
	snprintf(buf, buflen, "%u second(s)", second);
}

const char *diag2str(uint8_t diag)
{
	switch (diag) {
	case 0:
		return "ok";
	case 1:
		return "control detection time expired";
	case 2:
		return "echo function failed";
	case 3:
		return "neighbor signaled session down";
	case 4:
		return "forwarding plane reset";
	case 5:
		return "path down";
	case 6:
		return "concatenated path down";
	case 7:
		return "administratively down";
	case 8:
		return "reverse concatenated path down";
	default:
		return "unknown";
	}
}


/*
 * bfd_receive_id: callback to wait for an specific ID, otherwise dispatch to
 * the appropriated callback.
 */
static int bfd_receive_id(struct bfd_control_msg *bcm, bool *repeat, void *arg)
{
	struct bfd_receive_ctx *brc = arg;
	struct bfdd_response br;

	/* This is not the response we are waiting. */
	if (brc->brc_reqid != ntohs(bcm->bcm_id)) {
		brc->brc_dispatch(bcm, repeat, brc->brc_dispatch_arg);
		*repeat = true;
		return 0;
	}

	if (bcm->bcm_type != BMT_RESPONSE)
		return -1;

	if (bfd_response_parse((const char *)bcm->bcm_data, &br) == 0) {
		if (br.br_status == BRS_OK)
			return 0;
		else
			return -1;
	}

	return 0;
}
