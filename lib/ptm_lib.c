/* PTM Library
 * Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include "csv.h"
#include "ptm_lib.h"

#define DEBUG_E 0
#define DEBUG_V 0

#define ERRLOG(fmt, ...)                                                       \
	do {                                                                   \
		if (DEBUG_E)                                                   \
			fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__,          \
				__LINE__, __func__, ##__VA_ARGS__);            \
	} while (0)

#define DLOG(fmt, ...)                                                         \
	do {                                                                   \
		if (DEBUG_V)                                                   \
			fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__,          \
				__LINE__, __func__, ##__VA_ARGS__);            \
	} while (0)

typedef struct ptm_lib_msg_ctxt_s {
	int cmd_id;
	csv_t *csv;
	ptmlib_msg_type type;
} ptm_lib_msg_ctxt_t;

static csv_record_t *_ptm_lib_encode_header(csv_t *csv, csv_record_t *rec,
					    int msglen, int version, int type,
					    int cmd_id, char *client_name)
{
	char msglen_buf[16], vers_buf[16], type_buf[16], cmdid_buf[16];
	char client_buf[32];
	csv_record_t *rec1;

	sprintf(msglen_buf, "%4d", msglen);
	sprintf(vers_buf, "%4d", version);
	sprintf(type_buf, "%4d", type);
	sprintf(cmdid_buf, "%4d", cmd_id);
	snprintf(client_buf, 17, "%16.16s", client_name);
	if (rec) {
		rec1 = csv_encode_record(csv, rec, 5, msglen_buf, vers_buf,
					 type_buf, cmdid_buf, client_buf);
	} else {
		rec1 = csv_encode(csv, 5, msglen_buf, vers_buf, type_buf,
				  cmdid_buf, client_buf);
	}
	return (rec1);
}

static int _ptm_lib_decode_header(csv_t *csv, int *msglen, int *version,
				  int *type, int *cmd_id, char *client_name)
{
	char *hdr;
	csv_record_t *rec;
	csv_field_t *fld;
	int i, j;

	csv_decode(csv, NULL);
	rec = csv_record_iter(csv);
	if (rec == NULL) {
		DLOG("malformed CSV\n");
		return (-1);
	}
	hdr = csv_field_iter(rec, &fld);
	if (hdr == NULL) {
		DLOG("malformed CSV\n");
		return (-1);
	}
	*msglen = atoi(hdr);
	hdr = csv_field_iter_next(&fld);
	if (hdr == NULL) {
		DLOG("malformed CSV\n");
		return (-1);
	}
	*version = atoi(hdr);
	hdr = csv_field_iter_next(&fld);
	if (hdr == NULL) {
		DLOG("malformed CSV\n");
		return (-1);
	}
	*type = atoi(hdr);
	hdr = csv_field_iter_next(&fld);
	if (hdr == NULL) {
		DLOG("malformed CSV\n");
		return (-1);
	}
	*cmd_id = atoi(hdr);
	hdr = csv_field_iter_next(&fld);
	if (hdr == NULL) {
		DLOG("malformed CSV\n");
		return (-1);
	}
	/* remove leading spaces */
	for (i = j = 0; i < csv_field_len(fld); i++) {
		if (!isspace((int)hdr[i])) {
			client_name[j] = hdr[i];
			j++;
		}
	}
	client_name[j] = '\0';

	return (0);
}

int ptm_lib_append_msg(ptm_lib_handle_t *hdl, void *ctxt, const char *key,
		       const char *val)
{
	ptm_lib_msg_ctxt_t *p_ctxt = ctxt;
	csv_t *csv;
	csv_record_t *mh_rec, *rec;

	if (!p_ctxt) {
		ERRLOG("%s: no context \n", __FUNCTION__);
		return -1;
	}

	csv = p_ctxt->csv;
	mh_rec = csv_record_iter(csv);
	rec = csv_record_iter_next(mh_rec);

	/* append to the hdr record */
	rec = csv_append_record(csv, rec, 1, key);
	if (!rec) {
		ERRLOG("%s: Could not append key \n", __FUNCTION__);
		return -1;
	}

	rec = csv_record_iter_next(rec);
	/* append to the data record */
	rec = csv_append_record(csv, rec, 1, val);
	if (!rec) {
		ERRLOG("%s: Could not append val \n", __FUNCTION__);
		return -1;
	}

	/* update the msg hdr */
	_ptm_lib_encode_header(csv, mh_rec, (csvlen(csv) - PTMLIB_MSG_HDR_LEN),
			       PTMLIB_MSG_VERSION, p_ctxt->type, p_ctxt->cmd_id,
			       hdl->client_name);

	return 0;
}

int ptm_lib_init_msg(ptm_lib_handle_t *hdl, int cmd_id, int type, void *in_ctxt,
		     void **out_ctxt)
{
	ptm_lib_msg_ctxt_t *p_ctxt;
	ptm_lib_msg_ctxt_t *p_in_ctxt = in_ctxt;
	csv_t *csv;
	csv_record_t *rec, *d_rec;

	/* Initialize csv for using discrete record buffers */
	csv = csv_init(NULL, NULL, PTMLIB_MSG_SZ);

	if (!csv) {
		ERRLOG("%s: Could not allocate csv \n", __FUNCTION__);
		return -1;
	}

	rec = _ptm_lib_encode_header(csv, NULL, 0, PTMLIB_MSG_VERSION, type,
				     cmd_id, hdl->client_name);

	if (!rec) {
		ERRLOG("%s: Could not allocate record \n", __FUNCTION__);
		csv_clean(csv);
		csv_free(csv);
		return -1;
	}

	p_ctxt = calloc(1, sizeof(*p_ctxt));
	if (!p_ctxt) {
		ERRLOG("%s: Could not allocate context \n", __FUNCTION__);
		csv_clean(csv);
		csv_free(csv);
		return -1;
	}

	p_ctxt->csv = csv;
	p_ctxt->cmd_id = cmd_id;
	p_ctxt->type = type;

	*(ptm_lib_msg_ctxt_t **)out_ctxt = p_ctxt;

	/* caller supplied a context to initialize with? */
	if (p_in_ctxt) {
		/* insert the hdr rec */
		rec = csv_record_iter(p_in_ctxt->csv);
		csv_clone_record(p_in_ctxt->csv, rec, &d_rec);
		csv_insert_record(csv, d_rec);
		/* insert the data rec */
		rec = csv_record_iter_next(rec);
		csv_clone_record(p_in_ctxt->csv, rec, &d_rec);
		csv_insert_record(csv, d_rec);
	}
	return 0;
}

int ptm_lib_cleanup_msg(ptm_lib_handle_t *hdl, void *ctxt)
{
	ptm_lib_msg_ctxt_t *p_ctxt = ctxt;
	csv_t *csv;

	if (!p_ctxt) {
		ERRLOG("%s: no context \n", __FUNCTION__);
		return -1;
	}

	csv = p_ctxt->csv;

	csv_clean(csv);
	csv_free(csv);
	free(p_ctxt);

	return 0;
}

int ptm_lib_complete_msg(ptm_lib_handle_t *hdl, void *ctxt, char *buf, int *len)
{
	ptm_lib_msg_ctxt_t *p_ctxt = ctxt;
	csv_t *csv;
	csv_record_t *rec;

	if (!p_ctxt) {
		ERRLOG("%s: no context \n", __FUNCTION__);
		return -1;
	}

	csv = p_ctxt->csv;
	rec = csv_record_iter(csv);

	_ptm_lib_encode_header(csv, rec, (csvlen(csv) - PTMLIB_MSG_HDR_LEN),
			       PTMLIB_MSG_VERSION, p_ctxt->type, p_ctxt->cmd_id,
			       hdl->client_name);

	/* parse csv contents into string */
	if (buf && len) {
		if (csv_serialize(csv, buf, *len)) {
			ERRLOG("%s: cannot serialize\n", __FUNCTION__);
			return -1;
		}
		*len = csvlen(csv);
	}

	csv_clean(csv);
	csv_free(csv);
	free(p_ctxt);

	return 0;
}

int ptm_lib_find_key_in_msg(void *ctxt, const char *key, char *val)
{
	ptm_lib_msg_ctxt_t *p_ctxt = ctxt;
	csv_t *csv = p_ctxt->csv;
	csv_record_t *hrec, *drec;
	csv_field_t *hfld, *dfld;
	char *hstr, *dstr;

	/**
	 * skip over ptm hdr if present
	 * The next hdr is the keys (column name)
	 * The next hdr is the data
	 */
	if (csv_num_records(csv) > 2) {
		hrec = csv_record_iter(csv);
		hrec = csv_record_iter_next(hrec);
	} else {
		hrec = csv_record_iter(csv);
	}
	drec = csv_record_iter_next(hrec);
	val[0] = '\0';
	for (hstr = csv_field_iter(hrec, &hfld),
	    dstr = csv_field_iter(drec, &dfld);
	     (hstr && dstr); hstr = csv_field_iter_next(&hfld),
	    dstr = csv_field_iter_next(&dfld)) {
		if (!strncmp(hstr, key, csv_field_len(hfld))) {
			snprintf(val, csv_field_len(dfld) + 1, "%s", dstr);
			return 0;
		}
	}

	return -1;
}

static int _ptm_lib_read_ptm_socket(int fd, char *buf, int len)
{
	int retries = 0, rc;
	int bytes_read = 0;

	while (bytes_read != len) {
		rc = recv(fd, (void *)(buf + bytes_read), (len - bytes_read),
			  MSG_DONTWAIT);
		if (rc <= 0) {
			if (errno && (errno != EAGAIN)
			    && (errno != EWOULDBLOCK)) {
				ERRLOG("fatal recv error(%s), closing connection, rc %d\n",
				       strerror(errno), rc);
				return (rc);
			} else {
				if (retries++ < 2) {
					usleep(10000);
					continue;
				}
				DLOG("max retries - recv error(%d - %s) bytes read %d (%d)\n",
				     errno, strerror(errno), bytes_read, len);
				return (bytes_read);
			}
			break;
		} else {
			bytes_read += rc;
		}
	}

	return bytes_read;
}

int ptm_lib_process_msg(ptm_lib_handle_t *hdl, int fd, char *inbuf, int inlen,
			void *arg)
{
	int rc, len;
	char client_name[32];
	int cmd_id = 0, type = 0, ver = 0, msglen = 0;
	csv_t *csv;
	ptm_lib_msg_ctxt_t *p_ctxt = NULL;

	len = _ptm_lib_read_ptm_socket(fd, inbuf, PTMLIB_MSG_HDR_LEN);
	if (len <= 0)
		return (len);

	csv = csv_init(NULL, inbuf, PTMLIB_MSG_HDR_LEN);

	if (!csv) {
		DLOG("Cannot allocate csv for hdr\n");
		return (-1);
	}

	rc = _ptm_lib_decode_header(csv, &msglen, &ver, &type, &cmd_id,
				    client_name);

	csv_clean(csv);
	csv_free(csv);

	if (rc < 0) {
		/* could not decode the CSV - maybe its legacy cmd?
		 * get the entire cmd from the socket and see if we can process
		 * it
		 */
		if (len == PTMLIB_MSG_HDR_LEN) {
			len += _ptm_lib_read_ptm_socket(
				fd, (inbuf + PTMLIB_MSG_HDR_LEN),
				inlen - PTMLIB_MSG_HDR_LEN);
			if (len <= 0)
				return (len);
		}

		inbuf[len] = '\0';
		/* we only support the get-status cmd */
		if (strcmp(inbuf, PTMLIB_CMD_GET_STATUS)) {
			DLOG("unsupported legacy cmd %s\n", inbuf);
			return (-1);
		}
		/* internally create a csv-style cmd */
		ptm_lib_init_msg(hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL,
				 (void *)&p_ctxt);
		if (!p_ctxt) {
			DLOG("couldnt allocate context\n");
			return (-1);
		}
		ptm_lib_append_msg(hdl, p_ctxt, "cmd", PTMLIB_CMD_GET_STATUS);

	} else {

		if (msglen > inlen) {
			DLOG("msglen [%d] > inlen [%d]\n", msglen, inlen);
			return -1;
		}

		/* read the rest of the msg */
		len = _ptm_lib_read_ptm_socket(fd, inbuf, msglen);
		if (len <= 0) {
			return (len);
		}

		inbuf[len] = '\0';

		csv = csv_init(NULL, NULL, PTMLIB_MSG_SZ);
		if (!csv) {
			ERRLOG("Cannot allocate csv for msg\n");
			return -1;
		}

		csv_decode(csv, inbuf);
		p_ctxt = calloc(1, sizeof(*p_ctxt));
		if (!p_ctxt) {
			ERRLOG("%s: Could not allocate context \n",
			       __FUNCTION__);
			csv_clean(csv);
			csv_free(csv);
			return -1;
		}

		p_ctxt->csv = csv;
		p_ctxt->cmd_id = cmd_id;
		p_ctxt->type = type;
	}

	switch (p_ctxt->type) {
	case PTMLIB_MSG_TYPE_NOTIFICATION:
		if (hdl->notify_cb)
			hdl->notify_cb(arg, p_ctxt);
		break;
	case PTMLIB_MSG_TYPE_CMD:
		if (hdl->cmd_cb)
			hdl->cmd_cb(arg, p_ctxt);
		break;
	case PTMLIB_MSG_TYPE_RESPONSE:
		if (hdl->response_cb)
			hdl->response_cb(arg, p_ctxt);
		break;
	default:
		return -1;
	}

	csv_clean(p_ctxt->csv);
	csv_free(p_ctxt->csv);
	free(p_ctxt);

	return len;
}

ptm_lib_handle_t *ptm_lib_register(char *client_name, ptm_cmd_cb cmd_cb,
				   ptm_notify_cb notify_cb,
				   ptm_response_cb response_cb)
{
	ptm_lib_handle_t *hdl;

	hdl = calloc(1, sizeof(*hdl));

	if (hdl) {
		strncpy(hdl->client_name, client_name, PTMLIB_MAXNAMELEN - 1);
		hdl->cmd_cb = cmd_cb;
		hdl->notify_cb = notify_cb;
		hdl->response_cb = response_cb;
	}

	return hdl;
}

void ptm_lib_deregister(ptm_lib_handle_t *hdl)
{
	if (hdl) {
		memset(hdl, 0x00, sizeof(*hdl));
		free(hdl);
	}
}
