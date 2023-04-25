// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * March 6 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */
#ifndef _MGMT_MSG_H
#define _MGMT_MSG_H

#include "stream.h"
#include "frrevent.h"

/*
 * Messages on the stream start with a marker that encodes a version octet.
 */
#define MGMT_MSG_MARKER_PFX (0x23232300u) /* ASCII - "###\ooo"*/
#define MGMT_MSG_IS_MARKER(x) (((x)&0xFFFFFF00u) == MGMT_MSG_MARKER_PFX)
#define MGMT_MSG_MARKER(version) (MGMT_MSG_MARKER_PFX | (version))
#define MGMT_MSG_MARKER_VERSION(x) (0xFF & (x))

#define MGMT_MSG_VERSION_PROTOBUF 0
#define MGMT_MSG_VERSION_NATIVE 1

struct mgmt_msg_state {
	struct stream *ins;
	struct stream *outs;
	struct stream_fifo inq;
	struct stream_fifo outq;
	uint64_t nrxm;		/* number of received messages */
	uint64_t nrxb;		/* number of received bytes */
	uint64_t ntxm;		/* number of sent messages */
	uint64_t ntxb;		/* number of sent bytes */
	size_t max_read_buf;	/* should replace with max time value */
	size_t max_write_buf;	/* should replace with max time value */
	size_t max_msg_sz;
	char *idtag; /* identifying tag for messages */
};

struct mgmt_msg_hdr {
	uint32_t marker;
	uint32_t len;
};

enum mgmt_msg_rsched {
	MSR_SCHED_BOTH,	  /* schedule both queue and read */
	MSR_SCHED_STREAM, /* schedule read */
	MSR_DISCONNECT,	  /* disconnect and start reconnecting */
};

enum mgmt_msg_wsched {
	MSW_SCHED_NONE,	      /* no scheduling required */
	MSW_SCHED_STREAM,     /* schedule writing */
	MSW_DISCONNECT,	      /* disconnect and start reconnecting */
};

extern int mgmt_msg_connect(const char *path, size_t sendbuf, size_t recvbuf,
			    const char *dbgtag);
extern void mgmt_msg_destroy(struct mgmt_msg_state *ms);
extern void mgmt_msg_init(struct mgmt_msg_state *ms, size_t max_read_buf,
			  size_t max_write_buf, size_t max_msg_sz,
			  const char *idtag);
extern bool mgmt_msg_procbufs(struct mgmt_msg_state *ms,
			      void (*handle_msg)(uint8_t version, void *user,
						 uint8_t *msg, size_t msglen),
			      void *user, bool debug);
extern enum mgmt_msg_rsched mgmt_msg_read(struct mgmt_msg_state *ms, int fd,
					  bool debug);
extern size_t mgmt_msg_reset_writes(struct mgmt_msg_state *ms);
extern int mgmt_msg_send_msg(struct mgmt_msg_state *ms, uint8_t version,
			     void *msg, size_t len,
			     size_t (*packf)(void *msg, void *buf), bool debug);
extern enum mgmt_msg_wsched mgmt_msg_write(struct mgmt_msg_state *ms, int fd,
					   bool debug);

#endif /* _MGMT_MSG_H */
