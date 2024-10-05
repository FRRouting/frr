// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * March 6 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */
#ifndef _MGMT_MSG_H
#define _MGMT_MSG_H

#include "memory.h"
#include "stream.h"
#include "frrevent.h"

DECLARE_MTYPE(MSG_CONN);

/*
 * Messages on the stream start with a marker that encodes a version octet.
 */
#define MGMT_MSG_MARKER_PFX (0x23232300u) /* ASCII - "###\ooo"*/
#define MGMT_MSG_IS_MARKER(x) (((x)&0xFFFFFF00u) == MGMT_MSG_MARKER_PFX)
#define MGMT_MSG_MARKER(version) (MGMT_MSG_MARKER_PFX | (version))
#define MGMT_MSG_MARKER_VERSION(x) (0xFF & (x))

#define MGMT_MSG_VERSION_PROTOBUF 0
#define MGMT_MSG_VERSION_NATIVE 1

/* The absolute maximum message size (16MB) */
#define MGMT_MSG_MAX_MSG_ALLOC_LEN (16 * 1024 * 1024)

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

struct msg_conn;


extern int mgmt_msg_connect(const char *path, size_t sendbuf, size_t recvbuf,
			    const char *dbgtag);
extern bool mgmt_msg_procbufs(struct mgmt_msg_state *ms,
			      void (*handle_msg)(uint8_t version, uint8_t *msg,
						 size_t msglen, void *user),
			      void *user, bool debug);
extern enum mgmt_msg_rsched mgmt_msg_read(struct mgmt_msg_state *ms, int fd,
					  bool debug);
extern size_t mgmt_msg_reset_writes(struct mgmt_msg_state *ms);
extern int mgmt_msg_send_msg(struct mgmt_msg_state *ms, uint8_t version,
			     void *msg, size_t len,
			     size_t (*packf)(void *msg, void *buf), bool debug);
extern enum mgmt_msg_wsched mgmt_msg_write(struct mgmt_msg_state *ms, int fd,
					   bool debug);

extern void mgmt_msg_destroy(struct mgmt_msg_state *state);

extern void mgmt_msg_init(struct mgmt_msg_state *ms, size_t max_read_buf,
			  size_t max_write_buf, size_t max_msg_sz,
			  const char *idtag);

/*
 * Connections
 */

struct msg_conn {
	int fd;
	struct mgmt_msg_state mstate;
	struct event_loop *loop;
	struct event *read_ev;
	struct event *write_ev;
	struct event *proc_msg_ev;
	struct msg_conn *remote_conn;
	int (*notify_disconnect)(struct msg_conn *conn);
	void (*handle_msg)(uint8_t version, uint8_t *data, size_t len,
			   struct msg_conn *conn);
	void *user;
	uint short_circuit_depth;
	bool is_short_circuit;	/* true when the message being handled is SC */
	bool is_client;
	bool debug;
};


/*
 * `notify_disconnect` is not called when `msg_conn_cleanup` is called for a
 * msg_conn which is currently connected. The socket is closed but there is no
 * notification.
 */
extern void msg_conn_cleanup(struct msg_conn *conn);
extern void msg_conn_disconnect(struct msg_conn *conn, bool reconnect);
extern int msg_conn_send_msg(struct msg_conn *client, uint8_t version,
			     void *msg, size_t mlen,
			     size_t (*packf)(void *, void *),
			     bool short_circuit_ok);

/*
 * Client-side Connections
 */

struct msg_client {
	struct msg_conn conn;
	struct event *conn_retry_tmr;
	char *sopath;
	int (*notify_connect)(struct msg_client *client);
	bool short_circuit_ok;
};

/*
 * `notify_disconnect` is not called when `msg_client_cleanup` is called for a
 * msg_client which is currently connected. The socket is closed but there is no
 * notification.
 */
extern void msg_client_cleanup(struct msg_client *client);

/*
 * If `short_circuit_ok` is true, then the client-server connection will use a
 * socketpair() rather than a unix-domain socket. This must be passed true if
 * you wish to send messages short-circuit later.
 *
 * `notify_disconnect` is not called when the user `msg_client_cleanup` is
 * called for a client which is currently connected. The socket is closed
 * but there is no notification.
 */
extern void
msg_client_init(struct msg_client *client, struct event_loop *tm,
		const char *sopath,
		int (*notify_connect)(struct msg_client *client),
		int (*notify_disconnect)(struct msg_conn *client),
		void (*handle_msg)(uint8_t version, uint8_t *data, size_t len,
				   struct msg_conn *client),
		size_t max_read_buf, size_t max_write_buf, size_t max_msg_sz,
		bool short_circuit_ok, const char *idtag, bool debug);

/*
 * Server-side Connections
 */
#define MGMTD_MAX_CONN 32

PREDECL_LIST(msg_server_list);

struct msg_server {
	int fd;
	struct msg_server_list_item link;
	struct event_loop *loop;
	struct event *listen_ev;
	const char *sopath;
	const char *idtag;
	struct msg_conn *(*create)(int fd, union sockunion *su);
	struct debug *debug;
};

extern int msg_server_init(struct msg_server *server, const char *sopath,
			   struct event_loop *loop,
			   struct msg_conn *(*create)(int fd,
						      union sockunion *su),
			   const char *idtag, struct debug *debug);
extern void msg_server_cleanup(struct msg_server *server);

/*
 * `notify_disconnect` is not called when the user `msg_conn_cleanup` is
 * called for a client which is currently connected. The socket is closed
 * but there is no notification.
 */
struct msg_conn *
msg_server_conn_create(struct event_loop *tm, int fd,
		       int (*notify_disconnect)(struct msg_conn *conn),
		       void (*handle_msg)(uint8_t version, uint8_t *data,
					  size_t len, struct msg_conn *conn),
		       size_t max_read, size_t max_write, size_t max_size,
		       void *user, const char *idtag);

extern void msg_server_conn_delete(struct msg_conn *conn);

extern void
msg_conn_accept_init(struct msg_conn *conn, struct event_loop *tm, int fd,
		     int (*notify_disconnect)(struct msg_conn *conn),
		     void (*handle_msg)(uint8_t version, uint8_t *data,
					size_t len, struct msg_conn *conn),
		     size_t max_read, size_t max_write, size_t max_size,
		     const char *idtag);

#endif /* _MGMT_MSG_H */
