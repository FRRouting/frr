// SPDX-License-Identifier: GPL-2.0-or-later
/* Virtual terminal [aka TeletYpe] interface routine
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_VTY_H
#define _ZEBRA_VTY_H

#include <sys/types.h>
#ifdef HAVE_LIBPCRE2_POSIX
#ifndef _FRR_PCRE2_POSIX
#define _FRR_PCRE2_POSIX
#include <pcre2posix.h>
#endif /* _FRR_PCRE2_POSIX */
#elif defined(HAVE_LIBPCREPOSIX)
#include <pcreposix.h>
#else
#include <regex.h>
#endif /* HAVE_LIBPCRE2_POSIX */

#include "thread.h"
#include "log.h"
#include "sockunion.h"
#include "qobj.h"
#include "compiler.h"
#include "northbound.h"
#include "zlog_live.h"
#include "mgmt_fe_client.h"

#ifdef __cplusplus
extern "C" {
#endif

struct json_object;

#define VTY_BUFSIZ 4096
#define VTY_MAXHIST 20
#define VTY_MAXDEPTH 8

#define VTY_MAXCFGCHANGES 16

struct vty_error {
	char error_buf[VTY_BUFSIZ];
	uint32_t line_num;
};

struct vty_cfg_change {
	char xpath[XPATH_MAXLEN];
	enum nb_operation operation;
	const char *value;
};

PREDECL_DLIST(vtys);

/* VTY struct. */
struct vty {
	struct vtys_item itm;

	/* File descripter of this vty. */
	int fd;

	/* output FD, to support stdin/stdout combination */
	int wfd;

	/* File output, used for VTYSH only */
	FILE *of;
	FILE *of_saved;

	/* whether we are using pager or not */
	bool is_paged;

	/* Is this vty connect to file or not */
	enum { VTY_TERM, VTY_FILE, VTY_SHELL, VTY_SHELL_SERV } type;

	/* Node status of this vty */
	int node;

	/* Failure count */
	int fail;

	/* Output filer regex */
	bool filter;
	regex_t include;

	/* Line buffer */
	struct buffer *lbuf;

	/* Output buffer. */
	struct buffer *obuf;

	/* Command input buffer */
	char *buf;

	/* Command input error buffer */
	struct list *error;

	/* Command cursor point */
	int cp;

	/* Command length */
	int length;

	/* Command max length. */
	int max;

	/* Histry of command */
	char *hist[VTY_MAXHIST];

	/* History lookup current point */
	int hp;

	/* History insert end point */
	int hindex;

	/* Changes enqueued to be applied in the candidate configuration. */
	size_t num_cfg_changes;
	struct nb_cfg_change cfg_changes[VTY_MAXCFGCHANGES];

	/* XPath of the current node */
	int xpath_index;
	char xpath[VTY_MAXDEPTH][XPATH_MAXLEN];

	/* In configure mode. */
	bool config;

	/* Private candidate configuration mode. */
	bool private_config;

	/* Candidate configuration. */
	struct nb_config *candidate_config;

	/* Base candidate configuration. */
	struct nb_config *candidate_config_base;

	/* Dynamic transaction information. */
	bool pending_allowed;
	bool pending_commit;
	bool no_implicit_commit;
	char *pending_cmds_buf;
	size_t pending_cmds_buflen;
	size_t pending_cmds_bufpos;

	/* Confirmed-commit timeout and rollback configuration. */
	struct thread *t_confirmed_commit_timeout;
	struct nb_config *confirmed_commit_rollback;

	/* qobj object ID (replacement for "index") */
	uint64_t qobj_index;

	/* qobj second-level object ID (replacement for "index_sub") */
	uint64_t qobj_index_sub;

	/* For escape character. */
	unsigned char escape;

	/* Current vty status. */
	enum {
		VTY_NORMAL,
		VTY_CLOSE,
		VTY_MORE,
		VTY_MORELINE,
		VTY_PASSFD,
	} status;

	/* vtysh socket/fd passing (for terminal monitor) */
	int pass_fd;

	/* CLI command return value (likely CMD_SUCCESS) when pass_fd != -1 */
	uint8_t pass_fd_status[4];

	/* live logging target / terminal monitor */
	struct zlog_live_cfg live_log;

	/* IAC handling: was the last character received the
	   IAC (interpret-as-command) escape character (and therefore the next
	   character will be the command code)?  Refer to Telnet RFC 854. */
	unsigned char iac;

	/* IAC SB (option subnegotiation) handling */
	unsigned char iac_sb_in_progress;
/* At the moment, we care only about the NAWS (window size) negotiation,
   and that requires just a 5-character buffer (RFC 1073):
     <NAWS char> <16-bit width> <16-bit height> */
#define TELNET_NAWS_SB_LEN 5
	unsigned char sb_buf[TELNET_NAWS_SB_LEN];
	/* How many subnegotiation characters have we received?  We just drop
	   those that do not fit in the buffer. */
	size_t sb_len;

	/* Window width/height. */
	int width;
	int height;

	/* Configure lines. */
	int lines;

	/* Read and write thread. */
	struct thread *t_read;
	struct thread *t_write;

	/* Timeout seconds and thread. */
	unsigned long v_timeout;
	struct thread *t_timeout;

	/* What address is this vty comming from. */
	char address[SU_ADDRSTRLEN];

	/* "frame" output.  This is buffered and will be printed if some
	 * actual output follows, or will be discarded if the frame ends
	 * without any output. */
	size_t frame_pos;
	char frame[1024];

	uintptr_t mgmt_session_id;
	uint64_t mgmt_client_id;
	uint64_t mgmt_req_id;
	bool mgmt_req_pending;
	bool mgmt_locked_candidate_ds;
};

static inline void vty_push_context(struct vty *vty, int node, uint64_t id)
{
	vty->node = node;
	vty->qobj_index = id;
}

/* note: VTY_PUSH_CONTEXT(..., NULL) doesn't work, since it will try to
 * dereference "NULL->qobj_node.nid" */
#define VTY_PUSH_CONTEXT(nodeval, ptr)                                         \
	vty_push_context(vty, nodeval, QOBJ_ID_0SAFE(ptr))
#define VTY_PUSH_CONTEXT_NULL(nodeval) vty_push_context(vty, nodeval, 0ULL)
#define VTY_PUSH_CONTEXT_SUB(nodeval, ptr)                                     \
	do {                                                                   \
		vty->node = nodeval;                                           \
		/* qobj_index stays untouched */                               \
		vty->qobj_index_sub = QOBJ_ID_0SAFE(ptr);                      \
	} while (0)

/* can return NULL if context is invalid! */
#define VTY_GET_CONTEXT(structname)                                            \
	QOBJ_GET_TYPESAFE(vty->qobj_index, structname)
#define VTY_GET_CONTEXT_SUB(structname)                                        \
	QOBJ_GET_TYPESAFE(vty->qobj_index_sub, structname)

/* will return if ptr is NULL. */
#define VTY_CHECK_CONTEXT(ptr)                                                 \
	if (!ptr) {                                                            \
		vty_out(vty,                                                   \
			"Current configuration object was deleted "            \
			"by another process.\n");                              \
		return CMD_WARNING;                                            \
	}

/* struct structname *ptr = <context>;   ptr will never be NULL. */
#define VTY_DECLVAR_CONTEXT(structname, ptr)                                   \
	struct structname *ptr = VTY_GET_CONTEXT(structname);                  \
	VTY_CHECK_CONTEXT(ptr);
#define VTY_DECLVAR_CONTEXT_SUB(structname, ptr)                               \
	struct structname *ptr = VTY_GET_CONTEXT_SUB(structname);              \
	VTY_CHECK_CONTEXT(ptr);
#define VTY_DECLVAR_INSTANCE_CONTEXT(structname, ptr)                          \
	if (vty->qobj_index == 0)                                              \
		return CMD_NOT_MY_INSTANCE;                                    \
	struct structname *ptr = VTY_GET_CONTEXT(structname);                  \
	VTY_CHECK_CONTEXT(ptr);

#define VTY_DECLVAR_CONTEXT_VRF(vrfptr)                                        \
	struct vrf *vrfptr;                                                    \
	if (vty->node == CONFIG_NODE)                                          \
		vrfptr = vrf_lookup_by_id(VRF_DEFAULT);                        \
	else                                                                   \
		vrfptr = VTY_GET_CONTEXT(vrf);                                 \
	VTY_CHECK_CONTEXT(vrfptr);                                             \
	MACRO_REQUIRE_SEMICOLON() /* end */

/* XPath macros. */
#define VTY_PUSH_XPATH(nodeval, value)                                         \
	do {                                                                   \
		if (vty->xpath_index >= VTY_MAXDEPTH) {                        \
			vty_out(vty, "%% Reached maximum CLI depth (%u)\n",    \
				VTY_MAXDEPTH);                                 \
			return CMD_WARNING;                                    \
		}                                                              \
		vty->node = nodeval;                                           \
		strlcpy(vty->xpath[vty->xpath_index], value,                   \
			sizeof(vty->xpath[0]));                                \
		vty->xpath_index++;                                            \
	} while (0)

#define VTY_CURR_XPATH vty->xpath[vty->xpath_index - 1]

#define VTY_CHECK_XPATH                                                        \
	do {                                                                   \
		if (vty->type != VTY_FILE && !vty->private_config              \
		    && vty->xpath_index > 0                                    \
		    && !yang_dnode_exists(vty->candidate_config->dnode,        \
					  VTY_CURR_XPATH)) {                   \
			vty_out(vty,                                           \
				"Current configuration object was deleted "    \
				"by another process.\n\n");                    \
			return CMD_WARNING;                                    \
		}                                                              \
	} while (0)

struct vty_arg {
	const char *name;
	const char *value;
	const char **argv;
	int argc;
};

/* Integrated configuration file. */
#define INTEGRATE_DEFAULT_CONFIG "frr.conf"

/* Default time out value */
#define VTY_TIMEOUT_DEFAULT 600

/* Vty read buffer size. */
#define VTY_READ_BUFSIZ 512

/* Directory separator. */
#ifndef DIRECTORY_SEP
#define DIRECTORY_SEP '/'
#endif /* DIRECTORY_SEP */

#ifndef IS_DIRECTORY_SEP
#define IS_DIRECTORY_SEP(c) ((c) == DIRECTORY_SEP)
#endif

extern struct nb_config *vty_mgmt_candidate_config;

/* Prototypes. */
extern void vty_init(struct thread_master *, bool do_command_logging);
extern void vty_init_vtysh(void);
extern void vty_terminate(void);
extern void vty_reset(void);
extern struct vty *vty_new(void);
extern struct vty *vty_stdio(void (*atclose)(int isexit));

/* - vty_frame() output goes to a buffer (for context-begin markers)
 * - vty_out() will first print this buffer, and clear it
 * - vty_endframe() clears the buffer without printing it, and prints an
 *   extra string if the buffer was empty before (for context-end markers)
 */
extern int vty_out(struct vty *, const char *, ...) PRINTFRR(2, 3);
extern void vty_frame(struct vty *, const char *, ...) PRINTFRR(2, 3);
extern void vty_endframe(struct vty *, const char *);
extern bool vty_set_include(struct vty *vty, const char *regexp);
/* returns CMD_SUCCESS so you can do a one-line "return vty_json(...)"
 * NULL check and json_object_free() is included.
 *
 * _no_pretty means do not add a bunch of newlines and dump the output
 * as densely as possible.
 */
extern int vty_json(struct vty *vty, struct json_object *json);
extern int vty_json_no_pretty(struct vty *vty, struct json_object *json);
extern void vty_json_empty(struct vty *vty);
/* post fd to be passed to the vtysh client
 * fd is owned by the VTY code after this and will be closed when done
 */
extern void vty_pass_fd(struct vty *vty, int fd);

extern bool vty_read_config(struct nb_config *config, const char *config_file,
			    char *config_default_dir);
extern void vty_time_print(struct vty *, int);
extern void vty_serv_sock(const char *, unsigned short, const char *);
extern void vty_close(struct vty *);
extern char *vty_get_cwd(void);
extern void vty_update_xpath(const char *oldpath, const char *newpath);
extern int vty_config_enter(struct vty *vty, bool private_config,
			    bool exclusive);
extern void vty_config_exit(struct vty *);
extern int vty_config_node_exit(struct vty *);
extern int vty_shell(struct vty *);
extern int vty_shell_serv(struct vty *);
extern void vty_hello(struct vty *);

/* ^Z / SIGTSTP handling */
extern void vty_stdio_suspend(void);
extern void vty_stdio_resume(void);
extern void vty_stdio_close(void);

extern void vty_init_mgmt_fe(void);
extern bool vty_mgmt_fe_enabled(void);
extern int vty_mgmt_send_config_data(struct vty *vty);
extern int vty_mgmt_send_commit_config(struct vty *vty, bool validate_only,
				       bool abort);
extern int vty_mgmt_send_get_config(struct vty *vty, Mgmtd__DatastoreId datastore,
				    const char **xpath_list, int num_req);
extern int vty_mgmt_send_get_data(struct vty *vty, Mgmtd__DatastoreId datastore,
				  const char **xpath_list, int num_req);
extern int vty_mgmt_send_lockds_req(struct vty *vty, Mgmtd__DatastoreId ds_id,
				    bool lock);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_VTY_H */
