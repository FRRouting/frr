/* Virtual terminal [aka TeletYpe] interface routine
 * Copyright (C) 1997 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_VTY_H
#define _ZEBRA_VTY_H

#include <sys/types.h>
#include <regex.h>

#include "thread.h"
#include "log.h"
#include "sockunion.h"
#include "qobj.h"
#include "compiler.h"

#define VTY_BUFSIZ 4096
#define VTY_MAXHIST 20

/* VTY struct. */
struct vty {
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
	char *error_buf;

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

	/* qobj object ID (replacement for "index") */
	uint64_t qobj_index;

	/* qobj second-level object ID (replacement for "index_sub") */
	uint64_t qobj_index_sub;

	/* For escape character. */
	unsigned char escape;

	/* Current vty status. */
	enum { VTY_NORMAL, VTY_CLOSE, VTY_MORE, VTY_MORELINE } status;

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

	/* Terminal monitor. */
	int monitor;

	/* In configure mode. */
	int config;

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

/* Exported variables */
extern char integrate_default[];

/* Prototypes. */
extern void vty_init(struct thread_master *);
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
extern int vty_out(struct vty *, const char *, ...) PRINTF_ATTRIBUTE(2, 3);
extern void vty_frame(struct vty *, const char *, ...) PRINTF_ATTRIBUTE(2, 3);
extern void vty_endframe(struct vty *, const char *);
bool vty_set_include(struct vty *vty, const char *regexp);

extern bool vty_read_config(const char *, char *);
extern void vty_time_print(struct vty *, int);
extern void vty_serv_sock(const char *, unsigned short, const char *);
extern void vty_close(struct vty *);
extern char *vty_get_cwd(void);
extern void vty_log(const char *level, const char *proto, const char *fmt,
		    struct timestamp_control *, va_list);
extern int vty_config_lock(struct vty *);
extern int vty_config_unlock(struct vty *);
extern void vty_config_lockless(void);
extern int vty_shell(struct vty *);
extern int vty_shell_serv(struct vty *);
extern void vty_hello(struct vty *);

/* ^Z / SIGTSTP handling */
extern void vty_stdio_suspend(void);
extern void vty_stdio_resume(void);
extern void vty_stdio_close(void);

/* Send a fixed-size message to all vty terminal monitors; this should be
   an async-signal-safe function. */
extern void vty_log_fixed(char *buf, size_t len);

#endif /* _ZEBRA_VTY_H */
