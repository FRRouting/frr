// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Virtual terminal [aka TeletYpe] interface routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <lib/version.h>
#include <sys/types.h>
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
#include <stdio.h>

#include "debug.h"
#include "linklist.h"
#include "frrevent.h"
#include "buffer.h"
#include "command.h"
#include "sockunion.h"
#include "memory.h"
#include "log.h"
#include "prefix.h"
#include "filter.h"
#include "vty.h"
#include "privs.h"
#include "network.h"
#include "libfrr.h"
#include "frrstr.h"
#include "lib_errors.h"
#include "northbound_cli.h"
#include "printfrr.h"
#include "json.h"

#include <arpa/telnet.h>
#include <termios.h>

#include "lib/vty_clippy.c"

DEFINE_MTYPE_STATIC(LIB, VTY, "VTY");
DEFINE_MTYPE_STATIC(LIB, VTY_SERV, "VTY server");
DEFINE_MTYPE_STATIC(LIB, VTY_OUT_BUF, "VTY output buffer");
DEFINE_MTYPE_STATIC(LIB, VTY_HIST, "VTY history");

DECLARE_DLIST(vtys, struct vty, itm);

/* Vty events */
enum vty_event {
	VTY_SERV,
	VTY_READ,
	VTY_WRITE,
	VTY_TIMEOUT_RESET,
#ifdef VTYSH
	VTYSH_SERV,
	VTYSH_READ,
	VTYSH_WRITE
#endif /* VTYSH */
};

struct nb_config *vty_mgmt_candidate_config;

static struct mgmt_fe_client *mgmt_fe_client;
static bool mgmt_fe_connected;
static uint64_t mgmt_client_id_next;
static uint64_t mgmt_last_req_id = UINT64_MAX;

PREDECL_DLIST(vtyservs);

struct vty_serv {
	struct vtyservs_item itm;

	int sock;
	bool vtysh;

	struct event *t_accept;
};

DECLARE_DLIST(vtyservs, struct vty_serv, itm);

static void vty_event_serv(enum vty_event event, struct vty_serv *);
static void vty_event(enum vty_event, struct vty *);
static int vtysh_flush(struct vty *vty);

/* Extern host structure from command.c */
extern struct host host;

/* active listeners */
static struct vtyservs_head vty_servs[1] = {INIT_DLIST(vty_servs[0])};

/* active connections */
static struct vtys_head vty_sessions[1] = {INIT_DLIST(vty_sessions[0])};
static struct vtys_head vtysh_sessions[1] = {INIT_DLIST(vtysh_sessions[0])};

/* Vty timeout value. */
static unsigned long vty_timeout_val = VTY_TIMEOUT_DEFAULT;

/* Vty access-class command */
static char *vty_accesslist_name = NULL;

/* Vty access-calss for IPv6. */
static char *vty_ipv6_accesslist_name = NULL;

/* Current directory. */
static char vty_cwd[MAXPATHLEN];

/* Login password check. */
static int no_password_check = 0;

/* Integrated configuration file path */
static char integrate_default[] = SYSCONFDIR INTEGRATE_DEFAULT_CONFIG;

bool vty_log_commands;
static bool vty_log_commands_perm;

char const *const mgmt_daemons[] = {
#ifdef HAVE_STATICD
	"staticd",
#endif
};
uint mgmt_daemons_count = array_size(mgmt_daemons);


static int vty_mgmt_lock_candidate_inline(struct vty *vty)
{
	assert(!vty->mgmt_locked_candidate_ds);
	(void)vty_mgmt_send_lockds_req(vty, MGMTD_DS_CANDIDATE, true, true);
	return vty->mgmt_locked_candidate_ds ? 0 : -1;
}

static int vty_mgmt_unlock_candidate_inline(struct vty *vty)
{
	assert(vty->mgmt_locked_candidate_ds);
	(void)vty_mgmt_send_lockds_req(vty, MGMTD_DS_CANDIDATE, false, true);
	return vty->mgmt_locked_candidate_ds ? -1 : 0;
}

static int vty_mgmt_lock_running_inline(struct vty *vty)
{
	assert(!vty->mgmt_locked_running_ds);
	(void)vty_mgmt_send_lockds_req(vty, MGMTD_DS_RUNNING, true, true);
	return vty->mgmt_locked_running_ds ? 0 : -1;
}

static int vty_mgmt_unlock_running_inline(struct vty *vty)
{
	assert(vty->mgmt_locked_running_ds);
	(void)vty_mgmt_send_lockds_req(vty, MGMTD_DS_RUNNING, false, true);
	return vty->mgmt_locked_running_ds ? -1 : 0;
}

void vty_mgmt_resume_response(struct vty *vty, int ret)
{
	uint8_t header[4] = {0, 0, 0, 0};

	if (!vty->mgmt_req_pending_cmd) {
		zlog_err(
			"vty resume response called without mgmt_req_pending_cmd");
		return;
	}

	MGMTD_FE_CLIENT_DBG("resuming CLI cmd after %s on vty session-id: %" PRIu64
			    " with '%s'",
			    vty->mgmt_req_pending_cmd, vty->mgmt_session_id,
			    ret == CMD_SUCCESS ? "success" : "failed");

	vty->mgmt_req_pending_cmd = NULL;

	if (vty->type != VTY_FILE) {
		header[3] = ret;
		buffer_put(vty->obuf, header, 4);
		if (!vty->t_write && (vtysh_flush(vty) < 0)) {
			zlog_err("failed to vtysh_flush");
			/* Try to flush results; exit if a write error occurs */
			return;
		}
	}

	if (vty->status == VTY_CLOSE)
		vty_close(vty);
	else if (vty->type != VTY_FILE)
		vty_event(VTYSH_READ, vty);
	else
		/* should we assert here? */
		zlog_err("mgmtd: unexpected resume while reading config file");
}

void vty_frame(struct vty *vty, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsnprintfrr(vty->frame + vty->frame_pos,
		    sizeof(vty->frame) - vty->frame_pos, format, args);
	vty->frame_pos = strlen(vty->frame);
	va_end(args);
}

void vty_endframe(struct vty *vty, const char *endtext)
{
	if (vty->frame_pos == 0 && endtext)
		vty_out(vty, "%s", endtext);
	vty->frame_pos = 0;
}

bool vty_set_include(struct vty *vty, const char *regexp)
{
	int errcode;
	bool ret = true;
	char errbuf[256];

	if (!regexp) {
		if (vty->filter) {
			regfree(&vty->include);
			vty->filter = false;
		}
		return true;
	}

	errcode = regcomp(&vty->include, regexp,
			  REG_EXTENDED | REG_NEWLINE | REG_NOSUB);
	if (errcode) {
		ret = false;
		regerror(errcode, &vty->include, errbuf, sizeof(errbuf));
		vty_out(vty, "%% Regex compilation error: %s\n", errbuf);
	} else {
		vty->filter = true;
	}

	return ret;
}

/* VTY standard output function. */
int vty_out(struct vty *vty, const char *format, ...)
{
	va_list args;
	ssize_t len;
	char buf[1024];
	char *p = NULL;
	char *filtered;
	/* format string may contain %m, keep errno intact for printfrr */
	int saved_errno = errno;

	if (vty->frame_pos) {
		vty->frame_pos = 0;
		vty_out(vty, "%s", vty->frame);
	}

	va_start(args, format);
	errno = saved_errno;
	p = vasnprintfrr(MTYPE_VTY_OUT_BUF, buf, sizeof(buf), format, args);
	va_end(args);

	len = strlen(p);

	/* filter buffer */
	if (vty->filter) {
		vector lines = frrstr_split_vec(p, "\n");

		/* Place first value in the cache */
		char *firstline = vector_slot(lines, 0);
		buffer_put(vty->lbuf, (uint8_t *) firstline, strlen(firstline));

		/* If our split returned more than one entry, time to filter */
		if (vector_active(lines) > 1) {
			/*
			 * returned string is MTYPE_TMP so it matches the MTYPE
			 * of everything else in the vector
			 */
			char *bstr = buffer_getstr(vty->lbuf);
			buffer_reset(vty->lbuf);
			XFREE(MTYPE_TMP, lines->index[0]);
			vector_set_index(lines, 0, bstr);
			frrstr_filter_vec(lines, &vty->include);
			vector_compact(lines);
			/*
			 * Consider the string "foo\n". If the regex is an empty string
			 * and the line ended with a newline, then the vector will look
			 * like:
			 *
			 * [0]: 'foo'
			 * [1]: ''
			 *
			 * If the regex isn't empty, the vector will look like:
			 *
			 * [0]: 'foo'
			 *
			 * In this case we'd like to preserve the newline, so we add
			 * the empty string [1] as in the first example.
			 */
			if (p[strlen(p) - 1] == '\n' && vector_active(lines) > 0
			    && strlen(vector_slot(lines, vector_active(lines) - 1)))
				vector_set(lines, XSTRDUP(MTYPE_TMP, ""));

			filtered = frrstr_join_vec(lines, "\n");
		}
		else {
			filtered = NULL;
		}

		frrstr_strvec_free(lines);

	} else {
		filtered = p;
	}

	if (!filtered)
		goto done;

	switch (vty->type) {
	case VTY_TERM:
		/* print with crlf replacement */
		buffer_put_crlf(vty->obuf, (uint8_t *)filtered,
				strlen(filtered));
		break;
	case VTY_SHELL:
		if (vty->of) {
			fprintf(vty->of, "%s", filtered);
			fflush(vty->of);
		} else if (vty->of_saved) {
			fprintf(vty->of_saved, "%s", filtered);
			fflush(vty->of_saved);
		}
		break;
	case VTY_SHELL_SERV:
	case VTY_FILE:
	default:
		/* print without crlf replacement */
		buffer_put(vty->obuf, (uint8_t *)filtered, strlen(filtered));
		break;
	}

done:

	if (vty->filter && filtered)
		XFREE(MTYPE_TMP, filtered);

	/* If p is not different with buf, it is allocated buffer.  */
	if (p != buf)
		XFREE(MTYPE_VTY_OUT_BUF, p);

	return len;
}

static int vty_json_helper(struct vty *vty, struct json_object *json,
			   uint32_t options)
{
	const char *text;

	if (!json)
		return CMD_SUCCESS;

	text = json_object_to_json_string_ext(
		json, options);
	vty_out(vty, "%s\n", text);
	json_object_free(json);

	return CMD_SUCCESS;
}

int vty_json(struct vty *vty, struct json_object *json)
{
	return vty_json_helper(vty, json,
			       JSON_C_TO_STRING_PRETTY |
				       JSON_C_TO_STRING_NOSLASHESCAPE);
}

int vty_json_no_pretty(struct vty *vty, struct json_object *json)
{
	return vty_json_helper(vty, json, JSON_C_TO_STRING_NOSLASHESCAPE);
}

void vty_json_empty(struct vty *vty, struct json_object *json)
{
	json_object *jsonobj = json;

	if (!json)
		jsonobj = json_object_new_object();

	vty_json(vty, jsonobj);
}

/* Output current time to the vty. */
void vty_time_print(struct vty *vty, int cr)
{
	char buf[FRR_TIMESTAMP_LEN];

	if (frr_timestamp(0, buf, sizeof(buf)) == 0) {
		zlog_info("frr_timestamp error");
		return;
	}
	if (cr)
		vty_out(vty, "%s\n", buf);
	else
		vty_out(vty, "%s ", buf);

	return;
}

/* Say hello to vty interface. */
void vty_hello(struct vty *vty)
{
	if (host.motdfile) {
		FILE *f;
		char buf[4096];

		f = fopen(host.motdfile, "r");
		if (f) {
			while (fgets(buf, sizeof(buf), f)) {
				char *s;
				/* work backwards to ignore trailling isspace()
				 */
				for (s = buf + strlen(buf);
				     (s > buf) && isspace((unsigned char)s[-1]);
				     s--)
					;
				*s = '\0';
				vty_out(vty, "%s\n", buf);
			}
			fclose(f);
		} else
			vty_out(vty, "MOTD file not found\n");
	} else if (host.motd)
		vty_out(vty, "%s", host.motd);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
/* prompt formatting has a %s in the cmd_node prompt string.
 *
 * Also for some reason GCC emits the warning on the end of the function
 * (optimization maybe?) rather than on the vty_out line, so this pragma
 * wraps the entire function rather than just the vty_out line.
 */

/* Put out prompt and wait input from user. */
static void vty_prompt(struct vty *vty)
{
	if (vty->type == VTY_TERM) {
		vty_out(vty, cmd_prompt(vty->node), cmd_hostname_get());
	}
}
#pragma GCC diagnostic pop

/* Send WILL TELOPT_ECHO to remote server. */
static void vty_will_echo(struct vty *vty)
{
	unsigned char cmd[] = {IAC, WILL, TELOPT_ECHO, '\0'};
	vty_out(vty, "%s", cmd);
}

/* Make suppress Go-Ahead telnet option. */
static void vty_will_suppress_go_ahead(struct vty *vty)
{
	unsigned char cmd[] = {IAC, WILL, TELOPT_SGA, '\0'};
	vty_out(vty, "%s", cmd);
}

/* Make don't use linemode over telnet. */
static void vty_dont_linemode(struct vty *vty)
{
	unsigned char cmd[] = {IAC, DONT, TELOPT_LINEMODE, '\0'};
	vty_out(vty, "%s", cmd);
}

/* Use window size. */
static void vty_do_window_size(struct vty *vty)
{
	unsigned char cmd[] = {IAC, DO, TELOPT_NAWS, '\0'};
	vty_out(vty, "%s", cmd);
}

/* Authentication of vty */
static void vty_auth(struct vty *vty, char *buf)
{
	char *passwd = NULL;
	enum node_type next_node = 0;
	int fail;

	switch (vty->node) {
	case AUTH_NODE:
		if (host.encrypt)
			passwd = host.password_encrypt;
		else
			passwd = host.password;
		if (host.advanced)
			next_node = host.enable ? VIEW_NODE : ENABLE_NODE;
		else
			next_node = VIEW_NODE;
		break;
	case AUTH_ENABLE_NODE:
		if (host.encrypt)
			passwd = host.enable_encrypt;
		else
			passwd = host.enable;
		next_node = ENABLE_NODE;
		break;
	}

	if (passwd) {
		if (host.encrypt)
			fail = strcmp(crypt(buf, passwd), passwd);
		else
			fail = strcmp(buf, passwd);
	} else
		fail = 1;

	if (!fail) {
		vty->fail = 0;
		vty->node = next_node; /* Success ! */
	} else {
		vty->fail++;
		if (vty->fail >= 3) {
			if (vty->node == AUTH_NODE) {
				vty_out(vty,
					"%% Bad passwords, too many failures!\n");
				vty->status = VTY_CLOSE;
			} else {
				/* AUTH_ENABLE_NODE */
				vty->fail = 0;
				vty_out(vty,
					"%% Bad enable passwords, too many failures!\n");
				vty->status = VTY_CLOSE;
			}
		}
	}
}

/* Command execution over the vty interface. */
static int vty_command(struct vty *vty, char *buf)
{
	int ret;
	const char *protocolname;
	char *cp = NULL;

	assert(vty);

	/*
	 * Log non empty command lines
	 */
	if (vty_log_commands &&
	    strncmp(buf, "echo PING", strlen("echo PING")) != 0)
		cp = buf;
	if (cp != NULL) {
		/* Skip white spaces. */
		while (isspace((unsigned char)*cp) && *cp != '\0')
			cp++;
	}
	if (cp != NULL && *cp != '\0') {
		char vty_str[VTY_BUFSIZ];
		char prompt_str[VTY_BUFSIZ];

		/* format the base vty info */
		snprintf(vty_str, sizeof(vty_str), "vty[%d]@%s", vty->fd,
			 vty->address);

		/* format the prompt */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
		/* prompt formatting has a %s in the cmd_node prompt string */
		snprintf(prompt_str, sizeof(prompt_str), cmd_prompt(vty->node),
			 vty_str);
#pragma GCC diagnostic pop

		/* now log the command */
		zlog_notice("%s%s", prompt_str, buf);
	}

	RUSAGE_T before;
	RUSAGE_T after;
	unsigned long walltime, cputime;

	/* cmd_execute() may change cputime_enabled if we're executing the
	 * "service cputime-stats" command, which can result in nonsensical
	 * and very confusing warnings
	 */
	bool cputime_enabled_here = cputime_enabled;

	GETRUSAGE(&before);

	ret = cmd_execute(vty, buf, NULL, 0);

	GETRUSAGE(&after);

	walltime = event_consumed_time(&after, &before, &cputime);

	if (cputime_enabled_here && cputime_enabled && cputime_threshold
	    && cputime > cputime_threshold)
		/* Warn about CPU hog that must be fixed. */
		flog_warn(EC_LIB_SLOW_THREAD_CPU,
			  "CPU HOG: command took %lums (cpu time %lums): %s",
			  walltime / 1000, cputime / 1000, buf);
	else if (walltime_threshold && walltime > walltime_threshold)
		flog_warn(EC_LIB_SLOW_THREAD_WALL,
			  "STARVATION: command took %lums (cpu time %lums): %s",
			  walltime / 1000, cputime / 1000, buf);

	/* Get the name of the protocol if any */
	protocolname = frr_protoname;

	if (ret != CMD_SUCCESS)
		switch (ret) {
		case CMD_WARNING:
			if (vty->type == VTY_FILE)
				vty_out(vty, "Warning...\n");
			break;
		case CMD_ERR_AMBIGUOUS:
			vty_out(vty, "%% Ambiguous command.\n");
			break;
		case CMD_ERR_NO_MATCH:
			vty_out(vty, "%% [%s] Unknown command: %s\n",
				protocolname, buf);
			break;
		case CMD_ERR_INCOMPLETE:
			vty_out(vty, "%% Command incomplete.\n");
			break;
		}

	return ret;
}

static const char telnet_backward_char = 0x08;
static const char telnet_space_char = ' ';

/* Basic function to write buffer to vty. */
static void vty_write(struct vty *vty, const char *buf, size_t nbytes)
{
	if ((vty->node == AUTH_NODE) || (vty->node == AUTH_ENABLE_NODE))
		return;

	/* Should we do buffering here ?  And make vty_flush (vty) ? */
	buffer_put(vty->obuf, buf, nbytes);
}

/* Basic function to insert character into vty. */
static void vty_self_insert(struct vty *vty, char c)
{
	int i;
	int length;

	if (vty->length + 1 >= VTY_BUFSIZ)
		return;

	length = vty->length - vty->cp;
	memmove(&vty->buf[vty->cp + 1], &vty->buf[vty->cp], length);
	vty->buf[vty->cp] = c;

	vty_write(vty, &vty->buf[vty->cp], length + 1);
	for (i = 0; i < length; i++)
		vty_write(vty, &telnet_backward_char, 1);

	vty->cp++;
	vty->length++;

	vty->buf[vty->length] = '\0';
}

/* Self insert character 'c' in overwrite mode. */
static void vty_self_insert_overwrite(struct vty *vty, char c)
{
	if (vty->cp == vty->length) {
		vty_self_insert(vty, c);
		return;
	}

	vty->buf[vty->cp++] = c;
	vty_write(vty, &c, 1);
}

/**
 * Insert a string into vty->buf at the current cursor position.
 *
 * If the resultant string would be larger than VTY_BUFSIZ it is
 * truncated to fit.
 */
static void vty_insert_word_overwrite(struct vty *vty, char *str)
{
	if (vty->cp == VTY_BUFSIZ)
		return;

	size_t nwrite = MIN((int)strlen(str), VTY_BUFSIZ - vty->cp - 1);
	memcpy(&vty->buf[vty->cp], str, nwrite);
	vty->cp += nwrite;
	vty->length = MAX(vty->cp, vty->length);
	vty->buf[vty->length] = '\0';
	vty_write(vty, str, nwrite);
}

/* Forward character. */
static void vty_forward_char(struct vty *vty)
{
	if (vty->cp < vty->length) {
		vty_write(vty, &vty->buf[vty->cp], 1);
		vty->cp++;
	}
}

/* Backward character. */
static void vty_backward_char(struct vty *vty)
{
	if (vty->cp > 0) {
		vty->cp--;
		vty_write(vty, &telnet_backward_char, 1);
	}
}

/* Move to the beginning of the line. */
static void vty_beginning_of_line(struct vty *vty)
{
	while (vty->cp)
		vty_backward_char(vty);
}

/* Move to the end of the line. */
static void vty_end_of_line(struct vty *vty)
{
	while (vty->cp < vty->length)
		vty_forward_char(vty);
}

static void vty_kill_line_from_beginning(struct vty *);
static void vty_redraw_line(struct vty *);

/* Print command line history.  This function is called from
   vty_next_line and vty_previous_line. */
static void vty_history_print(struct vty *vty)
{
	int length;

	vty_kill_line_from_beginning(vty);

	/* Get previous line from history buffer */
	length = strlen(vty->hist[vty->hp]);
	memcpy(vty->buf, vty->hist[vty->hp], length);
	vty->cp = vty->length = length;
	vty->buf[vty->length] = '\0';

	/* Redraw current line */
	vty_redraw_line(vty);
}

/* Show next command line history. */
static void vty_next_line(struct vty *vty)
{
	int try_index;

	if (vty->hp == vty->hindex)
		return;

	/* Try is there history exist or not. */
	try_index = vty->hp;
	if (try_index == (VTY_MAXHIST - 1))
		try_index = 0;
	else
		try_index++;

	/* If there is not history return. */
	if (vty->hist[try_index] == NULL)
		return;
	else
		vty->hp = try_index;

	vty_history_print(vty);
}

/* Show previous command line history. */
static void vty_previous_line(struct vty *vty)
{
	int try_index;

	try_index = vty->hp;
	if (try_index == 0)
		try_index = VTY_MAXHIST - 1;
	else
		try_index--;

	if (vty->hist[try_index] == NULL)
		return;
	else
		vty->hp = try_index;

	vty_history_print(vty);
}

/* This function redraw all of the command line character. */
static void vty_redraw_line(struct vty *vty)
{
	vty_write(vty, vty->buf, vty->length);
	vty->cp = vty->length;
}

/* Forward word. */
static void vty_forward_word(struct vty *vty)
{
	while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
		vty_forward_char(vty);

	while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
		vty_forward_char(vty);
}

/* Backward word without skipping training space. */
static void vty_backward_pure_word(struct vty *vty)
{
	while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
		vty_backward_char(vty);
}

/* Backward word. */
static void vty_backward_word(struct vty *vty)
{
	while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
		vty_backward_char(vty);

	while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
		vty_backward_char(vty);
}

/* When '^D' is typed at the beginning of the line we move to the down
   level. */
static void vty_down_level(struct vty *vty)
{
	vty_out(vty, "\n");
	cmd_exit(vty);
	vty_prompt(vty);
	vty->cp = 0;
}

/* When '^Z' is received from vty, move down to the enable mode. */
static void vty_end_config(struct vty *vty)
{
	vty_out(vty, "\n");

	if (vty->config) {
		vty_config_exit(vty);
		vty->node = ENABLE_NODE;
	}

	vty_prompt(vty);
	vty->cp = 0;
}

/* Delete a character at the current point. */
static void vty_delete_char(struct vty *vty)
{
	int i;
	int size;

	if (vty->length == 0) {
		vty_down_level(vty);
		return;
	}

	if (vty->cp == vty->length)
		return; /* completion need here? */

	size = vty->length - vty->cp;

	vty->length--;
	memmove(&vty->buf[vty->cp], &vty->buf[vty->cp + 1], size - 1);
	vty->buf[vty->length] = '\0';

	if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
		return;

	vty_write(vty, &vty->buf[vty->cp], size - 1);
	vty_write(vty, &telnet_space_char, 1);

	for (i = 0; i < size; i++)
		vty_write(vty, &telnet_backward_char, 1);
}

/* Delete a character before the point. */
static void vty_delete_backward_char(struct vty *vty)
{
	if (vty->cp == 0)
		return;

	vty_backward_char(vty);
	vty_delete_char(vty);
}

/* Kill rest of line from current point. */
static void vty_kill_line(struct vty *vty)
{
	int i;
	int size;

	size = vty->length - vty->cp;

	if (size == 0)
		return;

	for (i = 0; i < size; i++)
		vty_write(vty, &telnet_space_char, 1);
	for (i = 0; i < size; i++)
		vty_write(vty, &telnet_backward_char, 1);

	memset(&vty->buf[vty->cp], 0, size);
	vty->length = vty->cp;
}

/* Kill line from the beginning. */
static void vty_kill_line_from_beginning(struct vty *vty)
{
	vty_beginning_of_line(vty);
	vty_kill_line(vty);
}

/* Delete a word before the point. */
static void vty_forward_kill_word(struct vty *vty)
{
	while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
		vty_delete_char(vty);
	while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
		vty_delete_char(vty);
}

/* Delete a word before the point. */
static void vty_backward_kill_word(struct vty *vty)
{
	while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
		vty_delete_backward_char(vty);
	while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
		vty_delete_backward_char(vty);
}

/* Transpose chars before or at the point. */
static void vty_transpose_chars(struct vty *vty)
{
	char c1, c2;

	/* If length is short or point is near by the beginning of line then
	   return. */
	if (vty->length < 2 || vty->cp < 1)
		return;

	/* In case of point is located at the end of the line. */
	if (vty->cp == vty->length) {
		c1 = vty->buf[vty->cp - 1];
		c2 = vty->buf[vty->cp - 2];

		vty_backward_char(vty);
		vty_backward_char(vty);
		vty_self_insert_overwrite(vty, c1);
		vty_self_insert_overwrite(vty, c2);
	} else {
		c1 = vty->buf[vty->cp];
		c2 = vty->buf[vty->cp - 1];

		vty_backward_char(vty);
		vty_self_insert_overwrite(vty, c1);
		vty_self_insert_overwrite(vty, c2);
	}
}

/* Do completion at vty interface. */
static void vty_complete_command(struct vty *vty)
{
	int i;
	int ret;
	char **matched = NULL;
	vector vline;

	if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
		return;

	vline = cmd_make_strvec(vty->buf);
	if (vline == NULL)
		return;

	/* In case of 'help \t'. */
	if (isspace((unsigned char)vty->buf[vty->length - 1]))
		vector_set(vline, NULL);

	matched = cmd_complete_command(vline, vty, &ret);

	cmd_free_strvec(vline);

	vty_out(vty, "\n");
	switch (ret) {
	case CMD_ERR_AMBIGUOUS:
		vty_out(vty, "%% Ambiguous command.\n");
		vty_prompt(vty);
		vty_redraw_line(vty);
		break;
	case CMD_ERR_NO_MATCH:
		/* vty_out (vty, "%% There is no matched command.\n"); */
		vty_prompt(vty);
		vty_redraw_line(vty);
		break;
	case CMD_COMPLETE_FULL_MATCH:
		if (!matched[0]) {
			/* 2016-11-28 equinox -- need to debug, SEGV here */
			vty_out(vty, "%% CLI BUG: FULL_MATCH with NULL str\n");
			vty_prompt(vty);
			vty_redraw_line(vty);
			break;
		}
		vty_prompt(vty);
		vty_redraw_line(vty);
		vty_backward_pure_word(vty);
		vty_insert_word_overwrite(vty, matched[0]);
		vty_self_insert(vty, ' ');
		XFREE(MTYPE_COMPLETION, matched[0]);
		break;
	case CMD_COMPLETE_MATCH:
		vty_prompt(vty);
		vty_redraw_line(vty);
		vty_backward_pure_word(vty);
		vty_insert_word_overwrite(vty, matched[0]);
		XFREE(MTYPE_COMPLETION, matched[0]);
		break;
	case CMD_COMPLETE_LIST_MATCH:
		for (i = 0; matched[i] != NULL; i++) {
			if (i != 0 && ((i % 6) == 0))
				vty_out(vty, "\n");
			vty_out(vty, "%-10s ", matched[i]);
			XFREE(MTYPE_COMPLETION, matched[i]);
		}
		vty_out(vty, "\n");

		vty_prompt(vty);
		vty_redraw_line(vty);
		break;
	case CMD_ERR_NOTHING_TODO:
		vty_prompt(vty);
		vty_redraw_line(vty);
		break;
	default:
		break;
	}
	XFREE(MTYPE_TMP, matched);
}

static void vty_describe_fold(struct vty *vty, int cmd_width,
			      unsigned int desc_width, struct cmd_token *token)
{
	char *buf;
	const char *cmd, *p;
	int pos;

	cmd = token->text;

	if (desc_width <= 0) {
		vty_out(vty, "  %-*s  %s\n", cmd_width, cmd, token->desc);
		return;
	}

	buf = XCALLOC(MTYPE_TMP, strlen(token->desc) + 1);

	for (p = token->desc; strlen(p) > desc_width; p += pos + 1) {
		for (pos = desc_width; pos > 0; pos--)
			if (*(p + pos) == ' ')
				break;

		if (pos == 0)
			break;

		memcpy(buf, p, pos);
		buf[pos] = '\0';
		vty_out(vty, "  %-*s  %s\n", cmd_width, cmd, buf);

		cmd = "";
	}

	vty_out(vty, "  %-*s  %s\n", cmd_width, cmd, p);

	XFREE(MTYPE_TMP, buf);
}

/* Describe matched command function. */
static void vty_describe_command(struct vty *vty)
{
	int ret;
	vector vline;
	vector describe;
	unsigned int i, width, desc_width;
	struct cmd_token *token, *token_cr = NULL;

	vline = cmd_make_strvec(vty->buf);

	/* In case of '> ?'. */
	if (vline == NULL) {
		vline = vector_init(1);
		vector_set(vline, NULL);
	} else if (isspace((unsigned char)vty->buf[vty->length - 1]))
		vector_set(vline, NULL);

	describe = cmd_describe_command(vline, vty, &ret);

	vty_out(vty, "\n");

	/* Ambiguous error. */
	switch (ret) {
	case CMD_ERR_AMBIGUOUS:
		vty_out(vty, "%% Ambiguous command.\n");
		goto out;
		break;
	case CMD_ERR_NO_MATCH:
		vty_out(vty, "%% There is no matched command.\n");
		goto out;
		break;
	}

	/* Get width of command string. */
	width = 0;
	for (i = 0; i < vector_active(describe); i++)
		if ((token = vector_slot(describe, i)) != NULL) {
			unsigned int len;

			if (token->text[0] == '\0')
				continue;

			len = strlen(token->text);

			if (width < len)
				width = len;
		}

	/* Get width of description string. */
	desc_width = vty->width - (width + 6);

	/* Print out description. */
	for (i = 0; i < vector_active(describe); i++)
		if ((token = vector_slot(describe, i)) != NULL) {
			if (token->text[0] == '\0')
				continue;

			if (strcmp(token->text, CMD_CR_TEXT) == 0) {
				token_cr = token;
				continue;
			}

			if (!token->desc)
				vty_out(vty, "  %-s\n", token->text);
			else if (desc_width >= strlen(token->desc))
				vty_out(vty, "  %-*s  %s\n", width, token->text,
					token->desc);
			else
				vty_describe_fold(vty, width, desc_width,
						  token);

			if (IS_VARYING_TOKEN(token->type)) {
				const char *ref = vector_slot(
					vline, vector_active(vline) - 1);

				vector varcomps = vector_init(VECTOR_MIN_SIZE);
				cmd_variable_complete(token, ref, varcomps);

				if (vector_active(varcomps) > 0) {
					char *ac = cmd_variable_comp2str(
						varcomps, vty->width);
					vty_out(vty, "%s\n", ac);
					XFREE(MTYPE_TMP, ac);
				}

				vector_free(varcomps);
			}
		}

	if ((token = token_cr)) {
		if (!token->desc)
			vty_out(vty, "  %-s\n", token->text);
		else if (desc_width >= strlen(token->desc))
			vty_out(vty, "  %-*s  %s\n", width, token->text,
				token->desc);
		else
			vty_describe_fold(vty, width, desc_width, token);
	}

out:
	cmd_free_strvec(vline);
	if (describe)
		vector_free(describe);

	vty_prompt(vty);
	vty_redraw_line(vty);
}

static void vty_clear_buf(struct vty *vty)
{
	memset(vty->buf, 0, vty->max);
}

/* ^C stop current input and do not add command line to the history. */
static void vty_stop_input(struct vty *vty)
{
	vty->cp = vty->length = 0;
	vty_clear_buf(vty);
	vty_out(vty, "\n");

	if (vty->config) {
		vty_config_exit(vty);
		vty->node = ENABLE_NODE;
	}

	vty_prompt(vty);

	/* Set history pointer to the latest one. */
	vty->hp = vty->hindex;
}

/* Add current command line to the history buffer. */
static void vty_hist_add(struct vty *vty)
{
	int index;

	if (vty->length == 0)
		return;

	index = vty->hindex ? vty->hindex - 1 : VTY_MAXHIST - 1;

	/* Ignore the same string as previous one. */
	if (vty->hist[index])
		if (strcmp(vty->buf, vty->hist[index]) == 0) {
			vty->hp = vty->hindex;
			return;
		}

	/* Insert history entry. */
	XFREE(MTYPE_VTY_HIST, vty->hist[vty->hindex]);
	vty->hist[vty->hindex] = XSTRDUP(MTYPE_VTY_HIST, vty->buf);

	/* History index rotation. */
	vty->hindex++;
	if (vty->hindex == VTY_MAXHIST)
		vty->hindex = 0;

	vty->hp = vty->hindex;
}

/* #define TELNET_OPTION_DEBUG */

/* Get telnet window size. */
static int vty_telnet_option(struct vty *vty, unsigned char *buf, int nbytes)
{
#ifdef TELNET_OPTION_DEBUG
	int i;

	for (i = 0; i < nbytes; i++) {
		switch (buf[i]) {
		case IAC:
			vty_out(vty, "IAC ");
			break;
		case WILL:
			vty_out(vty, "WILL ");
			break;
		case WONT:
			vty_out(vty, "WONT ");
			break;
		case DO:
			vty_out(vty, "DO ");
			break;
		case DONT:
			vty_out(vty, "DONT ");
			break;
		case SB:
			vty_out(vty, "SB ");
			break;
		case SE:
			vty_out(vty, "SE ");
			break;
		case TELOPT_ECHO:
			vty_out(vty, "TELOPT_ECHO \n");
			break;
		case TELOPT_SGA:
			vty_out(vty, "TELOPT_SGA \n");
			break;
		case TELOPT_NAWS:
			vty_out(vty, "TELOPT_NAWS \n");
			break;
		default:
			vty_out(vty, "%x ", buf[i]);
			break;
		}
	}
	vty_out(vty, "\n");

#endif /* TELNET_OPTION_DEBUG */

	switch (buf[0]) {
	case SB:
		vty->sb_len = 0;
		vty->iac_sb_in_progress = 1;
		return 0;
	case SE: {
		if (!vty->iac_sb_in_progress)
			return 0;

		if ((vty->sb_len == 0) || (vty->sb_buf[0] == '\0')) {
			vty->iac_sb_in_progress = 0;
			return 0;
		}
		switch (vty->sb_buf[0]) {
		case TELOPT_NAWS:
			if (vty->sb_len != TELNET_NAWS_SB_LEN)
				flog_err(
					EC_LIB_SYSTEM_CALL,
					"RFC 1073 violation detected: telnet NAWS option should send %d characters, but we received %lu",
					TELNET_NAWS_SB_LEN,
					(unsigned long)vty->sb_len);
			else if (sizeof(vty->sb_buf) < TELNET_NAWS_SB_LEN)
				flog_err(
					EC_LIB_DEVELOPMENT,
					"Bug detected: sizeof(vty->sb_buf) %lu < %d, too small to handle the telnet NAWS option",
					(unsigned long)sizeof(vty->sb_buf),
					TELNET_NAWS_SB_LEN);
			else {
				vty->width = ((vty->sb_buf[1] << 8)
					      | vty->sb_buf[2]);
				vty->height = ((vty->sb_buf[3] << 8)
					       | vty->sb_buf[4]);
#ifdef TELNET_OPTION_DEBUG
				vty_out(vty,
					"TELNET NAWS window size negotiation completed: width %d, height %d\n",
					vty->width, vty->height);
#endif
			}
			break;
		}
		vty->iac_sb_in_progress = 0;
		return 0;
	}
	default:
		break;
	}
	return 1;
}

/* Execute current command line. */
static int vty_execute(struct vty *vty)
{
	int ret;

	ret = CMD_SUCCESS;

	switch (vty->node) {
	case AUTH_NODE:
	case AUTH_ENABLE_NODE:
		vty_auth(vty, vty->buf);
		break;
	default:
		ret = vty_command(vty, vty->buf);
		if (vty->type == VTY_TERM)
			vty_hist_add(vty);
		break;
	}

	/* Clear command line buffer. */
	vty->cp = vty->length = 0;
	vty_clear_buf(vty);

	if (vty->status != VTY_CLOSE)
		vty_prompt(vty);

	return ret;
}

#define CONTROL(X)  ((X) - '@')
#define VTY_NORMAL     0
#define VTY_PRE_ESCAPE 1
#define VTY_ESCAPE     2
#define VTY_CR         3

/* Escape character command map. */
static void vty_escape_map(unsigned char c, struct vty *vty)
{
	switch (c) {
	case ('A'):
		vty_previous_line(vty);
		break;
	case ('B'):
		vty_next_line(vty);
		break;
	case ('C'):
		vty_forward_char(vty);
		break;
	case ('D'):
		vty_backward_char(vty);
		break;
	default:
		break;
	}

	/* Go back to normal mode. */
	vty->escape = VTY_NORMAL;
}

/* Quit print out to the buffer. */
static void vty_buffer_reset(struct vty *vty)
{
	buffer_reset(vty->obuf);
	buffer_reset(vty->lbuf);
	vty_prompt(vty);
	vty_redraw_line(vty);
}

/* Read data via vty socket. */
static void vty_read(struct event *thread)
{
	int i;
	int nbytes;
	unsigned char buf[VTY_READ_BUFSIZ];

	struct vty *vty = EVENT_ARG(thread);

	/* Read raw data from socket */
	if ((nbytes = read(vty->fd, buf, VTY_READ_BUFSIZ)) <= 0) {
		if (nbytes < 0) {
			if (ERRNO_IO_RETRY(errno)) {
				vty_event(VTY_READ, vty);
				return;
			}
			flog_err(
				EC_LIB_SOCKET,
				"%s: read error on vty client fd %d, closing: %s",
				__func__, vty->fd, safe_strerror(errno));
			buffer_reset(vty->obuf);
			buffer_reset(vty->lbuf);
		}
		vty->status = VTY_CLOSE;
	}

	for (i = 0; i < nbytes; i++) {
		if (buf[i] == IAC) {
			if (!vty->iac) {
				vty->iac = 1;
				continue;
			} else {
				vty->iac = 0;
			}
		}

		if (vty->iac_sb_in_progress && !vty->iac) {
			if (vty->sb_len < sizeof(vty->sb_buf))
				vty->sb_buf[vty->sb_len] = buf[i];
			vty->sb_len++;
			continue;
		}

		if (vty->iac) {
			/* In case of telnet command */
			int ret = 0;
			ret = vty_telnet_option(vty, buf + i, nbytes - i);
			vty->iac = 0;
			i += ret;
			continue;
		}


		if (vty->status == VTY_MORE) {
			switch (buf[i]) {
			case CONTROL('C'):
			case 'q':
			case 'Q':
				vty_buffer_reset(vty);
				break;
			default:
				break;
			}
			continue;
		}

		/* Escape character. */
		if (vty->escape == VTY_ESCAPE) {
			vty_escape_map(buf[i], vty);
			continue;
		}

		/* Pre-escape status. */
		if (vty->escape == VTY_PRE_ESCAPE) {
			switch (buf[i]) {
			case '[':
				vty->escape = VTY_ESCAPE;
				break;
			case 'b':
				vty_backward_word(vty);
				vty->escape = VTY_NORMAL;
				break;
			case 'f':
				vty_forward_word(vty);
				vty->escape = VTY_NORMAL;
				break;
			case 'd':
				vty_forward_kill_word(vty);
				vty->escape = VTY_NORMAL;
				break;
			case CONTROL('H'):
			case 0x7f:
				vty_backward_kill_word(vty);
				vty->escape = VTY_NORMAL;
				break;
			default:
				vty->escape = VTY_NORMAL;
				break;
			}
			continue;
		}

		if (vty->escape == VTY_CR) {
			/* if we get CR+NL, the NL results in an extra empty
			 * prompt line being printed without this;  just drop
			 * the NL if it immediately follows CR.
			 */
			vty->escape = VTY_NORMAL;

			if (buf[i] == '\n')
				continue;
		}

		switch (buf[i]) {
		case CONTROL('A'):
			vty_beginning_of_line(vty);
			break;
		case CONTROL('B'):
			vty_backward_char(vty);
			break;
		case CONTROL('C'):
			vty_stop_input(vty);
			break;
		case CONTROL('D'):
			vty_delete_char(vty);
			break;
		case CONTROL('E'):
			vty_end_of_line(vty);
			break;
		case CONTROL('F'):
			vty_forward_char(vty);
			break;
		case CONTROL('H'):
		case 0x7f:
			vty_delete_backward_char(vty);
			break;
		case CONTROL('K'):
			vty_kill_line(vty);
			break;
		case CONTROL('N'):
			vty_next_line(vty);
			break;
		case CONTROL('P'):
			vty_previous_line(vty);
			break;
		case CONTROL('T'):
			vty_transpose_chars(vty);
			break;
		case CONTROL('U'):
			vty_kill_line_from_beginning(vty);
			break;
		case CONTROL('W'):
			vty_backward_kill_word(vty);
			break;
		case CONTROL('Z'):
			vty_end_config(vty);
			break;
		case '\r':
			vty->escape = VTY_CR;
			fallthrough;
		case '\n':
			vty_out(vty, "\n");
			buffer_flush_available(vty->obuf, vty->wfd);
			vty_execute(vty);

			if (vty->pass_fd != -1) {
				close(vty->pass_fd);
				vty->pass_fd = -1;
			}
			break;
		case '\t':
			vty_complete_command(vty);
			break;
		case '?':
			if (vty->node == AUTH_NODE
			    || vty->node == AUTH_ENABLE_NODE)
				vty_self_insert(vty, buf[i]);
			else
				vty_describe_command(vty);
			break;
		case '\033':
			if (i + 1 < nbytes && buf[i + 1] == '[') {
				vty->escape = VTY_ESCAPE;
				i++;
			} else
				vty->escape = VTY_PRE_ESCAPE;
			break;
		default:
			if (buf[i] > 31 && buf[i] < 127)
				vty_self_insert(vty, buf[i]);
			break;
		}
	}

	/* Check status. */
	if (vty->status == VTY_CLOSE)
		vty_close(vty);
	else {
		vty_event(VTY_WRITE, vty);
		vty_event(VTY_READ, vty);
	}
}

/* Flush buffer to the vty. */
static void vty_flush(struct event *thread)
{
	int erase;
	buffer_status_t flushrc;
	struct vty *vty = EVENT_ARG(thread);

	/* Tempolary disable read thread. */
	if (vty->lines == 0)
		EVENT_OFF(vty->t_read);

	/* Function execution continue. */
	erase = ((vty->status == VTY_MORE || vty->status == VTY_MORELINE));

	/* N.B. if width is 0, that means we don't know the window size. */
	if ((vty->lines == 0) || (vty->width == 0) || (vty->height == 0))
		flushrc = buffer_flush_available(vty->obuf, vty->wfd);
	else if (vty->status == VTY_MORELINE)
		flushrc = buffer_flush_window(vty->obuf, vty->wfd, vty->width,
					      1, erase, 0);
	else
		flushrc = buffer_flush_window(
			vty->obuf, vty->wfd, vty->width,
			vty->lines >= 0 ? vty->lines : vty->height, erase, 0);
	switch (flushrc) {
	case BUFFER_ERROR:
		zlog_info("buffer_flush failed on vty client fd %d/%d, closing",
			  vty->fd, vty->wfd);
		buffer_reset(vty->lbuf);
		buffer_reset(vty->obuf);
		vty_close(vty);
		return;
	case BUFFER_EMPTY:
		if (vty->status == VTY_CLOSE)
			vty_close(vty);
		else {
			vty->status = VTY_NORMAL;
			if (vty->lines == 0)
				vty_event(VTY_READ, vty);
		}
		break;
	case BUFFER_PENDING:
		/* There is more data waiting to be written. */
		vty->status = VTY_MORE;
		if (vty->lines == 0)
			vty_event(VTY_WRITE, vty);
		break;
	}
}

/* Allocate new vty struct. */
struct vty *vty_new(void)
{
	struct vty *new = XCALLOC(MTYPE_VTY, sizeof(struct vty));

	new->fd = new->wfd = -1;
	new->of = stdout;
	new->lbuf = buffer_new(0);
	new->obuf = buffer_new(0); /* Use default buffer size. */
	new->buf = XCALLOC(MTYPE_VTY, VTY_BUFSIZ);
	new->max = VTY_BUFSIZ;
	new->pass_fd = -1;

	if (mgmt_fe_client) {
		if (!mgmt_client_id_next)
			mgmt_client_id_next++;
		new->mgmt_client_id = mgmt_client_id_next++;
		new->mgmt_session_id = 0;
		mgmt_fe_create_client_session(
			mgmt_fe_client, new->mgmt_client_id, (uintptr_t) new);
		/* we short-circuit create the session so it must be set now */
		assertf(new->mgmt_session_id != 0,
			"Failed to create client session for VTY");
	}

	return new;
}


/* allocate and initialise vty */
static struct vty *vty_new_init(int vty_sock)
{
	struct vty *vty;

	vty = vty_new();
	vty->fd = vty_sock;
	vty->wfd = vty_sock;
	vty->type = VTY_TERM;
	vty->node = AUTH_NODE;
	vty->fail = 0;
	vty->cp = 0;
	vty_clear_buf(vty);
	vty->length = 0;
	memset(vty->hist, 0, sizeof(vty->hist));
	vty->hp = 0;
	vty->hindex = 0;
	vty->xpath_index = 0;
	memset(vty->xpath, 0, sizeof(vty->xpath));
	vty->private_config = false;
	vty->candidate_config = vty_shared_candidate_config;
	vty->status = VTY_NORMAL;
	vty->lines = -1;
	vty->iac = 0;
	vty->iac_sb_in_progress = 0;
	vty->sb_len = 0;

	vtys_add_tail(vty_sessions, vty);

	return vty;
}

/* Create new vty structure. */
static struct vty *vty_create(int vty_sock, union sockunion *su)
{
	char buf[SU_ADDRSTRLEN];
	struct vty *vty;

	sockunion2str(su, buf, SU_ADDRSTRLEN);

	/* Allocate new vty structure and set up default values. */
	vty = vty_new_init(vty_sock);

	/* configurable parameters not part of basic init */
	vty->v_timeout = vty_timeout_val;
	strlcpy(vty->address, buf, sizeof(vty->address));
	if (no_password_check) {
		if (host.advanced)
			vty->node = ENABLE_NODE;
		else
			vty->node = VIEW_NODE;
	}
	if (host.lines >= 0)
		vty->lines = host.lines;

	if (!no_password_check) {
		/* Vty is not available if password isn't set. */
		if (host.password == NULL && host.password_encrypt == NULL) {
			vty_out(vty, "Vty password is not set.\n");
			vty->status = VTY_CLOSE;
			vty_close(vty);
			return NULL;
		}
	}

	/* Say hello to the world. */
	vty_hello(vty);
	if (!no_password_check)
		vty_out(vty, "\nUser Access Verification\n\n");

	/* Setting up terminal. */
	vty_will_echo(vty);
	vty_will_suppress_go_ahead(vty);

	vty_dont_linemode(vty);
	vty_do_window_size(vty);
	/* vty_dont_lflow_ahead (vty); */

	vty_prompt(vty);

	/* Add read/write thread. */
	vty_event(VTY_WRITE, vty);
	vty_event(VTY_READ, vty);

	return vty;
}

/* create vty for stdio */
static struct termios stdio_orig_termios;
static struct vty *stdio_vty = NULL;
static bool stdio_termios = false;
static void (*stdio_vty_atclose)(int isexit);

static void vty_stdio_reset(int isexit)
{
	if (stdio_vty) {
		if (stdio_termios)
			tcsetattr(0, TCSANOW, &stdio_orig_termios);
		stdio_termios = false;

		stdio_vty = NULL;

		if (stdio_vty_atclose)
			stdio_vty_atclose(isexit);
		stdio_vty_atclose = NULL;
	}
}

static void vty_stdio_atexit(void)
{
	vty_stdio_reset(1);
}

void vty_stdio_suspend(void)
{
	if (!stdio_vty)
		return;

	EVENT_OFF(stdio_vty->t_write);
	EVENT_OFF(stdio_vty->t_read);
	EVENT_OFF(stdio_vty->t_timeout);

	if (stdio_termios)
		tcsetattr(0, TCSANOW, &stdio_orig_termios);
	stdio_termios = false;
}

void vty_stdio_resume(void)
{
	if (!stdio_vty)
		return;

	if (!tcgetattr(0, &stdio_orig_termios)) {
		struct termios termios;

		termios = stdio_orig_termios;
		termios.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR
				     | IGNCR | ICRNL | IXON);
		termios.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN);
		termios.c_cflag &= ~(CSIZE | PARENB);
		termios.c_cflag |= CS8;
		tcsetattr(0, TCSANOW, &termios);
		stdio_termios = true;
	}

	vty_prompt(stdio_vty);

	/* Add read/write thread. */
	vty_event(VTY_WRITE, stdio_vty);
	vty_event(VTY_READ, stdio_vty);
}

void vty_stdio_close(void)
{
	if (!stdio_vty)
		return;
	vty_close(stdio_vty);
}

struct vty *vty_stdio(void (*atclose)(int isexit))
{
	struct vty *vty;

	/* refuse creating two vtys on stdio */
	if (stdio_vty)
		return NULL;

	vty = stdio_vty = vty_new_init(0);
	stdio_vty_atclose = atclose;
	vty->wfd = 1;

	/* always have stdio vty in a known _unchangeable_ state, don't want
	 * config
	 * to have any effect here to make sure scripting this works as intended
	 */
	vty->node = ENABLE_NODE;
	vty->v_timeout = 0;
	strlcpy(vty->address, "console", sizeof(vty->address));

	vty_stdio_resume();
	return vty;
}

/* Accept connection from the network. */
static void vty_accept(struct event *thread)
{
	struct vty_serv *vtyserv = EVENT_ARG(thread);
	int vty_sock;
	union sockunion su;
	int ret;
	unsigned int on;
	int accept_sock = vtyserv->sock;
	struct prefix p;
	struct access_list *acl = NULL;

	/* We continue hearing vty socket. */
	vty_event_serv(VTY_SERV, vtyserv);

	memset(&su, 0, sizeof(union sockunion));

	/* We can handle IPv4 or IPv6 socket. */
	vty_sock = sockunion_accept(accept_sock, &su);
	if (vty_sock < 0) {
		flog_err(EC_LIB_SOCKET, "can't accept vty socket : %s",
			 safe_strerror(errno));
		return;
	}
	set_nonblocking(vty_sock);
	set_cloexec(vty_sock);

	if (!sockunion2hostprefix(&su, &p)) {
		close(vty_sock);
		zlog_info("Vty unable to convert prefix from sockunion %pSU",
			  &su);
		return;
	}

	/* VTY's accesslist apply. */
	if (p.family == AF_INET && vty_accesslist_name) {
		if ((acl = access_list_lookup(AFI_IP, vty_accesslist_name))
		    && (access_list_apply(acl, &p) == FILTER_DENY)) {
			zlog_info("Vty connection refused from %pSU", &su);
			close(vty_sock);
			return;
		}
	}

	/* VTY's ipv6 accesslist apply. */
	if (p.family == AF_INET6 && vty_ipv6_accesslist_name) {
		if ((acl = access_list_lookup(AFI_IP6,
					      vty_ipv6_accesslist_name))
		    && (access_list_apply(acl, &p) == FILTER_DENY)) {
			zlog_info("Vty connection refused from %pSU", &su);
			close(vty_sock);
			return;
		}
	}

	on = 1;
	ret = setsockopt(vty_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&on,
			 sizeof(on));
	if (ret < 0)
		zlog_info("can't set sockopt to vty_sock : %s",
			  safe_strerror(errno));

	zlog_info("Vty connection from %pSU", &su);

	vty_create(vty_sock, &su);
}

static void vty_serv_sock_addrinfo(const char *hostname, unsigned short port)
{
	int ret;
	struct addrinfo req;
	struct addrinfo *ainfo;
	struct addrinfo *ainfo_save;
	int sock;
	char port_str[BUFSIZ];

	memset(&req, 0, sizeof(req));
	req.ai_flags = AI_PASSIVE;
	req.ai_family = AF_UNSPEC;
	req.ai_socktype = SOCK_STREAM;
	snprintf(port_str, sizeof(port_str), "%d", port);
	port_str[sizeof(port_str) - 1] = '\0';

	ret = getaddrinfo(hostname, port_str, &req, &ainfo);

	if (ret != 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL, "getaddrinfo failed: %s",
			     gai_strerror(ret));
		exit(1);
	}

	ainfo_save = ainfo;

	do {
		struct vty_serv *vtyserv;

		if (ainfo->ai_family != AF_INET && ainfo->ai_family != AF_INET6)
			continue;

		sock = socket(ainfo->ai_family, ainfo->ai_socktype,
			      ainfo->ai_protocol);
		if (sock < 0)
			continue;

		sockopt_v6only(ainfo->ai_family, sock);
		sockopt_reuseaddr(sock);
		sockopt_reuseport(sock);
		set_cloexec(sock);

		ret = bind(sock, ainfo->ai_addr, ainfo->ai_addrlen);
		if (ret < 0) {
			close(sock); /* Avoid sd leak. */
			continue;
		}

		ret = listen(sock, 3);
		if (ret < 0) {
			close(sock); /* Avoid sd leak. */
			continue;
		}

		vtyserv = XCALLOC(MTYPE_VTY_SERV, sizeof(*vtyserv));
		vtyserv->sock = sock;
		vtyservs_add_tail(vty_servs, vtyserv);

		vty_event_serv(VTY_SERV, vtyserv);
	} while ((ainfo = ainfo->ai_next) != NULL);

	freeaddrinfo(ainfo_save);
}

#ifdef VTYSH
/* For sockaddr_un. */
#include <sys/un.h>

/* VTY shell UNIX domain socket. */
static void vty_serv_un(const char *path)
{
	struct vty_serv *vtyserv;
	int ret;
	int sock, len;
	struct sockaddr_un serv;
	mode_t old_mask;
	struct zprivs_ids_t ids;

	/* First of all, unlink existing socket */
	unlink(path);

	/* Set umask */
	old_mask = umask(0007);

	/* Make UNIX domain socket. */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "Cannot create unix stream socket: %s",
			     safe_strerror(errno));
		return;
	}

	/* Make server socket. */
	memset(&serv, 0, sizeof(serv));
	serv.sun_family = AF_UNIX;
	strlcpy(serv.sun_path, path, sizeof(serv.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = serv.sun_len = SUN_LEN(&serv);
#else
	len = sizeof(serv.sun_family) + strlen(serv.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	set_cloexec(sock);

	ret = bind(sock, (struct sockaddr *)&serv, len);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET, "Cannot bind path %s: %s", path,
			     safe_strerror(errno));
		close(sock); /* Avoid sd leak. */
		return;
	}

	ret = listen(sock, 5);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET, "listen(fd %d) failed: %s", sock,
			     safe_strerror(errno));
		close(sock); /* Avoid sd leak. */
		return;
	}

	umask(old_mask);

	zprivs_get_ids(&ids);

	/* Hack: ids.gid_vty is actually a uint, but we stored -1 in it
	   earlier for the case when we don't need to chown the file
	   type casting it here to make a compare */
	if ((int)ids.gid_vty > 0) {
		/* set group of socket */
		if (chown(path, -1, ids.gid_vty)) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "vty_serv_un: could chown socket, %s",
				     safe_strerror(errno));
		}
	}

	vtyserv = XCALLOC(MTYPE_VTY_SERV, sizeof(*vtyserv));
	vtyserv->sock = sock;
	vtyserv->vtysh = true;
	vtyservs_add_tail(vty_servs, vtyserv);

	vty_event_serv(VTYSH_SERV, vtyserv);
}

/* #define VTYSH_DEBUG 1 */

static void vtysh_accept(struct event *thread)
{
	struct vty_serv *vtyserv = EVENT_ARG(thread);
	int accept_sock = vtyserv->sock;
	int sock;
	int client_len;
	struct sockaddr_un client;
	struct vty *vty;

	vty_event_serv(VTYSH_SERV, vtyserv);

	memset(&client, 0, sizeof(client));
	client_len = sizeof(struct sockaddr_un);

	sock = accept(accept_sock, (struct sockaddr *)&client,
		      (socklen_t *)&client_len);

	if (sock < 0) {
		flog_err(EC_LIB_SOCKET, "can't accept vty socket : %s",
			 safe_strerror(errno));
		return;
	}

	if (set_nonblocking(sock) < 0) {
		flog_err(
			EC_LIB_SOCKET,
			"vtysh_accept: could not set vty socket %d to non-blocking, %s, closing",
			sock, safe_strerror(errno));
		close(sock);
		return;
	}
	set_cloexec(sock);

#ifdef VTYSH_DEBUG
	printf("VTY shell accept\n");
#endif /* VTYSH_DEBUG */

	vty = vty_new();
	vty->fd = sock;
	vty->wfd = sock;
	vty->type = VTY_SHELL_SERV;
	vty->node = VIEW_NODE;
	vtys_add_tail(vtysh_sessions, vty);

	vty_event(VTYSH_READ, vty);
}

static int vtysh_do_pass_fd(struct vty *vty)
{
	struct iovec iov[1] = {
		{
			.iov_base = vty->pass_fd_status,
			.iov_len = sizeof(vty->pass_fd_status),
		},
	};
	union {
		uint8_t buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct msghdr mh = {
		.msg_iov = iov,
		.msg_iovlen = array_size(iov),
		.msg_control = u.buf,
		.msg_controllen = sizeof(u.buf),
	};
	struct cmsghdr *cmh = CMSG_FIRSTHDR(&mh);
	ssize_t ret;

	memset(&u.buf, 0, sizeof(u.buf));
	cmh->cmsg_level = SOL_SOCKET;
	cmh->cmsg_type = SCM_RIGHTS;
	cmh->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmh), &vty->pass_fd, sizeof(int));

	ret = sendmsg(vty->wfd, &mh, 0);
	if (ret < 0 && ERRNO_IO_RETRY(errno))
		return BUFFER_PENDING;

	close(vty->pass_fd);
	vty->pass_fd = -1;
	vty->status = VTY_NORMAL;

	if (ret <= 0)
		return BUFFER_ERROR;

	/* resume accepting commands (suspended in vtysh_read) */
	vty_event(VTYSH_READ, vty);

	if ((size_t)ret < sizeof(vty->pass_fd_status)) {
		size_t remains = sizeof(vty->pass_fd_status) - ret;

		buffer_put(vty->obuf, vty->pass_fd_status + ret, remains);
		return BUFFER_PENDING;
	}
	return BUFFER_EMPTY;
}

static int vtysh_flush(struct vty *vty)
{
	int ret;

	ret = buffer_flush_available(vty->obuf, vty->wfd);
	if (ret == BUFFER_EMPTY && vty->status == VTY_PASSFD)
		ret = vtysh_do_pass_fd(vty);

	switch (ret) {
	case BUFFER_PENDING:
		vty_event(VTYSH_WRITE, vty);
		break;
	case BUFFER_ERROR:
		flog_err(EC_LIB_SOCKET, "%s: write error to fd %d, closing",
			 __func__, vty->fd);
		buffer_reset(vty->lbuf);
		buffer_reset(vty->obuf);
		vty_close(vty);
		return -1;
	case BUFFER_EMPTY:
		break;
	}
	return 0;
}

void vty_pass_fd(struct vty *vty, int fd)
{
	if (vty->pass_fd != -1)
		close(vty->pass_fd);

	vty->pass_fd = fd;
}

bool mgmt_vty_read_configs(void)
{
	char path[PATH_MAX];
	struct vty *vty;
	FILE *confp;
	uint line_num = 0;
	uint count = 0;
	uint index;

	vty = vty_new();
	vty->wfd = STDERR_FILENO;
	vty->type = VTY_FILE;
	vty->node = CONFIG_NODE;
	vty->config = true;
	vty->pending_allowed = true;

	vty->candidate_config = vty_shared_candidate_config;

	vty_mgmt_lock_candidate_inline(vty);
	vty_mgmt_lock_running_inline(vty);

	for (index = 0; index < array_size(mgmt_daemons); index++) {
		snprintf(path, sizeof(path), "%s/%s.conf", frr_sysconfdir,
			 mgmt_daemons[index]);

		confp = vty_open_config(path, config_default);
		if (!confp)
			continue;

		zlog_info("mgmtd: reading config file: %s", path);

		/* Execute configuration file */
		line_num = 0;
		(void)config_from_file(vty, confp, &line_num);
		count++;

		fclose(confp);
	}

	snprintf(path, sizeof(path), "%s/mgmtd.conf", frr_sysconfdir);
	confp = vty_open_config(path, config_default);
	if (!confp) {
		char *orig;

		snprintf(path, sizeof(path), "%s/zebra.conf", frr_sysconfdir);
		orig = XSTRDUP(MTYPE_TMP, host_config_get());

		zlog_info("mgmtd: trying backup config file: %s", path);
		confp = vty_open_config(path, config_default);

		host_config_set(path);
		XFREE(MTYPE_TMP, orig);
	}

	if (confp) {
		zlog_info("mgmtd: reading config file: %s", path);

		line_num = 0;
		(void)config_from_file(vty, confp, &line_num);
		count++;

		fclose(confp);
	}

	/* Conditionally unlock as the config file may have "exit"d early which
	 * would then have unlocked things.
	 */
	if (vty->mgmt_locked_running_ds)
		vty_mgmt_unlock_running_inline(vty);
	if (vty->mgmt_locked_candidate_ds)
		vty_mgmt_unlock_candidate_inline(vty);

	vty->pending_allowed = false;

	if (!count)
		vty_close(vty);
	else
		vty_read_file_finish(vty, NULL);

	zlog_info("mgmtd: finished reading config files");

	return true;
}

static void vtysh_read(struct event *thread)
{
	int ret;
	int sock;
	int nbytes;
	struct vty *vty;
	unsigned char buf[VTY_READ_BUFSIZ];
	unsigned char *p;
	uint8_t header[4] = {0, 0, 0, 0};

	sock = EVENT_FD(thread);
	vty = EVENT_ARG(thread);

	/*
	 * This code looks like it can read multiple commands from the `buf`
	 * value returned by read(); however, it cannot in some cases.
	 *
	 * There are multiple paths out of the "copying to vty->buf" loop, which
	 * lose any content not yet copied from the stack `buf`, `passfd`,
	 * `CMD_SUSPEND` and finally if a front-end for mgmtd (generally this
	 * would be mgmtd itself). So these code paths are counting on vtysh not
	 * sending us more than 1 command line before waiting on the reply to
	 * that command.
	 */
	assert(vty->type == VTY_SHELL_SERV);

	if ((nbytes = read(sock, buf, VTY_READ_BUFSIZ)) <= 0) {
		if (nbytes < 0) {
			if (ERRNO_IO_RETRY(errno)) {
				vty_event(VTYSH_READ, vty);
				return;
			}
			flog_err(
				EC_LIB_SOCKET,
				"%s: read failed on vtysh client fd %d, closing: %s",
				__func__, sock, safe_strerror(errno));
		}
		buffer_reset(vty->lbuf);
		buffer_reset(vty->obuf);
		vty_close(vty);
#ifdef VTYSH_DEBUG
		printf("close vtysh\n");
#endif /* VTYSH_DEBUG */
		return;
	}

#ifdef VTYSH_DEBUG
	printf("line: %.*s\n", nbytes, buf);
#endif /* VTYSH_DEBUG */

	if (vty->length + nbytes >= VTY_BUFSIZ) {
		/* Clear command line buffer. */
		vty->cp = vty->length = 0;
		vty_clear_buf(vty);
		vty_out(vty, "%% Command is too long.\n");
	} else {
		for (p = buf; p < buf + nbytes; p++) {
			vty->buf[vty->length++] = *p;
			if (*p == '\0') {
				/* Pass this line to parser. */
				ret = vty_execute(vty);
/* Note that vty_execute clears the command buffer and resets
   vty->length to 0. */

/* Return result. */
#ifdef VTYSH_DEBUG
				printf("result: %d\n", ret);
				printf("vtysh node: %d\n", vty->node);
#endif /* VTYSH_DEBUG */
				if (vty->pass_fd >= 0) {
					memset(vty->pass_fd_status, 0, 4);
					vty->pass_fd_status[3] = ret;
					vty->status = VTY_PASSFD;

					if (!vty->t_write)
						vty_event(VTYSH_WRITE, vty);

					/* this introduces a "sequence point"
					 * command output is written normally,
					 * read processing is suspended until
					 * buffer is empty
					 * then retcode + FD is written
					 * then normal processing resumes
					 *
					 * => skip vty_event(VTYSH_READ, vty)!
					 */
					return;
				} else {
					assertf(vty->status != VTY_PASSFD,
						"%p address=%s passfd=%d", vty,
						vty->address, vty->pass_fd);

					/* normalize other invalid values */
					vty->pass_fd = -1;
				}

				/* hack for asynchronous "write integrated"
				 * - other commands in "buf" will be ditched
				 * - input during pending config-write is
				 * "unsupported" */
				if (ret == CMD_SUSPEND)
					break;

				/* with new infra we need to stop response till
				 * we get response through callback.
				 */
				if (vty->mgmt_req_pending_cmd) {
					MGMTD_FE_CLIENT_DBG(
						"postpone CLI response pending mgmtd %s on vty session-id %" PRIu64,
						vty->mgmt_req_pending_cmd,
						vty->mgmt_session_id);
					return;
				}

				/* warning: watchfrr hardcodes this result write
				 */
				header[3] = ret;
				buffer_put(vty->obuf, header, 4);

				if (!vty->t_write && (vtysh_flush(vty) < 0))
					/* Try to flush results; exit if a write
					 * error occurs. */
					return;
			}
		}
	}

	if (vty->status == VTY_CLOSE)
		vty_close(vty);
	else
		vty_event(VTYSH_READ, vty);
}

static void vtysh_write(struct event *thread)
{
	struct vty *vty = EVENT_ARG(thread);

	vtysh_flush(vty);
}

#endif /* VTYSH */

/* Determine address family to bind. */
void vty_serv_start(const char *addr, unsigned short port, const char *path)
{
	/* If port is set to 0, do not listen on TCP/IP at all! */
	if (port)
		vty_serv_sock_addrinfo(addr, port);

#ifdef VTYSH
	vty_serv_un(path);
#endif /* VTYSH */
}

void vty_serv_stop(void)
{
	struct vty_serv *vtyserv;

	while ((vtyserv = vtyservs_pop(vty_servs))) {
		EVENT_OFF(vtyserv->t_accept);
		close(vtyserv->sock);
		XFREE(MTYPE_VTY_SERV, vtyserv);
	}

	vtyservs_fini(vty_servs);
	vtyservs_init(vty_servs);
}

static void vty_error_delete(void *arg)
{
	struct vty_error *ve = arg;

	XFREE(MTYPE_TMP, ve);
}

/* Close vty interface.  Warning: call this only from functions that
   will be careful not to access the vty afterwards (since it has
   now been freed).  This is safest from top-level functions (called
   directly by the thread dispatcher). */
void vty_close(struct vty *vty)
{
	int i;
	bool was_stdio = false;

	vty->status = VTY_CLOSE;

	/*
	 * If we reach here with pending config to commit we will be losing it
	 * so warn the user.
	 */
	if (vty->mgmt_num_pending_setcfg)
		MGMTD_FE_CLIENT_ERR(
			"vty closed, uncommitted config will be lost.");

	/* Drop out of configure / transaction if needed. */
	vty_config_exit(vty);

	if (mgmt_fe_client && vty->mgmt_session_id) {
		MGMTD_FE_CLIENT_DBG("closing vty session");
		mgmt_fe_destroy_client_session(mgmt_fe_client,
					       vty->mgmt_client_id);
		vty->mgmt_session_id = 0;
	}

	/* Cancel threads.*/
	EVENT_OFF(vty->t_read);
	EVENT_OFF(vty->t_write);
	EVENT_OFF(vty->t_timeout);

	if (vty->pass_fd != -1) {
		close(vty->pass_fd);
		vty->pass_fd = -1;
	}
	zlog_live_close(&vty->live_log);

	/* Flush buffer. */
	buffer_flush_all(vty->obuf, vty->wfd);

	/* Free input buffer. */
	buffer_free(vty->obuf);
	buffer_free(vty->lbuf);

	/* Free command history. */
	for (i = 0; i < VTY_MAXHIST; i++) {
		XFREE(MTYPE_VTY_HIST, vty->hist[i]);
	}

	/* Unset vector. */
	if (vty->fd != -1) {
		if (vty->type == VTY_SHELL_SERV)
			vtys_del(vtysh_sessions, vty);
		else if (vty->type == VTY_TERM)
			vtys_del(vty_sessions, vty);
	}

	if (vty->wfd > 0 && vty->type == VTY_FILE)
		fsync(vty->wfd);

	/* Close socket.
	 * note check is for fd > STDERR_FILENO, not fd != -1.
	 * We never close stdin/stdout/stderr here, because we may be
	 * running in foreground mode with logging to stdout.  Also,
	 * additionally, we'd need to replace these fds with /dev/null. */
	if (vty->wfd > STDERR_FILENO && vty->wfd != vty->fd)
		close(vty->wfd);
	if (vty->fd > STDERR_FILENO)
		close(vty->fd);
	if (vty->fd == STDIN_FILENO)
		was_stdio = true;

	XFREE(MTYPE_TMP, vty->pending_cmds_buf);
	XFREE(MTYPE_VTY, vty->buf);

	if (vty->error) {
		vty->error->del = vty_error_delete;
		list_delete(&vty->error);
	}

	/* OK free vty. */
	XFREE(MTYPE_VTY, vty);

	if (was_stdio)
		vty_stdio_reset(0);
}

/* When time out occur output message then close connection. */
static void vty_timeout(struct event *thread)
{
	struct vty *vty;

	vty = EVENT_ARG(thread);
	vty->v_timeout = 0;

	/* Clear buffer*/
	buffer_reset(vty->lbuf);
	buffer_reset(vty->obuf);
	vty_out(vty, "\nVty connection is timed out.\n");

	/* Close connection. */
	vty->status = VTY_CLOSE;
	vty_close(vty);
}

/* Read up configuration file from file_name. */
void vty_read_file(struct nb_config *config, FILE *confp)
{
	struct vty *vty;
	unsigned int line_num = 0;

	vty = vty_new();
	/* vty_close won't close stderr;  if some config command prints
	 * something it'll end up there.  (not ideal; it'd be better if output
	 * from a file-load went to logging instead.  Also note that if this
	 * function is called after daemonizing, stderr will be /dev/null.)
	 *
	 * vty->fd will be -1 from vty_new()
	 */
	vty->wfd = STDERR_FILENO;
	vty->type = VTY_FILE;
	vty->node = CONFIG_NODE;
	vty->config = true;
	if (config)
		vty->candidate_config = config;
	else {
		vty->private_config = true;
		vty->candidate_config = nb_config_new(NULL);
	}

	/* Execute configuration file */
	(void)config_from_file(vty, confp, &line_num);

	vty_read_file_finish(vty, config);
}

void vty_read_file_finish(struct vty *vty, struct nb_config *config)
{
	struct vty_error *ve;
	struct listnode *node;

	/* Flush any previous errors before printing messages below */
	buffer_flush_all(vty->obuf, vty->wfd);

	for (ALL_LIST_ELEMENTS_RO(vty->error, node, ve)) {
		const char *message = NULL;
		char *nl;

		switch (ve->cmd_ret) {
		case CMD_SUCCESS:
			message = "Command succeeded";
			break;
		case CMD_ERR_NOTHING_TODO:
			message = "Nothing to do";
			break;
		case CMD_ERR_AMBIGUOUS:
			message = "Ambiguous command";
			break;
		case CMD_ERR_NO_MATCH:
			message = "No such command";
			break;
		case CMD_WARNING:
			message = "Command returned Warning";
			break;
		case CMD_WARNING_CONFIG_FAILED:
			message = "Command returned Warning Config Failed";
			break;
		case CMD_ERR_INCOMPLETE:
			message = "Command returned Incomplete";
			break;
		case CMD_ERR_EXEED_ARGC_MAX:
			message =
				"Command exceeded maximum number of Arguments";
			break;
		default:
			message = "Command returned unhandled error message";
			break;
		}

		nl = strchr(ve->error_buf, '\n');
		if (nl)
			*nl = '\0';
		flog_err(EC_LIB_VTY, "%s on config line %u: %s", message,
			 ve->line_num, ve->error_buf);
	}

	/*
	 * Automatically commit the candidate configuration after
	 * reading the configuration file.
	 */
	if (config == NULL) {
		struct nb_context context = {};
		char errmsg[BUFSIZ] = {0};
		int ret;

		context.client = NB_CLIENT_CLI;
		context.user = vty;
		ret = nb_candidate_commit(context, vty->candidate_config, true,
					  "Read configuration file", NULL,
					  errmsg, sizeof(errmsg));
		if (ret != NB_OK && ret != NB_ERR_NO_CHANGES)
			zlog_err(
				"%s: failed to read configuration file: %s (%s)",
				__func__, nb_err_name(ret), errmsg);
	}

	vty_close(vty);
}

static FILE *vty_use_backup_config(const char *fullpath)
{
	char *fullpath_sav, *fullpath_tmp;
	FILE *ret = NULL;
	int tmp, sav;
	int c;
	char buffer[512];

	size_t fullpath_sav_sz = strlen(fullpath) + strlen(CONF_BACKUP_EXT) + 1;
	fullpath_sav = malloc(fullpath_sav_sz);
	strlcpy(fullpath_sav, fullpath, fullpath_sav_sz);
	strlcat(fullpath_sav, CONF_BACKUP_EXT, fullpath_sav_sz);

	sav = open(fullpath_sav, O_RDONLY);
	if (sav < 0) {
		free(fullpath_sav);
		return NULL;
	}

	fullpath_tmp = malloc(strlen(fullpath) + 8);
	snprintf(fullpath_tmp, strlen(fullpath) + 8, "%s.XXXXXX", fullpath);

	/* Open file to configuration write. */
	tmp = mkstemp(fullpath_tmp);
	if (tmp < 0)
		goto out_close_sav;

	if (fchmod(tmp, CONFIGFILE_MASK) != 0)
		goto out_close;

	while ((c = read(sav, buffer, 512)) > 0) {
		if (write(tmp, buffer, c) <= 0)
			goto out_close;
	}
	close(sav);
	close(tmp);

	if (rename(fullpath_tmp, fullpath) == 0)
		ret = fopen(fullpath, "r");
	else
		unlink(fullpath_tmp);

	if (0) {
	out_close:
		close(tmp);
		unlink(fullpath_tmp);
	out_close_sav:
		close(sav);
	}

	free(fullpath_sav);
	free(fullpath_tmp);
	return ret;
}

FILE *vty_open_config(const char *config_file, char *config_default_dir)
{
	char cwd[MAXPATHLEN];
	FILE *confp = NULL;
	const char *fullpath;
	char *tmp = NULL;

	/* If -f flag specified. */
	if (config_file != NULL) {
		if (!IS_DIRECTORY_SEP(config_file[0])) {
			if (getcwd(cwd, MAXPATHLEN) == NULL) {
				flog_err_sys(
					EC_LIB_SYSTEM_CALL,
					"%s: failure to determine Current Working Directory %d!",
					__func__, errno);
				goto tmp_free_and_out;
			}
			size_t tmp_len = strlen(cwd) + strlen(config_file) + 2;
			tmp = XMALLOC(MTYPE_TMP, tmp_len);
			snprintf(tmp, tmp_len, "%s/%s", cwd, config_file);
			fullpath = tmp;
		} else
			fullpath = config_file;

		confp = fopen(fullpath, "r");

		if (confp == NULL) {
			flog_warn(
				EC_LIB_BACKUP_CONFIG,
				"%s: failed to open configuration file %s: %s, checking backup",
				__func__, fullpath, safe_strerror(errno));

			confp = vty_use_backup_config(fullpath);
			if (confp)
				flog_warn(EC_LIB_BACKUP_CONFIG,
					  "using backup configuration file!");
			else {
				flog_err(
					EC_LIB_VTY,
					"%s: can't open configuration file [%s]",
					__func__, config_file);
				goto tmp_free_and_out;
			}
		}
	} else {

		host_config_set(config_default_dir);

#ifdef VTYSH
		int ret;
		struct stat conf_stat;

		/* !!!!PLEASE LEAVE!!!!
		 * This is NEEDED for use with vtysh -b, or else you can get
		 * a real configuration food fight with a lot garbage in the
		 * merged configuration file it creates coming from the per
		 * daemon configuration files.  This also allows the daemons
		 * to start if there default configuration file is not
		 * present or ignore them, as needed when using vtysh -b to
		 * configure the daemons at boot - MAG
		 */

		/* Stat for vtysh Zebra.conf, if found startup and wait for
		 * boot configuration
		 */

		if (strstr(config_default_dir, "vtysh") == NULL) {
			ret = stat(integrate_default, &conf_stat);
			if (ret >= 0)
				goto tmp_free_and_out;
		}
#endif /* VTYSH */
		confp = fopen(config_default_dir, "r");
		if (confp == NULL) {
			flog_err(
				EC_LIB_SYSTEM_CALL,
				"%s: failed to open configuration file %s: %s, checking backup",
				__func__, config_default_dir,
				safe_strerror(errno));

			confp = vty_use_backup_config(config_default_dir);
			if (confp) {
				flog_warn(EC_LIB_BACKUP_CONFIG,
					  "using backup configuration file!");
				fullpath = config_default_dir;
			} else {
				flog_err(EC_LIB_VTY,
					 "can't open configuration file [%s]",
					 config_default_dir);
				goto tmp_free_and_out;
			}
		} else
			fullpath = config_default_dir;
	}

	host_config_set(fullpath);

tmp_free_and_out:
	XFREE(MTYPE_TMP, tmp);

	return confp;
}


bool vty_read_config(struct nb_config *config, const char *config_file,
		     char *config_default_dir)
{
	FILE *confp;

	confp = vty_open_config(config_file, config_default_dir);
	if (!confp)
		return false;

	vty_read_file(config, confp);

	fclose(confp);

	return true;
}

int vty_config_enter(struct vty *vty, bool private_config, bool exclusive,
		     bool file_lock)
{
	if (exclusive && !vty_mgmt_fe_enabled() &&
	    nb_running_lock(NB_CLIENT_CLI, vty)) {
		vty_out(vty, "%% Configuration is locked by other client\n");
		return CMD_WARNING;
	}

	/*
	 * We only need to do a lock when reading a config file as we will be
	 * sending a batch of setcfg changes followed by a single commit
	 * message. For user interactive mode we are doing implicit commits
	 * those will obtain the lock (or not) when they try and commit.
	 */
	if (file_lock && vty_mgmt_fe_enabled() && !private_config) {
		if (vty_mgmt_lock_candidate_inline(vty)) {
			vty_out(vty,
				"%% Can't enter config; candidate datastore locked by another session\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (vty_mgmt_lock_running_inline(vty)) {
			vty_out(vty,
				"%% Can't enter config; running datastore locked by another session\n");
			vty_mgmt_unlock_candidate_inline(vty);
			return CMD_WARNING_CONFIG_FAILED;
		}
		assert(vty->mgmt_locked_candidate_ds);
		assert(vty->mgmt_locked_running_ds);

		/*
		 * As datastores are locked explicitly, we don't need implicit
		 * commits and should allow pending changes.
		 */
		vty->pending_allowed = true;
	}

	vty->node = CONFIG_NODE;
	vty->config = true;
	vty->private_config = private_config;
	vty->xpath_index = 0;

	if (private_config) {
		vty->candidate_config = nb_config_dup(running_config);
		vty->candidate_config_base = nb_config_dup(running_config);
		vty_out(vty,
			"Warning: uncommitted changes will be discarded on exit.\n\n");
		return CMD_SUCCESS;
	}

	/*
	 * NOTE: On the MGMTD daemon we point the VTY candidate DS to
	 * the global MGMTD candidate DS. Else we point to the VTY
	 * Shared Candidate Config.
	 */
	vty->candidate_config = vty_mgmt_candidate_config
					? vty_mgmt_candidate_config
					: vty_shared_candidate_config;
	if (frr_get_cli_mode() == FRR_CLI_TRANSACTIONAL)
		vty->candidate_config_base = nb_config_dup(running_config);

	return CMD_SUCCESS;
}


void vty_config_exit(struct vty *vty)
{
	enum node_type node = vty->node;
	struct cmd_node *cnode;

	/* unlock and jump up to ENABLE_NODE if -and only if- we're
	 * somewhere below CONFIG_NODE */
	while (node && node != CONFIG_NODE) {
		cnode = vector_lookup(cmdvec, node);
		node = cnode->parent_node;
	}
	if (node != CONFIG_NODE)
		/* called outside config, e.g. vty_close() in ENABLE_NODE */
		return;

	while (vty->node != ENABLE_NODE)
		/* will call vty_config_node_exit() below */
		cmd_exit(vty);
}

int vty_config_node_exit(struct vty *vty)
{
	vty->xpath_index = 0;

	/* TODO: could we check for un-commited changes here? */

	vty->pending_allowed = false;

	if (vty->mgmt_locked_running_ds)
		vty_mgmt_unlock_running_inline(vty);

	if (vty->mgmt_locked_candidate_ds)
		vty_mgmt_unlock_candidate_inline(vty);

	/* Perform any pending commits. */
	(void)nb_cli_pending_commit_check(vty);

	/* Check if there's a pending confirmed commit. */
	if (vty->t_confirmed_commit_timeout) {
		vty_out(vty,
			"exiting with a pending confirmed commit. Rolling back to previous configuration.\n\n");
		nb_cli_confirmed_commit_rollback(vty);
		nb_cli_confirmed_commit_clean(vty);
	}

	(void)nb_running_unlock(NB_CLIENT_CLI, vty);

	if (vty->candidate_config) {
		if (vty->private_config)
			nb_config_free(vty->candidate_config);
		vty->candidate_config = NULL;
	}
	if (vty->candidate_config_base) {
		nb_config_free(vty->candidate_config_base);
		vty->candidate_config_base = NULL;
	}

	vty->config = false;

	/*
	 * If this is a config file and we are dropping out of config end
	 * parsing.
	 */
	if (vty->type == VTY_FILE && vty->status != VTY_CLOSE) {
		vty_out(vty, "exit from config node while reading config file");
		vty->status = VTY_CLOSE;
	}

	return 1;
}

/* Master of the threads. */
static struct event_loop *vty_master;

static void vty_event_serv(enum vty_event event, struct vty_serv *vty_serv)
{
	switch (event) {
	case VTY_SERV:
		event_add_read(vty_master, vty_accept, vty_serv, vty_serv->sock,
			       &vty_serv->t_accept);
		break;
#ifdef VTYSH
	case VTYSH_SERV:
		event_add_read(vty_master, vtysh_accept, vty_serv,
			       vty_serv->sock, &vty_serv->t_accept);
		break;
#endif /* VTYSH */
	case VTY_READ:
	case VTY_WRITE:
	case VTY_TIMEOUT_RESET:
	case VTYSH_READ:
	case VTYSH_WRITE:
		assert(!"vty_event_serv() called incorrectly");
	}
}

static void vty_event(enum vty_event event, struct vty *vty)
{
	switch (event) {
#ifdef VTYSH
	case VTYSH_READ:
		event_add_read(vty_master, vtysh_read, vty, vty->fd,
			       &vty->t_read);
		break;
	case VTYSH_WRITE:
		event_add_write(vty_master, vtysh_write, vty, vty->wfd,
				&vty->t_write);
		break;
#endif /* VTYSH */
	case VTY_READ:
		event_add_read(vty_master, vty_read, vty, vty->fd,
			       &vty->t_read);

		/* Time out treatment. */
		if (vty->v_timeout) {
			EVENT_OFF(vty->t_timeout);
			event_add_timer(vty_master, vty_timeout, vty,
					vty->v_timeout, &vty->t_timeout);
		}
		break;
	case VTY_WRITE:
		event_add_write(vty_master, vty_flush, vty, vty->wfd,
				&vty->t_write);
		break;
	case VTY_TIMEOUT_RESET:
		EVENT_OFF(vty->t_timeout);
		if (vty->v_timeout)
			event_add_timer(vty_master, vty_timeout, vty,
					vty->v_timeout, &vty->t_timeout);
		break;
	case VTY_SERV:
	case VTYSH_SERV:
		assert(!"vty_event() called incorrectly");
	}
}

DEFUN_NOSH (config_who,
       config_who_cmd,
       "who",
       "Display who is on vty\n")
{
	struct vty *v;

	frr_each (vtys, vty_sessions, v)
		vty_out(vty, "%svty[%d] connected from %s%s.\n",
			v->config ? "*" : " ", v->fd, v->address,
			zlog_live_is_null(&v->live_log) ? "" : ", live log");
	return CMD_SUCCESS;
}

/* Move to vty configuration mode. */
DEFUN_NOSH (line_vty,
       line_vty_cmd,
       "line vty",
       "Configure a terminal line\n"
       "Virtual terminal\n")
{
	vty->node = VTY_NODE;
	return CMD_SUCCESS;
}

/* Set time out value. */
static int exec_timeout(struct vty *vty, const char *min_str,
			const char *sec_str)
{
	unsigned long timeout = 0;

	/* min_str and sec_str are already checked by parser.  So it must be
	   all digit string. */
	if (min_str) {
		timeout = strtol(min_str, NULL, 10);
		timeout *= 60;
	}
	if (sec_str)
		timeout += strtol(sec_str, NULL, 10);

	vty_timeout_val = timeout;
	vty->v_timeout = timeout;
	vty_event(VTY_TIMEOUT_RESET, vty);


	return CMD_SUCCESS;
}

DEFUN (exec_timeout_min,
       exec_timeout_min_cmd,
       "exec-timeout (0-35791)",
       "Set timeout value\n"
       "Timeout value in minutes\n")
{
	int idx_number = 1;
	return exec_timeout(vty, argv[idx_number]->arg, NULL);
}

DEFUN (exec_timeout_sec,
       exec_timeout_sec_cmd,
       "exec-timeout (0-35791) (0-2147483)",
       "Set the EXEC timeout\n"
       "Timeout in minutes\n"
       "Timeout in seconds\n")
{
	int idx_number = 1;
	int idx_number_2 = 2;
	return exec_timeout(vty, argv[idx_number]->arg,
			    argv[idx_number_2]->arg);
}

DEFUN (no_exec_timeout,
       no_exec_timeout_cmd,
       "no exec-timeout",
       NO_STR
       "Set the EXEC timeout\n")
{
	return exec_timeout(vty, NULL, NULL);
}

/* Set vty access class. */
DEFUN (vty_access_class,
       vty_access_class_cmd,
       "access-class WORD",
       "Filter connections based on an IP access list\n"
       "IP access list\n")
{
	int idx_word = 1;
	if (vty_accesslist_name)
		XFREE(MTYPE_VTY, vty_accesslist_name);

	vty_accesslist_name = XSTRDUP(MTYPE_VTY, argv[idx_word]->arg);

	return CMD_SUCCESS;
}

/* Clear vty access class. */
DEFUN (no_vty_access_class,
       no_vty_access_class_cmd,
       "no access-class [WORD]",
       NO_STR
       "Filter connections based on an IP access list\n"
       "IP access list\n")
{
	int idx_word = 2;
	const char *accesslist = (argc == 3) ? argv[idx_word]->arg : NULL;
	if (!vty_accesslist_name
	    || (argc == 3 && strcmp(vty_accesslist_name, accesslist))) {
		vty_out(vty, "Access-class is not currently applied to vty\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	XFREE(MTYPE_VTY, vty_accesslist_name);

	vty_accesslist_name = NULL;

	return CMD_SUCCESS;
}

/* Set vty access class. */
DEFUN (vty_ipv6_access_class,
       vty_ipv6_access_class_cmd,
       "ipv6 access-class WORD",
       IPV6_STR
       "Filter connections based on an IP access list\n"
       "IPv6 access list\n")
{
	int idx_word = 2;
	if (vty_ipv6_accesslist_name)
		XFREE(MTYPE_VTY, vty_ipv6_accesslist_name);

	vty_ipv6_accesslist_name = XSTRDUP(MTYPE_VTY, argv[idx_word]->arg);

	return CMD_SUCCESS;
}

/* Clear vty access class. */
DEFUN (no_vty_ipv6_access_class,
       no_vty_ipv6_access_class_cmd,
       "no ipv6 access-class [WORD]",
       NO_STR
       IPV6_STR
       "Filter connections based on an IP access list\n"
       "IPv6 access list\n")
{
	int idx_word = 3;
	const char *accesslist = (argc == 4) ? argv[idx_word]->arg : NULL;

	if (!vty_ipv6_accesslist_name
	    || (argc == 4 && strcmp(vty_ipv6_accesslist_name, accesslist))) {
		vty_out(vty,
			"IPv6 access-class is not currently applied to vty\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	XFREE(MTYPE_VTY, vty_ipv6_accesslist_name);

	vty_ipv6_accesslist_name = NULL;

	return CMD_SUCCESS;
}

/* vty login. */
DEFUN (vty_login,
       vty_login_cmd,
       "login",
       "Enable password checking\n")
{
	no_password_check = 0;
	return CMD_SUCCESS;
}

DEFUN (no_vty_login,
       no_vty_login_cmd,
       "no login",
       NO_STR
       "Enable password checking\n")
{
	no_password_check = 1;
	return CMD_SUCCESS;
}

DEFUN (service_advanced_vty,
       service_advanced_vty_cmd,
       "service advanced-vty",
       "Set up miscellaneous service\n"
       "Enable advanced mode vty interface\n")
{
	host.advanced = 1;
	return CMD_SUCCESS;
}

DEFUN (no_service_advanced_vty,
       no_service_advanced_vty_cmd,
       "no service advanced-vty",
       NO_STR
       "Set up miscellaneous service\n"
       "Enable advanced mode vty interface\n")
{
	host.advanced = 0;
	return CMD_SUCCESS;
}

DEFUN_NOSH(terminal_monitor,
	   terminal_monitor_cmd,
	   "terminal monitor [detach]",
	   "Set terminal line parameters\n"
	   "Copy debug output to the current terminal line\n"
	   "Keep logging feed open independent of VTY session\n")
{
	int fd_ret = -1;

	if (vty->type != VTY_SHELL_SERV) {
		vty_out(vty, "%% not supported\n");
		return CMD_WARNING;
	}

	if (argc == 3) {
		struct zlog_live_cfg detach_log = {};

		zlog_live_open(&detach_log, LOG_DEBUG, &fd_ret);
		zlog_live_disown(&detach_log);
	} else
		zlog_live_open(&vty->live_log, LOG_DEBUG, &fd_ret);

	if (fd_ret == -1) {
		vty_out(vty, "%% error opening live log: %m\n");
		return CMD_WARNING;
	}

	vty_pass_fd(vty, fd_ret);
	return CMD_SUCCESS;
}

DEFUN_NOSH(no_terminal_monitor,
	   no_terminal_monitor_cmd,
	   "no terminal monitor",
	   NO_STR
	   "Set terminal line parameters\n"
	   "Copy debug output to the current terminal line\n")
{
	zlog_live_close(&vty->live_log);
	return CMD_SUCCESS;
}

DEFUN_NOSH(terminal_no_monitor,
	   terminal_no_monitor_cmd,
	   "terminal no monitor",
	   "Set terminal line parameters\n"
	   NO_STR
	   "Copy debug output to the current terminal line\n")
{
	return no_terminal_monitor(self, vty, argc, argv);
}


DEFUN_NOSH (show_history,
       show_history_cmd,
       "show history",
       SHOW_STR
       "Display the session command history\n")
{
	int index;

	for (index = vty->hindex + 1; index != vty->hindex;) {
		if (index == VTY_MAXHIST) {
			index = 0;
			continue;
		}

		if (vty->hist[index] != NULL)
			vty_out(vty, "  %s\n", vty->hist[index]);

		index++;
	}

	return CMD_SUCCESS;
}

/* vty login. */
DEFPY (log_commands,
       log_commands_cmd,
       "[no] log commands",
       NO_STR
       "Logging control\n"
       "Log all commands\n")
{
	if (no) {
		if (vty_log_commands_perm) {
			vty_out(vty,
				"Daemon started with permanent logging turned on for commands, ignoring\n");
			return CMD_WARNING;
		}

		vty_log_commands = false;
	} else
		vty_log_commands = true;

	return CMD_SUCCESS;
}

/* Display current configuration. */
static int vty_config_write(struct vty *vty)
{
	vty_frame(vty, "line vty\n");

	if (vty_accesslist_name)
		vty_out(vty, " access-class %s\n", vty_accesslist_name);

	if (vty_ipv6_accesslist_name)
		vty_out(vty, " ipv6 access-class %s\n",
			vty_ipv6_accesslist_name);

	/* exec-timeout */
	if (vty_timeout_val != VTY_TIMEOUT_DEFAULT)
		vty_out(vty, " exec-timeout %ld %ld\n", vty_timeout_val / 60,
			vty_timeout_val % 60);

	/* login */
	if (no_password_check)
		vty_out(vty, " no login\n");

	vty_endframe(vty, "exit\n");

	if (vty_log_commands)
		vty_out(vty, "log commands\n");

	vty_out(vty, "!\n");

	return CMD_SUCCESS;
}

static int vty_config_write(struct vty *vty);
struct cmd_node vty_node = {
	.name = "vty",
	.node = VTY_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-line)# ",
	.config_write = vty_config_write,
};

/* Reset all VTY status. */
void vty_reset(void)
{
	struct vty *vty;

	frr_each_safe (vtys, vty_sessions, vty) {
		buffer_reset(vty->lbuf);
		buffer_reset(vty->obuf);
		vty->status = VTY_CLOSE;
		vty_close(vty);
	}

	vty_timeout_val = VTY_TIMEOUT_DEFAULT;

	XFREE(MTYPE_VTY, vty_accesslist_name);
	XFREE(MTYPE_VTY, vty_ipv6_accesslist_name);
}

static void vty_save_cwd(void)
{
	char *c;

	c = getcwd(vty_cwd, sizeof(vty_cwd));

	if (!c) {
		/*
		 * At this point if these go wrong, more than likely
		 * the whole world is coming down around us
		 * Hence not worrying about it too much.
		 */
		if (chdir(SYSCONFDIR)) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "Failure to chdir to %s, errno: %d",
				     SYSCONFDIR, errno);
			exit(-1);
		}
		if (getcwd(vty_cwd, sizeof(vty_cwd)) == NULL) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "Failure to getcwd, errno: %d", errno);
			exit(-1);
		}
	}
}

char *vty_get_cwd(void)
{
	return vty_cwd;
}

int vty_shell(struct vty *vty)
{
	return vty->type == VTY_SHELL ? 1 : 0;
}

int vty_shell_serv(struct vty *vty)
{
	return vty->type == VTY_SHELL_SERV ? 1 : 0;
}

void vty_init_vtysh(void)
{
	/* currently nothing to do, but likely to have future use */
}


/*
 * These functions allow for CLI handling to be placed inside daemons; however,
 * currently they are only used by mgmtd, with mgmtd having each daemons CLI
 * functionality linked into it. This design choice was taken for efficiency.
 */

static void vty_mgmt_server_connected(struct mgmt_fe_client *client,
				      uintptr_t usr_data, bool connected)
{
	MGMTD_FE_CLIENT_DBG("Got %sconnected %s MGMTD Frontend Server",
			    !connected ? "dis: " : "",
			    !connected ? "from" : "to");

	/*
	 * We should not have any sessions for connecting or disconnecting case.
	 * The  fe client library will delete all session on disconnect before
	 * calling us.
	 */
	assert(mgmt_fe_client_session_count(client) == 0);

	mgmt_fe_connected = connected;

	/* Start or stop listening for vty connections */
	if (connected)
		frr_vty_serv_start();
	else
		frr_vty_serv_stop();
}

/*
 * A session has successfully been created for a vty.
 */
static void vty_mgmt_session_notify(struct mgmt_fe_client *client,
				    uintptr_t usr_data, uint64_t client_id,
				    bool create, bool success,
				    uintptr_t session_id, uintptr_t session_ctx)
{
	struct vty *vty;

	vty = (struct vty *)session_ctx;

	if (!success) {
		zlog_err("%s session for client %" PRIu64 " failed!",
			 create ? "Creating" : "Destroying", client_id);
		return;
	}

	MGMTD_FE_CLIENT_DBG("%s session for client %" PRIu64 " successfully",
			    create ? "Created" : "Destroyed", client_id);

	if (create) {
		assert(session_id != 0);
		vty->mgmt_session_id = session_id;
	} else {
		vty->mgmt_session_id = 0;
		/* We may come here by way of vty_close() and short-circuits */
		if (vty->status != VTY_CLOSE)
			vty_close(vty);
	}
}

static void vty_mgmt_ds_lock_notified(struct mgmt_fe_client *client,
				      uintptr_t usr_data, uint64_t client_id,
				      uintptr_t session_id,
				      uintptr_t session_ctx, uint64_t req_id,
				      bool lock_ds, bool success,
				      Mgmtd__DatastoreId ds_id,
				      char *errmsg_if_any)
{
	struct vty *vty;
	bool is_short_circuit = mgmt_fe_client_current_msg_short_circuit(client);

	vty = (struct vty *)session_ctx;

	assert(ds_id == MGMTD_DS_CANDIDATE || ds_id == MGMTD_DS_RUNNING);
	if (!success)
		zlog_err("%socking for DS %u failed, Err: '%s' vty %p",
			 lock_ds ? "L" : "Unl", ds_id, errmsg_if_any, vty);
	else {
		MGMTD_FE_CLIENT_DBG("%socked DS %u successfully",
				    lock_ds ? "L" : "Unl", ds_id);
		if (ds_id == MGMTD_DS_CANDIDATE)
			vty->mgmt_locked_candidate_ds = lock_ds;
		else
			vty->mgmt_locked_running_ds = lock_ds;
	}

	if (!is_short_circuit && vty->mgmt_req_pending_cmd) {
		assert(!strcmp(vty->mgmt_req_pending_cmd, "MESSAGE_LOCKDS_REQ"));
		vty_mgmt_resume_response(vty,
					 success ? CMD_SUCCESS : CMD_WARNING);
	}
}

static void vty_mgmt_set_config_result_notified(
	struct mgmt_fe_client *client, uintptr_t usr_data, uint64_t client_id,
	uintptr_t session_id, uintptr_t session_ctx, uint64_t req_id,
	bool success, Mgmtd__DatastoreId ds_id, bool implicit_commit,
	char *errmsg_if_any)
{
	struct vty *vty;

	vty = (struct vty *)session_ctx;

	if (!success) {
		zlog_err("SET_CONFIG request for client 0x%" PRIx64
			 " failed, Error: '%s'",
			 client_id, errmsg_if_any ? errmsg_if_any : "Unknown");
		vty_out(vty, "ERROR: SET_CONFIG request failed, Error: %s\n",
			errmsg_if_any ? errmsg_if_any : "Unknown");
	} else {
		MGMTD_FE_CLIENT_DBG("SET_CONFIG request for client 0x%" PRIx64
				    " req-id %" PRIu64 " was successfull",
				    client_id, req_id);
	}

	if (implicit_commit) {
		/* In this case the changes have been applied, we are done */
		vty_mgmt_unlock_candidate_inline(vty);
		vty_mgmt_unlock_running_inline(vty);
	}

	vty_mgmt_resume_response(vty, success ? CMD_SUCCESS
					      : CMD_WARNING_CONFIG_FAILED);
}

static void vty_mgmt_commit_config_result_notified(
	struct mgmt_fe_client *client, uintptr_t usr_data, uint64_t client_id,
	uintptr_t session_id, uintptr_t session_ctx, uint64_t req_id,
	bool success, Mgmtd__DatastoreId src_ds_id,
	Mgmtd__DatastoreId dst_ds_id, bool validate_only, char *errmsg_if_any)
{
	struct vty *vty;

	vty = (struct vty *)session_ctx;

	if (!success) {
		zlog_err("COMMIT_CONFIG request for client 0x%" PRIx64
			 " failed, Error: '%s'",
			 client_id, errmsg_if_any ? errmsg_if_any : "Unknown");
		vty_out(vty, "ERROR: COMMIT_CONFIG request failed, Error: %s\n",
			errmsg_if_any ? errmsg_if_any : "Unknown");
	} else {
		MGMTD_FE_CLIENT_DBG(
			"COMMIT_CONFIG request for client 0x%" PRIx64
			" req-id %" PRIu64 " was successfull",
			client_id, req_id);
		if (errmsg_if_any)
			vty_out(vty, "MGMTD: %s\n", errmsg_if_any);
	}

	vty_mgmt_resume_response(vty, success ? CMD_SUCCESS
					      : CMD_WARNING_CONFIG_FAILED);
}

static int vty_mgmt_get_data_result_notified(
	struct mgmt_fe_client *client, uintptr_t usr_data, uint64_t client_id,
	uintptr_t session_id, uintptr_t session_ctx, uint64_t req_id,
	bool success, Mgmtd__DatastoreId ds_id, Mgmtd__YangData **yang_data,
	size_t num_data, int next_key, char *errmsg_if_any)
{
	struct vty *vty;
	size_t indx;

	vty = (struct vty *)session_ctx;

	if (!success) {
		zlog_err("GET_DATA request for client 0x%" PRIx64
			 " failed, Error: '%s'",
			 client_id, errmsg_if_any ? errmsg_if_any : "Unknown");
		vty_out(vty, "ERROR: GET_DATA request failed, Error: %s\n",
			errmsg_if_any ? errmsg_if_any : "Unknown");
		vty_mgmt_resume_response(vty, CMD_WARNING);
		return -1;
	}

	MGMTD_FE_CLIENT_DBG("GET_DATA request succeeded, client 0x%" PRIx64
			    " req-id %" PRIu64,
			    client_id, req_id);

	if (req_id != mgmt_last_req_id) {
		mgmt_last_req_id = req_id;
		vty_out(vty, "[\n");
	}

	for (indx = 0; indx < num_data; indx++) {
		vty_out(vty, "  \"%s\": \"%s\"\n", yang_data[indx]->xpath,
			yang_data[indx]->value->encoded_str_val);
	}
	if (next_key < 0) {
		vty_out(vty, "]\n");
		vty_mgmt_resume_response(vty,
					 success ? CMD_SUCCESS : CMD_WARNING);
	}

	return 0;
}

static ssize_t vty_mgmt_libyang_print(void *user_data, const void *buf,
				      size_t count)
{
	struct vty *vty = user_data;

	vty_out(vty, "%.*s", (int)count, (const char *)buf);
	return count;
}

static void vty_out_yang_error(struct vty *vty, LYD_FORMAT format,
			       struct ly_err_item *ei)
{
	bool have_apptag = ei->apptag && ei->apptag[0] != 0;
	bool have_path = ei->path && ei->path[0] != 0;
	bool have_msg = ei->msg && ei->msg[0] != 0;
	const char *severity = NULL;
	const char *evalid = NULL;
	const char *ecode = NULL;
	LY_ERR err = ei->no;

	if (ei->level == LY_LLERR)
		severity = "error";
	else if (ei->level == LY_LLWRN)
		severity = "warning";

	switch (ei->no) {
	case LY_SUCCESS:
		ecode = "ok";
		break;
	case LY_EMEM:
		ecode = "out of memory";
		break;
	case LY_ESYS:
		ecode = "system error";
		break;
	case LY_EINVAL:
		ecode = "invalid value given";
		break;
	case LY_EEXIST:
		ecode = "item exists";
		break;
	case LY_ENOTFOUND:
		ecode = "item not found";
		break;
	case LY_EINT:
		ecode = "operation interrupted";
		break;
	case LY_EVALID:
		ecode = "validation failed";
		break;
	case LY_EDENIED:
		ecode = "access denied";
		break;
	case LY_EINCOMPLETE:
		ecode = "incomplete";
		break;
	case LY_ERECOMPILE:
		ecode = "compile error";
		break;
	case LY_ENOT:
		ecode = "not";
		break;
	default:
	case LY_EPLUGIN:
	case LY_EOTHER:
		ecode = "other";
		break;
	}

	if (err == LY_EVALID) {
		switch (ei->vecode) {
		case LYVE_SUCCESS:
			evalid = NULL;
			break;
		case LYVE_SYNTAX:
			evalid = "syntax";
			break;
		case LYVE_SYNTAX_YANG:
			evalid = "yang-syntax";
			break;
		case LYVE_SYNTAX_YIN:
			evalid = "yin-syntax";
			break;
		case LYVE_REFERENCE:
			evalid = "reference";
			break;
		case LYVE_XPATH:
			evalid = "xpath";
			break;
		case LYVE_SEMANTICS:
			evalid = "semantics";
			break;
		case LYVE_SYNTAX_XML:
			evalid = "xml-syntax";
			break;
		case LYVE_SYNTAX_JSON:
			evalid = "json-syntax";
			break;
		case LYVE_DATA:
			evalid = "data";
			break;
		default:
		case LYVE_OTHER:
			evalid = "other";
			break;
		}
	}

	switch (format) {
	case LYD_XML:
		vty_out(vty,
			"<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">");
		vty_out(vty, "<error-type>application</error-type>");
		if (severity)
			vty_out(vty, "<error-severity>%s</error-severity>",
				severity);
		if (ecode)
			vty_out(vty, "<error-code>%s</error-code>", ecode);
		if (evalid)
			vty_out(vty, "<error-validation>%s</error-validation>\n",
				evalid);
		if (have_path)
			vty_out(vty, "<error-path>%s</error-path>\n", ei->path);
		if (have_apptag)
			vty_out(vty, "<error-app-tag>%s</error-app-tag>\n",
				ei->apptag);
		if (have_msg)
			vty_out(vty, "<error-message>%s</error-message>\n",
				ei->msg);

		vty_out(vty, "</rpc-error>");
		break;
	case LYD_JSON:
		vty_out(vty, "{ \"error-type\": \"application\"");
		if (severity)
			vty_out(vty, ", \"error-severity\": \"%s\"", severity);
		if (ecode)
			vty_out(vty, ", \"error-code\": \"%s\"", ecode);
		if (evalid)
			vty_out(vty, ", \"error-validation\": \"%s\"", evalid);
		if (have_path)
			vty_out(vty, ", \"error-path\": \"%s\"", ei->path);
		if (have_apptag)
			vty_out(vty, ", \"error-app-tag\": \"%s\"", ei->apptag);
		if (have_msg)
			vty_out(vty, ", \"error-message\": \"%s\"", ei->msg);

		vty_out(vty, "}");
		break;
	case LYD_UNKNOWN:
	case LYD_LYB:
	default:
		vty_out(vty, "%% error");
		if (severity)
			vty_out(vty, " severity: %s", severity);
		if (evalid)
			vty_out(vty, " invalid: %s", evalid);
		if (have_path)
			vty_out(vty, " path: %s", ei->path);
		if (have_apptag)
			vty_out(vty, " app-tag: %s", ei->apptag);
		if (have_msg)
			vty_out(vty, " msg: %s", ei->msg);
		break;
	}
}

static uint vty_out_yang_errors(struct vty *vty, LYD_FORMAT format)
{
	struct ly_err_item *ei = ly_err_first(ly_native_ctx);
	uint count;

	if (!ei)
		return 0;

	if (format == LYD_JSON)
		vty_out(vty, "\"ietf-restconf:errors\": [ ");

	for (count = 0; ei; count++, ei = ei->next) {
		if (count)
			vty_out(vty, ", ");
		vty_out_yang_error(vty, format, ei);
	}

	if (format == LYD_JSON)
		vty_out(vty, " ]");

	ly_err_clean(ly_native_ctx, NULL);

	return count;
}


static int vty_mgmt_get_tree_result_notified(
	struct mgmt_fe_client *client, uintptr_t user_data, uint64_t client_id,
	uint64_t session_id, uintptr_t session_ctx, uint64_t req_id,
	Mgmtd__DatastoreId ds_id, LYD_FORMAT result_type, void *result,
	size_t len, int partial_error)
{
	struct vty *vty;
	struct lyd_node *dnode;
	int ret = CMD_SUCCESS;
	LY_ERR err;

	vty = (struct vty *)session_ctx;

	MGMTD_FE_CLIENT_DBG("GET_TREE request %ssucceeded, client 0x%" PRIx64
			    " req-id %" PRIu64,
			    partial_error ? "partially " : "", client_id,
			    req_id);

	assert(result_type == LYD_LYB ||
	       result_type == vty->mgmt_req_pending_data);

	if (vty->mgmt_req_pending_data == LYD_XML && partial_error)
		vty_out(vty,
			"<!-- some errors occurred gathering results -->\n");

	if (result_type == LYD_LYB) {
		/*
		 * parse binary into tree and print in the specified format
		 */
		result_type = vty->mgmt_req_pending_data;

		err = lyd_parse_data_mem(ly_native_ctx, result, LYD_LYB, 0, 0,
					 &dnode);
		if (!err)
			err = lyd_print_clb(vty_mgmt_libyang_print, vty, dnode,
					    result_type, LYD_PRINT_WITHSIBLINGS);
		lyd_free_all(dnode);

		if (vty_out_yang_errors(vty, result_type) || err)
			ret = CMD_WARNING;
	} else {
		/*
		 * Print the in-format result
		 */
		assert(result_type == LYD_XML || result_type == LYD_JSON);
		vty_out(vty, "%.*s\n", (int)len - 1, (const char *)result);
	}

	vty_mgmt_resume_response(vty, ret);

	return 0;
}

static int vty_mgmt_error_notified(struct mgmt_fe_client *client,
				   uintptr_t user_data, uint64_t client_id,
				   uint64_t session_id, uintptr_t session_ctx,
				   uint64_t req_id, int error,
				   const char *errstr)
{
	struct vty *vty = (struct vty *)session_ctx;
	const char *cname = mgmt_fe_client_name(client);

	if (!vty->mgmt_req_pending_cmd) {
		MGMTD_FE_CLIENT_DBG("Erorr with no pending command: %d returned for client %s 0x%" PRIx64
				    " session-id %" PRIu64 " req-id %" PRIu64
				    "error-str %s",
				    error, cname, client_id, session_id, req_id,
				    errstr);
		vty_out(vty,
			"%% Error %d from MGMTD for %s with no pending command: %s\n",
			error, cname, errstr);
		return CMD_WARNING;
	}

	MGMTD_FE_CLIENT_DBG("Erorr %d returned for client %s 0x%" PRIx64
			    " session-id %" PRIu64 " req-id %" PRIu64
			    "error-str %s",
			    error, cname, client_id, session_id, req_id, errstr);

	vty_out(vty, "%% %s (for %s, client %s)\n", errstr,
		vty->mgmt_req_pending_cmd, cname);

	vty_mgmt_resume_response(vty, error ? CMD_WARNING : CMD_SUCCESS);

	return 0;
}

static struct mgmt_fe_client_cbs mgmt_cbs = {
	.client_connect_notify = vty_mgmt_server_connected,
	.client_session_notify = vty_mgmt_session_notify,
	.lock_ds_notify = vty_mgmt_ds_lock_notified,
	.set_config_notify = vty_mgmt_set_config_result_notified,
	.commit_config_notify = vty_mgmt_commit_config_result_notified,
	.get_data_notify = vty_mgmt_get_data_result_notified,
	.get_tree_notify = vty_mgmt_get_tree_result_notified,
	.error_notify = vty_mgmt_error_notified,

};

void vty_init_mgmt_fe(void)
{
	char name[40];

	assert(vty_master);
	assert(!mgmt_fe_client);
	snprintf(name, sizeof(name), "vty-%s-%ld", frr_get_progname(),
		 (long)getpid());
	mgmt_fe_client = mgmt_fe_client_create(name, &mgmt_cbs, 0, vty_master);
	assert(mgmt_fe_client);
}

bool vty_mgmt_fe_enabled(void)
{
	return mgmt_fe_client && mgmt_fe_connected;
}

bool vty_mgmt_should_process_cli_apply_changes(struct vty *vty)
{
	return vty->type != VTY_FILE && vty_mgmt_fe_enabled();
}

int vty_mgmt_send_lockds_req(struct vty *vty, Mgmtd__DatastoreId ds_id,
			     bool lock, bool scok)
{
	assert(mgmt_fe_client);
	assert(vty->mgmt_session_id);

	vty->mgmt_req_id++;
	if (mgmt_fe_send_lockds_req(mgmt_fe_client, vty->mgmt_session_id,
				    vty->mgmt_req_id, ds_id, lock, scok)) {
		zlog_err("Failed sending %sLOCK-DS-REQ req-id %" PRIu64,
			 lock ? "" : "UN", vty->mgmt_req_id);
		vty_out(vty, "Failed to send %sLOCK-DS-REQ to MGMTD!\n",
			lock ? "" : "UN");
		return -1;
	}

	if (!scok)
		vty->mgmt_req_pending_cmd = "MESSAGE_LOCKDS_REQ";

	return 0;
}

int vty_mgmt_send_config_data(struct vty *vty, const char *xpath_base,
			      bool implicit_commit)
{
	Mgmtd__YangDataValue value[VTY_MAXCFGCHANGES];
	Mgmtd__YangData cfg_data[VTY_MAXCFGCHANGES];
	Mgmtd__YangCfgDataReq cfg_req[VTY_MAXCFGCHANGES];
	Mgmtd__YangCfgDataReq *cfgreq[VTY_MAXCFGCHANGES] = {0};
	char xpath[VTY_MAXCFGCHANGES][XPATH_MAXLEN];
	char *change_xpath;
	size_t indx;

	if (vty->type == VTY_FILE) {
		/*
		 * if this is a config file read we will not send any of the
		 * changes until we are done reading the file and have modified
		 * the local candidate DS.
		 */
		/* no-one else should be sending data right now */
		assert(!vty->mgmt_num_pending_setcfg);
		return 0;
	}

	/* If we are FE client and we have a vty then we have a session */
	assert(mgmt_fe_client && vty->mgmt_client_id && vty->mgmt_session_id);

	if (!vty->num_cfg_changes)
		return 0;

	/* grab the candidate and running lock prior to sending implicit commit
	 * command
	 */
	if (implicit_commit) {
		if (vty_mgmt_lock_candidate_inline(vty)) {
			vty_out(vty,
				"%% command failed, could not lock candidate DS\n");
			return -1;
		} else if (vty_mgmt_lock_running_inline(vty)) {
			vty_out(vty,
				"%% command failed, could not lock running DS\n");
			vty_mgmt_unlock_candidate_inline(vty);
			return -1;
		}
	}

	if (xpath_base == NULL)
		xpath_base = "";

	for (indx = 0; indx < vty->num_cfg_changes; indx++) {
		mgmt_yang_data_init(&cfg_data[indx]);

		if (vty->cfg_changes[indx].value) {
			mgmt_yang_data_value_init(&value[indx]);
			value[indx].encoded_str_val =
				(char *)vty->cfg_changes[indx].value;
			value[indx].value_case =
				MGMTD__YANG_DATA_VALUE__VALUE_ENCODED_STR_VAL;
			cfg_data[indx].value = &value[indx];
		}

		change_xpath = vty->cfg_changes[indx].xpath;

		memset(xpath[indx], 0, sizeof(xpath[indx]));
		/* If change xpath is relative, prepend base xpath. */
		if (change_xpath[0] == '.') {
			strlcpy(xpath[indx], xpath_base, sizeof(xpath[indx]));
			change_xpath++; /* skip '.' */
		}
		strlcat(xpath[indx], change_xpath, sizeof(xpath[indx]));

		cfg_data[indx].xpath = xpath[indx];

		mgmt_yang_cfg_data_req_init(&cfg_req[indx]);
		cfg_req[indx].data = &cfg_data[indx];
		switch (vty->cfg_changes[indx].operation) {
		case NB_OP_DESTROY:
			cfg_req[indx].req_type =
				MGMTD__CFG_DATA_REQ_TYPE__DELETE_DATA;
			break;

		case NB_OP_CREATE:
		case NB_OP_MODIFY:
		case NB_OP_MOVE:
		case NB_OP_PRE_VALIDATE:
		case NB_OP_APPLY_FINISH:
			cfg_req[indx].req_type =
				MGMTD__CFG_DATA_REQ_TYPE__SET_DATA;
			break;
		case NB_OP_GET_ELEM:
		case NB_OP_GET_NEXT:
		case NB_OP_GET_KEYS:
		case NB_OP_LOOKUP_ENTRY:
		case NB_OP_RPC:
		default:
			assertf(false,
				"Invalid operation type for send config: %d",
				vty->cfg_changes[indx].operation);
			/*NOTREACHED*/
			abort();
		}

		cfgreq[indx] = &cfg_req[indx];
	}
	if (!indx)
		return 0;

	vty->mgmt_req_id++;
	if (mgmt_fe_send_setcfg_req(mgmt_fe_client, vty->mgmt_session_id,
				    vty->mgmt_req_id, MGMTD_DS_CANDIDATE,
				    cfgreq, indx, implicit_commit,
				    MGMTD_DS_RUNNING)) {
		zlog_err("Failed to send %zu config xpaths to mgmtd", indx);
		vty_out(vty, "%% Failed to send commands to mgmtd\n");
		return -1;
	}

	vty->mgmt_req_pending_cmd = "MESSAGE_SETCFG_REQ";

	return 0;
}

int vty_mgmt_send_commit_config(struct vty *vty, bool validate_only, bool abort)
{
	if (mgmt_fe_client && vty->mgmt_session_id) {
		vty->mgmt_req_id++;
		if (mgmt_fe_send_commitcfg_req(
			    mgmt_fe_client, vty->mgmt_session_id,
			    vty->mgmt_req_id, MGMTD_DS_CANDIDATE,
			    MGMTD_DS_RUNNING, validate_only, abort)) {
			zlog_err("Failed sending COMMIT-REQ req-id %" PRIu64,
				 vty->mgmt_req_id);
			vty_out(vty, "Failed to send COMMIT-REQ to MGMTD!\n");
			return -1;
		}

		vty->mgmt_req_pending_cmd = "MESSAGE_COMMCFG_REQ";
		vty->mgmt_num_pending_setcfg = 0;
	}

	return 0;
}

int vty_mgmt_send_get_req(struct vty *vty, bool is_config,
			  Mgmtd__DatastoreId datastore, const char **xpath_list,
			  int num_req)
{
	Mgmtd__YangData yang_data[VTY_MAXCFGCHANGES];
	Mgmtd__YangGetDataReq get_req[VTY_MAXCFGCHANGES];
	Mgmtd__YangGetDataReq *getreq[VTY_MAXCFGCHANGES];
	int i;

	vty->mgmt_req_id++;

	for (i = 0; i < num_req; i++) {
		mgmt_yang_get_data_req_init(&get_req[i]);
		mgmt_yang_data_init(&yang_data[i]);

		yang_data->xpath = (char *)xpath_list[i];

		get_req[i].data = &yang_data[i];
		getreq[i] = &get_req[i];
	}
	if (mgmt_fe_send_get_req(mgmt_fe_client, vty->mgmt_session_id,
				 vty->mgmt_req_id, is_config, datastore, getreq,
				 num_req)) {
		zlog_err("Failed to send GET- to MGMTD for req-id %" PRIu64 ".",
			 vty->mgmt_req_id);
		vty_out(vty, "Failed to send GET-CONFIG to MGMTD!\n");
		return -1;
	}

	vty->mgmt_req_pending_cmd = "MESSAGE_GETCFG_REQ";

	return 0;
}

int vty_mgmt_send_get_tree_req(struct vty *vty, LYD_FORMAT result_type,
			       const char *xpath)
{
	LYD_FORMAT intern_format = result_type;

	vty->mgmt_req_id++;

	if (mgmt_fe_send_get_tree_req(mgmt_fe_client, vty->mgmt_session_id,
				      vty->mgmt_req_id, intern_format, xpath)) {
		zlog_err("Failed to send GET-TREE to MGMTD session-id: %" PRIu64
			 " req-id %" PRIu64 ".",
			 vty->mgmt_session_id, vty->mgmt_req_id);
		vty_out(vty, "Failed to send GET-TREE to MGMTD!\n");
		return -1;
	}

	vty->mgmt_req_pending_cmd = "MESSAGE_GET_TREE_REQ";
	vty->mgmt_req_pending_data = result_type;

	return 0;
}

/* Install vty's own commands like `who' command. */
void vty_init(struct event_loop *master_thread, bool do_command_logging)
{
	/* For further configuration read, preserve current directory. */
	vty_save_cwd();

	vty_master = master_thread;

	atexit(vty_stdio_atexit);

	/* Install bgp top node. */
	install_node(&vty_node);

	install_element(VIEW_NODE, &config_who_cmd);
	install_element(VIEW_NODE, &show_history_cmd);
	install_element(CONFIG_NODE, &line_vty_cmd);
	install_element(CONFIG_NODE, &service_advanced_vty_cmd);
	install_element(CONFIG_NODE, &no_service_advanced_vty_cmd);
	install_element(CONFIG_NODE, &show_history_cmd);
	install_element(CONFIG_NODE, &log_commands_cmd);

	if (do_command_logging) {
		vty_log_commands = true;
		vty_log_commands_perm = true;
	}

	install_element(ENABLE_NODE, &terminal_monitor_cmd);
	install_element(ENABLE_NODE, &terminal_no_monitor_cmd);
	install_element(ENABLE_NODE, &no_terminal_monitor_cmd);

	install_default(VTY_NODE);
	install_element(VTY_NODE, &exec_timeout_min_cmd);
	install_element(VTY_NODE, &exec_timeout_sec_cmd);
	install_element(VTY_NODE, &no_exec_timeout_cmd);
	install_element(VTY_NODE, &vty_access_class_cmd);
	install_element(VTY_NODE, &no_vty_access_class_cmd);
	install_element(VTY_NODE, &vty_login_cmd);
	install_element(VTY_NODE, &no_vty_login_cmd);
	install_element(VTY_NODE, &vty_ipv6_access_class_cmd);
	install_element(VTY_NODE, &no_vty_ipv6_access_class_cmd);
}

void vty_terminate(void)
{
	struct vty *vty;

	if (mgmt_fe_client) {
		mgmt_fe_client_destroy(mgmt_fe_client);
		mgmt_fe_client = 0;
	}

	memset(vty_cwd, 0x00, sizeof(vty_cwd));

	vty_reset();

	/* default state of vty_sessions is initialized & empty. */
	vtys_fini(vty_sessions);
	vtys_init(vty_sessions);

	/* vty_reset() doesn't close vtysh sessions */
	frr_each_safe (vtys, vtysh_sessions, vty) {
		buffer_reset(vty->lbuf);
		buffer_reset(vty->obuf);
		vty->status = VTY_CLOSE;
		vty_close(vty);
	}

	vtys_fini(vtysh_sessions);
	vtys_init(vtysh_sessions);

	vty_serv_stop();
}
