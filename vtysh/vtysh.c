/* Virtual terminal interface shell.
 * Copyright (C) 2000 Kunihiro Ishiguro
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

#include <zebra.h>

#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <dirent.h>
#include <stdio.h>
#include <string.h>

#include "linklist.h"
#include "command.h"
#include "memory.h"
#include "filter.h"
#include "vtysh/vtysh.h"
#include "log.h"
#include "bgpd/bgp_vty.h"
#include "ns.h"
#include "vrf.h"
#include "libfrr.h"
#include "command_graph.h"
#include "frrstr.h"
#include "json.h"
#include "ferr.h"

DEFINE_MTYPE_STATIC(MVTYSH, VTYSH_CMD, "Vtysh cmd copy")

/* Struct VTY. */
struct vty *vty;

/* VTY shell pager name. */
char *vtysh_pager_name = NULL;

/* VTY shell client structure */
struct vtysh_client {
	int fd;
	const char *name;
	int flag;
	char path[MAXPATHLEN];
	struct vtysh_client *next;
};

/* Some utility functions for working on vtysh-specific vty tasks */

static FILE *vty_open_pager(struct vty *vty)
{
	if (vty->is_paged)
		return vty->of;

	if (!vtysh_pager_name)
		return NULL;

	vty->of_saved = vty->of;
	vty->of = popen(vtysh_pager_name, "w");
	if (vty->of == NULL) {
		vty->of = vty->of_saved;
		perror("popen");
		exit(1);
	}

	vty->is_paged = true;

	return vty->of;
}

static int vty_close_pager(struct vty *vty)
{
	if (!vty->is_paged)
		return 0;

	fflush(vty->of);
	if (pclose(vty->of) == -1) {
		perror("pclose");
		exit(1);
	}

	vty->of = vty->of_saved;
	vty->is_paged = false;

	return 0;
}

static void vtysh_pager_envdef(bool fallback)
{
	char *pager_defined;

	pager_defined = getenv("VTYSH_PAGER");

	if (pager_defined)
		vtysh_pager_name = strdup(pager_defined);
	else if (fallback)
		vtysh_pager_name = strdup(VTYSH_PAGER);
}

/* --- */

struct vtysh_client vtysh_client[] = {
	{.fd = -1, .name = "zebra", .flag = VTYSH_ZEBRA, .next = NULL},
	{.fd = -1, .name = "ripd", .flag = VTYSH_RIPD, .next = NULL},
	{.fd = -1, .name = "ripngd", .flag = VTYSH_RIPNGD, .next = NULL},
	{.fd = -1, .name = "ospfd", .flag = VTYSH_OSPFD, .next = NULL},
	{.fd = -1, .name = "ospf6d", .flag = VTYSH_OSPF6D, .next = NULL},
	{.fd = -1, .name = "ldpd", .flag = VTYSH_LDPD, .next = NULL},
	{.fd = -1, .name = "bgpd", .flag = VTYSH_BGPD, .next = NULL},
	{.fd = -1, .name = "isisd", .flag = VTYSH_ISISD, .next = NULL},
	{.fd = -1, .name = "pimd", .flag = VTYSH_PIMD, .next = NULL},
	{.fd = -1, .name = "nhrpd", .flag = VTYSH_NHRPD, .next = NULL},
	{.fd = -1, .name = "eigrpd", .flag = VTYSH_EIGRPD, .next = NULL},
	{.fd = -1, .name = "babeld", .flag = VTYSH_BABELD, .next = NULL},
	{.fd = -1, .name = "sharpd", .flag = VTYSH_SHARPD, .next = NULL},
	{.fd = -1, .name = "fabricd", .flag = VTYSH_FABRICD, .next = NULL},
	{.fd = -1, .name = "watchfrr", .flag = VTYSH_WATCHFRR, .next = NULL},
	{.fd = -1, .name = "pbrd", .flag = VTYSH_PBRD, .next = NULL},
	{.fd = -1, .name = "staticd", .flag = VTYSH_STATICD, .next = NULL},
	{.fd = -1, .name = "bfdd", .flag = VTYSH_BFDD, .next = NULL},
	{.fd = -1, .name = "vrrpd", .flag = VTYSH_VRRPD, .next = NULL},
};

/* Searches for client by name, returns index */
static int vtysh_client_lookup(const char *name)
{
	int idx = -1;

	for (unsigned int i = 0; i < array_size(vtysh_client); i++) {
		if (strmatch(vtysh_client[i].name, name)) {
			idx = i;
			break;
		}
	}

	return idx;
}

enum vtysh_write_integrated vtysh_write_integrated =
	WRITE_INTEGRATED_UNSPECIFIED;

static int vtysh_reconnect(struct vtysh_client *vclient);

static void vclient_close(struct vtysh_client *vclient)
{
	if (vclient->fd >= 0) {
		if (vty->of)
			vty_out(vty,
				"Warning: closing connection to %s because of an I/O error!\n",
				vclient->name);
		close(vclient->fd);
		/* indicate as candidate for reconnect */
		vclient->fd = VTYSH_WAS_ACTIVE;
	}
}

/*
 * Send a CLI command to a client and read the response.
 *
 * Output will be printed to vty->of. If you want to suppress output, set that
 * to NULL.
 *
 * vclient
 *    the client to send the command to
 *
 * line
 *    the command to send
 *
 * callback
 *    if non-null, this will be called with each line of output received from
 *    the client passed in the second parameter
 *
 * cbarg
 *    optional first argument to pass to callback
 *
 * Returns:
 *    a status code
 */
static int vtysh_client_run(struct vtysh_client *vclient, const char *line,
			    void (*callback)(void *, const char *), void *cbarg)
{
	int ret;
	char stackbuf[4096];
	char *buf = stackbuf;
	size_t bufsz = sizeof(stackbuf);
	char *bufvalid, *end = NULL;
	char terminator[3] = {0, 0, 0};

	/* vclinet was previously active, try to reconnect */
	if (vclient->fd == VTYSH_WAS_ACTIVE) {
		ret = vtysh_reconnect(vclient);
		if (ret < 0)
			goto out_err;
	}

	if (vclient->fd < 0)
		return CMD_SUCCESS;

	ret = write(vclient->fd, line, strlen(line) + 1);
	if (ret <= 0) {
		/* close connection and try to reconnect */
		vclient_close(vclient);
		ret = vtysh_reconnect(vclient);
		if (ret < 0)
			goto out_err;
		/* retry line */
		ret = write(vclient->fd, line, strlen(line) + 1);
		if (ret <= 0)
			goto out_err;
	}

	bufvalid = buf;
	do {
		ssize_t nread =
			read(vclient->fd, bufvalid, buf + bufsz - bufvalid - 1);

		if (nread < 0 && (errno == EINTR || errno == EAGAIN))
			continue;

		if (nread <= 0) {
			if (vty->of)
				vty_out(vty,
					"vtysh: error reading from %s: %s (%d)",
					vclient->name, safe_strerror(errno),
					errno);
			goto out_err;
		}

		bufvalid += nread;

		/* Null terminate so we may pass this to *printf later. */
		bufvalid[0] = '\0';

		/*
		 * We expect string output from daemons, so instead of looking
		 * for the full 3 null bytes of the terminator, we check for
		 * just one instead and assume it is the first byte of the
		 * terminator. The presence of the full terminator is checked
		 * later.
		 */
		if (bufvalid - buf >= 4)
			end = memmem(bufvalid - 4, 4, "\0", 1);

		/*
		 * calculate # bytes we have, up to & not including the
		 * terminator if present
		 */
		size_t textlen = (end ? end : bufvalid) - buf;
		bool b = false;

		/* feed line processing callback if present */
		while (callback && bufvalid > buf && (end > buf || !end)) {
			textlen = (end ? end : bufvalid) - buf;
			char *eol = memchr(buf, '\n', textlen);
			if (eol)
				/* line break */
				*eol++ = '\0';
			else if (end == buf)
				/*
				 * no line break, end of input, no text left
				 * before end; nothing to write
				 */
				b = true;
			else if (end)
				/* no nl, end of input, but some text left */
				eol = end;
			else if (bufvalid == buf + bufsz - 1) {
				/*
				 * no nl, no end of input, no buffer space;
				 * realloc
				 */
				char *new;

				bufsz *= 2;
				if (buf == stackbuf) {
					new = XMALLOC(MTYPE_TMP, bufsz);
					memcpy(new, stackbuf, sizeof(stackbuf));
				} else
					new = XREALLOC(MTYPE_TMP, buf, bufsz);

				bufvalid = bufvalid - buf + new;
				buf = new;
				/* if end != NULL, we won't be reading more
				 * data... */
				assert(end == NULL);
				b = true;
			} else
				b = true;

			if (b)
				break;

			/* eol is at line end now, either \n => \0 or \0\0\0 */
			assert(eol && eol <= bufvalid);

			if (vty->of)
				vty_out(vty, "%s\n", buf);

			callback(cbarg, buf);

			/* shift back data and adjust bufvalid */
			memmove(buf, eol, bufvalid - eol);
			bufvalid -= eol - buf;
			if (end)
				end -= eol - buf;
		}

		/* else if no callback, dump raw */
		if (!callback) {
			if (vty->of)
				vty_out(vty, "%s", buf);
			memmove(buf, buf + textlen, bufvalid - buf - textlen);
			bufvalid -= textlen;
			if (end)
				end -= textlen;

			/*
			 * ----------------------------------------------------
			 * At this point `buf` should be in one of two states:
			 * - Empty (i.e. buf == bufvalid)
			 * - Contains up to 4 bytes of the terminator
			 * ----------------------------------------------------
			 */
			assert(((buf == bufvalid)
				|| (bufvalid - buf <= 4 && buf[0] == 0x00)));
		}

		/* if we have the terminator, break */
		if (end && bufvalid - buf == 4) {
			assert(!memcmp(buf, terminator, 3));
			ret = buf[3];
			break;
		}

	} while (true);
	goto out;

out_err:
	vclient_close(vclient);
	ret = CMD_SUCCESS;
out:
	if (buf != stackbuf)
		XFREE(MTYPE_TMP, buf);
	return ret;
}

static int vtysh_client_run_all(struct vtysh_client *head_client,
				const char *line, int continue_on_err,
				void (*callback)(void *, const char *),
				void *cbarg)
{
	struct vtysh_client *client;
	int rc, rc_all = CMD_SUCCESS;
	int correct_instance = 0, wrong_instance = 0;

	for (client = head_client; client; client = client->next) {
		rc = vtysh_client_run(client, line, callback, cbarg);
		if (rc == CMD_NOT_MY_INSTANCE) {
			wrong_instance++;
			continue;
		}
		if (client->fd > 0)
			correct_instance++;
		if (rc != CMD_SUCCESS) {
			if (!continue_on_err)
				return rc;
			rc_all = rc;
		}
	}
	if (wrong_instance && !correct_instance && vty->of) {
		vty_out(vty,
			"%% [%s]: command ignored as it targets an instance that is not running\n",
			head_client->name);
		rc_all = CMD_WARNING_CONFIG_FAILED;
	}
	return rc_all;
}

/*
 * Execute command against all daemons.
 *
 * head_client
 *    where to start walking in the daemon list
 *
 * line
 *    the specific command to execute
 *
 * Returns:
 *    a status code
 */
static int vtysh_client_execute(struct vtysh_client *head_client,
				const char *line)
{
	return vtysh_client_run_all(head_client, line, 0, NULL, NULL);
}

/* Execute by name */
static int vtysh_client_execute_name(const char *name, const char *line)
{
	int ret = CMD_SUCCESS;
	int idx_client = -1;

	idx_client = vtysh_client_lookup(name);
	if (idx_client != -1)
		ret = vtysh_client_execute(&vtysh_client[idx_client], line);
	else {
		vty_out(vty, "Client not found\n");
		ret = CMD_WARNING;
	}

	return ret;
}

/*
 * Retrieve all running config from daemons and parse it with the vtysh config
 * parser. Returned output is not displayed to the user.
 *
 * head_client
 *    where to start walking in the daemon list
 *
 * line
 *    the specific command to execute
 */
static void vtysh_client_config(struct vtysh_client *head_client, char *line)
{
	/* watchfrr currently doesn't load any config, and has some hardcoded
	 * settings that show up in "show run".  skip it here (for now at
	 * least) so we don't get that mangled up in config-write.
	 */
	if (head_client->flag == VTYSH_WATCHFRR)
		return;

	/* suppress output to user */
	vty->of_saved = vty->of;
	vty->of = NULL;
	vtysh_client_run_all(head_client, line, 1, vtysh_config_parse_line,
			     NULL);
	vty->of = vty->of_saved;
}

/* Command execution over the vty interface. */
static int vtysh_execute_func(const char *line, int pager)
{
	int ret, cmd_stat;
	unsigned int i;
	vector vline;
	const struct cmd_element *cmd;
	int tried = 0;
	int saved_ret, saved_node;

	/* Split readline string up into the vector. */
	vline = cmd_make_strvec(line);

	if (vline == NULL)
		return CMD_SUCCESS;

	if (user_mode) {
		if (strncmp("en", vector_slot(vline, 0), 2) == 0) {
			cmd_free_strvec(vline);
			vty_out(vty, "%% Command not allowed: enable\n");
			return CMD_WARNING;
		}
	}

	saved_ret = ret = cmd_execute(vty, line, &cmd, 1);
	saved_node = vty->node;

	/*
	 * If command doesn't succeeded in current node, try to walk up in node
	 * tree. Changing vty->node is enough to try it just out without actual
	 * walkup in the vtysh.
	 */
	while (ret != CMD_SUCCESS && ret != CMD_SUCCESS_DAEMON
	       && ret != CMD_WARNING && ret != CMD_WARNING_CONFIG_FAILED
	       && ret != CMD_ERR_AMBIGUOUS && ret != CMD_ERR_INCOMPLETE
	       && vty->node > CONFIG_NODE) {
		vty->node = node_parent(vty->node);
		ret = cmd_execute(vty, line, &cmd, 1);
		tried++;
	}

	vty->node = saved_node;

	/*
	 * If command succeeded in any other node than current (tried > 0) we
	 * have to move into node in the vtysh where it succeeded.
	 */
	if (ret == CMD_SUCCESS || ret == CMD_SUCCESS_DAEMON
	    || ret == CMD_WARNING) {
		if ((saved_node == BGP_VPNV4_NODE
		     || saved_node == BGP_VPNV6_NODE
		     || saved_node == BGP_IPV4_NODE
		     || saved_node == BGP_IPV6_NODE
		     || saved_node == BGP_FLOWSPECV4_NODE
		     || saved_node == BGP_FLOWSPECV6_NODE
		     || saved_node == BGP_IPV4M_NODE
		     || saved_node == BGP_IPV4L_NODE
		     || saved_node == BGP_IPV6L_NODE
		     || saved_node == BGP_IPV6M_NODE
		     || saved_node == BGP_EVPN_NODE
		     || saved_node == LDP_IPV4_NODE
		     || saved_node == LDP_IPV6_NODE)
		    && (tried == 1)) {
			vtysh_execute("exit-address-family");
		} else if ((saved_node == BGP_EVPN_VNI_NODE) && (tried == 1)) {
			vtysh_execute("exit-vni");
		} else if (saved_node == BGP_VRF_POLICY_NODE && (tried == 1)) {
			vtysh_execute("exit-vrf-policy");
		} else if ((saved_node == BGP_VNC_DEFAULTS_NODE
			    || saved_node == BGP_VNC_NVE_GROUP_NODE
			    || saved_node == BGP_VNC_L2_GROUP_NODE)
			   && (tried == 1)) {
			vtysh_execute("exit-vnc");
		} else if (saved_node == VRF_NODE && (tried == 1)) {
			vtysh_execute("exit-vrf");
		} else if ((saved_node == KEYCHAIN_KEY_NODE
			    || saved_node == LDP_PSEUDOWIRE_NODE
			    || saved_node == LDP_IPV4_IFACE_NODE
			    || saved_node == LDP_IPV6_IFACE_NODE)
			   && (tried == 1)) {
			vtysh_execute("exit");
		} else if (tried) {
			vtysh_execute("end");
			vtysh_execute("configure");
		}
	}
	/*
	 * If command didn't succeed in any node, continue with return value
	 * from first try.
	 */
	else if (tried) {
		ret = saved_ret;
	}

	cmd_free_strvec(vline);

	cmd_stat = ret;
	switch (ret) {
	case CMD_WARNING:
	case CMD_WARNING_CONFIG_FAILED:
		if (vty->type == VTY_FILE)
			vty_out(vty, "Warning...\n");
		break;
	case CMD_ERR_AMBIGUOUS:
		vty_out(vty, "%% Ambiguous command: %s\n", line);
		break;
	case CMD_ERR_NO_MATCH:
		vty_out(vty, "%% Unknown command: %s\n", line);
		break;
	case CMD_ERR_INCOMPLETE:
		vty_out(vty, "%% Command incomplete: %s\n", line);
		break;
	case CMD_SUCCESS_DAEMON: {
		/*
		 * FIXME: Don't open pager for exit commands. popen() causes
		 * problems if exited from vtysh at all. This hack shouldn't
		 * cause any problem but is really ugly.
		 */
		if (pager && strncmp(line, "exit", 4))
			vty_open_pager(vty);

		if (!strcmp(cmd->string, "configure")) {
			for (i = 0; i < array_size(vtysh_client); i++) {
				cmd_stat = vtysh_client_execute(
					&vtysh_client[i], line);
				if (cmd_stat == CMD_WARNING)
					break;
			}

			if (cmd_stat) {
				line = "end";
				vline = cmd_make_strvec(line);


				if (vline == NULL) {
					if (vty->is_paged)
						vty_close_pager(vty);
					return CMD_SUCCESS;
				}

				ret = cmd_execute_command(vline, vty, &cmd, 1);
				cmd_free_strvec(vline);
				if (ret != CMD_SUCCESS_DAEMON)
					break;
			} else if (cmd->func) {
				(*cmd->func)(cmd, vty, 0, NULL);
				break;
			}
		}

		cmd_stat = CMD_SUCCESS;
		struct vtysh_client *vc;
		for (i = 0; i < array_size(vtysh_client); i++) {
			if (cmd->daemon & vtysh_client[i].flag) {
				if (vtysh_client[i].fd < 0
				    && (cmd->daemon == vtysh_client[i].flag)) {
					for (vc = &vtysh_client[i]; vc;
					     vc = vc->next)
						if (vc->fd == VTYSH_WAS_ACTIVE)
							vtysh_reconnect(vc);
				}
				if (vtysh_client[i].fd < 0
				    && (cmd->daemon == vtysh_client[i].flag)) {
					bool any_inst = false;
					for (vc = &vtysh_client[i]; vc;
					     vc = vc->next)
						any_inst = any_inst
							   || (vc->fd > 0);
					if (!any_inst) {
						fprintf(stderr,
							"%s is not running\n",
							vtysh_client[i].name);
						continue;
					}
				}
				cmd_stat = vtysh_client_execute(
					&vtysh_client[i], line);
				if (cmd_stat != CMD_SUCCESS)
					break;
			}
		}
		if (cmd_stat != CMD_SUCCESS)
			break;

		if (cmd->func)
			(*cmd->func)(cmd, vty, 0, NULL);
	}
	}
	if (vty->is_paged)
		vty_close_pager(vty);

	return cmd_stat;
}

int vtysh_execute_no_pager(const char *line)
{
	return vtysh_execute_func(line, 0);
}

int vtysh_execute(const char *line)
{
	return vtysh_execute_func(line, 1);
}

static char *trim(char *s)
{
	size_t size;
	char *end;

	size = strlen(s);

	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace((unsigned char)*end))
		end--;
	*(end + 1) = '\0';

	while (*s && isspace((unsigned char)*s))
		s++;

	return s;
}

int vtysh_mark_file(const char *filename)
{
	struct vty *vty;
	FILE *confp = NULL;
	int ret;
	vector vline;
	int tried = 0;
	const struct cmd_element *cmd;
	int saved_ret, prev_node;
	int lineno = 0;
	char *vty_buf_copy = NULL;
	char *vty_buf_trimmed = NULL;

	if (strncmp("-", filename, 1) == 0)
		confp = stdin;
	else
		confp = fopen(filename, "r");

	if (confp == NULL) {
		fprintf(stderr, "%% Can't open config file %s due to '%s'.\n",
			filename, safe_strerror(errno));
		return (CMD_ERR_NO_FILE);
	}

	vty = vty_new();
	vty->wfd = STDERR_FILENO;
	vty->type = VTY_TERM;
	vty->node = CONFIG_NODE;

	vtysh_execute_no_pager("enable");
	vtysh_execute_no_pager("configure");
	vty_buf_copy = XCALLOC(MTYPE_VTYSH_CMD, VTY_BUFSIZ);

	while (fgets(vty->buf, VTY_BUFSIZ, confp)) {
		lineno++;
		tried = 0;
		strlcpy(vty_buf_copy, vty->buf, VTY_BUFSIZ);
		vty_buf_trimmed = trim(vty_buf_copy);

		switch (vty->node) {
		case LDP_IPV4_IFACE_NODE:
			if (strncmp(vty_buf_copy, "   ", 3)) {
				vty_out(vty, "  end\n");
				vty->node = LDP_IPV4_NODE;
			}
			break;
		case LDP_IPV6_IFACE_NODE:
			if (strncmp(vty_buf_copy, "   ", 3)) {
				vty_out(vty, "  end\n");
				vty->node = LDP_IPV6_NODE;
			}
			break;
		case LDP_PSEUDOWIRE_NODE:
			if (strncmp(vty_buf_copy, "  ", 2)) {
				vty_out(vty, " end\n");
				vty->node = LDP_L2VPN_NODE;
			}
			break;
		default:
			break;
		}

		if (vty_buf_trimmed[0] == '!' || vty_buf_trimmed[0] == '#') {
			vty_out(vty, "%s", vty->buf);
			continue;
		}

		/* Split readline string up into the vector. */
		vline = cmd_make_strvec(vty->buf);

		if (vline == NULL) {
			vty_out(vty, "%s", vty->buf);
			continue;
		}

		/*
		 * Ignore the "end" lines, we will generate these where
		 * appropriate
		 */
		if (strlen(vty_buf_trimmed) == 3
		    && strncmp("end", vty_buf_trimmed, 3) == 0) {
			cmd_free_strvec(vline);
			continue;
		}

		prev_node = vty->node;
		saved_ret = ret = cmd_execute_command_strict(vline, vty, &cmd);

		/*
		 * If command doesn't succeeded in current node, try to walk up
		 * in node tree. Changing vty->node is enough to try it just
		 * out without actual walkup in the vtysh.
		 */
		while (ret != CMD_SUCCESS && ret != CMD_SUCCESS_DAEMON
		       && ret != CMD_WARNING && ret != CMD_WARNING_CONFIG_FAILED
		       && ret != CMD_ERR_AMBIGUOUS && ret != CMD_ERR_INCOMPLETE
		       && vty->node > CONFIG_NODE) {
			vty->node = node_parent(vty->node);
			ret = cmd_execute_command_strict(vline, vty, &cmd);
			tried++;
		}

		/*
		 * If command succeeded in any other node than current (tried >
		 * 0) we have to move into node in the vtysh where it
		 * succeeded.
		 */
		if (ret == CMD_SUCCESS || ret == CMD_SUCCESS_DAEMON
		    || ret == CMD_WARNING) {
			if ((prev_node == BGP_VPNV4_NODE
			     || prev_node == BGP_VPNV6_NODE
			     || prev_node == BGP_IPV4_NODE
			     || prev_node == BGP_IPV6_NODE
			     || prev_node == BGP_FLOWSPECV4_NODE
			     || prev_node == BGP_FLOWSPECV6_NODE
			     || prev_node == BGP_IPV4L_NODE
			     || prev_node == BGP_IPV6L_NODE
			     || prev_node == BGP_IPV4M_NODE
			     || prev_node == BGP_IPV6M_NODE
			     || prev_node == BGP_EVPN_NODE)
			    && (tried == 1)) {
				vty_out(vty, "exit-address-family\n");
			} else if ((prev_node == BGP_EVPN_VNI_NODE)
				   && (tried == 1)) {
				vty_out(vty, "exit-vni\n");
			} else if ((prev_node == KEYCHAIN_KEY_NODE)
				   && (tried == 1)) {
				vty_out(vty, "exit\n");
			} else if (tried) {
				vty_out(vty, "end\n");
			}
		}
		/*
		 * If command didn't succeed in any node, continue with return
		 * value from first try.
		 */
		else if (tried) {
			ret = saved_ret;
			vty->node = prev_node;
		}

		cmd_free_strvec(vline);
		switch (ret) {
		case CMD_WARNING:
		case CMD_WARNING_CONFIG_FAILED:
			if (vty->type == VTY_FILE)
				fprintf(stderr, "line %d: Warning...: %s\n",
					lineno, vty->buf);
			fclose(confp);
			vty_close(vty);
			XFREE(MTYPE_VTYSH_CMD, vty_buf_copy);
			return ret;
		case CMD_ERR_AMBIGUOUS:
			fprintf(stderr, "line %d: %% Ambiguous command: %s\n",
				lineno, vty->buf);
			fclose(confp);
			vty_close(vty);
			XFREE(MTYPE_VTYSH_CMD, vty_buf_copy);
			return CMD_ERR_AMBIGUOUS;
		case CMD_ERR_NO_MATCH:
			fprintf(stderr, "line %d: %% Unknown command: %s\n",
				lineno, vty->buf);
			fclose(confp);
			vty_close(vty);
			XFREE(MTYPE_VTYSH_CMD, vty_buf_copy);
			return CMD_ERR_NO_MATCH;
		case CMD_ERR_INCOMPLETE:
			fprintf(stderr, "line %d: %% Command incomplete: %s\n",
				lineno, vty->buf);
			fclose(confp);
			vty_close(vty);
			XFREE(MTYPE_VTYSH_CMD, vty_buf_copy);
			return CMD_ERR_INCOMPLETE;
		case CMD_SUCCESS:
			vty_out(vty, "%s", vty->buf);
			if (strmatch(vty_buf_trimmed, "exit-vrf"))
				vty_out(vty, "end\n");
			break;
		case CMD_SUCCESS_DAEMON: {
			int cmd_stat;

			vty_out(vty, "%s", vty->buf);
			if (strmatch(vty_buf_trimmed, "exit-vrf"))
				vty_out(vty, "end\n");
			cmd_stat = vtysh_client_execute(&vtysh_client[0],
							vty->buf);
			if (cmd_stat != CMD_SUCCESS)
				break;

			if (cmd->func)
				(*cmd->func)(cmd, vty, 0, NULL);
		}
		}
	}
	/* This is the end */
	vty_out(vty, "\nend\n");
	vty_close(vty);
	XFREE(MTYPE_VTYSH_CMD, vty_buf_copy);

	if (confp != stdin)
		fclose(confp);

	return (0);
}

/* Configration make from file. */
int vtysh_config_from_file(struct vty *vty, FILE *fp)
{
	int ret;
	const struct cmd_element *cmd;
	int lineno = 0;
	/* once we have an error, we remember & return that */
	int retcode = CMD_SUCCESS;

	while (fgets(vty->buf, VTY_BUFSIZ, fp)) {
		lineno++;

		ret = command_config_read_one_line(vty, &cmd, lineno, 1);

		switch (ret) {
		case CMD_WARNING:
		case CMD_WARNING_CONFIG_FAILED:
			if (vty->type == VTY_FILE)
				fprintf(stderr, "line %d: Warning[%d]...: %s\n",
					lineno, vty->node, vty->buf);
			retcode = ret;

			break;
		case CMD_ERR_AMBIGUOUS:
			fprintf(stderr,
				"line %d: %% Ambiguous command[%d]: %s\n",
				lineno, vty->node, vty->buf);
			retcode = CMD_ERR_AMBIGUOUS;
			break;
		case CMD_ERR_NO_MATCH:
			fprintf(stderr, "line %d: %% Unknown command[%d]: %s",
				lineno, vty->node, vty->buf);
			retcode = CMD_ERR_NO_MATCH;
			break;
		case CMD_ERR_INCOMPLETE:
			fprintf(stderr,
				"line %d: %% Command incomplete[%d]: %s\n",
				lineno, vty->node, vty->buf);
			retcode = CMD_ERR_INCOMPLETE;
			break;
		case CMD_SUCCESS_DAEMON: {
			unsigned int i;
			int cmd_stat = CMD_SUCCESS;

			for (i = 0; i < array_size(vtysh_client); i++) {
				if (cmd->daemon & vtysh_client[i].flag) {
					cmd_stat = vtysh_client_execute(
						&vtysh_client[i], vty->buf);
					/*
					 * CMD_WARNING - Can mean that the
					 * command was parsed successfully but
					 * it was already entered in a few
					 * spots. As such if we receive a
					 * CMD_WARNING from a daemon we
					 * shouldn't stop talking to the other
					 * daemons for the particular command.
					 */
					if (cmd_stat != CMD_SUCCESS
					    && cmd_stat != CMD_WARNING) {
						fprintf(stderr,
							"line %d: Failure to communicate[%d] to %s, line: %s\n",
							lineno, cmd_stat,
							vtysh_client[i].name,
							vty->buf);
						retcode = cmd_stat;
						break;
					}
				}
			}
			if (cmd_stat != CMD_SUCCESS)
				break;

			if (cmd->func)
				(*cmd->func)(cmd, vty, 0, NULL);
		}
		}
	}

	return (retcode);
}

/*
 * Function processes cli commands terminated with '?' character when entered
 * through either 'vtysh' or 'vtysh -c' interfaces.
 */
static int vtysh_process_questionmark(const char *input, int input_len)
{
	int ret, width = 0;
	unsigned int i;
	vector vline, describe;
	struct cmd_token *token;

	if (!input)
		return 1;

	vline = cmd_make_strvec(input);

	/* In case of '> ?'. */
	if (vline == NULL) {
		vline = vector_init(1);
		vector_set(vline, NULL);
	} else if (input_len && isspace((unsigned char)input[input_len - 1]))
		vector_set(vline, NULL);

	describe = cmd_describe_command(vline, vty, &ret);

	/* Ambiguous and no match error. */
	switch (ret) {
	case CMD_ERR_AMBIGUOUS:
		cmd_free_strvec(vline);
		vector_free(describe);
		vty_out(vty, "%% Ambiguous command.\n");
		rl_on_new_line();
		return 0;
		break;
	case CMD_ERR_NO_MATCH:
		cmd_free_strvec(vline);
		if (describe)
			vector_free(describe);
		vty_out(vty, "%% There is no matched command.\n");
		rl_on_new_line();
		return 0;
		break;
	}

	/* Get width of command string. */
	width = 0;
	for (i = 0; i < vector_active(describe); i++)
		if ((token = vector_slot(describe, i)) != NULL) {
			if (token->text[0] == '\0')
				continue;

			int len = strlen(token->text);

			if (width < len)
				width = len;
		}

	for (i = 0; i < vector_active(describe); i++)
		if ((token = vector_slot(describe, i)) != NULL) {
			if (!token->desc)
				vty_out(vty, "  %-s\n", token->text);
			else
				vty_out(vty, "  %-*s  %s\n", width, token->text,
					token->desc);

			if (IS_VARYING_TOKEN(token->type)) {
				const char *ref = vector_slot(
					vline, vector_active(vline) - 1);

				vector varcomps = vector_init(VECTOR_MIN_SIZE);
				cmd_variable_complete(token, ref, varcomps);

				if (vector_active(varcomps) > 0) {
					int rows, cols;
					rl_get_screen_size(&rows, &cols);

					char *ac = cmd_variable_comp2str(
						varcomps, cols);
					vty_out(vty, "%s\n", ac);
					XFREE(MTYPE_TMP, ac);
				}

				vector_free(varcomps);
			}
		}

	cmd_free_strvec(vline);
	vector_free(describe);

	return 0;
}

/*
 * Entry point for user commands terminated with '?' character and typed through
 * the usual vtysh's stdin interface. This is the function being registered with
 * readline() api's.
 */
static int vtysh_rl_describe(int a, int b)
{
	int ret;

	vty_out(vty, "\n");

	ret = vtysh_process_questionmark(rl_line_buffer, rl_end);
	rl_on_new_line();

	return ret;
}

/*
 * Function in charged of processing vtysh instructions terminating with '?'
 * character and received through the 'vtysh -c' interface. If user's
 * instruction is well-formatted, we will call the same processing routine
 * utilized by the traditional vtysh's stdin interface.
 */
int vtysh_execute_command_questionmark(char *input)
{
	int input_len, qmark_count = 0;
	const char *str;

	if (!(input && *input))
		return 1;

	/* Finding out question_mark count and strlen */
	for (str = input; *str; ++str) {
		if (*str == '?')
			qmark_count++;
	}
	input_len = str - input;

	/*
	 * Verify that user's input terminates in '?' and that patterns such as
	 * 'cmd ? subcmd ?' are prevented.
	 */
	if (qmark_count != 1 || input[input_len - 1] != '?')
		return 1;

	/*
	 * Questionmark-processing function is not expecting to receive '?'
	 * character in input string.
	 */
	input[input_len - 1] = '\0';

	return vtysh_process_questionmark(input, input_len - 1);
}

/* Result of cmd_complete_command() call will be stored here
 * and used in new_completion() in order to put the space in
 * correct places only. */
int complete_status;

static char *command_generator(const char *text, int state)
{
	vector vline;
	static char **matched = NULL;
	static int index = 0;

	/* First call. */
	if (!state) {
		index = 0;

		if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
			return NULL;

		vline = cmd_make_strvec(rl_line_buffer);
		if (vline == NULL)
			return NULL;

		if (rl_end &&
		    isspace((unsigned char)rl_line_buffer[rl_end - 1]))
			vector_set(vline, NULL);

		matched = cmd_complete_command(vline, vty, &complete_status);
		cmd_free_strvec(vline);
	}

	if (matched && matched[index])
		/*
		 * this is free()'d by readline, but we leak 1 count of
		 * MTYPE_COMPLETION
		 */
		return matched[index++];

	XFREE(MTYPE_TMP, matched);
	matched = NULL;

	return NULL;
}

static char **new_completion(const char *text, int start, int end)
{
	char **matches;

	matches = rl_completion_matches(text, command_generator);

	if (matches) {
		rl_point = rl_end;
		if (complete_status != CMD_COMPLETE_FULL_MATCH)
			/* only append a space on full match */
			rl_completion_append_character = '\0';
	}

	return matches;
}

/* Vty node structures. */
static struct cmd_node bgp_node = {
	BGP_NODE, "%s(config-router)# ",
};

static struct cmd_node rip_node = {
	RIP_NODE, "%s(config-router)# ",
};

static struct cmd_node isis_node = {
	ISIS_NODE, "%s(config-router)# ",
};

static struct cmd_node openfabric_node = {
	OPENFABRIC_NODE, "%s(config-router)# ",
};

static struct cmd_node interface_node = {
	INTERFACE_NODE, "%s(config-if)# ",
};

static struct cmd_node pw_node = {
	PW_NODE, "%s(config-pw)# ",
};

static struct cmd_node vrf_node = {
	VRF_NODE, "%s(config-vrf)# ",
};

static struct cmd_node nh_group_node = {
	NH_GROUP_NODE,
	"%s(config-nh-group)# ",
};

static struct cmd_node rmap_node = {RMAP_NODE, "%s(config-route-map)# "};

static struct cmd_node pbr_map_node = {PBRMAP_NODE, "%s(config-pbr-map)# "};

static struct cmd_node zebra_node = {ZEBRA_NODE, "%s(config-router)# "};

static struct cmd_node bgp_vpnv4_node = {BGP_VPNV4_NODE,
					 "%s(config-router-af)# "};

static struct cmd_node bgp_vpnv6_node = {BGP_VPNV6_NODE,
					 "%s(config-router-af)# "};

static struct cmd_node bgp_flowspecv4_node = {BGP_FLOWSPECV4_NODE,
					"%s(config-router-af)# "};

static struct cmd_node bgp_flowspecv6_node = {BGP_FLOWSPECV6_NODE,
					"%s(config-router-af)# "};

static struct cmd_node bgp_ipv4_node = {BGP_IPV4_NODE,
					"%s(config-router-af)# "};

static struct cmd_node bgp_ipv4m_node = {BGP_IPV4M_NODE,
					 "%s(config-router-af)# "};

static struct cmd_node bgp_ipv4l_node = {BGP_IPV4L_NODE,
					 "%s(config-router-af)# "};

static struct cmd_node bgp_ipv6_node = {BGP_IPV6_NODE,
					"%s(config-router-af)# "};

static struct cmd_node bgp_ipv6m_node = {BGP_IPV6M_NODE,
					 "%s(config-router-af)# "};

static struct cmd_node bgp_evpn_node = {BGP_EVPN_NODE,
					"%s(config-router-af)# "};

static struct cmd_node bgp_evpn_vni_node = {BGP_EVPN_VNI_NODE,
					    "%s(config-router-af-vni)# "};

static struct cmd_node bgp_ipv6l_node = {BGP_IPV6L_NODE,
					 "%s(config-router-af)# "};

static struct cmd_node bgp_vnc_defaults_node = {
	BGP_VNC_DEFAULTS_NODE, "%s(config-router-vnc-defaults)# "};

static struct cmd_node bgp_vnc_nve_group_node = {
	BGP_VNC_NVE_GROUP_NODE, "%s(config-router-vnc-nve-group)# "};

static struct cmd_node bgp_vrf_policy_node = {BGP_VRF_POLICY_NODE,
					      "%s(config-router-vrf-policy)# "};

static struct cmd_node bgp_vnc_l2_group_node = {
	BGP_VNC_L2_GROUP_NODE, "%s(config-router-vnc-l2-group)# "};

static struct cmd_node bmp_node = {BMP_NODE, "%s(config-bgp-bmp)# "};

static struct cmd_node ospf_node = {OSPF_NODE, "%s(config-router)# "};

static struct cmd_node eigrp_node = {EIGRP_NODE, "%s(config-router)# "};

static struct cmd_node babel_node = {BABEL_NODE, "%s(config-router)# "};

static struct cmd_node ripng_node = {RIPNG_NODE, "%s(config-router)# "};

static struct cmd_node ospf6_node = {OSPF6_NODE, "%s(config-ospf6)# "};

static struct cmd_node ldp_node = {LDP_NODE, "%s(config-ldp)# "};

static struct cmd_node ldp_ipv4_node = {LDP_IPV4_NODE, "%s(config-ldp-af)# "};

static struct cmd_node ldp_ipv6_node = {LDP_IPV6_NODE, "%s(config-ldp-af)# "};

static struct cmd_node ldp_ipv4_iface_node = {LDP_IPV4_IFACE_NODE,
					      "%s(config-ldp-af-if)# "};

static struct cmd_node ldp_ipv6_iface_node = {LDP_IPV6_IFACE_NODE,
					      "%s(config-ldp-af-if)# "};

static struct cmd_node ldp_l2vpn_node = {LDP_L2VPN_NODE, "%s(config-l2vpn)# "};

static struct cmd_node ldp_pseudowire_node = {LDP_PSEUDOWIRE_NODE,
					      "%s(config-l2vpn-pw)# "};

static struct cmd_node keychain_node = {KEYCHAIN_NODE, "%s(config-keychain)# "};

static struct cmd_node keychain_key_node = {KEYCHAIN_KEY_NODE,
					    "%s(config-keychain-key)# "};

struct cmd_node link_params_node = {
	LINK_PARAMS_NODE, "%s(config-link-params)# ",
};

static struct cmd_node rpki_node = {RPKI_NODE, "%s(config-rpki)# ", 1};

#if HAVE_BFDD > 0
static struct cmd_node bfd_node = {
	BFD_NODE,
	"%s(config-bfd)# ",
};

static struct cmd_node bfd_peer_node = {
	BFD_PEER_NODE,
	"%s(config-bfd-peer)# ",
};
#endif /* HAVE_BFDD */

/* Defined in lib/vty.c */
extern struct cmd_node vty_node;

/* When '^Z' is received from vty, move down to the enable mode. */
static int vtysh_end(void)
{
	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		/* Nothing to do. */
		break;
	default:
		vty->node = ENABLE_NODE;
		break;
	}
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_REALLYALL, vtysh_end_all, vtysh_end_all_cmd, "end",
	"End current mode and change to enable mode\n")
{
	return vtysh_end();
}

DEFUNSH(VTYSH_BGPD, router_bgp, router_bgp_cmd,
	"router bgp [(1-4294967295) [<view|vrf> WORD]]",
	ROUTER_STR BGP_STR AS_STR
	"BGP view\nBGP VRF\n"
	"View/VRF name\n")
{
	vty->node = BGP_NODE;
	return CMD_SUCCESS;
}

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUNSH(VTYSH_BGPD, address_family_vpnv4, address_family_vpnv4_cmd,
	"address-family vpnv4 [unicast]",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_VPNV4_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_vpnv6, address_family_vpnv6_cmd,
	"address-family vpnv6 [unicast]",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_VPNV6_NODE;
	return CMD_SUCCESS;
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFUNSH(VTYSH_BGPD, address_family_ipv4, address_family_ipv4_cmd,
	"address-family ipv4 [unicast]",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family Modifier\n")
{
	vty->node = BGP_IPV4_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_flowspecv4, address_family_flowspecv4_cmd,
	"address-family ipv4 flowspec",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family Modifier\n")
{
	vty->node = BGP_FLOWSPECV4_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_flowspecv6, address_family_flowspecv6_cmd,
	"address-family ipv6 flowspec",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family Modifier\n")
{
	vty->node = BGP_FLOWSPECV6_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_ipv4_multicast,
	address_family_ipv4_multicast_cmd, "address-family ipv4 multicast",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_IPV4M_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_ipv4_vpn, address_family_ipv4_vpn_cmd,
	"address-family ipv4 vpn",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_VPNV4_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_ipv4_labeled_unicast,
	address_family_ipv4_labeled_unicast_cmd,
	"address-family ipv4 labeled-unicast",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_IPV4L_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_ipv6, address_family_ipv6_cmd,
	"address-family ipv6 [unicast]",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_IPV6_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_ipv6_multicast,
	address_family_ipv6_multicast_cmd, "address-family ipv6 multicast",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_IPV6M_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_ipv6_vpn, address_family_ipv6_vpn_cmd,
	"address-family ipv6 vpn",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_VPNV6_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_ipv6_labeled_unicast,
	address_family_ipv6_labeled_unicast_cmd,
	"address-family ipv6 labeled-unicast",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_IPV6L_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD,
	rpki,
	rpki_cmd,
	"rpki",
	"Enable rpki and enter rpki configuration mode\n")
{
	vty->node = RPKI_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD,
	bmp_targets,
	bmp_targets_cmd,
	"bmp targets BMPTARGETS",
	"BGP Monitoring Protocol\n"
	"Create BMP target group\n"
	"Name of the BMP target group\n")
{
	vty->node = BMP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, address_family_evpn, address_family_evpn_cmd,
	"address-family <l2vpn evpn>",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family modifier\n")
{
	vty->node = BGP_EVPN_NODE;
	return CMD_SUCCESS;
}

#if defined(HAVE_CUMULUS)
DEFUNSH_HIDDEN(VTYSH_BGPD, address_family_evpn2, address_family_evpn2_cmd,
	       "address-family evpn",
	       "Enter Address Family command mode\n"
	       "EVPN Address family\n")
{
	vty->node = BGP_EVPN_NODE;
	return CMD_SUCCESS;
}
#endif

DEFUNSH(VTYSH_BGPD, bgp_evpn_vni, bgp_evpn_vni_cmd, "vni " CMD_VNI_RANGE,
	"VXLAN Network Identifier\n"
	"VNI number\n")
{
	vty->node = BGP_EVPN_VNI_NODE;
	return CMD_SUCCESS;
}

#if defined(ENABLE_BGP_VNC)
DEFUNSH(VTYSH_BGPD, vnc_defaults, vnc_defaults_cmd, "vnc defaults",
	"VNC/RFP related configuration\n"
	"Configure default NVE group\n")
{
	vty->node = BGP_VNC_DEFAULTS_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, vnc_nve_group, vnc_nve_group_cmd, "vnc nve-group NAME",
	"VNC/RFP related configuration\n"
	"Configure a NVE group\n"
	"Group name\n")
{
	vty->node = BGP_VNC_NVE_GROUP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, vnc_vrf_policy, vnc_vrf_policy_cmd, "vrf-policy NAME",
	"Configure a VRF policy group\n"
	"Group name\n")
{
	vty->node = BGP_VRF_POLICY_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, vnc_l2_group, vnc_l2_group_cmd, "vnc l2-group NAME",
	"VNC/RFP related configuration\n"
	"Configure a L2 group\n"
	"Group name\n")
{
	vty->node = BGP_VNC_L2_GROUP_NODE;
	return CMD_SUCCESS;
}
#endif

DEFUNSH(VTYSH_KEYS, key_chain, key_chain_cmd, "key chain WORD",
	"Authentication key management\n"
	"Key-chain management\n"
	"Key-chain name\n")
{
	vty->node = KEYCHAIN_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_KEYS, key, key_cmd, "key (0-2147483647)",
	"Configure a key\n"
	"Key identifier number\n")
{
	vty->node = KEYCHAIN_KEY_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_RIPD, router_rip, router_rip_cmd, "router rip [vrf NAME]",
	ROUTER_STR "RIP\n" VRF_CMD_HELP_STR)
{
	vty->node = RIP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_RIPNGD, router_ripng, router_ripng_cmd, "router ripng [vrf NAME]",
	ROUTER_STR "RIPng\n" VRF_CMD_HELP_STR)
{
	vty->node = RIPNG_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_OSPFD, router_ospf, router_ospf_cmd,
	"router ospf [(1-65535)] [vrf NAME]",
	"Enable a routing process\n"
	"Start OSPF configuration\n"
	"Instance ID\n"
	VRF_CMD_HELP_STR)
{
	vty->node = OSPF_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_EIGRPD, router_eigrp, router_eigrp_cmd, "router eigrp (1-65535) [vrf NAME]",
	"Enable a routing process\n"
	"Start EIGRP configuration\n"
	"AS number to use\n"
	VRF_CMD_HELP_STR)
{
	vty->node = EIGRP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BABELD, router_babel, router_babel_cmd, "router babel",
	"Enable a routing process\n"
	"Make Babel instance command\n")
{
	vty->node = BABEL_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_OSPF6D, router_ospf6, router_ospf6_cmd, "router ospf6",
	ROUTER_STR OSPF6_STR)
{
	vty->node = OSPF6_NODE;
	return CMD_SUCCESS;
}

#if defined(HAVE_LDPD)
DEFUNSH(VTYSH_LDPD, ldp_mpls_ldp, ldp_mpls_ldp_cmd, "mpls ldp",
	"Global MPLS configuration subcommands\n"
	"Label Distribution Protocol\n")
{
	vty->node = LDP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_LDPD, ldp_address_family_ipv4, ldp_address_family_ipv4_cmd,
	"address-family ipv4",
	"Configure Address Family and its parameters\n"
	"IPv4\n")
{
	vty->node = LDP_IPV4_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_LDPD, ldp_address_family_ipv6, ldp_address_family_ipv6_cmd,
	"address-family ipv6",
	"Configure Address Family and its parameters\n"
	"IPv6\n")
{
	vty->node = LDP_IPV6_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_LDPD, ldp_exit_address_family, ldp_exit_address_family_cmd,
	"exit-address-family", "Exit from Address Family configuration mode\n")
{
	if (vty->node == LDP_IPV4_NODE || vty->node == LDP_IPV6_NODE)
		vty->node = LDP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_LDPD, ldp_interface_ifname, ldp_interface_ifname_cmd,
	"interface IFNAME",
	"Enable LDP on an interface and enter interface submode\n"
	"Interface's name\n")
{
	switch (vty->node) {
	case LDP_IPV4_NODE:
		vty->node = LDP_IPV4_IFACE_NODE;
		break;
	case LDP_IPV6_NODE:
		vty->node = LDP_IPV6_IFACE_NODE;
		break;
	default:
		break;
	}

	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_LDPD, ldp_l2vpn_word_type_vpls, ldp_l2vpn_word_type_vpls_cmd,
	"l2vpn WORD type vpls",
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n")
{
	vty->node = LDP_L2VPN_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_LDPD, ldp_member_pseudowire_ifname,
	ldp_member_pseudowire_ifname_cmd, "member pseudowire IFNAME",
	"L2VPN member configuration\n"
	"Pseudowire interface\n"
	"Interface's name\n")
{
	vty->node = LDP_PSEUDOWIRE_NODE;
	return CMD_SUCCESS;
}
#endif

DEFUNSH(VTYSH_ISISD, router_isis, router_isis_cmd, "router isis WORD",
	ROUTER_STR
	"ISO IS-IS\n"
	"ISO Routing area tag\n")
{
	vty->node = ISIS_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_FABRICD, router_openfabric, router_openfabric_cmd, "router openfabric WORD",
	ROUTER_STR
	"OpenFabric routing protocol\n"
	"ISO Routing area tag\n")
{
	vty->node = OPENFABRIC_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_RMAP, vtysh_route_map, vtysh_route_map_cmd,
	"route-map WORD <deny|permit> (1-65535)",
	"Create route-map or enter route-map command mode\n"
	"Route map tag\n"
	"Route map denies set operations\n"
	"Route map permits set operations\n"
	"Sequence to insert to/delete from existing route-map entry\n")
{
	vty->node = RMAP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_PBRD, vtysh_pbr_map, vtysh_pbr_map_cmd,
	"pbr-map PBRMAP seq (1-700)",
	"Create pbr-map or enter pbr-map command mode\n"
	"The name of the PBR MAP\n"
	"Sequence to insert to/delete from existing pbr-map entry\n"
	"Sequence number\n")
{
	vty->node = PBRMAP_NODE;
	return CMD_SUCCESS;
}

#if HAVE_BFDD > 0
DEFUNSH(VTYSH_BFDD, bfd_enter, bfd_enter_cmd, "bfd", "Configure BFD peers\n")
{
	vty->node = BFD_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BFDD, bfd_peer_enter, bfd_peer_enter_cmd,
	"peer <A.B.C.D|X:X::X:X> [{multihop|local-address <A.B.C.D|X:X::X:X>|interface IFNAME|vrf NAME}]",
	"Configure peer\n"
	"IPv4 peer address\n"
	"IPv6 peer address\n"
	"Configure multihop\n"
	"Configure local address\n"
	"IPv4 local address\n"
	"IPv6 local address\n"
	INTERFACE_STR
	"Configure interface name to use\n"
	"Configure VRF\n"
	"Configure VRF name\n")
{
	vty->node = BFD_PEER_NODE;
	return CMD_SUCCESS;
}
#endif /* HAVE_BFDD */

DEFSH(VTYSH_PBRD, vtysh_no_pbr_map_cmd, "no pbr-map PBRMAP [seq (1-700)]",
	NO_STR
	"Delete pbr-map\n"
	"The name of  the PBR MAP\n"
	"Sequence to delete from existing pbr-map entry\n"
	"Sequence number\n")

DEFUNSH(VTYSH_ALL, vtysh_line_vty, vtysh_line_vty_cmd, "line vty",
	"Configure a terminal line\n"
	"Virtual terminal\n")
{
	vty->node = VTY_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_REALLYALL, vtysh_enable, vtysh_enable_cmd, "enable",
	"Turn on privileged mode command\n")
{
	vty->node = ENABLE_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_REALLYALL, vtysh_disable, vtysh_disable_cmd, "disable",
	"Turn off privileged mode command\n")
{
	if (vty->node == ENABLE_NODE)
		vty->node = VIEW_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_REALLYALL, vtysh_config_terminal, vtysh_config_terminal_cmd,
	"configure [terminal]",
	"Configuration from vty interface\n"
	"Configuration terminal\n")
{
	vty->node = CONFIG_NODE;
	return CMD_SUCCESS;
}

static int vtysh_exit(struct vty *vty)
{
	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		exit(0);
		break;
	case CONFIG_NODE:
		vty->node = ENABLE_NODE;
		break;
	case INTERFACE_NODE:
	case PW_NODE:
	case VRF_NODE:
	case NH_GROUP_NODE:
	case ZEBRA_NODE:
	case BGP_NODE:
	case RIP_NODE:
	case RIPNG_NODE:
	case OSPF_NODE:
	case OSPF6_NODE:
	case EIGRP_NODE:
	case BABEL_NODE:
	case LDP_NODE:
	case LDP_L2VPN_NODE:
	case ISIS_NODE:
	case OPENFABRIC_NODE:
	case RMAP_NODE:
	case PBRMAP_NODE:
	case VTY_NODE:
	case KEYCHAIN_NODE:
	case BFD_NODE:
	case RPKI_NODE:
		vtysh_execute("end");
		vtysh_execute("configure");
		vty->node = CONFIG_NODE;
		break;
	case BGP_VPNV4_NODE:
	case BGP_VPNV6_NODE:
	case BGP_IPV4_NODE:
	case BGP_IPV4M_NODE:
	case BGP_IPV4L_NODE:
	case BGP_IPV6_NODE:
	case BGP_IPV6M_NODE:
	case BGP_IPV6L_NODE:
	case BGP_FLOWSPECV4_NODE:
	case BGP_FLOWSPECV6_NODE:
	case BGP_VRF_POLICY_NODE:
	case BGP_EVPN_NODE:
	case BGP_VNC_DEFAULTS_NODE:
	case BGP_VNC_NVE_GROUP_NODE:
	case BGP_VNC_L2_GROUP_NODE:
	case BMP_NODE:
		vty->node = BGP_NODE;
		break;
	case BGP_EVPN_VNI_NODE:
		vty->node = BGP_EVPN_NODE;
		break;
	case LDP_IPV4_NODE:
	case LDP_IPV6_NODE:
		vty->node = LDP_NODE;
		break;
	case LDP_IPV4_IFACE_NODE:
		vty->node = LDP_IPV4_NODE;
		break;
	case LDP_IPV6_IFACE_NODE:
		vty->node = LDP_IPV6_NODE;
		break;
	case LDP_PSEUDOWIRE_NODE:
		vty->node = LDP_L2VPN_NODE;
		break;
	case KEYCHAIN_KEY_NODE:
		vty->node = KEYCHAIN_NODE;
		break;
	case LINK_PARAMS_NODE:
		vty->node = INTERFACE_NODE;
		break;
	case BFD_PEER_NODE:
		vty->node = BFD_NODE;
		break;
	default:
		break;
	}
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_REALLYALL, vtysh_exit_all, vtysh_exit_all_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_ALL, vtysh_quit_all, vtysh_quit_all_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_all(self, vty, argc, argv);
}

DEFUNSH(VTYSH_BGPD, exit_address_family, exit_address_family_cmd,
	"exit-address-family", "Exit from Address Family configuration mode\n")
{
	if (vty->node == BGP_IPV4_NODE || vty->node == BGP_IPV4M_NODE
	    || vty->node == BGP_IPV4L_NODE || vty->node == BGP_VPNV4_NODE
	    || vty->node == BGP_VPNV6_NODE || vty->node == BGP_IPV6_NODE
	    || vty->node == BGP_IPV6L_NODE || vty->node == BGP_IPV6M_NODE
	    || vty->node == BGP_EVPN_NODE
	    || vty->node == BGP_FLOWSPECV4_NODE
	    || vty->node == BGP_FLOWSPECV6_NODE)
		vty->node = BGP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, exit_vni, exit_vni_cmd, "exit-vni", "Exit from VNI mode\n")
{
	if (vty->node == BGP_EVPN_VNI_NODE)
		vty->node = BGP_EVPN_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, exit_vnc_config, exit_vnc_config_cmd, "exit-vnc",
	"Exit from VNC configuration mode\n")
{
	if (vty->node == BGP_VNC_DEFAULTS_NODE
	    || vty->node == BGP_VNC_NVE_GROUP_NODE
	    || vty->node == BGP_VNC_L2_GROUP_NODE)
		vty->node = BGP_NODE;
	return CMD_SUCCESS;

}

DEFUNSH(VTYSH_BGPD, rpki_exit, rpki_exit_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	vtysh_exit(vty);
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, rpki_quit, rpki_quit_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return rpki_exit(self, vty, argc, argv);
}

DEFUNSH(VTYSH_BGPD, bmp_exit, bmp_exit_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	vtysh_exit(vty);
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, bmp_quit, bmp_quit_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return bmp_exit(self, vty, argc, argv);
}

DEFUNSH(VTYSH_VRF, exit_vrf_config, exit_vrf_config_cmd, "exit-vrf",
	"Exit from VRF configuration mode\n")
{
	if (vty->node == VRF_NODE)
		vty->node = CONFIG_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD, exit_vrf_policy, exit_vrf_policy_cmd, "exit-vrf-policy",
	"Exit from VRF policy configuration mode\n")
{
	if (vty->node == BGP_VRF_POLICY_NODE)
		vty->node = BGP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_RIPD, vtysh_exit_ripd, vtysh_exit_ripd_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_RIPD, vtysh_quit_ripd, vtysh_quit_ripd_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_ripd(self, vty, argc, argv);
}

DEFUNSH(VTYSH_RIPNGD, vtysh_exit_ripngd, vtysh_exit_ripngd_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_RIPNGD, vtysh_quit_ripngd, vtysh_quit_ripngd_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_ripngd(self, vty, argc, argv);
}

DEFUNSH(VTYSH_RMAP, vtysh_exit_rmap, vtysh_exit_rmap_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_RMAP, vtysh_quit_rmap, vtysh_quit_rmap_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_rmap(self, vty, argc, argv);
}

DEFUNSH(VTYSH_PBRD, vtysh_exit_pbr_map, vtysh_exit_pbr_map_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_PBRD, vtysh_quit_pbr_map, vtysh_quit_pbr_map_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_rmap(self, vty, argc, argv);
}

DEFUNSH(VTYSH_BGPD, vtysh_exit_bgpd, vtysh_exit_bgpd_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_BGPD, vtysh_quit_bgpd, vtysh_quit_bgpd_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_bgpd(self, vty, argc, argv);
}

DEFUNSH(VTYSH_OSPFD, vtysh_exit_ospfd, vtysh_exit_ospfd_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_OSPFD, vtysh_quit_ospfd, vtysh_quit_ospfd_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_ospfd(self, vty, argc, argv);
}

DEFUNSH(VTYSH_EIGRPD, vtysh_exit_eigrpd, vtysh_exit_eigrpd_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_EIGRPD, vtysh_quit_eigrpd, vtysh_quit_eigrpd_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_EIGRPD, vtysh_exit_babeld, vtysh_exit_babeld_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_BABELD, vtysh_quit_babeld, vtysh_quit_babeld_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_OSPF6D, vtysh_exit_ospf6d, vtysh_exit_ospf6d_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_OSPF6D, vtysh_quit_ospf6d, vtysh_quit_ospf6d_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_ospf6d(self, vty, argc, argv);
}

#if defined(HAVE_LDPD)
DEFUNSH(VTYSH_LDPD, vtysh_exit_ldpd, vtysh_exit_ldpd_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

ALIAS(vtysh_exit_ldpd, vtysh_quit_ldpd_cmd, "quit",
      "Exit current mode and down to previous mode\n")
#endif

DEFUNSH(VTYSH_ISISD, vtysh_exit_isisd, vtysh_exit_isisd_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_ISISD, vtysh_quit_isisd, vtysh_quit_isisd_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_isisd(self, vty, argc, argv);
}

#if HAVE_BFDD > 0
DEFUNSH(VTYSH_BFDD, vtysh_exit_bfdd, vtysh_exit_bfdd_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

ALIAS(vtysh_exit_bfdd, vtysh_quit_bfdd_cmd, "quit",
      "Exit current mode and down to previous mode\n")
#endif

DEFUNSH(VTYSH_FABRICD, vtysh_exit_fabricd, vtysh_exit_fabricd_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_FABRICD, vtysh_quit_fabricd, vtysh_quit_fabricd_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_fabricd(self, vty, argc, argv);
}

DEFUNSH(VTYSH_ALL, vtysh_exit_line_vty, vtysh_exit_line_vty_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_ALL, vtysh_quit_line_vty, vtysh_quit_line_vty_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_line_vty(self, vty, argc, argv);
}

DEFUNSH(VTYSH_INTERFACE, vtysh_interface, vtysh_interface_cmd,
	"interface IFNAME [vrf NAME]",
	"Select an interface to configure\n"
	"Interface's name\n" VRF_CMD_HELP_STR)
{
	vty->node = INTERFACE_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ZEBRA, vtysh_pseudowire, vtysh_pseudowire_cmd,
	"pseudowire IFNAME",
	"Static pseudowire configuration\n"
	"Pseudowire name\n")
{
	vty->node = PW_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_PBRD | VTYSH_SHARPD, vtysh_nexthop_group, vtysh_nexthop_group_cmd,
	"nexthop-group NHGNAME",
	"Nexthop Group configuration\n"
	"Name of the Nexthop Group\n")
{
	vty->node = NH_GROUP_NODE;
	return CMD_SUCCESS;
}

DEFSH(VTYSH_PBRD | VTYSH_SHARPD, vtysh_no_nexthop_group_cmd,
      "no nexthop-group NHGNAME",
      NO_STR
      "Nexthop Group Configuration\n"
      "Name of the Nexthop Group\n")

DEFUNSH(VTYSH_VRF, vtysh_vrf, vtysh_vrf_cmd, "vrf NAME",
	"Select a VRF to configure\n"
	"VRF's name\n")
{
	vty->node = VRF_NODE;
	return CMD_SUCCESS;
}

DEFSH(VTYSH_ZEBRA, vtysh_vrf_netns_cmd,
      "netns NAME",
      "Attach VRF to a Namespace\n"
      "The file name in " NS_RUN_DIR ", or a full pathname\n")

DEFSH(VTYSH_ZEBRA, vtysh_no_vrf_netns_cmd,
      "no netns [NAME]",
      NO_STR
      "Detach VRF from a Namespace\n"
      "The file name in " NS_RUN_DIR ", or a full pathname\n")

DEFUNSH(VTYSH_VRF, vtysh_exit_vrf, vtysh_exit_vrf_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_VRF, vtysh_quit_vrf, vtysh_quit_vrf_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_vrf(self, vty, argc, argv);
}

DEFUNSH(VTYSH_PBRD | VTYSH_SHARPD, vtysh_exit_nexthop_group, vtysh_exit_nexthop_group_cmd,
	"exit", "Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_PBRD | VTYSH_SHARPD, vtysh_quit_nexthop_group, vtysh_quit_nexthop_group_cmd,
	"quit", "Exit current mode and down to previous mode\n")
{
	return vtysh_exit_nexthop_group(self, vty, argc, argv);
}

DEFUNSH(VTYSH_INTERFACE, vtysh_exit_interface, vtysh_exit_interface_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_INTERFACE, vtysh_quit_interface, vtysh_quit_interface_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_interface(self, vty, argc, argv);
}

DEFUN (vtysh_show_poll,
       vtysh_show_poll_cmd,
       "show thread poll",
       SHOW_STR
       "Thread information\n"
       "Thread Poll Information\n")
{
	unsigned int i;
	int ret = CMD_SUCCESS;
	char line[100];

	snprintf(line, sizeof(line), "do show thread poll\n");
	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0) {
			vty_out(vty, "Thread statistics for %s:\n",
				vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line);
			vty_out(vty, "\n");
		}
	return ret;
}

#ifndef EXCLUDE_CPU_TIME
DEFUN (vtysh_show_thread,
       vtysh_show_thread_cmd,
       "show thread cpu [FILTER]",
       SHOW_STR
       "Thread information\n"
       "Thread CPU usage\n"
       "Display filter (rwtexb)\n")
{
	unsigned int i;
	int idx = 0;
	int ret = CMD_SUCCESS;
	char line[100];

	const char *filter =
		argv_find(argv, argc, "FILTER", &idx) ? argv[idx]->arg : "";

	snprintf(line, sizeof(line), "do show thread cpu %s\n", filter);
	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0) {
			vty_out(vty, "Thread statistics for %s:\n",
				vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line);
			vty_out(vty, "\n");
		}
	return ret;
}
#endif

DEFUN (vtysh_show_work_queues,
       vtysh_show_work_queues_cmd,
       "show work-queues",
       SHOW_STR
       "Work Queue information\n")
{
	unsigned int i;
	int ret = CMD_SUCCESS;
	char line[] = "do show work-queues\n";

	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0) {
			vty_out(vty, "Work queue statistics for %s:\n",
				vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line);
			vty_out(vty, "\n");
		}

	return ret;
}

DEFUN (vtysh_show_work_queues_daemon,
       vtysh_show_work_queues_daemon_cmd,
       "show work-queues " DAEMONS_LIST,
       SHOW_STR
       "Work Queue information\n"
       DAEMONS_STR)
{
	int idx_protocol = 2;

	return vtysh_client_execute_name(argv[idx_protocol]->text,
					 "show work-queues\n");
}

DEFUNSH(VTYSH_ZEBRA, vtysh_link_params, vtysh_link_params_cmd, "link-params",
	LINK_PARAMS_STR)
{
	vty->node = LINK_PARAMS_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ZEBRA, exit_link_params, exit_link_params_cmd, "exit-link-params",
	"Exit from Link Params configuration node\n")
{
	if (vty->node == LINK_PARAMS_NODE)
		vty->node = INTERFACE_NODE;
	return CMD_SUCCESS;
}

static int show_per_daemon(const char *line, const char *headline)
{
	unsigned int i;
	int ret = CMD_SUCCESS;

	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0) {
			vty_out(vty, headline, vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line);
			vty_out(vty, "\n");
		}

	return ret;
}

DEFUNSH_HIDDEN (0x00,
                vtysh_debug_all,
                vtysh_debug_all_cmd,
                "[no] debug all",
                NO_STR
                DEBUG_STR
                "Toggle all debugs on or off\n")
{
	return CMD_SUCCESS;
}

DEFUN (vtysh_show_debugging,
       vtysh_show_debugging_cmd,
       "show debugging",
       SHOW_STR
       DEBUG_STR)
{
	return show_per_daemon("do show debugging\n", "");
}

DEFUN (vtysh_show_debugging_hashtable,
       vtysh_show_debugging_hashtable_cmd,
       "show debugging hashtable [statistics]",
       SHOW_STR
       DEBUG_STR
       "Statistics about hash tables\n"
       "Statistics about hash tables\n")
{
	vty_out(vty, "\n");
	vty_out(vty,
		"Load factor (LF) - average number of elements across all buckets\n");
	vty_out(vty,
		"Full load factor (FLF) - average number of elements across full buckets\n\n");
	vty_out(vty,
		"Standard deviation (SD) is calculated for both the LF and FLF\n");
	vty_out(vty,
		"and indicates the typical deviation of bucket chain length\n");
	vty_out(vty, "from the value in the corresponding load factor.\n\n");

	return show_per_daemon("do show debugging hashtable\n",
			       "Hashtable statistics for %s:\n");
}

DEFUN (vtysh_show_error_code,
       vtysh_show_error_code_cmd,
       "show error <(1-4294967296)|all> [json]",
       SHOW_STR
       "Information on errors\n"
       "Error code to get info about\n"
       "Information on all errors\n"
       JSON_STR)
{
	uint32_t arg = 0;

	if (!strmatch(argv[2]->text, "all"))
		arg = strtoul(argv[2]->arg, NULL, 10);

	/* If it's not a shared code, send it to all the daemons */
	if (arg < LIB_FERR_START || arg > LIB_FERR_END) {
		char *fcmd = argv_concat(argv, argc, 0);
		char cmd[256];

		snprintf(cmd, sizeof(cmd), "do %s", fcmd);
		show_per_daemon(cmd, "");
		XFREE(MTYPE_TMP, fcmd);
		/* Otherwise, print it ourselves to avoid duplication */
	} else {
		bool json = strmatch(argv[argc - 1]->text, "json");

		if (!strmatch(argv[2]->text, "all"))
			arg = strtoul(argv[2]->arg, NULL, 10);

		log_ref_display(vty, arg, json);
	}

	return CMD_SUCCESS;
}

/* Northbound. */
DEFUN (show_yang_operational_data,
       show_yang_operational_data_cmd,
       "show yang operational-data XPATH\
         [{\
	   format <json|xml>\
	   |translate WORD\
	 }]" DAEMONS_LIST,
       SHOW_STR
       "YANG information\n"
       "Show YANG operational data\n"
       "XPath expression specifying the YANG data path\n"
       "Set the output format\n"
       "JavaScript Object Notation\n"
       "Extensible Markup Language\n"
       "Translate operational data\n"
       "YANG module translator\n"
       DAEMONS_STR)
{
	int idx_protocol = argc - 1;
	char *fcmd = argv_concat(argv, argc - 1, 0);
	int ret = vtysh_client_execute_name(argv[idx_protocol]->text, fcmd);
	XFREE(MTYPE_TMP, fcmd);
	return ret;
}

DEFUNSH(VTYSH_ALL, debug_nb,
	debug_nb_cmd,
	"[no] debug northbound\
	   [<\
	    callbacks [{configuration|state|rpc}]\
	    |notifications\
	    |events\
	    |libyang\
	   >]",
	NO_STR
	DEBUG_STR
	"Northbound debugging\n"
	"Callbacks\n"
	"Configuration\n"
	"State\n"
	"RPC\n"
	"Notifications\n"
	"Events\n"
	"libyang debugging\n")
{
	return CMD_SUCCESS;
}

/* Memory */
DEFUN (vtysh_show_memory,
       vtysh_show_memory_cmd,
       "show memory",
       SHOW_STR
       "Memory statistics\n")
{
	return show_per_daemon("do show memory\n", "Memory statistics for %s:\n");
}

DEFUN (vtysh_show_modules,
       vtysh_show_modules_cmd,
       "show modules",
       SHOW_STR
       "Loaded modules\n")
{
	return show_per_daemon("do show modules\n",
			       "Module information for %s:\n");
}

/* Logging commands. */
DEFUN (vtysh_show_logging,
       vtysh_show_logging_cmd,
       "show logging",
       SHOW_STR
       "Show current logging configuration\n")
{
	return show_per_daemon("do show logging\n",
			       "Logging configuration for %s:\n");
}

DEFUNSH(VTYSH_ALL, vtysh_log_stdout, vtysh_log_stdout_cmd, "log stdout",
	"Logging control\n"
	"Set stdout logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_log_stdout_level, vtysh_log_stdout_level_cmd,
	"log stdout <emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>",
	"Logging control\n"
	"Set stdout logging level\n" LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_log_stdout, no_vtysh_log_stdout_cmd,
	"no log stdout [LEVEL]", NO_STR
	"Logging control\n"
	"Cancel logging to stdout\n"
	"Logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_log_file, vtysh_log_file_cmd, "log file FILENAME",
	"Logging control\n"
	"Logging to file\n"
	"Logging filename\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_log_file_level, vtysh_log_file_level_cmd,
	"log file FILENAME <emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>",
	"Logging control\n"
	"Logging to file\n"
	"Logging filename\n" LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_log_file, no_vtysh_log_file_cmd,
	"no log file [FILENAME [LEVEL]]", NO_STR
	"Logging control\n"
	"Cancel logging to file\n"
	"Logging file name\n"
	"Logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_log_monitor, vtysh_log_monitor_cmd,
	"log monitor [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
	"Logging control\n"
	"Set terminal line (monitor) logging level\n" LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_log_monitor, no_vtysh_log_monitor_cmd,
	"no log monitor [LEVEL]", NO_STR
	"Logging control\n"
	"Disable terminal line (monitor) logging\n"
	"Logging level\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_log_syslog, vtysh_log_syslog_cmd,
	"log syslog [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
	"Logging control\n"
	"Set syslog logging level\n" LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_log_syslog, no_vtysh_log_syslog_cmd,
	"no log syslog [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
	NO_STR
	"Logging control\n"
	"Cancel logging to syslog\n"
	LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_log_facility, vtysh_log_facility_cmd,
	"log facility <kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>",
	"Logging control\n"
	"Facility parameter for syslog messages\n" LOG_FACILITY_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_log_facility, no_vtysh_log_facility_cmd,
	"no log facility [<kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>]",
	NO_STR
	"Logging control\n"
	"Reset syslog facility to default (daemon)\n"
	LOG_FACILITY_DESC)
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_log_record_priority, vtysh_log_record_priority_cmd,
	"log record-priority",
	"Logging control\n"
	"Log the priority of the message within the message\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_log_record_priority,
	no_vtysh_log_record_priority_cmd, "no log record-priority", NO_STR
	"Logging control\n"
	"Do not log the priority of the message within the message\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_log_timestamp_precision,
	vtysh_log_timestamp_precision_cmd, "log timestamp precision (0-6)",
	"Logging control\n"
	"Timestamp configuration\n"
	"Set the timestamp precision\n"
	"Number of subsecond digits\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_debug_memstats,
	vtysh_debug_memstats_cmd, "[no] debug memstats-at-exit",
	NO_STR
	"Debug\n"
	"Print memory statistics at exit\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_log_timestamp_precision,
	no_vtysh_log_timestamp_precision_cmd, "no log timestamp precision",
	NO_STR
	"Logging control\n"
	"Timestamp configuration\n"
	"Reset the timestamp precision to the default value of 0\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_service_password_encrypt,
	vtysh_service_password_encrypt_cmd, "service password-encryption",
	"Set up miscellaneous service\n"
	"Enable encrypted passwords\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_service_password_encrypt,
	no_vtysh_service_password_encrypt_cmd, "no service password-encryption",
	NO_STR
	"Set up miscellaneous service\n"
	"Enable encrypted passwords\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_config_password, vtysh_password_cmd,
	"password [(8-8)] LINE",
	"Modify the terminal connection password\n"
	"Specifies a HIDDEN password will follow\n"
	"The password string\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_config_password, no_vtysh_password_cmd,
	"no password", NO_STR
	"Modify the terminal connection password\n")
{
	vty_out(vty, NO_PASSWD_CMD_WARNING);

	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, vtysh_config_enable_password, vtysh_enable_password_cmd,
	"enable password [(8-8)] LINE",
	"Modify enable password parameters\n"
	"Assign the privileged level password\n"
	"Specifies a HIDDEN password will follow\n"
	"The 'enable' password string\n")
{
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_ALL, no_vtysh_config_enable_password,
	no_vtysh_enable_password_cmd, "no enable password", NO_STR
	"Modify enable password parameters\n"
	"Assign the privileged level password\n")
{
	vty_out(vty, NO_PASSWD_CMD_WARNING);

	return CMD_SUCCESS;
}

/* Log filter */
DEFUN (vtysh_log_filter,
       vtysh_log_filter_cmd,
       "[no] log-filter WORD ["DAEMONS_LIST"]",
       NO_STR
       FILTER_LOG_STR
       "String to filter by\n"
       DAEMONS_STR)
{
	char *filter = NULL;
	char *daemon = NULL;
	int found = 0;
	int idx = 0;
	int daemon_idx = 2;
	int total_len = 0;
	int len = 0;

	char line[ZLOG_FILTER_LENGTH_MAX + 20];

	found = argv_find(argv, argc, "no", &idx);
	if (found == 1) {
		len = snprintf(line, sizeof(line), "no log-filter");
		daemon_idx += 1;
	} else
		len = snprintf(line, sizeof(line), "log-filter");

	total_len += len;

	idx = 1;
	found = argv_find(argv, argc, "WORD", &idx);
	if (found != 1) {
		vty_out(vty, "%% No filter string given\n");
		return CMD_WARNING;
	}
	filter = argv[idx]->arg;

	if (strnlen(filter, ZLOG_FILTER_LENGTH_MAX + 1)
	    > ZLOG_FILTER_LENGTH_MAX) {
		vty_out(vty, "%% Filter is too long\n");
		return CMD_WARNING;
	}

	len = snprintf(line + total_len, sizeof(line) - total_len, " %s\n",
		       filter);

	if ((len < 0) || (size_t)(total_len + len) > sizeof(line)) {
		vty_out(vty, "%% Error buffering filter to daemons\n");
		return CMD_ERR_INCOMPLETE;
	}

	if (argc >= (daemon_idx + 1))
		daemon = argv[daemon_idx]->text;

	if (daemon != NULL) {
		vty_out(vty, "Applying log filter change to %s:\n", daemon);
		return vtysh_client_execute_name(daemon, line);
	} else
		return show_per_daemon(line,
				       "Applying log filter change to %s:\n");
}

/* Clear log filters */
DEFUN (vtysh_log_filter_clear,
       vtysh_log_filter_clear_cmd,
       "log-filter clear ["DAEMONS_LIST"]",
       FILTER_LOG_STR
       CLEAR_STR
       DAEMONS_STR)
{
	char *daemon = NULL;
	int daemon_idx = 2;

	char line[] = "clear log-filter\n";

	if (argc >= (daemon_idx + 1))
		daemon = argv[daemon_idx]->text;

	if (daemon != NULL) {
		vty_out(vty, "Clearing all filters applied to %s:\n", daemon);
		return vtysh_client_execute_name(daemon, line);
	} else
		return show_per_daemon(line,
				       "Clearing all filters applied to %s:\n");
}

/* Show log filter */
DEFUN (vtysh_show_log_filter,
       vtysh_show_log_filter_cmd,
       "show log-filter",
       SHOW_STR
       FILTER_LOG_STR)
{
	char line[] = "do show log-filter\n";

	return show_per_daemon(line, "Log filters applied to %s:\n");
}

DEFUN (vtysh_write_terminal,
       vtysh_write_terminal_cmd,
       "write terminal ["DAEMONS_LIST"]",
       "Write running configuration to memory, network, or terminal\n"
       "Write to terminal\n"
       DAEMONS_STR)
{
	unsigned int i;
	char line[] = "do write terminal\n";

	vty_out(vty, "Building configuration...\n");
	vty_out(vty, "\nCurrent configuration:\n");
	vty_out(vty, "!\n");

	for (i = 0; i < array_size(vtysh_client); i++)
		if ((argc < 3)
		    || (strmatch(vtysh_client[i].name, argv[2]->text)))
			vtysh_client_config(&vtysh_client[i], line);

	/* Integrate vtysh specific configuration. */
	vty_open_pager(vty);
	vtysh_config_write();
	vtysh_config_dump();
	vty_close_pager(vty);
	vty_out(vty, "end\n");

	return CMD_SUCCESS;
}

DEFUN (vtysh_show_running_config,
       vtysh_show_running_config_cmd,
       "show running-config ["DAEMONS_LIST"]",
       SHOW_STR
       "Current operating configuration\n"
       DAEMONS_STR)
{
	return vtysh_write_terminal(self, vty, argc, argv);
}

DEFUN (vtysh_integrated_config,
       vtysh_integrated_config_cmd,
       "service integrated-vtysh-config",
       "Set up miscellaneous service\n"
       "Write configuration into integrated file\n")
{
	vtysh_write_integrated = WRITE_INTEGRATED_YES;
	return CMD_SUCCESS;
}

DEFUN (no_vtysh_integrated_config,
       no_vtysh_integrated_config_cmd,
       "no service integrated-vtysh-config",
       NO_STR
       "Set up miscellaneous service\n"
       "Write configuration into integrated file\n")
{
	vtysh_write_integrated = WRITE_INTEGRATED_NO;
	return CMD_SUCCESS;
}

static void backup_config_file(const char *fbackup)
{
	char *integrate_sav = NULL;

	size_t integrate_sav_sz = strlen(fbackup) + strlen(CONF_BACKUP_EXT) + 1;
	integrate_sav = malloc(integrate_sav_sz);
	strlcpy(integrate_sav, fbackup, integrate_sav_sz);
	strlcat(integrate_sav, CONF_BACKUP_EXT, integrate_sav_sz);

	/* Move current configuration file to backup config file. */
	if (unlink(integrate_sav) != 0) {
		vty_out(vty, "Warning: %s unlink failed\n", integrate_sav);
	}
	if (rename(fbackup, integrate_sav) != 0) {
		vty_out(vty, "Error renaming %s to %s\n", fbackup,
			integrate_sav);
	}
	free(integrate_sav);
}

int vtysh_write_config_integrated(void)
{
	unsigned int i;
	char line[] = "do write terminal\n";
	FILE *fp;
	int fd;
#ifdef FRR_USER
	struct passwd *pwentry;
#endif
#ifdef FRR_GROUP
	struct group *grentry;
#endif
	uid_t uid = -1;
	gid_t gid = -1;
	struct stat st;
	int err = 0;

	vty_out(vty, "Building Configuration...\n");

	backup_config_file(frr_config);
	fp = fopen(frr_config, "w");
	if (fp == NULL) {
		vty_out(vty,
			"%% Error: failed to open configuration file %s: %s\n",
			frr_config, safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}
	fd = fileno(fp);

	for (i = 0; i < array_size(vtysh_client); i++)
		vtysh_client_config(&vtysh_client[i], line);

	vtysh_config_write();
	vty->of_saved = vty->of;
	vty->of = fp;
	vtysh_config_dump();
	vty->of = vty->of_saved;

	if (fchmod(fd, CONFIGFILE_MASK) != 0) {
		printf("%% Warning: can't chmod configuration file %s: %s\n",
		       frr_config, safe_strerror(errno));
		err++;
	}

#ifdef FRR_USER
	pwentry = getpwnam(FRR_USER);
	if (pwentry)
		uid = pwentry->pw_uid;
	else {
		printf("%% Warning: could not look up user \"%s\"\n", FRR_USER);
		err++;
	}
#endif
#ifdef FRR_GROUP
	grentry = getgrnam(FRR_GROUP);
	if (grentry)
		gid = grentry->gr_gid;
	else {
		printf("%% Warning: could not look up group \"%s\"\n",
		       FRR_GROUP);
		err++;
	}
#endif

	if (!fstat(fd, &st)) {
		if (st.st_uid == uid)
			uid = -1;
		if (st.st_gid == gid)
			gid = -1;
		if ((uid != (uid_t)-1 || gid != (gid_t)-1)
		    && fchown(fd, uid, gid)) {
			printf("%% Warning: can't chown configuration file %s: %s\n",
			       frr_config, safe_strerror(errno));
			err++;
		}
	} else {
		printf("%% Warning: stat() failed on %s: %s\n", frr_config,
		       safe_strerror(errno));
		err++;
	}

	fclose(fp);

	printf("Integrated configuration saved to %s\n", frr_config);
	if (err)
		return CMD_WARNING;

	printf("[OK]\n");
	return CMD_SUCCESS;
}

static bool want_config_integrated(void)
{
	struct stat s;

	switch (vtysh_write_integrated) {
	case WRITE_INTEGRATED_UNSPECIFIED:
		if (stat(frr_config, &s) && errno == ENOENT)
			return false;
		return true;
	case WRITE_INTEGRATED_NO:
		return false;
	case WRITE_INTEGRATED_YES:
		return true;
	}
	return true;
}

DEFUN (vtysh_write_memory,
       vtysh_write_memory_cmd,
       "write [<memory|file>]",
       "Write running configuration to memory, network, or terminal\n"
       "Write configuration to the file (same as write file)\n"
       "Write configuration to the file (same as write memory)\n")
{
	int ret = CMD_SUCCESS;
	char line[] = "do write memory\n";
	unsigned int i;

	vty_out(vty, "Note: this version of vtysh never writes vtysh.conf\n");

	/* If integrated frr.conf explicitely set. */
	if (want_config_integrated()) {
		ret = CMD_WARNING_CONFIG_FAILED;

		/* first attempt to use watchfrr if it's available */
		bool used_watchfrr = false;

		for (i = 0; i < array_size(vtysh_client); i++)
			if (vtysh_client[i].flag == VTYSH_WATCHFRR)
				break;
		if (i < array_size(vtysh_client) && vtysh_client[i].fd != -1) {
			used_watchfrr = true;
			ret = vtysh_client_execute(&vtysh_client[i],
						   "do write integrated");
		}

		/*
		 * If we didn't use watchfrr, fallback to writing the config
		 * ourselves
		 */
		if (!used_watchfrr) {
			printf("\nWarning: attempting direct configuration write without "
			       "watchfrr.\nFile permissions and ownership may be "
			       "incorrect, or write may fail.\n\n");
			ret = vtysh_write_config_integrated();
		}
		return ret;
	}

	vty_out(vty, "Building Configuration...\n");

	for (i = 0; i < array_size(vtysh_client); i++)
		ret = vtysh_client_execute(&vtysh_client[i], line);

	return ret;
}

DEFUN (vtysh_copy_running_config,
       vtysh_copy_running_config_cmd,
       "copy running-config startup-config",
       "Copy from one file to another\n"
       "Copy from current system configuration\n"
       "Copy to startup configuration\n")
{
	return vtysh_write_memory(self, vty, argc, argv);
}

DEFUN (vtysh_terminal_paginate,
       vtysh_terminal_paginate_cmd,
       "[no] terminal paginate",
       NO_STR
       "Set terminal line parameters\n"
       "Use pager for output scrolling\n")
{
	free(vtysh_pager_name);
	vtysh_pager_name = NULL;

	if (strcmp(argv[0]->text, "no"))
		vtysh_pager_envdef(true);
	return CMD_SUCCESS;
}

DEFUN (vtysh_terminal_length,
       vtysh_terminal_length_cmd,
       "[no] terminal length (0-4294967295)",
       NO_STR
       "Set terminal line parameters\n"
       "Set number of lines on a screen\n"
       "Number of lines on screen (0 for no pausing, nonzero to use pager)\n")
{
	int idx_number = 2;
	unsigned long lines;

	free(vtysh_pager_name);
	vtysh_pager_name = NULL;

	if (!strcmp(argv[0]->text, "no") || !strcmp(argv[1]->text, "no")) {
		/* "terminal no length" = use VTYSH_PAGER */
		vtysh_pager_envdef(true);
		return CMD_SUCCESS;
	}

	lines = strtoul(argv[idx_number]->arg, NULL, 10);
	if (lines != 0) {
		vty_out(vty,
			"%% The \"terminal length\" command is deprecated and its value is ignored.\n"
			"%% Please use \"terminal paginate\" instead with OS TTY length handling.\n");
		vtysh_pager_envdef(true);
	}

	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(vtysh_terminal_length,
       vtysh_terminal_no_length_cmd,
       "terminal no length",
       "Set terminal line parameters\n"
       NO_STR
       "Set number of lines on a screen\n")

DEFUN (vtysh_show_daemons,
       vtysh_show_daemons_cmd,
       "show daemons",
       SHOW_STR
       "Show list of running daemons\n")
{
	unsigned int i;

	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0)
			vty_out(vty, " %s", vtysh_client[i].name);
	vty_out(vty, "\n");

	return CMD_SUCCESS;
}

/* Execute command in child process. */
static void execute_command(const char *command, int argc, const char *arg1,
			    const char *arg2)
{
	pid_t pid;
	int status;

	/* Call fork(). */
	pid = fork();

	if (pid < 0) {
		/* Failure of fork(). */
		fprintf(stderr, "Can't fork: %s\n", safe_strerror(errno));
		exit(1);
	} else if (pid == 0) {
		/* This is child process. */
		switch (argc) {
		case 0:
			execlp(command, command, (const char *)NULL);
			break;
		case 1:
			execlp(command, command, arg1, (const char *)NULL);
			break;
		case 2:
			execlp(command, command, arg1, arg2,
			       (const char *)NULL);
			break;
		}

		/* When execlp suceed, this part is not executed. */
		fprintf(stderr, "Can't execute %s: %s\n", command,
			safe_strerror(errno));
		exit(1);
	} else {
		/* This is parent. */
		execute_flag = 1;
		wait4(pid, &status, 0, NULL);
		execute_flag = 0;
	}
}

DEFUN (vtysh_ping,
       vtysh_ping_cmd,
       "ping WORD",
       "Send echo messages\n"
       "Ping destination address or hostname\n")
{
	int idx = 1;

	argv_find(argv, argc, "WORD", &idx);
	execute_command("ping", 1, argv[idx]->arg, NULL);
	return CMD_SUCCESS;
}

ALIAS(vtysh_ping, vtysh_ping_ip_cmd, "ping ip WORD",
      "Send echo messages\n"
      "IP echo\n"
      "Ping destination address or hostname\n")

DEFUN (vtysh_traceroute,
       vtysh_traceroute_cmd,
       "traceroute WORD",
       "Trace route to destination\n"
       "Trace route to destination address or hostname\n")
{
	int idx = 1;

	argv_find(argv, argc, "WORD", &idx);
	execute_command("traceroute", 1, argv[idx]->arg, NULL);
	return CMD_SUCCESS;
}

ALIAS(vtysh_traceroute, vtysh_traceroute_ip_cmd, "traceroute ip WORD",
      "Trace route to destination\n"
      "IP trace\n"
      "Trace route to destination address or hostname\n")

DEFUN (vtysh_mtrace,
       vtysh_mtrace_cmd,
       "mtrace WORD [WORD]",
       "Multicast trace route to multicast source\n"
       "Multicast trace route to multicast source address\n"
       "Multicast trace route for multicast group address\n")
{
	if (argc == 2)
		execute_command("mtracebis", 1, argv[1]->arg, NULL);
	else
		execute_command("mtracebis", 2, argv[1]->arg, argv[2]->arg);
	return CMD_SUCCESS;
}

DEFUN (vtysh_ping6,
       vtysh_ping6_cmd,
       "ping ipv6 WORD",
       "Send echo messages\n"
       "IPv6 echo\n"
       "Ping destination address or hostname\n")
{
	execute_command("ping6", 1, argv[2]->arg, NULL);
	return CMD_SUCCESS;
}

DEFUN (vtysh_traceroute6,
       vtysh_traceroute6_cmd,
       "traceroute ipv6 WORD",
       "Trace route to destination\n"
       "IPv6 trace\n"
       "Trace route to destination address or hostname\n")
{
	execute_command("traceroute6", 1, argv[2]->arg, NULL);
	return CMD_SUCCESS;
}

#if defined(HAVE_SHELL_ACCESS)
DEFUN (vtysh_telnet,
       vtysh_telnet_cmd,
       "telnet WORD",
       "Open a telnet connection\n"
       "IP address or hostname of a remote system\n")
{
	execute_command("telnet", 1, argv[1]->arg, NULL);
	return CMD_SUCCESS;
}

DEFUN (vtysh_telnet_port,
       vtysh_telnet_port_cmd,
       "telnet WORD PORT",
       "Open a telnet connection\n"
       "IP address or hostname of a remote system\n"
       "TCP Port number\n")
{
	execute_command("telnet", 2, argv[1]->arg, argv[2]->arg);
	return CMD_SUCCESS;
}

DEFUN (vtysh_ssh,
       vtysh_ssh_cmd,
       "ssh WORD",
       "Open an ssh connection\n"
       "[user@]host\n")
{
	execute_command("ssh", 1, argv[1]->arg, NULL);
	return CMD_SUCCESS;
}

DEFUN (vtysh_start_shell,
       vtysh_start_shell_cmd,
       "start-shell",
       "Start UNIX shell\n")
{
	execute_command("sh", 0, NULL, NULL);
	return CMD_SUCCESS;
}

DEFUN (vtysh_start_bash,
       vtysh_start_bash_cmd,
       "start-shell bash",
       "Start UNIX shell\n"
       "Start bash\n")
{
	execute_command("bash", 0, NULL, NULL);
	return CMD_SUCCESS;
}

DEFUN (vtysh_start_zsh,
       vtysh_start_zsh_cmd,
       "start-shell zsh",
       "Start UNIX shell\n"
       "Start Z shell\n")
{
	execute_command("zsh", 0, NULL, NULL);
	return CMD_SUCCESS;
}
#endif

DEFUN (config_list,
       config_list_cmd,
       "list [permutations]",
       "Print command list\n"
       "Print all possible command permutations\n")
{
	return cmd_list_cmds(vty, argc == 2);
}

DEFUN (vtysh_output_file,
       vtysh_output_file_cmd,
       "output file FILE",
       "Direct vtysh output to file\n"
       "Direct vtysh output to file\n"
       "Path to dump output to\n")
{
	const char *path = argv[argc - 1]->arg;
	vty->of = fopen(path, "a");
	if (!vty->of) {
		vty_out(vty, "Failed to open file '%s': %s\n", path,
			safe_strerror(errno));
		vty->of = stdout;
	}
	return CMD_SUCCESS;
}

DEFUN (no_vtysh_output_file,
       no_vtysh_output_file_cmd,
       "no output file [FILE]",
       NO_STR
       "Direct vtysh output to file\n"
       "Direct vtysh output to file\n"
       "Path to dump output to\n")
{
	if (vty->of != stdout) {
		fclose(vty->of);
		vty->of = stdout;
	}
	return CMD_SUCCESS;
}

DEFUN(find,
      find_cmd,
      "find REGEX",
      "Find CLI command matching a regular expression\n"
      "Search pattern (POSIX regex)\n")
{
	char *pattern = argv[1]->arg;
	const struct cmd_node *node;
	const struct cmd_element *cli;
	vector clis;

	regex_t exp = {};

	int cr = regcomp(&exp, pattern, REG_NOSUB | REG_EXTENDED);

	if (cr != 0) {
		switch (cr) {
		case REG_BADBR:
			vty_out(vty, "%% Invalid \\{...\\} expression\n");
			break;
		case REG_BADRPT:
			vty_out(vty, "%% Bad repetition operator\n");
			break;
		case REG_BADPAT:
			vty_out(vty, "%% Regex syntax error\n");
			break;
		case REG_ECOLLATE:
			vty_out(vty, "%% Invalid collating element\n");
			break;
		case REG_ECTYPE:
			vty_out(vty, "%% Invalid character class name\n");
			break;
		case REG_EESCAPE:
			vty_out(vty,
				"%% Regex ended with escape character (\\)\n");
			break;
		case REG_ESUBREG:
			vty_out(vty,
				"%% Invalid number in \\digit construction\n");
			break;
		case REG_EBRACK:
			vty_out(vty, "%% Unbalanced square brackets\n");
			break;
		case REG_EPAREN:
			vty_out(vty, "%% Unbalanced parentheses\n");
			break;
		case REG_EBRACE:
			vty_out(vty, "%% Unbalanced braces\n");
			break;
		case REG_ERANGE:
			vty_out(vty,
				"%% Invalid endpoint in range expression\n");
			break;
		case REG_ESPACE:
			vty_out(vty, "%% Failed to compile (out of memory)\n");
			break;
		}

		goto done;
	}


	for (unsigned int i = 0; i < vector_active(cmdvec); i++) {
		node = vector_slot(cmdvec, i);
		if (!node)
			continue;
		clis = node->cmd_vector;
		for (unsigned int j = 0; j < vector_active(clis); j++) {
			cli = vector_slot(clis, j);

			if (regexec(&exp, cli->string, 0, NULL, 0) == 0)
				vty_out(vty, "  (%s)  %s\n",
					node_names[node->node], cli->string);
		}
	}

done:
	regfree(&exp);
	return CMD_SUCCESS;
}

DEFUN_HIDDEN(show_cli_graph_vtysh,
	     show_cli_graph_vtysh_cmd,
	     "show cli graph",
	     SHOW_STR
	     "CLI reflection\n"
	     "Dump current command space as DOT graph\n")
{
	struct cmd_node *cn = vector_slot(cmdvec, vty->node);
	char *dot = cmd_graph_dump_dot(cn->cmdgraph);

	vty_out(vty, "%s\n", dot);
	XFREE(MTYPE_TMP, dot);
	return CMD_SUCCESS;
}

static void vtysh_install_default(enum node_type node)
{
	install_element(node, &config_list_cmd);
	install_element(node, &find_cmd);
	install_element(node, &show_cli_graph_vtysh_cmd);
	install_element(node, &vtysh_output_file_cmd);
	install_element(node, &no_vtysh_output_file_cmd);
}

/* Making connection to protocol daemon. */
static int vtysh_connect(struct vtysh_client *vclient)
{
	int ret;
	int sock, len;
	struct sockaddr_un addr;
	struct stat s_stat;
	const char *path;

	if (!vclient->path[0])
		snprintf(vclient->path, sizeof(vclient->path), "%s/%s.vty",
			 vtydir, vclient->name);
	path = vclient->path;

	/* Stat socket to see if we have permission to access it. */
	ret = stat(path, &s_stat);
	if (ret < 0 && errno != ENOENT) {
		fprintf(stderr, "vtysh_connect(%s): stat = %s\n", path,
			safe_strerror(errno));
		exit(1);
	}

	if (ret >= 0) {
		if (!S_ISSOCK(s_stat.st_mode)) {
			fprintf(stderr, "vtysh_connect(%s): Not a socket\n",
				path);
			exit(1);
		}
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
#ifdef DEBUG
		fprintf(stderr, "vtysh_connect(%s): socket = %s\n", path,
			safe_strerror(errno));
#endif /* DEBUG */
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ret = connect(sock, (struct sockaddr *)&addr, len);
	if (ret < 0) {
#ifdef DEBUG
		fprintf(stderr, "vtysh_connect(%s): connect = %s\n", path,
			safe_strerror(errno));
#endif /* DEBUG */
		close(sock);
		return -1;
	}
	vclient->fd = sock;

	return 0;
}

static int vtysh_reconnect(struct vtysh_client *vclient)
{
	int ret;

	fprintf(stderr, "Warning: connecting to %s...", vclient->name);
	ret = vtysh_connect(vclient);
	if (ret < 0) {
		fprintf(stderr, "failed!\n");
		return ret;
	}
	fprintf(stderr, "success!\n");
	if (vtysh_client_execute(vclient, "enable") < 0)
		return -1;
	return vtysh_execute_no_pager("end");
}

/* Return true if str ends with suffix, else return false */
static int ends_with(const char *str, const char *suffix)
{
	if (!str || !suffix)
		return 0;
	size_t lenstr = strlen(str);
	size_t lensuffix = strlen(suffix);
	if (lensuffix > lenstr)
		return 0;
	return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

static void vtysh_client_sorted_insert(struct vtysh_client *head_client,
				       struct vtysh_client *client)
{
	struct vtysh_client *prev_node, *current_node;

	prev_node = head_client;
	current_node = head_client->next;
	while (current_node) {
		if (strcmp(current_node->path, client->path) > 0)
			break;

		prev_node = current_node;
		current_node = current_node->next;
	}
	client->next = current_node;
	prev_node->next = client;
}

#define MAXIMUM_INSTANCES 10

static void vtysh_update_all_instances(struct vtysh_client *head_client)
{
	struct vtysh_client *client;
	DIR *dir;
	struct dirent *file;
	int n = 0;

	if (head_client->flag != VTYSH_OSPFD)
		return;

	/* ls vty_sock_dir and look for all files ending in .vty */
	dir = opendir(vtydir);
	if (dir) {
		while ((file = readdir(dir)) != NULL) {
			if (frrstr_startswith(file->d_name, "ospfd-")
			    && ends_with(file->d_name, ".vty")) {
				if (n == MAXIMUM_INSTANCES) {
					fprintf(stderr,
						"Parsing %s, client limit(%d) reached!\n",
						vtydir, n);
					break;
				}
				client = (struct vtysh_client *)malloc(
					sizeof(struct vtysh_client));
				client->fd = -1;
				client->name = "ospfd";
				client->flag = VTYSH_OSPFD;
				snprintf(client->path, sizeof(client->path),
					 "%s/%s", vtydir, file->d_name);
				client->next = NULL;
				vtysh_client_sorted_insert(head_client, client);
				n++;
			}
		}
		closedir(dir);
	}
}

static int vtysh_connect_all_instances(struct vtysh_client *head_client)
{
	struct vtysh_client *client;
	int rc = 0;

	vtysh_update_all_instances(head_client);

	client = head_client->next;
	while (client) {
		if (vtysh_connect(client) == 0)
			rc++;
		client = client->next;
	}

	return rc;
}

int vtysh_connect_all(const char *daemon_name)
{
	unsigned int i;
	int rc = 0;
	int matches = 0;

	for (i = 0; i < array_size(vtysh_client); i++) {
		if (!daemon_name
		    || !strcmp(daemon_name, vtysh_client[i].name)) {
			matches++;
			if (vtysh_connect(&vtysh_client[i]) == 0)
				rc++;

			rc += vtysh_connect_all_instances(&vtysh_client[i]);
		}
	}
	if (!matches)
		fprintf(stderr, "Error: no daemons match name %s!\n",
			daemon_name);
	return rc;
}

/* To disable readline's filename completion. */
static char *vtysh_completion_entry_function(const char *ignore,
					     int invoking_key)
{
	return NULL;
}

void vtysh_readline_init(void)
{
	/* readline related settings. */
	rl_initialize();
	rl_bind_key('?', (rl_command_func_t *)vtysh_rl_describe);
	rl_completion_entry_function = vtysh_completion_entry_function;
	rl_attempted_completion_function = new_completion;
}

char *vtysh_prompt(void)
{
	static char buf[512];

	snprintf(buf, sizeof buf, cmd_prompt(vty->node), cmd_hostname_get());
	return buf;
}

static void vtysh_ac_line(void *arg, const char *line)
{
	vector comps = arg;
	size_t i;
	for (i = 0; i < vector_active(comps); i++)
		if (!strcmp(line, (char *)vector_slot(comps, i)))
			return;
	vector_set(comps, XSTRDUP(MTYPE_COMPLETION, line));
}

static void vtysh_autocomplete(vector comps, struct cmd_token *token)
{
	char accmd[256];
	size_t i;

	snprintf(accmd, sizeof(accmd), "autocomplete %d %s %s", token->type,
		 token->text, token->varname ? token->varname : "-");

	vty->of_saved = vty->of;
	vty->of = NULL;
	for (i = 0; i < array_size(vtysh_client); i++)
		vtysh_client_run_all(&vtysh_client[i], accmd, 1, vtysh_ac_line,
				     comps);
	vty->of = vty->of_saved;
}

static const struct cmd_variable_handler vtysh_var_handler[] = {
	{/* match all */
	 .tokenname = NULL,
	 .varname = NULL,
	 .completions = vtysh_autocomplete},
	{.completions = NULL}};

void vtysh_uninit(void)
{
	if (vty->of != stdout)
		fclose(vty->of);
}

void vtysh_init_vty(void)
{
	/* Make vty structure. */
	vty = vty_new();
	vty->type = VTY_SHELL;
	vty->node = VIEW_NODE;

	/* set default output */
	vty->of = stdout;
	vtysh_pager_envdef(false);

	/* Initialize commands. */
	cmd_init(0);
	cmd_variable_handler_register(vtysh_var_handler);

	/* Install nodes. */
	install_node(&bgp_node, NULL);
	install_node(&rip_node, NULL);
	install_node(&interface_node, NULL);
	install_node(&pw_node, NULL);
	install_node(&link_params_node, NULL);
	install_node(&vrf_node, NULL);
	install_node(&nh_group_node, NULL);
	install_node(&rmap_node, NULL);
	install_node(&pbr_map_node, NULL);
	install_node(&zebra_node, NULL);
	install_node(&bgp_vpnv4_node, NULL);
	install_node(&bgp_vpnv6_node, NULL);
	install_node(&bgp_flowspecv4_node, NULL);
	install_node(&bgp_flowspecv6_node, NULL);
	install_node(&bgp_ipv4_node, NULL);
	install_node(&bgp_ipv4m_node, NULL);
	install_node(&bgp_ipv4l_node, NULL);
	install_node(&bgp_ipv6_node, NULL);
	install_node(&bgp_ipv6m_node, NULL);
	install_node(&bgp_ipv6l_node, NULL);
	install_node(&bgp_vrf_policy_node, NULL);
	install_node(&bgp_evpn_node, NULL);
	install_node(&bgp_evpn_vni_node, NULL);
	install_node(&bgp_vnc_defaults_node, NULL);
	install_node(&bgp_vnc_nve_group_node, NULL);
	install_node(&bgp_vnc_l2_group_node, NULL);
	install_node(&ospf_node, NULL);
	install_node(&eigrp_node, NULL);
	install_node(&babel_node, NULL);
	install_node(&ripng_node, NULL);
	install_node(&ospf6_node, NULL);
	install_node(&ldp_node, NULL);
	install_node(&ldp_ipv4_node, NULL);
	install_node(&ldp_ipv6_node, NULL);
	install_node(&ldp_ipv4_iface_node, NULL);
	install_node(&ldp_ipv6_iface_node, NULL);
	install_node(&ldp_l2vpn_node, NULL);
	install_node(&ldp_pseudowire_node, NULL);
	install_node(&keychain_node, NULL);
	install_node(&keychain_key_node, NULL);
	install_node(&isis_node, NULL);
	install_node(&openfabric_node, NULL);
	install_node(&vty_node, NULL);
	install_node(&rpki_node, NULL);
	install_node(&bmp_node, NULL);
#if HAVE_BFDD > 0
	install_node(&bfd_node, NULL);
	install_node(&bfd_peer_node, NULL);
#endif /* HAVE_BFDD */

	struct cmd_node *node;
	for (unsigned int i = 0; i < vector_active(cmdvec); i++) {
		node = vector_slot(cmdvec, i);
		if (!node || node->node == VIEW_NODE)
			continue;
		vtysh_install_default(node->node);
	}

	install_element(VIEW_NODE, &vtysh_enable_cmd);
	install_element(ENABLE_NODE, &vtysh_config_terminal_cmd);
	install_element(ENABLE_NODE, &vtysh_disable_cmd);

	/* "exit" command. */
	install_element(VIEW_NODE, &vtysh_exit_all_cmd);
	install_element(CONFIG_NODE, &vtysh_exit_all_cmd);
	install_element(VIEW_NODE, &vtysh_quit_all_cmd);
	install_element(CONFIG_NODE, &vtysh_quit_all_cmd);
	install_element(RIP_NODE, &vtysh_exit_ripd_cmd);
	install_element(RIP_NODE, &vtysh_quit_ripd_cmd);
	install_element(RIPNG_NODE, &vtysh_exit_ripngd_cmd);
	install_element(RIPNG_NODE, &vtysh_quit_ripngd_cmd);
	install_element(OSPF_NODE, &vtysh_exit_ospfd_cmd);
	install_element(OSPF_NODE, &vtysh_quit_ospfd_cmd);
	install_element(EIGRP_NODE, &vtysh_exit_eigrpd_cmd);
	install_element(EIGRP_NODE, &vtysh_quit_eigrpd_cmd);
	install_element(BABEL_NODE, &vtysh_exit_babeld_cmd);
	install_element(BABEL_NODE, &vtysh_quit_babeld_cmd);
	install_element(OSPF6_NODE, &vtysh_exit_ospf6d_cmd);
	install_element(OSPF6_NODE, &vtysh_quit_ospf6d_cmd);
#if defined(HAVE_LDPD)
	install_element(LDP_NODE, &vtysh_exit_ldpd_cmd);
	install_element(LDP_NODE, &vtysh_quit_ldpd_cmd);
	install_element(LDP_IPV4_NODE, &vtysh_exit_ldpd_cmd);
	install_element(LDP_IPV4_NODE, &vtysh_quit_ldpd_cmd);
	install_element(LDP_IPV4_NODE, &ldp_exit_address_family_cmd);
	install_element(LDP_IPV6_NODE, &vtysh_exit_ldpd_cmd);
	install_element(LDP_IPV6_NODE, &vtysh_quit_ldpd_cmd);
	install_element(LDP_IPV6_NODE, &ldp_exit_address_family_cmd);
	install_element(LDP_IPV4_IFACE_NODE, &vtysh_exit_ldpd_cmd);
	install_element(LDP_IPV4_IFACE_NODE, &vtysh_quit_ldpd_cmd);
	install_element(LDP_IPV6_IFACE_NODE, &vtysh_exit_ldpd_cmd);
	install_element(LDP_IPV6_IFACE_NODE, &vtysh_quit_ldpd_cmd);
	install_element(LDP_L2VPN_NODE, &vtysh_exit_ldpd_cmd);
	install_element(LDP_L2VPN_NODE, &vtysh_quit_ldpd_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &vtysh_exit_ldpd_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &vtysh_quit_ldpd_cmd);
#endif
	install_element(BGP_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_VPNV4_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_VPNV4_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_VPNV6_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_VPNV6_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_IPV4_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_IPV4_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_IPV4M_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_IPV4M_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_IPV4L_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_IPV4L_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_IPV6_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_IPV6_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_IPV6M_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_IPV6M_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_EVPN_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_EVPN_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_EVPN_VNI_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_EVPN_VNI_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_IPV6L_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_IPV6L_NODE, &vtysh_quit_bgpd_cmd);
#if defined(ENABLE_BGP_VNC)
	install_element(BGP_VRF_POLICY_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vtysh_quit_bgpd_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &vtysh_exit_bgpd_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &vtysh_quit_bgpd_cmd);
#endif
	install_element(ISIS_NODE, &vtysh_exit_isisd_cmd);
	install_element(ISIS_NODE, &vtysh_quit_isisd_cmd);
	install_element(OPENFABRIC_NODE, &vtysh_exit_fabricd_cmd);
	install_element(OPENFABRIC_NODE, &vtysh_quit_fabricd_cmd);
	install_element(KEYCHAIN_NODE, &vtysh_exit_ripd_cmd);
	install_element(KEYCHAIN_NODE, &vtysh_quit_ripd_cmd);
	install_element(KEYCHAIN_KEY_NODE, &vtysh_exit_ripd_cmd);
	install_element(KEYCHAIN_KEY_NODE, &vtysh_quit_ripd_cmd);
	install_element(RMAP_NODE, &vtysh_exit_rmap_cmd);
	install_element(RMAP_NODE, &vtysh_quit_rmap_cmd);
	install_element(PBRMAP_NODE, &vtysh_exit_pbr_map_cmd);
	install_element(PBRMAP_NODE, &vtysh_quit_pbr_map_cmd);
#if HAVE_BFDD > 0
	/* Enter node. */
	install_element(CONFIG_NODE, &bfd_enter_cmd);
	install_element(BFD_NODE, &bfd_peer_enter_cmd);

	/* Exit/quit node. */
	install_element(BFD_NODE, &vtysh_exit_bfdd_cmd);
	install_element(BFD_NODE, &vtysh_quit_bfdd_cmd);
	install_element(BFD_PEER_NODE, &vtysh_exit_bfdd_cmd);
	install_element(BFD_PEER_NODE, &vtysh_quit_bfdd_cmd);

	/* End/exit all. */
	install_element(BFD_NODE, &vtysh_end_all_cmd);
	install_element(BFD_PEER_NODE, &vtysh_end_all_cmd);
#endif /* HAVE_BFDD */
	install_element(VTY_NODE, &vtysh_exit_line_vty_cmd);
	install_element(VTY_NODE, &vtysh_quit_line_vty_cmd);

	/* "end" command. */
	install_element(CONFIG_NODE, &vtysh_end_all_cmd);
	install_element(ENABLE_NODE, &vtysh_end_all_cmd);
	install_element(RIP_NODE, &vtysh_end_all_cmd);
	install_element(RIPNG_NODE, &vtysh_end_all_cmd);
	install_element(OSPF_NODE, &vtysh_end_all_cmd);
	install_element(EIGRP_NODE, &vtysh_end_all_cmd);
	install_element(BABEL_NODE, &vtysh_end_all_cmd);
	install_element(OSPF6_NODE, &vtysh_end_all_cmd);
	install_element(LDP_NODE, &vtysh_end_all_cmd);
	install_element(LDP_IPV4_NODE, &vtysh_end_all_cmd);
	install_element(LDP_IPV6_NODE, &vtysh_end_all_cmd);
	install_element(LDP_IPV4_IFACE_NODE, &vtysh_end_all_cmd);
	install_element(LDP_IPV6_IFACE_NODE, &vtysh_end_all_cmd);
	install_element(LDP_L2VPN_NODE, &vtysh_end_all_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &vtysh_end_all_cmd);
	install_element(BGP_NODE, &vtysh_end_all_cmd);
	install_element(BGP_IPV4_NODE, &vtysh_end_all_cmd);
	install_element(BGP_IPV4M_NODE, &vtysh_end_all_cmd);
	install_element(BGP_IPV4L_NODE, &vtysh_end_all_cmd);
	install_element(BGP_VPNV4_NODE, &vtysh_end_all_cmd);
	install_element(BGP_VPNV6_NODE, &vtysh_end_all_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &vtysh_end_all_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &vtysh_end_all_cmd);
	install_element(BGP_IPV6_NODE, &vtysh_end_all_cmd);
	install_element(BGP_IPV6M_NODE, &vtysh_end_all_cmd);
	install_element(BGP_IPV6L_NODE, &vtysh_end_all_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vtysh_end_all_cmd);
	install_element(BGP_EVPN_NODE, &vtysh_end_all_cmd);
	install_element(BGP_EVPN_VNI_NODE, &vtysh_end_all_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vtysh_end_all_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vtysh_end_all_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &vtysh_end_all_cmd);
	install_element(ISIS_NODE, &vtysh_end_all_cmd);
	install_element(OPENFABRIC_NODE, &vtysh_end_all_cmd);
	install_element(KEYCHAIN_NODE, &vtysh_end_all_cmd);
	install_element(KEYCHAIN_KEY_NODE, &vtysh_end_all_cmd);
	install_element(RMAP_NODE, &vtysh_end_all_cmd);
	install_element(PBRMAP_NODE, &vtysh_end_all_cmd);
	install_element(VTY_NODE, &vtysh_end_all_cmd);

	install_element(INTERFACE_NODE, &vtysh_end_all_cmd);
	install_element(INTERFACE_NODE, &vtysh_exit_interface_cmd);
	install_element(LINK_PARAMS_NODE, &exit_link_params_cmd);
	install_element(LINK_PARAMS_NODE, &vtysh_end_all_cmd);
	install_element(LINK_PARAMS_NODE, &vtysh_exit_interface_cmd);
	install_element(INTERFACE_NODE, &vtysh_quit_interface_cmd);

	install_element(PW_NODE, &vtysh_end_all_cmd);
	install_element(PW_NODE, &vtysh_exit_interface_cmd);
	install_element(PW_NODE, &vtysh_quit_interface_cmd);

	install_element(CONFIG_NODE, &vtysh_nexthop_group_cmd);
	install_element(NH_GROUP_NODE, &vtysh_end_all_cmd);
	install_element(NH_GROUP_NODE, &vtysh_exit_nexthop_group_cmd);
	install_element(NH_GROUP_NODE, &vtysh_quit_nexthop_group_cmd);

	install_element(VRF_NODE, &vtysh_end_all_cmd);
	install_element(VRF_NODE, &vtysh_exit_vrf_cmd);
	install_element(VRF_NODE, &vtysh_quit_vrf_cmd);

	install_element(CONFIG_NODE, &router_eigrp_cmd);
	install_element(CONFIG_NODE, &router_babel_cmd);
	install_element(CONFIG_NODE, &router_rip_cmd);
	install_element(CONFIG_NODE, &router_ripng_cmd);
	install_element(CONFIG_NODE, &router_ospf_cmd);
	install_element(CONFIG_NODE, &router_ospf6_cmd);
#if defined(HAVE_LDPD)
	install_element(CONFIG_NODE, &ldp_mpls_ldp_cmd);
	install_element(LDP_NODE, &ldp_address_family_ipv4_cmd);
	install_element(LDP_NODE, &ldp_address_family_ipv6_cmd);
	install_element(LDP_IPV4_NODE, &ldp_interface_ifname_cmd);
	install_element(LDP_IPV6_NODE, &ldp_interface_ifname_cmd);
	install_element(CONFIG_NODE, &ldp_l2vpn_word_type_vpls_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_member_pseudowire_ifname_cmd);
#endif
	install_element(CONFIG_NODE, &router_isis_cmd);
	install_element(CONFIG_NODE, &router_openfabric_cmd);
	install_element(CONFIG_NODE, &router_bgp_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(BGP_NODE, &address_family_vpnv4_cmd);
	install_element(BGP_NODE, &address_family_vpnv6_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */
#if defined(ENABLE_BGP_VNC)
	install_element(BGP_NODE, &vnc_vrf_policy_cmd);
	install_element(BGP_NODE, &vnc_defaults_cmd);
	install_element(BGP_NODE, &vnc_nve_group_cmd);
	install_element(BGP_NODE, &vnc_l2_group_cmd);
#endif
	install_element(BGP_NODE, &address_family_ipv4_cmd);
	install_element(BGP_NODE, &address_family_ipv4_multicast_cmd);
	install_element(BGP_NODE, &address_family_ipv4_vpn_cmd);
	install_element(BGP_NODE, &address_family_ipv4_labeled_unicast_cmd);
	install_element(BGP_NODE, &address_family_ipv6_cmd);
	install_element(BGP_NODE, &address_family_ipv6_multicast_cmd);
	install_element(BGP_NODE, &address_family_ipv6_vpn_cmd);
	install_element(BGP_NODE, &address_family_ipv6_labeled_unicast_cmd);
	install_element(BGP_NODE, &address_family_evpn_cmd);
	install_element(BGP_NODE, &address_family_flowspecv4_cmd);
	install_element(BGP_NODE, &address_family_flowspecv6_cmd);
#if defined(HAVE_CUMULUS)
	install_element(BGP_NODE, &address_family_evpn2_cmd);
#endif
	install_element(BGP_VPNV4_NODE, &exit_address_family_cmd);
	install_element(BGP_VPNV6_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV4_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV4M_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV4L_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6M_NODE, &exit_address_family_cmd);
	install_element(BGP_EVPN_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6L_NODE, &exit_address_family_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &exit_address_family_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &exit_address_family_cmd);

	install_element(BGP_NODE, &bmp_targets_cmd);
	install_element(BMP_NODE, &bmp_exit_cmd);
	install_element(BMP_NODE, &bmp_quit_cmd);
	install_element(BMP_NODE, &vtysh_end_all_cmd);

	install_element(CONFIG_NODE, &rpki_cmd);
	install_element(RPKI_NODE, &rpki_exit_cmd);
	install_element(RPKI_NODE, &rpki_quit_cmd);
	install_element(RPKI_NODE, &vtysh_end_all_cmd);

	/* EVPN commands */
	install_element(BGP_EVPN_NODE, &bgp_evpn_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE, &exit_vni_cmd);

	install_element(BGP_VRF_POLICY_NODE, &exit_vrf_policy_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &exit_vnc_config_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &exit_vnc_config_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &exit_vnc_config_cmd);

	install_element(CONFIG_NODE, &key_chain_cmd);
	install_element(CONFIG_NODE, &vtysh_route_map_cmd);
	install_element(CONFIG_NODE, &vtysh_pbr_map_cmd);
	install_element(CONFIG_NODE, &vtysh_no_pbr_map_cmd);
	install_element(CONFIG_NODE, &vtysh_line_vty_cmd);
	install_element(KEYCHAIN_NODE, &key_cmd);
	install_element(KEYCHAIN_NODE, &key_chain_cmd);
	install_element(KEYCHAIN_KEY_NODE, &key_chain_cmd);
	install_element(CONFIG_NODE, &vtysh_interface_cmd);
	install_element(CONFIG_NODE, &vtysh_pseudowire_cmd);
	install_element(INTERFACE_NODE, &vtysh_link_params_cmd);
	install_element(ENABLE_NODE, &vtysh_show_running_config_cmd);
	install_element(ENABLE_NODE, &vtysh_copy_running_config_cmd);

	install_element(CONFIG_NODE, &vtysh_vrf_cmd);
	install_element(VRF_NODE, &vtysh_vrf_netns_cmd);
	install_element(VRF_NODE, &vtysh_no_vrf_netns_cmd);
	install_element(VRF_NODE, &exit_vrf_config_cmd);

	install_element(CONFIG_NODE, &vtysh_no_nexthop_group_cmd);

	/* "write terminal" command. */
	install_element(ENABLE_NODE, &vtysh_write_terminal_cmd);

	install_element(CONFIG_NODE, &vtysh_integrated_config_cmd);
	install_element(CONFIG_NODE, &no_vtysh_integrated_config_cmd);

	/* "write memory" command. */
	install_element(ENABLE_NODE, &vtysh_write_memory_cmd);

	install_element(CONFIG_NODE, &vtysh_terminal_paginate_cmd);
	install_element(VIEW_NODE, &vtysh_terminal_paginate_cmd);
	install_element(VIEW_NODE, &vtysh_terminal_length_cmd);
	install_element(VIEW_NODE, &vtysh_terminal_no_length_cmd);
	install_element(VIEW_NODE, &vtysh_show_daemons_cmd);

	install_element(VIEW_NODE, &vtysh_ping_cmd);
	install_element(VIEW_NODE, &vtysh_ping_ip_cmd);
	install_element(VIEW_NODE, &vtysh_traceroute_cmd);
	install_element(VIEW_NODE, &vtysh_traceroute_ip_cmd);
	install_element(VIEW_NODE, &vtysh_mtrace_cmd);
	install_element(VIEW_NODE, &vtysh_ping6_cmd);
	install_element(VIEW_NODE, &vtysh_traceroute6_cmd);
#if defined(HAVE_SHELL_ACCESS)
	install_element(VIEW_NODE, &vtysh_telnet_cmd);
	install_element(VIEW_NODE, &vtysh_telnet_port_cmd);
	install_element(VIEW_NODE, &vtysh_ssh_cmd);
#endif
#if defined(HAVE_SHELL_ACCESS)
	install_element(ENABLE_NODE, &vtysh_start_shell_cmd);
	install_element(ENABLE_NODE, &vtysh_start_bash_cmd);
	install_element(ENABLE_NODE, &vtysh_start_zsh_cmd);
#endif

	/* debugging */
	install_element(VIEW_NODE, &vtysh_show_debugging_cmd);
	install_element(VIEW_NODE, &vtysh_show_error_code_cmd);
	install_element(VIEW_NODE, &vtysh_show_debugging_hashtable_cmd);
	install_element(ENABLE_NODE, &vtysh_debug_all_cmd);
	install_element(CONFIG_NODE, &vtysh_debug_all_cmd);
	install_element(ENABLE_NODE, &vtysh_debug_memstats_cmd);
	install_element(CONFIG_NODE, &vtysh_debug_memstats_cmd);

	/* northbound */
	install_element(VIEW_NODE, &show_yang_operational_data_cmd);
	install_element(ENABLE_NODE, &debug_nb_cmd);
	install_element(CONFIG_NODE, &debug_nb_cmd);

	/* misc lib show commands */
	install_element(VIEW_NODE, &vtysh_show_memory_cmd);
	install_element(VIEW_NODE, &vtysh_show_modules_cmd);
	install_element(VIEW_NODE, &vtysh_show_work_queues_cmd);
	install_element(VIEW_NODE, &vtysh_show_work_queues_daemon_cmd);
#ifndef EXCLUDE_CPU_TIME
	install_element(VIEW_NODE, &vtysh_show_thread_cmd);
#endif
	install_element(VIEW_NODE, &vtysh_show_poll_cmd);

	/* Logging */
	install_element(VIEW_NODE, &vtysh_show_logging_cmd);
	install_element(VIEW_NODE, &vtysh_show_log_filter_cmd);
	install_element(CONFIG_NODE, &vtysh_log_filter_cmd);
	install_element(CONFIG_NODE, &vtysh_log_filter_clear_cmd);
	install_element(CONFIG_NODE, &vtysh_log_stdout_cmd);
	install_element(CONFIG_NODE, &vtysh_log_stdout_level_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_stdout_cmd);
	install_element(CONFIG_NODE, &vtysh_log_file_cmd);
	install_element(CONFIG_NODE, &vtysh_log_file_level_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_file_cmd);
	install_element(CONFIG_NODE, &vtysh_log_monitor_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_monitor_cmd);
	install_element(CONFIG_NODE, &vtysh_log_syslog_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_syslog_cmd);
	install_element(CONFIG_NODE, &vtysh_log_facility_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_facility_cmd);
	install_element(CONFIG_NODE, &vtysh_log_record_priority_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_record_priority_cmd);
	install_element(CONFIG_NODE, &vtysh_log_timestamp_precision_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_timestamp_precision_cmd);

	install_element(CONFIG_NODE, &vtysh_service_password_encrypt_cmd);
	install_element(CONFIG_NODE, &no_vtysh_service_password_encrypt_cmd);

	install_element(CONFIG_NODE, &vtysh_password_cmd);
	install_element(CONFIG_NODE, &no_vtysh_password_cmd);
	install_element(CONFIG_NODE, &vtysh_enable_password_cmd);
	install_element(CONFIG_NODE, &no_vtysh_enable_password_cmd);
}
