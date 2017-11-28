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

DEFINE_MTYPE_STATIC(MVTYSH, VTYSH_CMD, "Vtysh cmd copy")

/* Struct VTY. */
struct vty *vty;

/* VTY shell pager name. */
char *vtysh_pager_name = NULL;

/* VTY shell client structure. */
struct vtysh_client {
	int fd;
	const char *name;
	int flag;
	char path[MAXPATHLEN];
	struct vtysh_client *next;
};

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
	{.fd = -1, .name = "watchfrr", .flag = VTYSH_WATCHFRR, .next = NULL},
};

enum vtysh_write_integrated vtysh_write_integrated =
	WRITE_INTEGRATED_UNSPECIFIED;

static void vclient_close(struct vtysh_client *vclient)
{
	if (vclient->fd >= 0) {
		fprintf(stderr,
			"Warning: closing connection to %s because of an I/O error!\n",
			vclient->name);
		close(vclient->fd);
		vclient->fd = -1;
	}
}

/* Return true if str begins with prefix, else return false */
static int begins_with(const char *str, const char *prefix)
{
	if (!str || !prefix)
		return 0;
	size_t lenstr = strlen(str);
	size_t lenprefix = strlen(prefix);
	if (lenprefix > lenstr)
		return 0;
	return strncmp(str, prefix, lenprefix) == 0;
}

static int vtysh_client_run(struct vtysh_client *vclient, const char *line,
			    FILE *fp, void (*callback)(void *, const char *),
			    void *cbarg)
{
	int ret;
	char stackbuf[4096];
	char *buf = stackbuf;
	size_t bufsz = sizeof(stackbuf);
	char *bufvalid, *end = NULL;
	char terminator[3] = {0, 0, 0};

	if (vclient->fd < 0)
		return CMD_SUCCESS;

	ret = write(vclient->fd, line, strlen(line) + 1);
	if (ret <= 0)
		goto out_err;

	bufvalid = buf;
	do {
		ssize_t nread =
			read(vclient->fd, bufvalid, buf + bufsz - bufvalid);

		if (nread < 0 && (errno == EINTR || errno == EAGAIN))
			continue;

		if (nread <= 0) {
			fprintf(stderr, "vtysh: error reading from %s: %s (%d)",
				vclient->name, safe_strerror(errno), errno);
			goto out_err;
		}

		bufvalid += nread;

		end = memmem(buf, bufvalid - buf, terminator,
			     sizeof(terminator));
		if (end + sizeof(terminator) + 1 > bufvalid)
			/* found \0\0\0 but return code hasn't been read yet */
			end = NULL;
		if (end)
			ret = end[sizeof(terminator)];

		while (bufvalid > buf && (end > buf || !end)) {
			size_t textlen = (end ? end : bufvalid) - buf;
			char *eol = memchr(buf, '\n', textlen);
			if (eol)
				/* line break */
				*eol++ = '\0';
			else if (end == buf)
				/* no line break, end of input, no text left
				 * before end
				 * => don't insert an empty line at the end */
				break;
			else if (end)
				/* no line break, end of input, but some text
				 * left */
				eol = end;
			else
				/* continue reading */
				break;

			/* eol is at a line end now, either \n => \0 or \0\0\0
			 */
			assert(eol && eol <= bufvalid);

			if (fp) {
				fputs(buf, fp);
				fputc('\n', fp);
			}
			if (callback)
				callback(cbarg, buf);

			if (eol == end)
				/* \n\0\0\0 */
				break;

			memmove(buf, eol, bufvalid - eol);
			bufvalid -= eol - buf;
			if (end)
				end -= eol - buf;
		}

		if (bufvalid == buf + bufsz) {
			char *new;
			bufsz *= 2;
			if (buf == stackbuf) {
				new = XMALLOC(MTYPE_TMP, bufsz);
				memcpy(new, stackbuf, sizeof(stackbuf));
			} else
				new = XREALLOC(MTYPE_TMP, buf, bufsz);

			bufvalid = bufvalid - buf + new;
			buf = new;
			/* if end != NULL, we won't be reading more data... */
			assert(end == NULL);
		}
	} while (!end);
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
				const char *line, int continue_on_err, FILE *fp,
				void (*callback)(void *, const char *),
				void *cbarg)
{
	struct vtysh_client *client;
	int rc, rc_all = CMD_SUCCESS;
	int correct_instance = 0, wrong_instance = 0;

	for (client = head_client; client; client = client->next) {
		rc = vtysh_client_run(client, line, fp, callback, cbarg);
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
	if (wrong_instance && !correct_instance && fp) {
		fprintf(fp,
			"%% [%s]: command ignored as it targets an instance that is not running\n",
			head_client->name);
		rc_all = CMD_WARNING_CONFIG_FAILED;
	}
	return rc_all;
}

static int vtysh_client_execute(struct vtysh_client *head_client,
				const char *line, FILE *fp)
{
	return vtysh_client_run_all(head_client, line, 0, fp, NULL, NULL);
}

static void vtysh_client_config(struct vtysh_client *head_client, char *line)
{
	/* watchfrr currently doesn't load any config, and has some hardcoded
	 * settings that show up in "show run".  skip it here (for now at
	 * least) so we don't get that mangled up in config-write.
	 */
	if (head_client->flag == VTYSH_WATCHFRR)
		return;

	vtysh_client_run_all(head_client, line, 1, NULL,
			     vtysh_config_parse_line, NULL);
}

void vtysh_pager_init(void)
{
	char *pager_defined;

	pager_defined = getenv("VTYSH_PAGER");

	if (pager_defined)
		vtysh_pager_name = strdup(pager_defined);
	else
		vtysh_pager_name = strdup(VTYSH_PAGER);
}

/* Command execution over the vty interface. */
static int vtysh_execute_func(const char *line, int pager)
{
	int ret, cmd_stat;
	u_int i;
	vector vline;
	const struct cmd_element *cmd;
	FILE *fp = NULL;
	int closepager = 0;
	int tried = 0;
	int saved_ret, saved_node;

	/* Split readline string up into the vector. */
	vline = cmd_make_strvec(line);

	if (vline == NULL)
		return CMD_SUCCESS;

	saved_ret = ret = cmd_execute_command(vline, vty, &cmd, 1);
	saved_node = vty->node;

	/* If command doesn't succeeded in current node, try to walk up in node
	 * tree.
	 * Changing vty->node is enough to try it just out without actual walkup
	 * in
	 * the vtysh. */
	while (ret != CMD_SUCCESS && ret != CMD_SUCCESS_DAEMON
	       && ret != CMD_WARNING && ret != CMD_WARNING_CONFIG_FAILED
	       && vty->node > CONFIG_NODE) {
		vty->node = node_parent(vty->node);
		ret = cmd_execute_command(vline, vty, &cmd, 1);
		tried++;
	}

	vty->node = saved_node;

	/* If command succeeded in any other node than current (tried > 0) we
	 * have
	 * to move into node in the vtysh where it succeeded. */
	if (ret == CMD_SUCCESS || ret == CMD_SUCCESS_DAEMON
	    || ret == CMD_WARNING) {
		if ((saved_node == BGP_VPNV4_NODE
		     || saved_node == BGP_VPNV6_NODE
		     || saved_node == BGP_IPV4_NODE
		     || saved_node == BGP_IPV6_NODE
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
		} else if ((saved_node == KEYCHAIN_KEY_NODE
			    || saved_node == LDP_PSEUDOWIRE_NODE
			    || saved_node == LDP_IPV4_IFACE_NODE
			    || saved_node == LDP_IPV6_IFACE_NODE)
			   && (tried == 1)) {
			vtysh_execute("exit");
		} else if (tried) {
			vtysh_execute("end");
			vtysh_execute("configure terminal");
		}
	}
	/* If command didn't succeed in any node, continue with return value
	 * from
	 * first try. */
	else if (tried) {
		ret = saved_ret;
	}

	cmd_free_strvec(vline);

	cmd_stat = ret;
	switch (ret) {
	case CMD_WARNING:
	case CMD_WARNING_CONFIG_FAILED:
		if (vty->type == VTY_FILE)
			fprintf(stdout, "Warning...\n");
		break;
	case CMD_ERR_AMBIGUOUS:
		fprintf(stdout, "%% Ambiguous command.\n");
		break;
	case CMD_ERR_NO_MATCH:
		fprintf(stdout, "%% Unknown command.\n");
		break;
	case CMD_ERR_INCOMPLETE:
		fprintf(stdout, "%% Command incomplete.\n");
		break;
	case CMD_SUCCESS_DAEMON: {
		/* FIXME: Don't open pager for exit commands. popen() causes
		 * problems
		 * if exited from vtysh at all. This hack shouldn't cause any
		 * problem
		 * but is really ugly. */
		if (pager && vtysh_pager_name
		    && (strncmp(line, "exit", 4) != 0)) {
			fp = popen(vtysh_pager_name, "w");
			if (fp == NULL) {
				perror("popen failed for pager");
				fp = stdout;
			} else
				closepager = 1;
		} else
			fp = stdout;

		if (!strcmp(cmd->string, "configure terminal")) {
			for (i = 0; i < array_size(vtysh_client); i++) {
				cmd_stat = vtysh_client_execute(
					&vtysh_client[i], line, fp);
				if (cmd_stat == CMD_WARNING)
					break;
			}

			if (cmd_stat) {
				line = "end";
				vline = cmd_make_strvec(line);

				if (vline == NULL) {
					if (pager && vtysh_pager_name && fp
					    && closepager) {
						if (pclose(fp) == -1) {
							perror("pclose failed for pager");
						}
						fp = NULL;
					}
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
					&vtysh_client[i], line, fp);
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
	if (pager && vtysh_pager_name && fp && closepager) {
		if (pclose(fp) == -1) {
			perror("pclose failed for pager");
		}
		fp = NULL;
	}
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
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

	while (*s && isspace(*s))
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
	vty->fd = 0; /* stdout */
	vty->type = VTY_TERM;
	vty->node = CONFIG_NODE;

	vtysh_execute_no_pager("enable");
	vtysh_execute_no_pager("configure terminal");
	vty_buf_copy = XCALLOC(MTYPE_VTYSH_CMD, VTY_BUFSIZ);

	while (fgets(vty->buf, VTY_BUFSIZ, confp)) {
		lineno++;
		tried = 0;
		strcpy(vty_buf_copy, vty->buf);
		vty_buf_trimmed = trim(vty_buf_copy);

		switch (vty->node) {
		case LDP_IPV4_IFACE_NODE:
			if (strncmp(vty_buf_copy, "   ", 3)) {
				fprintf(stdout, "  end\n");
				vty->node = LDP_IPV4_NODE;
			}
			break;
		case LDP_IPV6_IFACE_NODE:
			if (strncmp(vty_buf_copy, "   ", 3)) {
				fprintf(stdout, "  end\n");
				vty->node = LDP_IPV6_NODE;
			}
			break;
		case LDP_PSEUDOWIRE_NODE:
			if (strncmp(vty_buf_copy, "  ", 2)) {
				fprintf(stdout, " end\n");
				vty->node = LDP_L2VPN_NODE;
			}
			break;
		default:
			break;
		}

		if (vty_buf_trimmed[0] == '!' || vty_buf_trimmed[0] == '#') {
			fprintf(stdout, "%s", vty->buf);
			continue;
		}

		/* Split readline string up into the vector. */
		vline = cmd_make_strvec(vty->buf);

		if (vline == NULL) {
			fprintf(stdout, "%s", vty->buf);
			continue;
		}

		/* Ignore the "end" lines, we will generate these where
		 * appropriate */
		if (strlen(vty_buf_trimmed) == 3
		    && strncmp("end", vty_buf_trimmed, 3) == 0) {
			cmd_free_strvec(vline);
			continue;
		}

		prev_node = vty->node;
		saved_ret = ret = cmd_execute_command_strict(vline, vty, &cmd);

		/* If command doesn't succeeded in current node, try to walk up
		 * in node tree.
		 * Changing vty->node is enough to try it just out without
		 * actual walkup in
		 * the vtysh. */
		while (ret != CMD_SUCCESS && ret != CMD_SUCCESS_DAEMON
		       && ret != CMD_WARNING && ret != CMD_WARNING_CONFIG_FAILED
		       && vty->node > CONFIG_NODE) {
			vty->node = node_parent(vty->node);
			ret = cmd_execute_command_strict(vline, vty, &cmd);
			tried++;
		}

		/* If command succeeded in any other node than current (tried >
		 * 0) we have
		 * to move into node in the vtysh where it succeeded. */
		if (ret == CMD_SUCCESS || ret == CMD_SUCCESS_DAEMON
		    || ret == CMD_WARNING) {
			if ((prev_node == BGP_VPNV4_NODE
			     || prev_node == BGP_VPNV6_NODE
			     || prev_node == BGP_IPV4_NODE
			     || prev_node == BGP_IPV6_NODE
			     || prev_node == BGP_IPV4L_NODE
			     || prev_node == BGP_IPV6L_NODE
			     || prev_node == BGP_IPV4M_NODE
			     || prev_node == BGP_IPV6M_NODE
			     || prev_node == BGP_EVPN_NODE)
			    && (tried == 1)) {
				fprintf(stdout, "exit-address-family\n");
			} else if ((prev_node == BGP_EVPN_VNI_NODE)
				   && (tried == 1)) {
				fprintf(stdout, "exit-vni\n");
			} else if ((prev_node == KEYCHAIN_KEY_NODE)
				   && (tried == 1)) {
				fprintf(stdout, "exit\n");
			} else if (tried) {
				fprintf(stdout, "end\n");
			}
		}
		/* If command didn't succeed in any node, continue with return
		 * value from
		 * first try. */
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
			fprintf(stdout, "%s", vty->buf);
			break;
		case CMD_SUCCESS_DAEMON: {
			u_int i;
			int cmd_stat = CMD_SUCCESS;

			fprintf(stdout, "%s", vty->buf);
			for (i = 0; i < array_size(vtysh_client); i++) {
				if (cmd->daemon & vtysh_client[i].flag) {
					cmd_stat = vtysh_client_execute(
						&vtysh_client[i], vty->buf,
						stdout);
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
	}
	/* This is the end */
	fprintf(stdout, "\nend\n");
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
	int retcode = CMD_SUCCESS;

	while (fgets(vty->buf, VTY_BUFSIZ, fp)) {
		lineno++;

		ret = command_config_read_one_line(vty, &cmd, 1);

		switch (ret) {
		case CMD_WARNING:
		case CMD_WARNING_CONFIG_FAILED:
			if (vty->type == VTY_FILE)
				fprintf(stderr, "line %d: Warning[%d]...: %s\n",
					lineno, vty->node, vty->buf);
			retcode = ret; /* once we have an error, we remember &
					  return that */
			break;
		case CMD_ERR_AMBIGUOUS:
			fprintf(stderr,
				"line %d: %% Ambiguous command[%d]: %s\n",
				lineno, vty->node, vty->buf);
			retcode = CMD_ERR_AMBIGUOUS; /* once we have an error,
							we remember & return
							that */
			break;
		case CMD_ERR_NO_MATCH:
			fprintf(stderr, "line %d: %% Unknown command[%d]: %s",
				lineno, vty->node, vty->buf);
			retcode =
				CMD_ERR_NO_MATCH; /* once we have an error, we
						     remember & return that */
			break;
		case CMD_ERR_INCOMPLETE:
			fprintf(stderr,
				"line %d: %% Command incomplete[%d]: %s\n",
				lineno, vty->node, vty->buf);
			retcode = CMD_ERR_INCOMPLETE; /* once we have an error,
							 we remember & return
							 that */
			break;
		case CMD_SUCCESS_DAEMON: {
			u_int i;
			int cmd_stat = CMD_SUCCESS;

			for (i = 0; i < array_size(vtysh_client); i++) {
				if (cmd->daemon & vtysh_client[i].flag) {
					cmd_stat = vtysh_client_execute(
						&vtysh_client[i], vty->buf,
						stdout);
					/*
					 * CMD_WARNING - Can mean that the
					 * command was
					 * parsed successfully but it was
					 * already entered
					 * in a few spots.  As such if we
					 * receive a
					 * CMD_WARNING from a daemon we
					 * shouldn't stop
					 * talking to the other daemons for the
					 * particular
					 * command.
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

/* We don't care about the point of the cursor when '?' is typed. */
static int vtysh_rl_describe(void)
{
	int ret;
	unsigned int i;
	vector vline;
	vector describe;
	int width;
	struct cmd_token *token;

	vline = cmd_make_strvec(rl_line_buffer);

	/* In case of '> ?'. */
	if (vline == NULL) {
		vline = vector_init(1);
		vector_set(vline, NULL);
	} else if (rl_end && isspace((int)rl_line_buffer[rl_end - 1]))
		vector_set(vline, NULL);

	fprintf(stdout, "\n");

	describe = cmd_describe_command(vline, vty, &ret);

	/* Ambiguous and no match error. */
	switch (ret) {
	case CMD_ERR_AMBIGUOUS:
		cmd_free_strvec(vline);
		vector_free(describe);
		fprintf(stdout, "%% Ambiguous command.\n");
		rl_on_new_line();
		return 0;
		break;
	case CMD_ERR_NO_MATCH:
		cmd_free_strvec(vline);
		if (describe)
			vector_free(describe);
		fprintf(stdout, "%% There is no matched command.\n");
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
				fprintf(stdout, "  %-s\n", token->text);
			else
				fprintf(stdout, "  %-*s  %s\n", width,
					token->text, token->desc);

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
					fprintf(stdout, "%s\n", ac);
					XFREE(MTYPE_TMP, ac);
				}

				vector_free(varcomps);
			}
		}

	cmd_free_strvec(vline);
	vector_free(describe);

	rl_on_new_line();

	return 0;
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

		if (rl_end && isspace((int)rl_line_buffer[rl_end - 1]))
			vector_set(vline, NULL);

		matched = cmd_complete_command(vline, vty, &complete_status);
		cmd_free_strvec(vline);
	}

	if (matched && matched[index])
		/* this is free()'d by readline, but we leak 1 count of
		 * MTYPE_COMPLETION */
		return matched[index++];

	XFREE(MTYPE_TMP, matched);
	matched = NULL;

	return NULL;
}

static char **new_completion(char *text, int start, int end)
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

static struct cmd_node interface_node = {
	INTERFACE_NODE, "%s(config-if)# ",
};

static struct cmd_node pw_node = {
	PW_NODE, "%s(config-pw)# ",
};

static struct cmd_node ns_node = {
	NS_NODE, "%s(config-logical-router)# ",
};

static struct cmd_node vrf_node = {
	VRF_NODE, "%s(config-vrf)# ",
};

static struct cmd_node rmap_node = {RMAP_NODE, "%s(config-route-map)# "};

static struct cmd_node zebra_node = {ZEBRA_NODE, "%s(config-router)# "};

static struct cmd_node bgp_vpnv4_node = {BGP_VPNV4_NODE,
					 "%s(config-router-af)# "};

static struct cmd_node bgp_vpnv6_node = {BGP_VPNV6_NODE,
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

#if defined(HAVE_RPKI)
static struct cmd_node rpki_node = {RPKI_NODE, "%s(config-rpki)# ", 1};
#endif

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

DEFUNSH(VTYSH_BGPD, address_family_ipv4, address_family_ipv4_cmd,
	"address-family ipv4 [unicast]",
	"Enter Address Family command mode\n"
	"Address Family\n"
	"Address Family Modifier\n")
{
	vty->node = BGP_IPV4_NODE;
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

#if defined(HAVE_RPKI)
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
	rpki_exit,
	rpki_exit_cmd,
	"exit",
	"Exit current mode and down to previous mode\n")
{
	vty->node = CONFIG_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_BGPD,
	rpki_quit,
	rpki_quit_cmd,
	"quit",
	"Exit current mode and down to previous mode\n")
{
	return rpki_exit(self, vty, argc, argv);
}
#endif

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

DEFUNSH(VTYSH_BGPD, bgp_evpn_vni, bgp_evpn_vni_cmd, "vni (1-16777215)",
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

DEFUNSH(VTYSH_RIPD, key_chain, key_chain_cmd, "key chain WORD",
	"Authentication key management\n"
	"Key-chain management\n"
	"Key-chain name\n")
{
	vty->node = KEYCHAIN_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_RIPD, key, key_cmd, "key (0-2147483647)",
	"Configure a key\n"
	"Key identifier number\n")
{
	vty->node = KEYCHAIN_KEY_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_RIPD, router_rip, router_rip_cmd, "router rip",
	ROUTER_STR "RIP\n")
{
	vty->node = RIP_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_RIPNGD, router_ripng, router_ripng_cmd, "router ripng",
	ROUTER_STR "RIPng\n")
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

DEFUNSH(VTYSH_EIGRPD, router_eigrp, router_eigrp_cmd, "router eigrp (1-65535)",
	"Enable a routing process\n"
	"Start EIGRP configuration\n"
	"AS number to use\n")
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
	"ISO Routing area tag")
{
	vty->node = ISIS_NODE;
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
	"configure terminal",
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
	case NS_NODE:
	case VRF_NODE:
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
	case MASC_NODE:
	case RMAP_NODE:
	case VTY_NODE:
	case KEYCHAIN_NODE:
		vtysh_execute("end");
		vtysh_execute("configure terminal");
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
	case BGP_VRF_POLICY_NODE:
	case BGP_EVPN_NODE:
	case BGP_VNC_DEFAULTS_NODE:
	case BGP_VNC_NVE_GROUP_NODE:
	case BGP_VNC_L2_GROUP_NODE:
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
	    || vty->node == BGP_EVPN_NODE)
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

DEFUNSH(VTYSH_BGPD, exit_vrf_policy, exit_vrf_policy_cmd, "exit-vrf-policy",
	"Exit from VRF  configuration mode\n")
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

/* TODO Implement "no interface command in isisd. */
DEFSH(VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_RIPNGD | VTYSH_OSPFD | VTYSH_OSPF6D
	      | VTYSH_EIGRPD,
      vtysh_no_interface_cmd, "no interface IFNAME", NO_STR
      "Delete a pseudo interface's configuration\n"
      "Interface's name\n")

DEFSH(VTYSH_ZEBRA, vtysh_no_interface_vrf_cmd, "no interface IFNAME vrf NAME",
      NO_STR
      "Delete a pseudo interface's configuration\n"
      "Interface's name\n" VRF_CMD_HELP_STR)

DEFUNSH(VTYSH_NS, vtysh_ns, vtysh_ns_cmd, "logical-router (1-65535) ns NAME",
	"Enable a logical-router\n"
	"Specify the logical-router indentifier\n"
	"The Name Space\n"
	"The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	vty->node = NS_NODE;
	return CMD_SUCCESS;
}

DEFUNSH(VTYSH_VRF, vtysh_vrf, vtysh_vrf_cmd, "vrf NAME",
	"Select a VRF to configure\n"
	"VRF's name\n")
{
	vty->node = VRF_NODE;
	return CMD_SUCCESS;
}

DEFSH(VTYSH_ZEBRA, vtysh_no_vrf_cmd, "no vrf NAME", NO_STR
      "Delete a pseudo vrf's configuration\n"
      "VRF's name\n")

DEFUNSH(VTYSH_NS, vtysh_exit_ns, vtysh_exit_ns_cmd, "exit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit(vty);
}

DEFUNSH(VTYSH_NS, vtysh_quit_ns, vtysh_quit_ns_cmd, "quit",
	"Exit current mode and down to previous mode\n")
{
	return vtysh_exit_ns(self, vty, argc, argv);
}

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

/* TODO Implement interface description commands in ripngd, ospf6d
 * and isisd. */
DEFSH(VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_OSPFD | VTYSH_EIGRPD,
      vtysh_interface_desc_cmd, "description LINE...",
      "Interface specific description\n"
      "Characters describing this interface\n")

DEFSH(VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_OSPFD | VTYSH_EIGRPD,
      vtysh_no_interface_desc_cmd, "no description",
      NO_STR "Interface specific description\n")

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
			fprintf(stdout, "Thread statistics for %s:\n",
				vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line,
						   stdout);
			fprintf(stdout, "\n");
		}
	return ret;
}

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
			fprintf(stdout, "Work queue statistics for %s:\n",
				vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line,
						   stdout);
			fprintf(stdout, "\n");
		}

	return ret;
}

DEFUN (vtysh_show_work_queues_daemon,
       vtysh_show_work_queues_daemon_cmd,
       "show work-queues <zebra|ripd|ripngd|ospfd|ospf6d|bgpd|isisd>",
       SHOW_STR
       "Work Queue information\n"
       "For the zebra daemon\n"
       "For the rip daemon\n"
       "For the ripng daemon\n"
       "For the ospf daemon\n"
       "For the ospfv6 daemon\n"
       "For the bgp daemon\n"
       "For the isis daemon\n")
{
	int idx_protocol = 2;
	unsigned int i;
	int ret = CMD_SUCCESS;

	for (i = 0; i < array_size(vtysh_client); i++) {
		if (strmatch(vtysh_client[i].name, argv[idx_protocol]->text))
			break;
	}

	ret = vtysh_client_execute(&vtysh_client[i], "show work-queues\n",
				   stdout);

	return ret;
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
			fprintf(stdout, headline, vtysh_client[i].name);
			ret = vtysh_client_execute(&vtysh_client[i], line,
						   stdout);
			fprintf(stdout, "\n");
		}

	return ret;
}

DEFUN (vtysh_show_debugging,
       vtysh_show_debugging_cmd,
       "show debugging",
       SHOW_STR
       DEBUG_STR)
{
	return show_per_daemon("do show debugging\n",
			       "");
}

DEFUN (vtysh_show_debugging_hashtable,
       vtysh_show_debugging_hashtable_cmd,
       "show debugging hashtable [statistics]",
       SHOW_STR
       DEBUG_STR
       "Statistics about hash tables\n"
       "Statistics about hash tables\n")
{
	fprintf(stdout, "\n");
	fprintf(stdout,
		"Load factor (LF) - average number of elements across all buckets\n");
	fprintf(stdout,
		"Full load factor (FLF) - average number of elements across full buckets\n\n");
	fprintf(stdout,
		"Standard deviation (SD) is calculated for both the LF and FLF\n");
	fprintf(stdout,
		"and indicates the typical deviation of bucket chain length\n");
	fprintf(stdout, "from the value in the corresponding load factor.\n\n");

	return show_per_daemon("do show debugging hashtable\n",
			       "Hashtable statistics for %s:\n");
}

/* Memory */
DEFUN (vtysh_show_memory,
       vtysh_show_memory_cmd,
       "show memory",
       SHOW_STR
       "Memory statistics\n")
{
	return show_per_daemon("show memory\n",
			       "Memory statistics for %s:\n");
}

DEFUN (vtysh_show_modules,
       vtysh_show_modules_cmd,
       "show modules",
       SHOW_STR
       "Loaded modules\n")
{
	return show_per_daemon("show modules\n",
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
	"no log syslog [LEVEL]", NO_STR
	"Logging control\n"
	"Cancel logging to syslog\n"
	"Logging level\n")
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
	"no log facility [FACILITY]", NO_STR
	"Logging control\n"
	"Reset syslog facility to default (daemon)\n"
	"Syslog facility\n")

{
	return CMD_SUCCESS;
}

DEFUNSH_DEPRECATED(
	VTYSH_ALL, vtysh_log_trap, vtysh_log_trap_cmd,
	"log trap <emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>",
	"Logging control\n"
	"(Deprecated) Set logging level and default for all destinations\n" LOG_LEVEL_DESC)

{
	return CMD_SUCCESS;
}

DEFUNSH_DEPRECATED(VTYSH_ALL, no_vtysh_log_trap, no_vtysh_log_trap_cmd,
		   "no log trap [LEVEL]", NO_STR
		   "Logging control\n"
		   "Permit all logging information\n"
		   "Logging level\n")
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
	"Assign the terminal connection password\n"
	"Specifies a HIDDEN password will follow\n"
	"The password string\n")
{
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
	return CMD_SUCCESS;
}

DEFUN (vtysh_write_terminal,
       vtysh_write_terminal_cmd,
       "write terminal [<zebra|ripd|ripngd|ospfd|ospf6d|ldpd|bgpd|isisd|pimd>]",
       "Write running configuration to memory, network, or terminal\n"
       "Write to terminal\n"
       "For the zebra daemon\n"
       "For the rip daemon\n"
       "For the ripng daemon\n"
       "For the ospf daemon\n"
       "For the ospfv6 daemon\n"
       "For the ldpd daemon\n"
       "For the bgp daemon\n"
       "For the isis daemon\n"
       "For the pim daemon\n")
{
	u_int i;
	char line[] = "do write terminal\n";
	FILE *fp = NULL;

	if (vtysh_pager_name) {
		fp = popen(vtysh_pager_name, "w");
		if (fp == NULL) {
			perror("popen");
			exit(1);
		}
	} else
		fp = stdout;

	vty_out(vty, "Building configuration...\n");
	vty_out(vty, "\nCurrent configuration:\n");
	vty_out(vty, "!\n");

	for (i = 0; i < array_size(vtysh_client); i++)
		if ((argc < 3)
		    || (strmatch(vtysh_client[i].name, argv[2]->text)))
			vtysh_client_config(&vtysh_client[i], line);

	/* Integrate vtysh specific configuration. */
	vtysh_config_write();

	vtysh_config_dump(fp);

	if (vtysh_pager_name && fp) {
		fflush(fp);
		if (pclose(fp) == -1) {
			perror("pclose");
			exit(1);
		}
		fp = NULL;
	}

	vty_out(vty, "end\n");
	return CMD_SUCCESS;
}

DEFUN (vtysh_show_running_config,
       vtysh_show_running_config_cmd,
       "show running-config [<zebra|ripd|ripngd|ospfd|ospf6d|ldpd|bgpd|isisd|pimd>]",
       SHOW_STR
       "Current operating configuration\n"
       "For the zebra daemon\n"
       "For the rip daemon\n"
       "For the ripng daemon\n"
       "For the ospf daemon\n"
       "For the ospfv6 daemon\n"
       "For the ldp daemon\n"
       "For the bgp daemon\n"
       "For the isis daemon\n"
       "For the pim daemon\n")
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

	integrate_sav = malloc(strlen(fbackup) + strlen(CONF_BACKUP_EXT) + 1);
	strcpy(integrate_sav, fbackup);
	strcat(integrate_sav, CONF_BACKUP_EXT);

	/* Move current configuration file to backup config file. */
	unlink(integrate_sav);
	rename(fbackup, integrate_sav);
	free(integrate_sav);
}

int vtysh_write_config_integrated(void)
{
	u_int i;
	char line[] = "do write terminal\n";
	FILE *fp;
	int fd;
	struct passwd *pwentry;
	struct group *grentry;
	uid_t uid = -1;
	gid_t gid = -1;
	struct stat st;
	int err = 0;

	fprintf(stdout, "Building Configuration...\n");

	backup_config_file(frr_config);
	fp = fopen(frr_config, "w");
	if (fp == NULL) {
		fprintf(stdout,
			"%% Error: failed to open configuration file %s: %s\n",
			frr_config, safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}
	fd = fileno(fp);

	for (i = 0; i < array_size(vtysh_client); i++)
		vtysh_client_config(&vtysh_client[i], line);

	vtysh_config_write();
	vtysh_config_dump(fp);

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
	u_int i;

	fprintf(stdout,
		"Note: this version of vtysh never writes vtysh.conf\n");

	/* If integrated frr.conf explicitely set. */
	if (want_config_integrated()) {
		ret = CMD_WARNING_CONFIG_FAILED;
		for (i = 0; i < array_size(vtysh_client); i++)
			if (vtysh_client[i].flag == VTYSH_WATCHFRR)
				break;
		if (i < array_size(vtysh_client) && vtysh_client[i].fd != -1)
			ret = vtysh_client_execute(&vtysh_client[i],
						   "do write integrated",
						   stdout);

		if (ret != CMD_SUCCESS) {
			printf("\nWarning: attempting direct configuration write without "
			       "watchfrr.\nFile permissions and ownership may be "
			       "incorrect, or write may fail.\n\n");
			ret = vtysh_write_config_integrated();
		}
		return ret;
	}

	fprintf(stdout, "Building Configuration...\n");

	for (i = 0; i < array_size(vtysh_client); i++)
		ret = vtysh_client_execute(&vtysh_client[i], line, stdout);

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

DEFUN (vtysh_terminal_length,
       vtysh_terminal_length_cmd,
       "terminal length (0-512)",
       "Set terminal line parameters\n"
       "Set number of lines on a screen\n"
       "Number of lines on screen (0 for no pausing)\n")
{
	int idx_number = 2;
	int lines;
	char *endptr = NULL;
	char default_pager[10];

	lines = strtol(argv[idx_number]->arg, &endptr, 10);
	if (lines < 0 || lines > 512 || *endptr != '\0') {
		vty_out(vty, "length is malformed\n");
		return CMD_WARNING;
	}

	if (vtysh_pager_name) {
		free(vtysh_pager_name);
		vtysh_pager_name = NULL;
	}

	if (lines != 0) {
		snprintf(default_pager, 10, "more -%i", lines);
		vtysh_pager_name = strdup(default_pager);
	}

	return CMD_SUCCESS;
}

DEFUN (vtysh_terminal_no_length,
       vtysh_terminal_no_length_cmd,
       "terminal no length",
       "Set terminal line parameters\n"
       NO_STR
       "Set number of lines on a screen\n")
{
	if (vtysh_pager_name) {
		free(vtysh_pager_name);
		vtysh_pager_name = NULL;
	}

	vtysh_pager_init();
	return CMD_SUCCESS;
}

DEFUN (vtysh_show_daemons,
       vtysh_show_daemons_cmd,
       "show daemons",
       SHOW_STR
       "Show list of running daemons\n")
{
	u_int i;

	for (i = 0; i < array_size(vtysh_client); i++)
		if (vtysh_client[i].fd >= 0)
			vty_out(vty, " %s", vtysh_client[i].name);
	vty_out(vty, "\n");

	return CMD_SUCCESS;
}

/* Execute command in child process. */
static void execute_command(const char *command, int argc,
			    const char *arg1, const char *arg2)
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

DEFUN(find,
      find_cmd,
      "find COMMAND...",
      "Find CLI command containing text\n"
      "Text to search for\n")
{
	char *text = argv_concat(argv, argc, 1);
	const struct cmd_node *node;
	const struct cmd_element *cli;
	vector clis;

	for (unsigned int i = 0; i < vector_active(cmdvec); i++) {
		node = vector_slot(cmdvec, i);
		if (!node)
			continue;
		clis = node->cmd_vector;
		for (unsigned int j = 0; j < vector_active(clis); j++) {
			cli = vector_slot(clis, j);
			if (strcasestr(cli->string, text))
				fprintf(stdout, "  (%s)  %s\n",
					node_names[node->node], cli->string);
		}
	}

	XFREE(MTYPE_TMP, text);

	return CMD_SUCCESS;
}

static void vtysh_install_default(enum node_type node)
{
	install_element(node, &config_list_cmd);
	install_element(node, &find_cmd);
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

static void vtysh_update_all_insances(struct vtysh_client *head_client)
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
			if (begins_with(file->d_name, "ospfd-")
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

	vtysh_update_all_insances(head_client);

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
	u_int i;
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
	rl_attempted_completion_function =
		(rl_completion_func_t *)new_completion;
}

char *vtysh_prompt(void)
{
	static char buf[100];

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

	for (i = 0; i < array_size(vtysh_client); i++)
		vtysh_client_run_all(&vtysh_client[i], accmd, 1, NULL,
				     vtysh_ac_line, comps);
}

static const struct cmd_variable_handler vtysh_var_handler[] = {
	{/* match all */
	 .tokenname = NULL,
	 .varname = NULL,
	 .completions = vtysh_autocomplete},
	{.completions = NULL}};

void vtysh_init_vty(void)
{
	/* Make vty structure. */
	vty = vty_new();
	vty->type = VTY_SHELL;
	vty->node = VIEW_NODE;

	/* Initialize commands. */
	cmd_init(0);
	cmd_variable_handler_register(vtysh_var_handler);

	/* Install nodes. */
	install_node(&bgp_node, NULL);
	install_node(&rip_node, NULL);
	install_node(&interface_node, NULL);
	install_node(&pw_node, NULL);
	install_node(&link_params_node, NULL);
	install_node(&ns_node, NULL);
	install_node(&vrf_node, NULL);
	install_node(&rmap_node, NULL);
	install_node(&zebra_node, NULL);
	install_node(&bgp_vpnv4_node, NULL);
	install_node(&bgp_vpnv6_node, NULL);
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
	install_node(&vty_node, NULL);
#if defined(HAVE_RPKI)
	install_node(&rpki_node, NULL);
#endif

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
	install_element(KEYCHAIN_NODE, &vtysh_exit_ripd_cmd);
	install_element(KEYCHAIN_NODE, &vtysh_quit_ripd_cmd);
	install_element(KEYCHAIN_KEY_NODE, &vtysh_exit_ripd_cmd);
	install_element(KEYCHAIN_KEY_NODE, &vtysh_quit_ripd_cmd);
	install_element(RMAP_NODE, &vtysh_exit_rmap_cmd);
	install_element(RMAP_NODE, &vtysh_quit_rmap_cmd);
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
	install_element(KEYCHAIN_NODE, &vtysh_end_all_cmd);
	install_element(KEYCHAIN_KEY_NODE, &vtysh_end_all_cmd);
	install_element(RMAP_NODE, &vtysh_end_all_cmd);
	install_element(VTY_NODE, &vtysh_end_all_cmd);

	install_element(INTERFACE_NODE, &vtysh_interface_desc_cmd);
	install_element(INTERFACE_NODE, &vtysh_no_interface_desc_cmd);
	install_element(INTERFACE_NODE, &vtysh_end_all_cmd);
	install_element(INTERFACE_NODE, &vtysh_exit_interface_cmd);
	install_element(LINK_PARAMS_NODE, &exit_link_params_cmd);
	install_element(LINK_PARAMS_NODE, &vtysh_end_all_cmd);
	install_element(LINK_PARAMS_NODE, &vtysh_exit_interface_cmd);
	install_element(INTERFACE_NODE, &vtysh_quit_interface_cmd);

	install_element(PW_NODE, &vtysh_end_all_cmd);
	install_element(PW_NODE, &vtysh_exit_interface_cmd);
	install_element(PW_NODE, &vtysh_quit_interface_cmd);

	install_element(NS_NODE, &vtysh_end_all_cmd);

	install_element(CONFIG_NODE, &vtysh_ns_cmd);
	install_element(NS_NODE, &vtysh_exit_ns_cmd);
	install_element(NS_NODE, &vtysh_quit_ns_cmd);

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
	install_element(CONFIG_NODE, &router_bgp_cmd);
	install_element(BGP_NODE, &address_family_vpnv4_cmd);
	install_element(BGP_NODE, &address_family_vpnv6_cmd);
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

#if defined(HAVE_RPKI)
	install_element(CONFIG_NODE, &rpki_cmd);
	install_element(RPKI_NODE, &rpki_exit_cmd);
	install_element(RPKI_NODE, &rpki_quit_cmd);
	install_element(RPKI_NODE, &vtysh_end_all_cmd);
#endif

	/* EVPN commands */
	install_element(BGP_EVPN_NODE, &bgp_evpn_vni_cmd);
	install_element(BGP_EVPN_VNI_NODE, &exit_vni_cmd);

	install_element(BGP_VRF_POLICY_NODE, &exit_vrf_policy_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &exit_vnc_config_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &exit_vnc_config_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &exit_vnc_config_cmd);

	install_element(CONFIG_NODE, &key_chain_cmd);
	install_element(CONFIG_NODE, &vtysh_route_map_cmd);
	install_element(CONFIG_NODE, &vtysh_line_vty_cmd);
	install_element(KEYCHAIN_NODE, &key_cmd);
	install_element(KEYCHAIN_NODE, &key_chain_cmd);
	install_element(KEYCHAIN_KEY_NODE, &key_chain_cmd);
	install_element(CONFIG_NODE, &vtysh_interface_cmd);
	install_element(CONFIG_NODE, &vtysh_no_interface_cmd);
	install_element(CONFIG_NODE, &vtysh_no_interface_vrf_cmd);
	install_element(CONFIG_NODE, &vtysh_pseudowire_cmd);
	install_element(INTERFACE_NODE, &vtysh_link_params_cmd);
	install_element(ENABLE_NODE, &vtysh_show_running_config_cmd);
	install_element(ENABLE_NODE, &vtysh_copy_running_config_cmd);

	install_element(CONFIG_NODE, &vtysh_vrf_cmd);
	install_element(CONFIG_NODE, &vtysh_no_vrf_cmd);

	/* "write terminal" command. */
	install_element(ENABLE_NODE, &vtysh_write_terminal_cmd);

	install_element(CONFIG_NODE, &vtysh_integrated_config_cmd);
	install_element(CONFIG_NODE, &no_vtysh_integrated_config_cmd);

	/* "write memory" command. */
	install_element(ENABLE_NODE, &vtysh_write_memory_cmd);

	install_element(VIEW_NODE, &vtysh_terminal_length_cmd);
	install_element(VIEW_NODE, &vtysh_terminal_no_length_cmd);
	install_element(VIEW_NODE, &vtysh_show_daemons_cmd);

	install_element(VIEW_NODE, &vtysh_ping_cmd);
	install_element(VIEW_NODE, &vtysh_ping_ip_cmd);
	install_element(VIEW_NODE, &vtysh_traceroute_cmd);
	install_element(VIEW_NODE, &vtysh_traceroute_ip_cmd);
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

	install_element(VIEW_NODE, &vtysh_show_debugging_cmd);
	install_element(VIEW_NODE, &vtysh_show_debugging_hashtable_cmd);
	install_element(VIEW_NODE, &vtysh_show_memory_cmd);
	install_element(VIEW_NODE, &vtysh_show_modules_cmd);

	install_element(VIEW_NODE, &vtysh_show_work_queues_cmd);
	install_element(VIEW_NODE, &vtysh_show_work_queues_daemon_cmd);

	install_element(VIEW_NODE, &vtysh_show_thread_cmd);

	/* Logging */
	install_element(VIEW_NODE, &vtysh_show_logging_cmd);
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
	install_element(CONFIG_NODE, &vtysh_log_trap_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_trap_cmd);
	install_element(CONFIG_NODE, &vtysh_log_facility_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_facility_cmd);
	install_element(CONFIG_NODE, &vtysh_log_record_priority_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_record_priority_cmd);
	install_element(CONFIG_NODE, &vtysh_log_timestamp_precision_cmd);
	install_element(CONFIG_NODE, &no_vtysh_log_timestamp_precision_cmd);

	install_element(CONFIG_NODE, &vtysh_service_password_encrypt_cmd);
	install_element(CONFIG_NODE, &no_vtysh_service_password_encrypt_cmd);

	install_element(CONFIG_NODE, &vtysh_password_cmd);
	install_element(CONFIG_NODE, &vtysh_enable_password_cmd);
	install_element(CONFIG_NODE, &no_vtysh_enable_password_cmd);
}
