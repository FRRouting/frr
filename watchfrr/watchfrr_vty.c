/*
 * watchfrr CLI functions.
 *
 * Copyright (C) 2016  David Lamparter for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <sys/wait.h>

#include "memory.h"
#include "log.h"
#include "vty.h"
#include "command.h"

#include "watchfrr.h"

pid_t integrated_write_pid;
static int integrated_result_fd;

DEFUN(config_write_integrated,
      config_write_integrated_cmd,
      "write integrated",
      "Write running configuration to memory, network, or terminal\n"
      "Write integrated all-daemon frr.conf file\n")
{
	pid_t child;
	sigset_t oldmask, sigmask;

	const char *e_inprog = "Configuration write already in progress.";
	const char *e_dmn = "Not all daemons are up, cannot write config.";

	if (integrated_write_pid != -1) {
		vty_out(vty, "%% %s\n", e_inprog);
		return CMD_WARNING;
	}

	/* check that all daemons are up before clobbering config */
	if (!check_all_up()) {
		vty_out(vty, "%% %s\n", e_dmn);
		/*
		 * vtysh interprets this return value to mean that it should
		 * not try to write the config itself
		 */
		return CMD_WARNING_CONFIG_FAILED;
	}

	fflush(stdout);
	fflush(stderr);

	/* need to temporarily block SIGCHLD because it could arrive between
	 * fork() call and setting the integrated_write_pid variable.  This
	 * would mean the completion call gets lost and this hangs forever.
	 */
	sigemptyset(&oldmask);
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sigmask, &oldmask);

	child = fork();
	if (child == -1) {
		vty_out(vty, "%% configuration write fork() failed: %s.\n",
			safe_strerror(errno));
		sigprocmask(SIG_SETMASK, &oldmask, NULL);
		return CMD_WARNING;
	}
	if (child != 0) {
		/* note: the VTY won't write a command return value to vtysh;
		 * the
		 * session temporarily enters an intentional "hang" state.  This
		 * is
		 * to make sure latency in vtysh doing the config write (several
		 * seconds is not rare to see) does not interfere with
		 * watchfrr's
		 * supervisor job.
		 *
		 * The fd is duplicated here so we don't need to hold a vty
		 * pointer
		 * (which could become invalid in the meantime).
		 */
		integrated_write_pid = child;
		integrated_result_fd = dup(vty->wfd);
		sigprocmask(SIG_SETMASK, &oldmask, NULL);
		return CMD_SUSPEND;
	}

	/* redirect stdout/stderr to vty session.  Note vty->wfd is marked
	 * CLOEXEC, but dup2 will clear that flag. */
	dup2(vty->wfd, 1);
	dup2(vty->wfd, 2);

	/* don't allow the user to pass parameters, we're root here!
	 * should probably harden vtysh at some point too... */
	execl(VTYSH_BIN_PATH, "vtysh", "-w", NULL);

	/* unbuffered write; we just messed with stdout... */
	char msg[512];
	snprintf(msg, sizeof(msg), "error executing %s: %s\n", VTYSH_BIN_PATH,
		 safe_strerror(errno));
	write(1, msg, strlen(msg));
	exit(1);
}

DEFUN_NOSH (show_debugging_watchfrr,
            show_debugging_watchfrr_cmd,
            "show debugging [watchfrr]",
            SHOW_STR
            DEBUG_STR
            WATCHFRR_STR)
{
	return CMD_SUCCESS;
}

void integrated_write_sigchld(int status)
{
	uint8_t reply[4] = {0, 0, 0, CMD_WARNING};

	if (WIFEXITED(status)) {
		zlog_info("configuration write completed with exit code %d",
			  WEXITSTATUS(status));
		reply[3] = WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		zlog_warn("configuration write terminated by signal %d",
			  WTERMSIG(status));
	} else {
		zlog_warn("configuration write terminated");
	}

	if (reply[3] != CMD_SUCCESS) {
		/* failure might be silent in vtysh without this */
		static const char msg[] = "% Configuration write failed.\n";
		write(integrated_result_fd, msg, strlen(msg));
	}

	/* don't care about failures here, if the connection is broken the
	 * return value will just be lost. */
	write(integrated_result_fd, reply, sizeof(reply));
	close(integrated_result_fd);

	integrated_write_pid = -1;
}

void watchfrr_vty_init(void)
{
	integrated_write_pid = -1;
	install_element(ENABLE_NODE, &config_write_integrated_cmd);
	install_element(ENABLE_NODE, &show_debugging_watchfrr_cmd);
	install_element(CONFIG_NODE, &show_debugging_watchfrr_cmd);
}
