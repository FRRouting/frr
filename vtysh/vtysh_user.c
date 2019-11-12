/* User authentication for vtysh.
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
#include <lib/version.h>

#include <pwd.h>

#ifdef USE_PAM
#include <security/pam_appl.h>
#ifdef HAVE_PAM_MISC_H
#include <security/pam_misc.h>
#endif
#ifdef HAVE_OPENPAM_H
#include <security/openpam.h>
#endif
#endif /* USE_PAM */

#include "memory.h"
#include "linklist.h"
#include "command.h"
#include "vtysh/vtysh_user.h"

/*
 * Compiler is warning about prototypes not being declared.
 * The DEFUNSH and DEFUN macro's are messing with the
 * compiler I believe.  This is just to make it happy.
 */
#ifdef USE_PAM
static int vtysh_pam(const char *);
#endif
int vtysh_auth(void);
void vtysh_user_init(void);

extern struct list *config_top;
extern void config_add_line(struct list *config, const char *line);

#ifdef USE_PAM
static struct pam_conv conv = {PAM_CONV_FUNC, NULL};

static int vtysh_pam(const char *user)
{
	int ret;
	pam_handle_t *pamh = NULL;

	/* Start PAM. */
	ret = pam_start(FRR_PAM_NAME, user, &conv, &pamh);

	/* Is user really user? */
	if (ret == PAM_SUCCESS)
		ret = pam_authenticate(pamh, 0);

	if (ret != PAM_SUCCESS)
		fprintf(stderr, "vtysh_pam: Failure to initialize pam: %s(%d)",
			pam_strerror(pamh, ret), ret);

	/* close Linux-PAM */
	if (pam_end(pamh, ret) != PAM_SUCCESS) {
		pamh = NULL;
		fprintf(stderr, "vtysh_pam: failed to release authenticator: %s(%d)\n",
			pam_strerror(pamh, ret), ret);
		exit(1);
	}

	return ret == PAM_SUCCESS ? 0 : 1;
}
#endif /* USE_PAM */

struct vtysh_user {
	char *name;
	uint8_t nopassword;
};

struct list *userlist;

static struct vtysh_user *user_new(void)
{
	return XCALLOC(MTYPE_TMP, sizeof(struct vtysh_user));
}

static struct vtysh_user *user_lookup(const char *name)
{
	struct listnode *node, *nnode;
	struct vtysh_user *user;

	for (ALL_LIST_ELEMENTS(userlist, node, nnode, user)) {
		if (strcmp(user->name, name) == 0)
			return user;
	}
	return NULL;
}

void user_config_write(void)
{
	struct listnode *node, *nnode;
	struct vtysh_user *user;
	char line[128];

	for (ALL_LIST_ELEMENTS(userlist, node, nnode, user)) {
		if (user->nopassword) {
			sprintf(line, "username %s nopassword", user->name);
			config_add_line(config_top, line);
		}
	}
}

static struct vtysh_user *user_get(const char *name)
{
	struct vtysh_user *user;
	user = user_lookup(name);
	if (user)
		return user;

	user = user_new();
	user->name = strdup(name);
	listnode_add(userlist, user);

	return user;
}

DEFUN (vtysh_banner_motd_file,
       vtysh_banner_motd_file_cmd,
       "banner motd file FILE",
       "Set banner\n"
       "Banner for motd\n"
       "Banner from a file\n"
       "Filename\n")
{
	int idx_file = 3;
	return cmd_banner_motd_file(argv[idx_file]->arg);
}

DEFUN (vtysh_banner_motd_line,
       vtysh_banner_motd_line_cmd,
       "banner motd line LINE...",
       "Set banner\n"
       "Banner for motd\n"
       "Banner from an input\n"
       "Text\n")
{
	int idx = 0;
	char *motd;

	argv_find(argv, argc, "LINE", &idx);
	motd = argv_concat(argv, argc, idx);

	cmd_banner_motd_line(motd);
	XFREE(MTYPE_TMP, motd);

	return CMD_SUCCESS;
}

DEFUN (username_nopassword,
       username_nopassword_cmd,
       "username WORD nopassword",
       "\n"
       "\n"
       "\n")
{
	int idx_word = 1;
	struct vtysh_user *user;
	user = user_get(argv[idx_word]->arg);
	user->nopassword = 1;
	return CMD_SUCCESS;
}

int vtysh_auth(void)
{
	struct vtysh_user *user;
	struct passwd *passwd;

	if ((passwd = getpwuid(geteuid())) == NULL) {
		fprintf(stderr, "could not lookup user ID %d\n",
			(int)geteuid());
		exit(1);
	}

	user = user_lookup(passwd->pw_name);
	if (user && user->nopassword)
		/* Pass through */;
	else {
#ifdef USE_PAM
		if (vtysh_pam(passwd->pw_name))
			exit(0);
#endif /* USE_PAM */
	}
	return 0;
}

char *vtysh_get_home(void)
{
	struct passwd *passwd;
	char *homedir;

	if ((homedir = getenv("HOME")) != NULL)
		return homedir;

	/* Fallback if HOME is undefined */
	passwd = getpwuid(getuid());

	return passwd ? passwd->pw_dir : NULL;
}

void vtysh_user_init(void)
{
	userlist = list_new();
	install_element(CONFIG_NODE, &username_nopassword_cmd);
	install_element(CONFIG_NODE, &vtysh_banner_motd_file_cmd);
	install_element(CONFIG_NODE, &vtysh_banner_motd_line_cmd);
}
