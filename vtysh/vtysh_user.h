// SPDX-License-Identifier: GPL-2.0-or-later
/* User authentication for vtysh.
 * Copyright (C) 2000 Kunihiro Ishiguro
 */

#ifndef _VTYSH_USER_H
#define _VTYSH_USER_H

int vtysh_auth(void);
void vtysh_user_init(void);
void user_config_write(void);

char *vtysh_get_home(void);

#endif /* _VTYSH_USER_H */
