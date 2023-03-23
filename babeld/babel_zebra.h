// SPDX-License-Identifier: MIT
/*
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
*/

#ifndef BABEL_ZEBRA_H
#define BABEL_ZEBRA_H

#include "vty.h"

extern struct zclient *zclient;

void babelz_zebra_init(void);
void babel_zebra_close_connexion(void);
extern int debug_babel_config_write (struct vty *);

#endif
