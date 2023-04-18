// SPDX-License-Identifier: MIT
/*
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
*/

#ifndef BABEL_MAIN_H
#define BABEL_MAIN_H

#include "vty.h"

extern struct timeval babel_now;         /* current time             */
extern struct event_loop *master;	 /* quagga's threads handler */
extern int debug;
extern int resend_delay;

extern unsigned char myid[8];

extern const unsigned char zeroes[16], ones[16];

extern int protocol_port;
extern unsigned char protocol_group[16];
extern int protocol_socket;
extern int kernel_socket;
extern int max_request_hopcount;

void babel_load_state_file(void);
void show_babel_main_configuration (struct vty *vty);

#endif /* BABEL_MAIN_H */
