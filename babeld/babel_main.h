/*
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef BABEL_MAIN_H
#define BABEL_MAIN_H

#include "vty.h"

extern struct timeval babel_now;         /* current time             */
extern struct thread_master *master;     /* quagga's threads handler */
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
