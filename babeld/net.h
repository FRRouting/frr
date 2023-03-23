// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
*/

#ifndef BABEL_NET_H
#define BABEL_NET_H

int babel_socket(int port);
int babel_recv(int s, void *buf, int buflen, struct sockaddr *sin, int slen);
int babel_send(int s,
               void *buf1, int buflen1, void *buf2, int buflen2,
               struct sockaddr *sin, int slen);
int tcp_server_socket(int port, int local);

#endif /* BABEL_NET_H */
