// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>

#include "babeld.h"
#include "util.h"
#include "net.h"
#include "sockopt.h"

int
babel_socket(int port)
{
    struct sockaddr_in6 sin6;
    int s, rc;
    int saved_errno;
    int one = 1, zero = 0;

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                    &zero, sizeof(zero));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                    &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                    &one, sizeof(one));
    if(rc < 0)
        goto fail;

    setsockopt_ipv6_tclass (s, IPTOS_PREC_INTERNETCONTROL);

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    rc = bind(s, (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc < 0)
        goto fail;

    return s;

 fail:
    saved_errno = errno;
    close(s);
    errno = saved_errno;
    return -1;
}

int
babel_recv(int s, void *buf, int buflen, struct sockaddr *sin, int slen)
{
    struct iovec iovec;
    struct msghdr msg;
    int rc;

    memset(&msg, 0, sizeof(msg));
    iovec.iov_base = buf;
    iovec.iov_len = buflen;
    msg.msg_name = sin;
    msg.msg_namelen = slen;
    msg.msg_iov = &iovec;
    msg.msg_iovlen = 1;

    rc = recvmsg(s, &msg, 0);
    return rc;
}

int
babel_send(int s,
           void *buf1, int buflen1, void *buf2, int buflen2,
           struct sockaddr *sin, int slen)
{
    struct iovec iovec[2];
    struct msghdr msg;
    int rc;

    iovec[0].iov_base = buf1;
    iovec[0].iov_len = buflen1;
    iovec[1].iov_base = buf2;
    iovec[1].iov_len = buflen2;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = sin;
    msg.msg_namelen = slen;
    msg.msg_iov = iovec;
    msg.msg_iovlen = 2;

 again:
    rc = sendmsg(s, &msg, 0);
    if(rc < 0) {
        if(errno == EINTR)
            goto again;
        else if(errno == EAGAIN) {
            int rc2;
            rc2 = wait_for_fd(1, s, 5);
            if(rc2 > 0)
                goto again;
            errno = EAGAIN;
        }
    }
    return rc;
}

int
tcp_server_socket(int port, int local)
{
    struct sockaddr_in6 sin6;
    int s, rc, saved_errno;
    int one = 1;

    s = socket(PF_INET6, SOCK_STREAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    if(local) {
        rc = inet_pton(AF_INET6, "::1", &sin6.sin6_addr);
        if(rc < 0)
            goto fail;
    }
    rc = bind(s, (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc < 0)
        goto fail;

    rc = listen(s, 2);
    if(rc < 0)
        goto fail;

    return s;

 fail:
    saved_errno = errno;
    close(s);
    errno = saved_errno;
    return -1;
}
