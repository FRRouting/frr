#ifndef _ZEBRA_NHRP_H
#define _ZEBRA_NHRP_H

#include <zebra.h>
#include <thread.h>

#define ZEBRA_GRE_NHRP_6WIND_RCV_BUF 500

extern int zebra_nhrp_6wind_fd;
extern bool zebra_nhrp_fastpath_configured;
extern struct thread *zebra_nhrp_log_thread;

int zebra_nhrp_6wind_configure_listen_port(uint16_t port);

int zebra_nhrp_6wind_access(int *fd_fp, int *fd_orig);

int zebra_nhrp_netlink_fastpath_parse(int fd, int orig_fd, int *status);

int zebra_nhrp_6wind_log_recv(struct thread *t);

#endif /* _ZEBRA_NHRP_H */

