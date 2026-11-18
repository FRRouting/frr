/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CNLAB_TCP_SNAPSHOT_H
#define CNLAB_TCP_SNAPSHOT_H
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
/* Same-host IPv4 established stream primitive. No application/FSM commit.
 * SACK holes, ECN and nonstandard TCP options are currently rejected.
 * Import caller MUST physically fence the destination until explicit activation.
 */
struct tcp_snapshot {
    struct sockaddr_in local, remote;
    struct tcp_info info;
    struct tcp_repair_window window;
    uint32_t send_end, recv_end, timestamp;
    int outq, unsent, unread, mss;
    int cork, nodelay, sndbuf, rcvbuf, user_timeout, status_flags;
    unsigned char *send_data, *recv_data;
    uint64_t capture_mono_ns, pause_ns;
};
void tcp_snapshot_free(struct tcp_snapshot *s);
int tcp_snapshot_export(int fd,struct tcp_snapshot *s);
int tcp_snapshot_export_hold(int fd,struct tcp_snapshot *s);
int tcp_snapshot_import_fenced(const struct tcp_snapshot *s,uint64_t *duration_ns);
int tcp_snapshot_activate(int fd);
#endif
