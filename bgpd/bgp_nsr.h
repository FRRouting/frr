/* Experimental exact-connection input and kernel-accepted output journal. */
#ifndef CNLAB_BGP_NSR_H
#define CNLAB_BGP_NSR_H
#include "lib/hook.h"
#include <sys/uio.h>
DECLARE_HOOK(cnlab_bgp_input, (struct peer_connection *c, uint8_t type, bgp_size_t size, struct stream *s), (c,type,size,s));
DECLARE_HOOK(cnlab_bgp_written, (struct peer_connection *c, const struct iovec *iov, size_t count, size_t accepted), (c,iov,count,accepted));
DECLARE_HOOK(cnlab_bgp_socket_identity, (int fd, const union sockunion *local, const union sockunion *remote), (fd,local,remote));

DECLARE_HOOK(cnlab_bgp_native_event_gate,(struct peer_connection *c,int kind,afi_t afi,safi_t safi),(c,kind,afi,safi));
DECLARE_HOOK(cnlab_bgp_native_event,(struct peer_connection *c,int kind,afi_t afi,safi_t safi),(c,kind,afi,safi));
int cnlab_bgp_native_event_begin(struct peer_connection *c,int kind,afi_t afi,safi_t safi);
int cnlab_bgp_restore_hold_timer(struct peer_connection *c,int64_t remaining_us);
int cnlab_bgp_replay_native_event(struct peer_connection *c,int kind,afi_t afi,safi_t safi);
bool cnlab_bgp_keepalive_pause(struct peer_connection *c,struct timeval *last);
void cnlab_bgp_keepalive_resume(struct peer_connection *c,const struct timeval *last);
extern int cnlab_bgp_start_owner_listener(const char *address);
DECLARE_HOOK(cnlab_bgp_open_restart_bit, (struct peer *peer, bool *restart), (peer,restart));

#endif
