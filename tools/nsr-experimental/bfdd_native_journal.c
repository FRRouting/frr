/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental native BFD state journal. No state import or promotion. */
#include <zebra.h>
#include "lib/module.h"
#include "lib/version.h"
#include "lib/json.h"
#include "lib/log.h"
#include "lib/frrevent.h"
#include "bfdd/bfd.h"
#include "bfdd/bfd_nsr.h"
#include <sys/un.h>
#include <sys/socket.h>
#include <time.h>
static int replica_fd=-1;
static uint64_t record_id;
static bool failed;
static int64_t remaining(struct event *ev) {
    if(!event_is_scheduled(ev))return -1;
    struct timeval t=event_timer_remain(ev);
    return (int64_t)t.tv_sec*1000000+t.tv_usec;
}
static int record_state(struct bfd_session *bs,const char *phase) {
    if(getenv("CNLAB_NSR_JOURNAL_STANDBY"))return 0;
    if(getenv("CNLAB_NSR_RX_JOURNAL_ONLY")&&strcmp(phase,"rx_applied"))return 0;
    json_object *j=json_object_new_object();
    struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
#define JI(k,v) json_object_object_add(j,k,json_object_new_int64(v))
#define JS(k,v) json_object_object_add(j,k,json_object_new_string(v))
    JS("schema","cnlab-native-bfd-v1");JI("pid",getpid());
    JI("record_id",++record_id);JI("observed_monotonic_ns",(uint64_t)ts.tv_sec*1000000000+ts.tv_nsec);
    JS("phase",phase);JI("state",bs->ses_state);
    char peer[INET6_ADDRSTRLEN],local[INET6_ADDRSTRLEN];
    inet_ntop(bs->key.family,&bs->key.peer,peer,sizeof(peer));
    inet_ntop(bs->key.family,&bs->key.local,local,sizeof(local));
    JS("peer_ipv4",peer);JS("local_ip",local);JS("ifname",bs->key.ifname);JS("vrfname",bs->key.vrfname);
    JI("family",bs->key.family);JI("mhop",bs->key.mhop);
    json_object_object_add(j,"has_authentication",json_object_new_boolean(bs->kc!=NULL));
    json_object_object_add(j,"echo_active",json_object_new_boolean(CHECK_FLAG(bs->flags,BFD_SESS_FLAG_ECHO_ACTIVE)));
    JI("my_discriminator",bs->discrs.my_discr);JI("remote_discriminator",bs->discrs.remote_discr);
    JI("local_diag",bs->local_diag);JI("remote_diag",bs->remote_diag);
    JI("polling",bs->polling);JI("demand_mode",bs->demand_mode);
    JI("detect_mult",bs->detect_mult);JI("remote_detect_mult",bs->remote_detect_mult);
    JI("detection_timeout_us",bs->detect_TO);JI("transmit_timeout_us",bs->xmt_TO);
    JI("transmit_actual_us",bs->xmt_TO_actual);
    JI("local_min_tx_us",bs->cur_timers.desired_min_tx);JI("local_min_rx_us",bs->cur_timers.required_min_rx);
    JI("remote_min_tx_us",bs->remote_timers.desired_min_tx);JI("remote_min_rx_us",bs->remote_timers.required_min_rx);
    JI("rx_timer_remaining_us",remaining(bs->recvtimer_ev));
    JI("tx_timer_remaining_us",remaining(bs->xmttimer_ev));
    JI("uptime_monotonic_us",(int64_t)bs->uptime.tv_sec*1000000+bs->uptime.tv_usec);
    JI("downtime_monotonic_us",(int64_t)bs->downtime.tv_sec*1000000+bs->downtime.tv_usec);
    JI("auth_tx_seq",bs->auth_seq_num);JI("auth_rx_seq",bs->auth_last_rx_seq_num);
    json_object_object_add(j,"promotable_checkpoint",json_object_new_boolean(false));
    const char *text=json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN);
    ssize_t n=send(replica_fd,text,strlen(text),MSG_DONTWAIT|MSG_NOSIGNAL);
    if(n!=(ssize_t)strlen(text) && !failed){failed=true;zlog_err("CNLAB BFD replica observer disconnected; NOT promotable");}
    json_object_put(j);return failed ? -1:0;
}
static int module_init(void) {
    const char *path=getenv("CNLAB_NSR_REPLICA_SOCK");
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    if(!path || strncmp(path,"/run/frr-nsr/",13) || strlen(path)>=sizeof(addr.sun_path))return -1;
    strlcpy(addr.sun_path,path,sizeof(addr.sun_path));
    replica_fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    int journal_budget=16*1024*1024;if(replica_fd<0||setsockopt(replica_fd,SOL_SOCKET,SO_SNDBUFFORCE,&journal_budget,sizeof(journal_budget)))return -1;
    if(replica_fd<0 || connect(replica_fd,(struct sockaddr *)&addr,sizeof(addr)))return -1;
    hook_register(cnlab_bfd_state,record_state);return 0;
}
FRR_MODULE_SETUP(.name="cnlab_bfdd_native_journal",.version=FRR_VERSION,
    .description="Native BFD state replication observer; not promotable",.init=module_init,);
