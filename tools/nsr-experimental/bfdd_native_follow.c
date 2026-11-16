/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental native BFD follower with guarded activation.
 * All BFD sends are blocked by a daemon hook. Applies complete, fresh,
 * unauthenticated/no-echo IPv4 steady-state snapshots to real FRR objects.
 */
#include <zebra.h>
#include "lib/module.h"
#include "lib/version.h"
#include "lib/json.h"
#include "lib/frrevent.h"
#include "lib/hash.h"
#include "bfdd/bfd.h"
#include "bfdd/bfd_nsr.h"
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <fcntl.h>
#include "lib/privs.h"
#include "owner_claim.h"
static struct event_loop *loop;
static struct event *accept_event;
static int listener=-1;
static uint64_t blocked_sends,last_id,shadow_id_relocations;
static bool native_active,tx_started,defer_tx;
static int64_t producer_pid;
struct control {int fd;struct event *event;};
static uint64_t clock_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static int block_send(struct bfd_session *bs){(void)bs;if(native_active&&tx_started)return 0;blocked_sends++;return 1;}
static json_object *error(const char *why){json_object *j=json_object_new_object();json_object_object_add(j,"applied",json_object_new_boolean(false));json_object_object_add(j,"error",json_object_new_string(why));return j;}
static bool integer(json_object *j,const char *key,int64_t *v){json_object *o;if(!json_object_object_get_ex(j,key,&o)||json_object_get_type(o)!=json_type_int)return false;*v=json_object_get_int64(o);return true;}
static const char *string(json_object *j,const char *key){json_object *o;if(!json_object_object_get_ex(j,key,&o)||json_object_get_type(o)!=json_type_string)return NULL;return json_object_get_string(o);}
struct match {struct in_addr peer;struct bfd_session *bs;unsigned count;};
static void find_peer(struct hash_bucket *bucket,void *arg){struct match *m=arg;struct bfd_session *bs=bucket->data;if(bs->key.family==AF_INET&&!bs->key.mhop&&!memcmp(&bs->key.peer,&m->peer,sizeof(m->peer))){m->bs=bs;m->count++;}}
static int64_t remaining(struct event *e){if(!event_is_scheduled(e))return -1;struct timeval t=event_timer_remain(e);return (int64_t)t.tv_sec*1000000+t.tv_usec;}
struct bfd_applied {struct bfd_session *session;uint64_t record;};
static struct bfd_applied applied[256];static size_t applied_count;
static struct bfd_applied *applied_for(struct bfd_session *bs){
 for(size_t i=0;i<applied_count;i++)if(applied[i].session==bs)return &applied[i];
 if(applied_count==array_size(applied))return NULL;
 applied[applied_count].session=bs;return &applied[applied_count++];
}
static bool uncommitted_shadow(struct bfd_session *bs){
 if(native_active||tx_started||bs->ses_state!=PTM_BFD_DOWN||bs->discrs.remote_discr)return false;
 for(size_t i=0;i<applied_count;i++)if(applied[i].session==bs&&applied[i].record)return false;
 return true;
}
#include "bfd_id_reservation.h"
static json_object *native_status(struct bfd_session *bs){
    json_object *j=json_object_new_object();
#define NUM(k,v) json_object_object_add(j,k,json_object_new_int64(v))
    NUM("shadow_id_relocations",shadow_id_relocations);NUM("native_state",bs->ses_state);NUM("native_my_discriminator",bs->discrs.my_discr);NUM("native_remote_discriminator",bs->discrs.remote_discr);
    NUM("rx_timer_remaining_us",remaining(bs->recvtimer_ev));NUM("tx_timer_remaining_us",remaining(bs->xmttimer_ev));
    NUM("detection_timeout_us",bs->detect_TO);NUM("blocked_send_attempts",blocked_sends);struct bfd_applied *entry=applied_for(bs);NUM("last_applied_record",entry?entry->record:0);
    json_object_object_add(j,"native_id_index_matches",json_object_new_boolean(bfd_id_lookup(bs->discrs.my_discr)==bs));
    json_object_object_add(j,"send_gate_closed",json_object_new_boolean(!native_active||!tx_started));json_object_object_add(j,"promotable_checkpoint",json_object_new_boolean(false));
    return j;
}
struct snapshot {int64_t observed,id,pid,state,my,remote,rx,tx,detect,mult,rmult,ltx,lrx,rtx,rrx,diag,rdiag,poll,demand,uptime,downtime,actual_tx;};
static json_object *apply(json_object *j);
static json_object *apply_many(json_object *j,const char *operation);
static json_object *apply(json_object *j){
    if(!j)return error("invalid_json");
    const char *operation=string(j,"action");
    if(operation&&(!strcmp(operation,"batch")||!strcmp(operation,"query_all")||!strcmp(operation,"activate_all")||!strcmp(operation,"start_all")))return apply_many(j,operation);
    const char *peer=string(j,"peer_ipv4");struct match m={0};
    if(!peer||inet_pton(AF_INET,peer,&m.peer)!=1)return error("invalid_peer");
    bfd_id_iterate(find_peer,&m);if(m.count!=1)return error("native_peer_missing_or_ambiguous");
    struct bfd_session *bs=m.bs;
    const char *action=string(j,"action");if(action&&!strcmp(action,"query"))return native_status(bs);
    if(action&&!strcmp(action,"activate")){
        int64_t epoch;if(!integer(j,"epoch",&epoch))return error("epoch_required");
        if(native_active)return error("already_active");
        if(bs->ses_state!=PTM_BFD_UP||remaining(bs->recvtimer_ev)<=0)return error("native_bfd_not_ready");
        if(!owner_claim("bfdd",epoch,&bglobal.bfdd_privs))return error("owner_grant_refused");
        native_active=true;tx_started=!defer_tx;if(!owner_ready("bfdd",epoch,&bglobal.bfdd_privs))return error("owner_readiness_commit_failed");json_object *reply=native_status(bs);json_object_object_add(reply,"activated",json_object_new_boolean(true));return reply;
    }
    if(action&&!strcmp(action,"start_tx")){
        int64_t epoch;if(!integer(j,"epoch",&epoch)||epoch<1)return error("wrong_epoch");
        if(!native_active||tx_started)return error("native_tx_phase_invalid");
        if(bs->ses_state!=PTM_BFD_UP||remaining(bs->recvtimer_ev)<=0)return error("native_bfd_not_ready");
        if(!owner_action("bfdd",epoch,&bglobal.bfdd_privs,"confirm_release"))return error("physical_release_not_committed");
        tx_started=true;bfd_xmttimer_delete(bs);struct timeval due={0};event_add_timer_tv(loop,bfd_xmt_cb,bs,&due,&bs->xmttimer_ev);
        json_object *reply=native_status(bs);json_object_object_add(reply,"started_native_tx",json_object_new_boolean(true));return reply;
    }
    if(native_active)return error("replication_after_activation_forbidden");
    const char *schema=string(j,"schema"),*phase=string(j,"phase");
    if(!schema||strcmp(schema,"cnlab-native-bfd-v1")||!phase||strcmp(phase,"rx_applied"))return error("complete_rx_snapshot_required");
    int64_t family,mhop;const char *local=string(j,"local_ip"),*ifname=string(j,"ifname"),*vrf=string(j,"vrfname");struct in_addr local_addr;
    if(!integer(j,"family",&family)||family!=AF_INET||!integer(j,"mhop",&mhop)||mhop||!local||inet_pton(AF_INET,local,&local_addr)!=1||memcmp(&bs->key.local,&local_addr,sizeof(local_addr))||!ifname||strcmp(ifname,bs->key.ifname)||!vrf||strcmp(vrf,bs->key.vrfname))return error("session_key_mismatch");
    struct snapshot s;
#define GET(member,key) if(!integer(j,key,&s.member))return error("missing_or_invalid_" key)
    GET(observed,"observed_monotonic_ns");GET(id,"record_id");GET(pid,"pid");GET(state,"state");GET(my,"my_discriminator");GET(remote,"remote_discriminator");
    GET(rx,"rx_timer_remaining_us");GET(tx,"tx_timer_remaining_us");GET(detect,"detection_timeout_us");GET(mult,"detect_mult");GET(rmult,"remote_detect_mult");
    GET(ltx,"local_min_tx_us");GET(lrx,"local_min_rx_us");GET(rtx,"remote_min_tx_us");GET(rrx,"remote_min_rx_us");
    GET(diag,"local_diag");GET(rdiag,"remote_diag");GET(poll,"polling");GET(demand,"demand_mode");GET(uptime,"uptime_monotonic_us");GET(downtime,"downtime_monotonic_us");GET(actual_tx,"transmit_actual_us");
    json_object *auth,*echo;
    if(!json_object_object_get_ex(j,"has_authentication",&auth)||json_object_get_type(auth)!=json_type_boolean||json_object_get_boolean(auth)||!json_object_object_get_ex(j,"echo_active",&echo)||json_object_get_type(echo)!=json_type_boolean||json_object_get_boolean(echo)||bs->kc||CHECK_FLAG(bs->flags,BFD_SESS_FLAG_ECHO_ACTIVE))return error("auth_or_echo_unsupported");
    if(s.state!=PTM_BFD_UP||s.my<=0||s.my>UINT32_MAX||s.remote<=0||s.remote>UINT32_MAX||s.rmult<1||s.rmult>255||s.rtx<1||s.rtx>UINT32_MAX||s.rrx<1||s.rrx>UINT32_MAX)return error("unsupported_state");
    if(s.demand||s.poll<0||s.poll>1||s.diag<0||s.diag>31||s.rdiag<0||s.rdiag>31||s.uptime<0||s.downtime<0||s.actual_tx<0||s.actual_tx>UINT32_MAX)return error("unsupported_flags_or_timers");
    if(s.mult!=bs->detect_mult||s.ltx!=bs->timers.desired_min_tx||s.lrx!=bs->timers.required_min_rx)return error("local_configuration_mismatch");
    uint64_t expected=(uint64_t)s.rmult*(s.lrx>s.rtx?s.lrx:s.rtx);
    uint64_t budget=(uint64_t)bs->detect_mult*(bs->timers.desired_min_tx>bs->timers.required_min_rx?bs->timers.desired_min_tx:bs->timers.required_min_rx);
    if(s.detect<=0||(uint64_t)s.detect!=expected||(uint64_t)s.detect>budget||s.rx<=0||s.rx>s.detect)return error("detection_budget_mismatch");
    uint64_t now=clock_ns();if(s.observed<=0||(uint64_t)s.observed>now)return error("clock_domain_mismatch");
    int64_t elapsed=(now-s.observed)/1000;
    if(elapsed>=s.rx)return error("expired_snapshot");
    if(s.id<=0||s.pid<=0||(producer_pid&&producer_pid!=s.pid)||(uint64_t)s.id<=last_id)return error("replayed_or_wrong_producer");
    if(!cnlab_bfd_reserve_snapshot_id(bs,(uint32_t)s.my,uncommitted_shadow,&shadow_id_relocations))return error("discriminator_collision");
    uint32_t old=bs->discrs.my_discr;
    if(old!=(uint32_t)s.my){
        if(bfd_id_delete(old)!=bs)return error("old_native_id_missing");
        bs->discrs.my_discr=s.my;
        if(!bfd_id_insert(bs)){bs->discrs.my_discr=old;bfd_id_insert(bs);return error("native_id_insert_failed");}
    }
    uint8_t previous_state=bs->ses_state;
    bfd_recvtimer_delete(bs);bfd_xmttimer_delete(bs);
    bs->discrs.remote_discr=s.remote;bs->ses_state=s.state;bs->local_diag=s.diag;bs->remote_diag=s.rdiag;
    bs->polling=s.poll;bs->demand_mode=s.demand;bs->remote_detect_mult=s.rmult;
    bs->cur_timers.desired_min_tx=s.ltx;bs->cur_timers.required_min_rx=s.lrx;
    bs->remote_timers.desired_min_tx=s.rtx;bs->remote_timers.required_min_rx=s.rrx;
    bs->detect_TO=s.detect;bs->xmt_TO=s.ltx;bs->xmt_TO_actual=s.actual_tx;
    bs->uptime.tv_sec=s.uptime/1000000;bs->uptime.tv_usec=s.uptime%1000000;
    bs->downtime.tv_sec=s.downtime/1000000;bs->downtime.tv_usec=s.downtime%1000000;
    elapsed=(clock_ns()-s.observed)/1000;
    int64_t rx=s.rx-elapsed-100,tx=s.tx-elapsed-100;
    if(rx<=0){ptm_bfd_sess_dn(bs,1,false);return error("expired_during_apply");}
    if(tx<0)tx=0;
    struct timeval rt={.tv_sec=rx/1000000,.tv_usec=rx%1000000},tt={.tv_sec=tx/1000000,.tv_usec=tx%1000000};
    event_add_timer_tv(loop,bfd_recvtimer_cb,bs,&rt,&bs->recvtimer_ev);
    event_add_timer_tv(loop,bfd_xmt_cb,bs,&tt,&bs->xmttimer_ev);
    last_id=s.id;producer_pid=s.pid;struct bfd_applied *entry=applied_for(bs);if(!entry)return error("peer_state_limit");entry->record=s.id;
    if(previous_state!=PTM_BFD_UP)ptm_bfd_notify(bs,PTM_BFD_UP);
    json_object *reply=native_status(bs);json_object_object_add(reply,"applied",json_object_new_boolean(true));
    json_object_object_add(reply,"source_record_id",json_object_new_int64(s.id));
    return reply;
}
static json_object *apply_many(json_object *j,const char *operation){
 json_object *items=NULL,*rows=json_object_new_array(),*result=json_object_new_object();bool records=!strcmp(operation,"batch"),activate=!strcmp(operation,"activate_all"),start=!strcmp(operation,"start_all");
 if(!json_object_object_get_ex(j,records?"records":"peers",&items)||json_object_get_type(items)!=json_type_array||!json_object_array_length(items)||json_object_array_length(items)>256){json_object_put(rows);json_object_put(result);return error("invalid_batch_bound");}
 struct bfd_session *sessions[256];size_t total=json_object_array_length(items);int64_t epoch=0;const char *failure=NULL;
 if((activate||start)&&(!integer(j,"epoch",&epoch)||epoch<1||total!=applied_count))failure="complete_activation_set_required";
 for(size_t i=0;i<total&&!failure;i++){
  json_object *item=json_object_array_get_idx(items,i);
  if(records){json_object *reply=apply(item),*why=NULL;if(json_object_object_get_ex(reply,"error",&why)){json_object_object_add(result,"error",json_object_get(why));failure="BFD_batch_refused";}json_object_put(reply);continue;}
  struct match m={0};if(json_object_get_type(item)!=json_type_string||inet_pton(AF_INET,json_object_get_string(item),&m.peer)!=1){failure="invalid_peer";break;}
  bfd_id_iterate(find_peer,&m);if(m.count!=1){failure="native_peer_missing_or_ambiguous";break;}sessions[i]=m.bs;
  for(size_t k=0;k<i;k++)if(sessions[k]==sessions[i])failure="duplicate_peer";
  if((activate||start)&&(m.bs->ses_state!=PTM_BFD_UP||remaining(m.bs->recvtimer_ev)<=0||m.bs->detect_TO!=900000))failure="native_bfd_not_ready";
  json_object *row=native_status(m.bs);json_object_object_add(row,"peer",json_object_get(item));json_object_array_add(rows,row);
 }
 if(!failure&&activate){
  if(native_active||!defer_tx||!owner_claim("bfdd",epoch,&bglobal.bfdd_privs))failure="owner_grant_refused";
  else{native_active=true;tx_started=false;if(!owner_ready("bfdd",epoch,&bglobal.bfdd_privs))failure="owner_readiness_commit_failed";}
 }
 if(!failure&&start){
  if(!native_active||tx_started||!owner_action("bfdd",epoch,&bglobal.bfdd_privs,"confirm_release"))failure="physical_release_not_committed";
  else{unsetenv("CNLAB_NSR_JOURNAL_STANDBY");tx_started=true;for(size_t i=0;i<total;i++){bfd_xmttimer_delete(sessions[i]);struct timeval due={0};event_add_timer_tv(loop,bfd_xmt_cb,sessions[i],&due,&sessions[i]->xmttimer_ev);}}
 }
 json_object_object_add(result,"ok",json_object_new_boolean(!failure));json_object_object_add(result,"count",json_object_new_int64(total));json_object_object_add(result,"peers",rows);
 if(failure){json_object *existing;if(!json_object_object_get_ex(result,"error",&existing))json_object_object_add(result,"error",json_object_new_string(failure));}
 if(activate)json_object_object_add(result,"activated",json_object_new_boolean(!failure));
 if(start)json_object_object_add(result,"started_native_tx",json_object_new_boolean(!failure));
 return result;
}
static void control_read(struct event *event){
    struct control *c=EVENT_ARG(event);char data[159999];ssize_t n=recv(c->fd,data,sizeof(data)-1,MSG_DONTWAIT);
    json_object *j=NULL,*reply;
    if(n>0&&n<(ssize_t)sizeof(data)-1){data[n]=0;j=json_tokener_parse(data);}
    reply=apply(j);const char *text=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);
    send(c->fd,text,strlen(text),MSG_NOSIGNAL|MSG_DONTWAIT);if(j)json_object_put(j);json_object_put(reply);close(c->fd);free(c);
}
static void accept_control(struct event *event){
    (void)event;event_add_read(loop,accept_control,NULL,listener,&accept_event);
    int fd=accept4(listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);if(fd<0)return;
    int buffer=1024*1024;setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer));
    struct control *c=calloc(1,sizeof(*c));if(!c){close(fd);return;}c->fd=fd;
    event_add_read(loop,control_read,c,fd,&c->event);
}
static int late_init(struct event_loop *master){loop=master;event_add_read(loop,accept_control,NULL,listener,&accept_event);return 0;}
static int module_init(void){
    defer_tx=getenv("CNLAB_NSR_BFD_DEFER_TX")&&!strcmp(getenv("CNLAB_NSR_BFD_DEFER_TX"),"1");
    const char *path=getenv("CNLAB_NSR_BFD_FOLLOW_SOCK");struct sockaddr_un addr={.sun_family=AF_UNIX};
    if(!path||strncmp(path,"/run/frr-nsr/",13)||strlen(path)>=sizeof(addr.sun_path))return -1;
    strlcpy(addr.sun_path,path,sizeof(addr.sun_path));listener=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if(listener<0||bind(listener,(struct sockaddr *)&addr,sizeof(addr))||listen(listener,8))return -1;
    chmod(path,0600);hook_register(cnlab_bfd_send_blocked,block_send);hook_register(frr_late_init,late_init);return 0;
}
FRR_MODULE_SETUP(.name="cnlab_bfdd_native_follow",.version=FRR_VERSION,.description="Fenced native BFD state follower; no promotion API",.init=module_init,);
