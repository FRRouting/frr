/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Real input connection and exact kernel-accepted writev byte journal.
 * send() to replica is not an application/FIB commit. No promotion here.
 */
#include <zebra.h>
#include "lib/module.h"
#include "lib/version.h"
#include "lib/json.h"
#include "lib/stream.h"
#include "lib/sockunion.h"
#include "lib/frrevent.h"
#include "lib/ringbuf.h"
#include "lib/privs.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_keepalives.h"
#include "tcp_snapshot.h"
#include <fcntl.h>
#include <sys/stat.h>
extern struct zebra_privs_t bgpd_privs;
#include "lib/log.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_nsr.h"
#include "bgpd/bgp_vty.h"
#include "replay_idle.h"
#include <sys/un.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
static int replica_fd=-1;
static uint64_t record_id;
static bool failed;
static pthread_mutex_t journal_lock=PTHREAD_MUTEX_INITIALIZER;
/* A reset socket may retain readable BGP frames but getpeername returns
 * ENOTCONN. Cache only a previously kernel-observed tuple under SO_COOKIE;
 * neither FD numbers nor peer pointers identify a socket lifetime. Bounded
 * table exhaustion poisons the journal, never evicts an active identity. */
struct identity {uint64_t cookie;struct sockaddr_in local,remote;};
static struct identity identities[1024];
static size_t identity_count;
static bool identify(int fd,struct sockaddr_in *local,struct sockaddr_in *remote,uint64_t *cookie,bool *cached){
    socklen_t n=sizeof(*cookie);*cached=false;
    if(getsockopt(fd,SOL_SOCKET,SO_COOKIE,cookie,&n)||n!=sizeof(*cookie)||!*cookie)return false;
    size_t index=0;while(index<identity_count&&identities[index].cookie!=*cookie)index++;
    n=sizeof(*local);bool valid=getsockname(fd,(struct sockaddr *)local,&n)==0;
    n=sizeof(*remote);valid=valid&&getpeername(fd,(struct sockaddr *)remote,&n)==0&&local->sin_family==AF_INET&&remote->sin_family==AF_INET;
    if(valid){
        if(index==identity_count){if(identity_count==array_size(identities))return false;identity_count++;identities[index].cookie=*cookie;identities[index].local=*local;identities[index].remote=*remote;}
        else if(memcmp(&identities[index].local,local,sizeof(*local))||memcmp(&identities[index].remote,remote,sizeof(*remote)))return false;
        return true;
    }
    if(index==identity_count)return false;
    *local=identities[index].local;*remote=identities[index].remote;*cached=true;return true;
}
static int socket_identity(int fd,const union sockunion *local,const union sockunion *remote){
    if(local->sa.sa_family!=AF_INET||remote->sa.sa_family!=AF_INET)return 0;
    uint64_t cookie=0;socklen_t n=sizeof(cookie);int rc=0;
    pthread_mutex_lock(&journal_lock);
    if(getsockopt(fd,SOL_SOCKET,SO_COOKIE,&cookie,&n)||n!=sizeof(cookie)||!cookie||!local->sin.sin_port||!remote->sin.sin_port){failed=true;rc=-1;}
    else{
        size_t i=0;while(i<identity_count&&identities[i].cookie!=cookie)i++;
        if(i==identity_count){
            if(i==array_size(identities)){failed=true;rc=-1;}
            else{identities[i].cookie=cookie;identities[i].local=local->sin;identities[i].remote=remote->sin;identity_count++;}
        }
        else if(identities[i].local.sin_addr.s_addr!=local->sin.sin_addr.s_addr||identities[i].local.sin_port!=local->sin.sin_port||identities[i].remote.sin_addr.s_addr!=remote->sin.sin_addr.s_addr||identities[i].remote.sin_port!=remote->sin.sin_port){failed=true;rc=-1;}
    }
    pthread_mutex_unlock(&journal_lock);return rc;
}
static int record_bytes(struct peer_connection *c,const char *schema,int type,const unsigned char *bytes,size_t length){
    json_object *j=json_object_new_object();struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
#define NUM(k,v) json_object_object_add(j,k,json_object_new_int64(v))
#define STR(k,v) json_object_object_add(j,k,json_object_new_string(v))
    STR("schema",schema);NUM("pid",getpid());NUM("record_id",++record_id);
    NUM("observed_monotonic_ns",(uint64_t)ts.tv_sec*1000000000+ts.tv_nsec);
    STR("peer",c->peer->host);NUM("type",type);NUM("wire_size",length);
    NUM("fsm_before_dispatch",c->status);NUM("negotiated_holdtime",c->peer->v_holdtime);
    NUM("capabilities",c->peer->cap);NUM("uptime_monotonic",c->peer->uptime);
    struct sockaddr_in local={0},remote={0};char lip[INET_ADDRSTRLEN],rip[INET_ADDRSTRLEN],key[128];
    uint64_t cookie=0;bool cached=false;
    if(!identify(c->fd,&local,&remote,&cookie,&cached)){zlog_err("CNLAB identity unavailable fd=%d status=%d errno=%d schema=%s id=%llu",c->fd,c->status,errno,schema,(unsigned long long)record_id);failed=true;json_object_put(j);return -1;}
    NUM("socket_cookie",cookie);json_object_object_add(j,"identity_from_cookie_cache",json_object_new_boolean(cached));
    inet_ntop(AF_INET,&local.sin_addr,lip,sizeof(lip));inet_ntop(AF_INET,&remote.sin_addr,rip,sizeof(rip));
    snprintf(key,sizeof(key),"%s:%u-%s:%u",lip,ntohs(local.sin_port),rip,ntohs(remote.sin_port));
    STR("local_ip",lip);STR("remote_ip",rip);NUM("local_port",ntohs(local.sin_port));NUM("remote_port",ntohs(remote.sin_port));STR("session_key",key);
    char *hex=malloc(length*2+1);if(!hex){failed=true;json_object_put(j);return -1;}
    static const char digits[]="0123456789abcdef";
    for(size_t i=0;i<length;i++){hex[2*i]=digits[bytes[i]>>4];hex[2*i+1]=digits[bytes[i]&15];}hex[length*2]=0;
    json_object_object_add(j,"wire_hex",json_object_new_string_len(hex,length*2));free(hex);
    json_object_object_add(j,"journal_failed",json_object_new_boolean(failed));
    json_object_object_add(j,"promotable_checkpoint",json_object_new_boolean(false));
    const char *text=json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN);ssize_t sent=send(replica_fd,text,strlen(text),MSG_DONTWAIT|MSG_NOSIGNAL);
    if(sent!=(ssize_t)strlen(text)){if(!failed)zlog_err("CNLAB native journal lost a record; replica NOT eligible");failed=true;}
    json_object_put(j);return failed?-1:0;
}
static int input(struct peer_connection *c,uint8_t type,bgp_size_t size,struct stream *s){
    if(getenv("CNLAB_NSR_BGP_FOLLOWER"))return 0;
    if(stream_get_endp(s)!=size)return -1;
    pthread_mutex_lock(&journal_lock);int rc=record_bytes(c,"cnlab-native-input-v1",type,STREAM_DATA(s),size);pthread_mutex_unlock(&journal_lock);return rc;
}
static int output(struct peer_connection *c,const struct iovec *iov,size_t count,size_t accepted){
    if(getenv("CNLAB_NSR_BGP_FOLLOWER"))return 0;
    unsigned char block[16384];size_t used=0,left=accepted;
    pthread_mutex_lock(&journal_lock);
    for(size_t i=0;i<count&&left;i++){
        const unsigned char *p=iov[i].iov_base;size_t n=iov[i].iov_len;if(n>left)n=left;left-=n;
        while(n){size_t copy=sizeof(block)-used;if(copy>n)copy=n;memcpy(block+used,p,copy);used+=copy;p+=copy;n-=copy;
            if(used==sizeof(block)){record_bytes(c,"cnlab-native-output-v1",0,block,used);used=0;}}
    }
    if(left)failed=true;
    if(used)record_bytes(c,"cnlab-native-output-v1",0,block,used);
    pthread_mutex_unlock(&journal_lock);return failed?-1:0;
}
static int native_event(struct peer_connection *c,int kind,afi_t afi,safi_t safi){
    if(getenv("CNLAB_NSR_BGP_FOLLOWER"))return 0;
    if(kind==1&&(afi!=AFI_IP||safi!=SAFI_UNICAST)){failed=true;return -1;}
    if(kind==2&&cnlab_idle_update_scan(c))kind=4;
    pthread_mutex_lock(&journal_lock);int rc=record_bytes(c,"cnlab-native-event-v1",kind,(const unsigned char *)"",0);pthread_mutex_unlock(&journal_lock);return rc;
}
/* Explicitly planned quiesce for integration work. No unexpected-crash NSR
 * claim. Caller must physically fence primary output before requesting it. */
static int export_listener=-1;
static struct event *export_event;
static struct event_loop *export_loop;
static char export_directory[256];
static uint64_t checkpoint_number;
static pthread_mutex_t barrier_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_cond=PTHREAD_COND_INITIALIZER;
static bool io_ready,io_resume;
static struct event *io_barrier_event;
static void io_barrier(struct event *event){
    (void)event;pthread_mutex_lock(&barrier_mutex);io_ready=true;pthread_cond_broadcast(&barrier_cond);
    while(!io_resume)pthread_cond_wait(&barrier_cond,&barrier_mutex);
    io_ready=false;pthread_cond_broadcast(&barrier_cond);pthread_mutex_unlock(&barrier_mutex);
}
static bool pause_io(void){
    pthread_mutex_lock(&barrier_mutex);io_ready=false;io_resume=false;
    event_add_event(bgp_pth_io->master,io_barrier,NULL,0,&io_barrier_event);
    struct timespec deadline;clock_gettime(CLOCK_REALTIME,&deadline);deadline.tv_nsec+=200000000;if(deadline.tv_nsec>=1000000000){deadline.tv_sec++;deadline.tv_nsec-=1000000000;}
    while(!io_ready){if(pthread_cond_timedwait(&barrier_cond,&barrier_mutex,&deadline)){io_resume=true;pthread_cond_broadcast(&barrier_cond);pthread_mutex_unlock(&barrier_mutex);return false;}}
    pthread_mutex_unlock(&barrier_mutex);return true;
}
static void resume_io(void){pthread_mutex_lock(&barrier_mutex);io_resume=true;pthread_cond_broadcast(&barrier_cond);while(io_ready)pthread_cond_wait(&barrier_cond,&barrier_mutex);pthread_mutex_unlock(&barrier_mutex);}

struct export_control {int fd;struct event *event;};
struct image {uint64_t magic;uint32_t version,abi;struct tcp_snapshot s;uint64_t checksum;};
static uint64_t hashbytes(uint64_t h,const void *data,size_t n){const unsigned char *p=data;while(n--){h^=*p++;h*=1099511628211ULL;}return h;}
static bool writeall(int fd,const void *data,size_t n){const unsigned char *p=data;while(n){ssize_t wrote=write(fd,p,n);if(wrote<=0)return false;p+=wrote;n-=wrote;}return true;}
static int save_image(const char *path,struct tcp_snapshot *snapshot){
    struct image image={.magic=0x434e4c5443503031ULL,.version=1,.abi=sizeof(image),.s=*snapshot};image.s.send_data=image.s.recv_data=NULL;
    uint64_t h=hashbytes(1469598103934665603ULL,&image,sizeof(image));h=hashbytes(h,snapshot->send_data,snapshot->outq);h=hashbytes(h,snapshot->recv_data,snapshot->unread);image.checksum=h;
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);if(fd<0)return -1;
    bool ok=writeall(fd,&image,sizeof(image))&&writeall(fd,snapshot->send_data,snapshot->outq)&&writeall(fd,snapshot->recv_data,snapshot->unread)&&fsync(fd)==0;int saved=errno;close(fd);errno=saved;return ok?0:-1;
}
static char *image_hex(struct tcp_snapshot *snapshot){
    if(snapshot->outq+snapshot->unread>64000)return NULL;
    struct image image;memset(&image,0,sizeof(image));image.magic=0x434e4c5443503031ULL;image.version=1;image.abi=sizeof(image);image.s=*snapshot;image.s.send_data=image.s.recv_data=NULL;
    uint64_t hash=hashbytes(1469598103934665603ULL,&image,sizeof(image));hash=hashbytes(hash,snapshot->send_data,snapshot->outq);hash=hashbytes(hash,snapshot->recv_data,snapshot->unread);image.checksum=hash;
    size_t total=sizeof(image)+snapshot->outq+snapshot->unread;unsigned char *raw=malloc(total);char *hex=malloc(total*2+1);if(!raw||!hex){free(raw);free(hex);return NULL;}
    memcpy(raw,&image,sizeof(image));memcpy(raw+sizeof(image),snapshot->send_data,snapshot->outq);memcpy(raw+sizeof(image)+snapshot->outq,snapshot->recv_data,snapshot->unread);
    static const char digits[]="0123456789abcdef";for(size_t i=0;i<total;i++){hex[2*i]=digits[raw[i]>>4];hex[2*i+1]=digits[raw[i]&15];}hex[2*total]=0;free(raw);return hex;
}
/* One native event-loop / I/O barrier covers the entire session set.
 * Images are sent inline: source-side fsync per session is not a replica
 * durability boundary. The surviving device commits the complete bundle. */
static json_object *capture_batch(json_object *request){
    struct selected {struct peer *peer;uint64_t cookie;struct timeval last;bool paused;};
    struct selected chosen[256]={0};json_object *items=NULL,*rows=json_object_new_array(),*reply=json_object_new_object();size_t total=0;uint64_t frontier=0;bool frozen=false;const char *why=NULL;
    if(!json_object_object_get_ex(request,"sessions",&items)||json_object_get_type(items)!=json_type_array||json_object_array_length(items)<1||json_object_array_length(items)>256){why="invalid_session_batch";goto done;}
    total=json_object_array_length(items);struct bgp *bgp=bgp_get_default();if(!bgp){why="bgp_not_configured";goto done;}
    if(bgp->coalesce_time||bgp->heuristic_coalesce){why="batch_profile_requires_coalesce_zero";goto done;}
    if(!bgp->mq||bgp->mq->size){why="native_route_queue_not_empty";goto done;}
    for(size_t i=0;i<total;i++){
        json_object *item=json_object_array_get_idx(items,i),*ip=NULL,*cookie=NULL;union sockunion su;
        if(!json_object_object_get_ex(item,"peer",&ip)||!json_object_object_get_ex(item,"socket_cookie",&cookie)||str2sockunion(json_object_get_string(ip),&su)<0){why="invalid_source_identity";goto done;}
        struct peer *peer=peer_lookup(bgp,&su);uint64_t actual=0;socklen_t n=sizeof(actual);
        if(!peer||!peer->connection||peer->connection->status!=Established||peer->connection->fd<0||peer->password||getsockopt(peer->connection->fd,SOL_SOCKET,SO_COOKIE,&actual,&n)||!actual||actual!=(uint64_t)json_object_get_int64(cookie)){why="source_session_not_current";goto done;}
        for(size_t k=0;k<i;k++)if(chosen[k].peer==peer){why="duplicate_source_peer";goto done;}
        if(getenv("CNLAB_NSR_ABORT_ON_CLOSE")){
            struct linger linger={.l_onoff=1,.l_linger=0};
            if(setsockopt(peer->connection->fd,SOL_SOCKET,SO_LINGER,&linger,sizeof(linger))){why="socket_retirement_guard_failed";goto done;}
        }
        chosen[i].peer=peer;chosen[i].cookie=actual;
        chosen[i].paused=cnlab_bgp_keepalive_pause(peer->connection,&chosen[i].last);
        if(!chosen[i].paused){why="keepalive_pause_failed";goto done;}
    }
    if(!pause_io()){why="io_thread_pause_failed";goto done;}frozen=true;frontier=record_id;
    for(size_t i=0;i<total;i++){
        struct peer_connection *c=chosen[i].peer->connection;
        if(c->ibuf->count||c->obuf->count||ringbuf_remain(c->ibuf_work)||!event_is_scheduled(c->t_holdtime)){why="nonempty_native_application_queue";goto done;}
    }
    for(size_t i=0;i<total;i++){
        struct peer *peer=chosen[i].peer;struct tcp_snapshot snapshot={0};int rc=-1;
        frr_with_privs(&bgpd_privs){rc=tcp_snapshot_export(peer->connection->fd,&snapshot);}
        if(rc){why="TCP_snapshot_failed";goto done;}
        char *hex=image_hex(&snapshot);
        if(!hex){tcp_snapshot_free(&snapshot);why="inline_image_bound";goto done;}
        json_object *row=json_object_new_object();struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);struct timeval hold=event_timer_remain(peer->connection->t_holdtime);
#define BNUM(k,v) json_object_object_add(row,k,json_object_new_int64(v))
        json_object_object_add(row,"peer",json_object_new_string(peer->host));json_object_object_add(row,"checkpoint_hex",json_object_new_string(hex));free(hex);
        BNUM("source_pid",getpid());BNUM("source_socket_cookie",chosen[i].cookie);BNUM("last_record_id",frontier);BNUM("capture_mono_ns",snapshot.capture_mono_ns);
        BNUM("bgp_timer_capture_ns",(uint64_t)now.tv_sec*1000000000+now.tv_nsec);BNUM("hold_remaining_us",(int64_t)hold.tv_sec*1000000+hold.tv_usec);
        BNUM("keepalive_last_monotonic_us",(int64_t)chosen[i].last.tv_sec*1000000+chosen[i].last.tv_usec);BNUM("negotiated_holdtime",peer->v_holdtime);BNUM("negotiated_keepalive",peer->v_keepalive);
        BNUM("last_write_monotonic",atomic_load_explicit(&peer->last_write,memory_order_relaxed));BNUM("last_update_monotonic",atomic_load_explicit(&peer->last_update,memory_order_relaxed));
        BNUM("outq",snapshot.outq);BNUM("unsent",snapshot.unsent);BNUM("unread",snapshot.unread);BNUM("send_end",snapshot.send_end);BNUM("recv_end",snapshot.recv_end);
        json_object_object_add(row,"journal_failed",json_object_new_boolean(failed));json_object_object_add(row,"source_frozen",json_object_new_boolean(false));json_object_object_add(row,"planned_quiesce",json_object_new_boolean(false));
        json_object_array_add(rows,row);tcp_snapshot_free(&snapshot);
#undef BNUM
    }
 done:
    if(frozen)resume_io();
    for(size_t i=0;i<total;i++)if(chosen[i].paused)cnlab_bgp_keepalive_resume(chosen[i].peer->connection,&chosen[i].last);
    json_object_object_add(reply,"exported",json_object_new_boolean(!why&&!failed));json_object_object_add(reply,"frontier_record_id",json_object_new_int64(frontier));json_object_object_add(reply,"sessions",rows);
    if(why)json_object_object_add(reply,"error",json_object_new_string(why));
    return reply;
}
#include "native_rib.h"
static void export_read(struct event *event){
    struct export_control *control=EVENT_ARG(event);char request[65536];ssize_t n=recv(control->fd,request,sizeof(request)-1,MSG_DONTWAIT);
    json_object *j=NULL,*reply=json_object_new_object();bool frozen=false,resume=false,ka_paused=false;struct timeval ka_last={0};struct peer_connection *captured_connection=NULL;const char *why="invalid_request";
    if(n>0){request[n]=0;j=json_tokener_parse(request);}
    json_object *batch_action=NULL;
    if(j&&json_object_object_get_ex(j,"action",&batch_action)&&!strcmp(json_object_get_string(batch_action),"rib_snapshot")){
        json_object_put(reply);reply=native_rib();
        const char *out=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);
        send(control->fd,out,strlen(out),MSG_NOSIGNAL);close(control->fd);free(control);json_object_put(reply);json_object_put(j);return;
    }
    if(j&&json_object_object_get_ex(j,"action",&batch_action)&&!strcmp(json_object_get_string(batch_action),"retire_fenced")){
        struct bgp *bgp=bgp_get_default();struct listnode *node;struct peer *peer;
        struct linger abort_close={.l_onoff=1,.l_linger=0};bool ok=bgp!=NULL;
        if(bgp)for(ALL_LIST_ELEMENTS_RO(bgp->peer,node,peer)){
            if(peer->connection&&peer->connection->fd>=0 &&
               setsockopt(peer->connection->fd,SOL_SOCKET,SO_LINGER,&abort_close,sizeof(abort_close)))ok=false;
        }
        json_object_object_add(reply,"armed",json_object_new_boolean(ok));
        const char *out=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);
        send(control->fd,out,strlen(out),MSG_NOSIGNAL);close(control->fd);free(control);json_object_put(reply);json_object_put(j);return;
    }
    if(j&&json_object_object_get_ex(j,"action",&batch_action)&&!strcmp(json_object_get_string(batch_action),"startup_ready")){
        bool ready=!bgp_config_inprocess()&&!event_is_scheduled(bm->t_rmap_update);
        json_object_object_add(reply,"ready",json_object_new_boolean(ready));
        const char *out=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);
        send(control->fd,out,strlen(out),MSG_NOSIGNAL);close(control->fd);free(control);json_object_put(reply);json_object_put(j);return;
    }
    if(j&&json_object_object_get_ex(j,"action",&batch_action)&&!strcmp(json_object_get_string(batch_action),"capture_batch")){
        json_object_put(reply);reply=capture_batch(j);const char *payload=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);
        if(strlen(payload)>400000){json_object_put(reply);reply=json_object_new_object();json_object_object_add(reply,"error",json_object_new_string("local_batch_frame_bound"));payload=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);}
        send(control->fd,payload,strlen(payload),MSG_NOSIGNAL);close(control->fd);free(control);json_object_put(reply);json_object_put(j);return;
    }
    json_object *peer_value,*cookie_value,*action_value;
    if(j&&json_object_object_get_ex(j,"peer",&peer_value)&&json_object_object_get_ex(j,"socket_cookie",&cookie_value)&&json_object_object_get_ex(j,"action",&action_value)){
        const char *peer_ip=json_object_get_string(peer_value),*action=json_object_get_string(action_value);uint64_t expected=json_object_get_int64(cookie_value),actual=0;socklen_t length=sizeof(actual);union sockunion su;
        struct bgp *bgp=bgp_get_default();struct peer *peer=NULL;
        if(bgp&&str2sockunion(peer_ip,&su)==0)peer=peer_lookup(bgp,&su);
        if(peer&&peer->connection&&peer->connection->status==Established&&peer->connection->fd>=0&&getsockopt(peer->connection->fd,SOL_SOCKET,SO_COOKIE,&actual,&length)==0&&actual==expected){
            struct peer_connection *c=peer->connection;
            if(!strcmp(action,"source_fd_negative_probe")){
                json_object_object_add(reply,"source_fd_probe",json_object_new_boolean(true));
                const char *text=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);struct iovec iov={.iov_base=(void *)text,.iov_len=strlen(text)};char ancillary[CMSG_SPACE(sizeof(int))];struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=ancillary,.msg_controllen=sizeof(ancillary)};struct cmsghdr *cm=CMSG_FIRSTHDR(&msg);cm->cmsg_level=SOL_SOCKET;cm->cmsg_type=SCM_RIGHTS;cm->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(cm),&c->fd,sizeof(int));sendmsg(control->fd,&msg,MSG_NOSIGNAL);
                close(control->fd);free(control);json_object_put(reply);json_object_put(j);return;
            }
            if(!strcmp(action,"planned_quiesce_export")||!strcmp(action,"capture_resume")){
                resume=!strcmp(action,"capture_resume");captured_connection=c;
                if(resume)ka_paused=cnlab_bgp_keepalive_pause(c,&ka_last);else bgp_keepalives_off(c);why="io_thread_stop_failed";
                if(resume?(ka_paused&&pause_io()):frr_pthread_stop(bgp_pth_io,NULL)==0){
                    frozen=true;why="nonempty_native_application_queue";
                    if(c->ibuf->count==0&&c->obuf->count==0&&ringbuf_remain(c->ibuf_work)==0&&c->peer->bgp->mq&&c->peer->bgp->mq->size==0&&c->peer->v_holdtime>0&&event_is_scheduled(c->t_holdtime)&&!c->peer->password){
                        struct tcp_snapshot snapshot={0};int rc=-1;frr_with_privs(&bgpd_privs){rc=resume?tcp_snapshot_export(c->fd,&snapshot):tcp_snapshot_export_hold(c->fd,&snapshot);}
                        why="tcp_snapshot_failed";
                        if(rc==0){
                            char path[384];snprintf(path,sizeof(path),"%s/checkpoint-%d-%llu-%llu.bin",export_directory,getpid(),(unsigned long long)actual,(unsigned long long)++checkpoint_number);why="image_save_failed";
                            if(save_image(path,&snapshot)==0){
                                struct timespec timer_clock;clock_gettime(CLOCK_MONOTONIC,&timer_clock);uint64_t timer_ns=(uint64_t)timer_clock.tv_sec*1000000000+timer_clock.tv_nsec;
                                struct timeval hold=event_timer_remain(c->t_holdtime);
                                json_object_object_add(reply,"bgp_timer_capture_ns",json_object_new_int64(timer_ns));
                                json_object_object_add(reply,"hold_remaining_us",json_object_new_int64((int64_t)hold.tv_sec*1000000+hold.tv_usec));
                                json_object_object_add(reply,"negotiated_holdtime",json_object_new_int64(peer->v_holdtime));
                                json_object_object_add(reply,"negotiated_keepalive",json_object_new_int64(peer->v_keepalive));
                                json_object_object_add(reply,"keepalive_last_monotonic_us",json_object_new_int64((int64_t)ka_last.tv_sec*1000000+ka_last.tv_usec));
                                json_object_object_add(reply,"last_write_monotonic",json_object_new_int64(atomic_load_explicit(&peer->last_write,memory_order_relaxed)));
                                json_object_object_add(reply,"last_update_monotonic",json_object_new_int64(atomic_load_explicit(&peer->last_update,memory_order_relaxed)));
                                if(resume){char *hex=image_hex(&snapshot);if(hex){json_object_object_add(reply,"checkpoint_hex",json_object_new_string(hex));free(hex);}else json_object_object_add(reply,"inline_checkpoint_failed",json_object_new_boolean(true));}
                                json_object_object_add(reply,"exported",json_object_new_boolean(true));json_object_object_add(reply,"image",json_object_new_string(path));json_object_object_add(reply,"source_pid",json_object_new_int64(getpid()));json_object_object_add(reply,"source_socket_cookie",json_object_new_int64(actual));json_object_object_add(reply,"last_record_id",json_object_new_int64(record_id));json_object_object_add(reply,"capture_mono_ns",json_object_new_int64(snapshot.capture_mono_ns));json_object_object_add(reply,"outq",json_object_new_int64(snapshot.outq));json_object_object_add(reply,"unsent",json_object_new_int64(snapshot.unsent));json_object_object_add(reply,"unread",json_object_new_int64(snapshot.unread));json_object_object_add(reply,"send_end",json_object_new_int64(snapshot.send_end));json_object_object_add(reply,"recv_end",json_object_new_int64(snapshot.recv_end));json_object_object_add(reply,"planned_quiesce",json_object_new_boolean(!resume));json_object_object_add(reply,"journal_failed",json_object_new_boolean(failed));why=NULL;
                            }
                            tcp_snapshot_free(&snapshot);
                        }
                    }
                }
            }
        }else why="source_session_not_current";
    }
    if(resume&&captured_connection){if(frozen)resume_io();if(ka_paused)cnlab_bgp_keepalive_resume(captured_connection,&ka_last);frozen=false;}
    if(why)json_object_object_add(reply,"error",json_object_new_string(why));
    json_object_object_add(reply,"source_frozen",json_object_new_boolean(frozen));const char *text=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);send(control->fd,text,strlen(text),MSG_NOSIGNAL);close(control->fd);free(control);json_object_put(reply);if(j)json_object_put(j);
    /* Explicitly freeze the native application after replying. Exact external
     * process death is mandatory; this control path never resumes or promotes. */
    if(frozen)for(;;)pause();
}
static void export_accept(struct event *event){
    (void)event;event_add_read(export_loop,export_accept,NULL,export_listener,&export_event);int fd=accept4(export_listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);if(fd<0)return;int buffer=1024*1024;setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer));
    struct export_control *c=calloc(1,sizeof(*c));if(!c){close(fd);return;}c->fd=fd;event_add_read(export_loop,export_read,c,fd,&c->event);
}
static int export_late_init(struct event_loop *master){export_loop=master;event_add_read(master,export_accept,NULL,export_listener,&export_event);return 0;}
static int module_init(void){
    const char *path=getenv("CNLAB_NSR_REPLICA_SOCK");struct sockaddr_un addr={.sun_family=AF_UNIX};
    if(!path||strncmp(path,"/run/frr-nsr/",13)||strlen(path)>=sizeof(addr.sun_path))return -1;
    strlcpy(addr.sun_path,path,sizeof(addr.sun_path));replica_fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    int journal_budget=16*1024*1024;if(replica_fd<0||setsockopt(replica_fd,SOL_SOCKET,SO_SNDBUFFORCE,&journal_budget,sizeof(journal_budget)))return -1;
    if(replica_fd<0||connect(replica_fd,(struct sockaddr *)&addr,sizeof(addr)))return -1;
    const char *directory=getenv("CNLAB_NSR_EXPORT_DIRECTORY");
    if(directory){
        if(strncmp(directory,"/run/frr-nsr/",13)||strlen(directory)>=sizeof(export_directory))return -1;
        strlcpy(export_directory,directory,sizeof(export_directory));char path[108];if(snprintf(path,sizeof(path),"%s/x-%d.sock",directory,getpid())>=(int)sizeof(path))return -1;
        struct sockaddr_un control={.sun_family=AF_UNIX};strlcpy(control.sun_path,path,sizeof(control.sun_path));export_listener=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(export_listener<0||bind(export_listener,(struct sockaddr *)&control,sizeof(control))||listen(export_listener,4))return -1;chmod(path,0600);hook_register(frr_late_init,export_late_init);
    }
    hook_register(cnlab_bgp_native_event,native_event);hook_register(cnlab_bgp_socket_identity,socket_identity);hook_register(cnlab_bgp_input,input);hook_register(cnlab_bgp_written,output);return 0;
}
FRR_MODULE_SETUP(.name="cnlab_bgpd_native_journal",.version=FRR_VERSION,.description="Exact connection input and kernel-accepted output bytes",.init=module_init,);
