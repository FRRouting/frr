/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental native BGP shadow input application and guarded activation.
 * Replays genuine primary input into the real FRR dispatcher and FSM.
 * No TCP listener, no connect, no peer FD. Outbound data remains in FRR FIFO.
 */
#include <zebra.h>
#include "lib/module.h"
#include "lib/version.h"
#include "lib/json.h"
#include "lib/frrevent.h"
#include "lib/stream.h"
#include "lib/monotime.h"
#include "lib/log.h"
#include "lib/workqueue.h"
#include "bgpd/bgp_keepalives.h"
#include "lib/sockunion.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nsr.h"
#include "replay_idle.h"
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <netinet/tcp.h>
#include "lib/privs.h"
extern struct zebra_privs_t bgpd_privs;
#include "owner_claim.h"
#include <time.h>
static struct event_loop *loop;
static struct event *accept_event,*match_event;
static bool consume_output,bulk_activation,compact_status,slim_records,replaying_meta_event;
static int listener=-1;
struct candidate {int64_t cookie;size_t size;uint64_t observed,open_capabilities;unsigned char bytes[4096];unsigned char *written;size_t written_size,matched;uint64_t retired;struct sockaddr_in local,remote;bool tuple_valid;};
struct shadow_transition {uint64_t at_ns,record;int before,after,event,reset;};
struct follow_state {
    bool output_poisoned,transport_active,native_event_mode,replaying_event;
    struct peer * active_peer;
    unsigned char mismatch_expected[32],mismatch_actual[32];
    size_t mismatch_size,mismatch_offset;uint64_t mismatch_record;
    struct shadow_transition transitions[16];size_t transition_count;
    int staged_fd;
    uint64_t last_observed_ns,staged_capture_ns,staged_hold_deadline_ns,staged_keepalive_last_us,last_id,applied,buffered_opens,foreign_records,output_records,matched_total;
    int64_t producer_pid,source_cookie,open_cookie;
    struct candidate candidates[64];size_t candidate_count;
    struct candidate *replaying_open;
};
static struct follow_state *states[256];static size_t state_count;
static struct follow_state *state_for(struct peer *peer,bool create){
    for(size_t i=0;i<state_count;i++)if(states[i]->active_peer==peer)return states[i];
    if(!create||state_count==array_size(states))return NULL;
    struct follow_state *s=calloc(1,sizeof(*s));if(!s)return NULL;
    s->active_peer=peer;s->staged_fd=-1;states[state_count++]=s;return s;
}
/* Only the source's journaled timer-dependent OPEN decision is replayed.
 * Native encoding and the complete byte-for-byte output comparison remain
 * unchanged; live sockets and other peers cannot inherit this override. */
static int replay_open_restart_bit(struct peer *peer,bool *restart){
    struct follow_state *s=state_for(peer,false);
    if(s&&!s->transport_active&&s->replaying_open)
        *restart=CHECK_FLAG(s->replaying_open->open_capabilities,PEER_CAP_GRACEFUL_RESTART_R_BIT_ADV);
    return 0;
}
struct control {int fd;struct event *event,*deadline;json_object *reply;};
static uint64_t clock_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static int observe_shadow_transition(struct peer *peer){
    struct follow_state *s=state_for(peer,false);
    if(!s||s->transport_active)return 0;
    struct peer_connection *c=peer->connection;
    struct shadow_transition *t=&s->transitions[s->transition_count++%16];
    *t=(struct shadow_transition){.at_ns=clock_ns(),.record=s->last_id,
        .before=c->ostatus,.after=c->status,.event=peer->cur_event,.reset=peer->last_reset};
    return 0;
}
static void add_transitions(json_object *j,struct follow_state *s){
    json_object *rows=json_object_new_array();size_t first=s->transition_count>16?s->transition_count-16:0;
    for(size_t i=first;i<s->transition_count;i++){
        struct shadow_transition *t=&s->transitions[i%16];json_object *row=json_object_new_object();
        json_object_object_add(row,"at_ns",json_object_new_int64(t->at_ns));
        json_object_object_add(row,"last_record",json_object_new_int64(t->record));
        json_object_object_add(row,"before",json_object_new_int(t->before));
        json_object_object_add(row,"after",json_object_new_int(t->after));
        json_object_object_add(row,"event",json_object_new_int(t->event));
        json_object_object_add(row,"last_reset",json_object_new_int(t->reset));
        if(t->reset>=0&&(unsigned)t->reset<=PEER_DOWN_CEASE_UNKNOWN)json_object_object_add(row,"last_reset_reason",json_object_new_string(peer_down_str[t->reset]));
        json_object_array_add(rows,row);
    }
    json_object_object_add(j,"shadow_transitions",rows);
}
static json_object *error(const char *why){json_object *j=json_object_new_object();json_object_object_add(j,"dispatched",json_object_new_boolean(false));json_object_object_add(j,"error",json_object_new_string(why));return j;}
static bool integer(json_object *j,const char *key,int64_t *v){json_object *o;if(!json_object_object_get_ex(j,key,&o)||json_object_get_type(o)!=json_type_int)return false;*v=json_object_get_int64(o);return true;}
static const char *string(json_object *j,const char *key){json_object *o;if(!json_object_object_get_ex(j,key,&o)||json_object_get_type(o)!=json_type_string)return NULL;return json_object_get_string(o);}
static void add_mismatch(json_object *j,struct follow_state *state){
    if(!state->mismatch_size)return;
    char expected[65],actual[65];static const char hex[]="0123456789abcdef";
    for(size_t i=0;i<state->mismatch_size;i++){
        expected[2*i]=hex[state->mismatch_expected[i]>>4];expected[2*i+1]=hex[state->mismatch_expected[i]&15];
        actual[2*i]=hex[state->mismatch_actual[i]>>4];actual[2*i+1]=hex[state->mismatch_actual[i]&15];
    }
    expected[2*state->mismatch_size]=actual[2*state->mismatch_size]=0;
    json_object *m=json_object_new_object();
    json_object_object_add(m,"source_record",json_object_new_int64(state->mismatch_record));
    json_object_object_add(m,"stream_offset",json_object_new_int64(state->mismatch_offset));
    json_object_object_add(m,"expected_hex",json_object_new_string(expected));
    json_object_object_add(m,"actual_hex",json_object_new_string(actual));
    json_object_object_add(j,"output_mismatch",m);
}
static json_object *status(struct peer *peer,struct follow_state *state){
    struct peer_connection *c=peer->connection;json_object *j=json_object_new_object();
#define ADD(k,v) json_object_object_add(j,k,json_object_new_int64(v))
    add_mismatch(j,state);
    if(slim_records){json_object_object_add(j,"output_poisoned",json_object_new_boolean(state->output_poisoned));return j;}
    if(!compact_status||state->output_poisoned)add_transitions(j,state);
    size_t pending=0,matched=0;
    for(size_t i=0;i<state->candidate_count;i++)if(state->candidates[i].cookie==state->source_cookie){pending=state->candidates[i].written_size-state->candidates[i].matched;matched=state->candidates[i].retired+state->candidates[i].matched;}
    json_object_object_add(j,"transport_active",json_object_new_boolean(state->transport_active));ADD("staged_capture_ns",state->staged_capture_ns);ADD("staged_fd",state->staged_fd);ADD("last_observed_ns",state->last_observed_ns);ADD("primary_output_pending",pending);ADD("primary_output_matched",matched);ADD("primary_output_records",state->output_records);ADD("matched_total",state->matched_total);
    json_object_object_add(j,"output_poisoned",json_object_new_boolean(state->output_poisoned));
    json_object_object_add(j,"output_consumption_enabled",json_object_new_boolean(consume_output));
    json_object_object_add(j,"native_event_mode",json_object_new_boolean(state->native_event_mode));
    ADD("buffered_opens",state->buffered_opens);ADD("foreign_records",state->foreign_records);ADD("source_pid",state->producer_pid);ADD("source_socket_cookie",state->source_cookie);ADD("open_socket_cookie",state->open_cookie);ADD("route_queue_pending",peer->bgp->mq?(int64_t)peer->bgp->mq->size:-1);ADD("negotiated_holdtime",peer->v_holdtime);ADD("negotiated_keepalive",peer->v_keepalive);ADD("staged_keepalive_last_us",state->staged_keepalive_last_us);ADD("staged_hold_deadline_ns",state->staged_hold_deadline_ns);ADD("native_fsm",c->status);ADD("native_peer_fd",c->fd);ADD("native_established_count",peer->established);
    ADD("native_outbound_queued",c->obuf?c->obuf->count:0);ADD("native_input_queued",c->ibuf?c->ibuf->count:0);ADD("dispatched_inputs",state->applied);ADD("last_record_id",state->last_id);
    /* Read-only view of actual native pending bytes. Never discard a FIFO
     * entry merely because a primary record claims it was sent. */
    size_t used=0;bool overflow=false;char hex[131073];
    static const char digits[]="0123456789abcdef";
    frr_with_mutex(&c->io_mtx){
        for(struct stream *s=c->obuf?c->obuf->head:NULL;s;s=s->next){
            size_t n=STREAM_READABLE(s);
            if(n>65536-used){overflow=true;break;}
            const unsigned char *data=stream_pnt(s);
            for(size_t i=0;i<n;i++){hex[2*used]=digits[data[i]>>4];hex[2*used+1]=digits[data[i]&15];used++;}
        }
    }
    hex[2*used]=0;ADD("native_output_bytes",used);
    if(!compact_status)json_object_object_add(j,"native_output_hex",json_object_new_string(hex));
    json_object_object_add(j,"native_output_overflow",json_object_new_boolean(overflow));
    json_object_object_add(j,"promotable_checkpoint",json_object_new_boolean(false));return j;
}
static int hexval(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
/* Compare the entire currently comparable prefix before mutating any native
 * stream. Only bytes proved equal to kernel-accepted primary output retire.
 * TCP unacked/unsent bytes remain in the separate imported kernel queues. */
static void match_output(struct follow_state *state){
    if(!consume_output||state->output_poisoned||!state->active_peer)return;
    struct peer_connection *c=state->active_peer->connection;struct candidate *history=NULL;
    for(size_t i=0;i<state->candidate_count;i++)if(state->candidates[i].cookie==state->source_cookie)history=&state->candidates[i];
    if(!history||c->fd>=0)return;
    size_t left=history->written_size-history->matched;
    /* A real source KEEPALIVE write is a scheduling event, not injected wire.
     * Generate its counterpart through FRR, then compare before retirement. */
    if(left>=19 && c->status==Established && c->obuf && c->obuf->count==0){
        const unsigned char *next=history->written+history->matched;bool marker=true;
        for(size_t i=0;i<16;i++)if(next[i]!=255)marker=false;
        if(marker&&next[16]==0&&next[17]==19&&next[18]==BGP_MSG_KEEPALIVE)bgp_keepalive_send(c);
    }
    frr_with_mutex(&c->io_mtx){
        size_t offset=0;
        for(struct stream *s=c->obuf?c->obuf->head:NULL;s&&offset<left;s=s->next){
            size_t n=STREAM_READABLE(s);if(n>left-offset)n=left-offset;
            if(memcmp(stream_pnt(s),history->written+history->matched+offset,n)){
                const unsigned char *actual=stream_pnt(s),*expected=history->written+history->matched+offset;
                size_t first=0;while(first<n&&actual[first]==expected[first])first++;
                state->mismatch_size=n-first>32?32:n-first;
                memcpy(state->mismatch_expected,expected+first,state->mismatch_size);
                memcpy(state->mismatch_actual,actual+first,state->mismatch_size);
                state->mismatch_offset=history->retired+history->matched+offset+first;
                state->mismatch_record=state->last_id;
                state->output_poisoned=true;break;
            }
            offset+=n;
        }
        if(!state->output_poisoned){
            size_t remaining=offset;
            while(remaining){
                struct stream *s=stream_fifo_head(c->obuf);size_t n=STREAM_READABLE(s);
                if(n>remaining){stream_forward_getp(s,remaining);remaining=0;break;}
                remaining-=n;s=stream_fifo_pop(c->obuf);uint8_t type=STREAM_DATA(s)[18];
                switch(type){
                case BGP_MSG_OPEN:atomic_fetch_add_explicit(&state->active_peer->open_out,1,memory_order_relaxed);break;
                case BGP_MSG_KEEPALIVE:atomic_fetch_add_explicit(&state->active_peer->keepalive_out,1,memory_order_relaxed);break;
                case BGP_MSG_UPDATE:atomic_fetch_add_explicit(&state->active_peer->update_out,1,memory_order_relaxed);atomic_store_explicit(&state->active_peer->last_update,monotime(NULL),memory_order_relaxed);break;
                default:break;
                }
                stream_free(s);
            }
            history->matched+=offset;state->matched_total+=offset;
            if(offset){atomic_store_explicit(&state->active_peer->last_write,monotime(NULL),memory_order_relaxed);atomic_store_explicit(&c->last_sendq_ok,monotime(NULL),memory_order_relaxed);}
        }
    }
}
static void match_tick(struct event *event){(void)event;for(size_t i=0;i<state_count;i++)match_output(states[i]);event_add_timer_msec(loop,match_tick,NULL,10,&match_event);}
static bool bind_tuple(json_object *j,struct candidate *history){
    const char *lip=string(j,"local_ip"),*rip=string(j,"remote_ip");int64_t lp,rp;
    struct sockaddr_in local={.sin_family=AF_INET},remote={.sin_family=AF_INET};
    if(!lip||!rip||!integer(j,"local_port",&lp)||!integer(j,"remote_port",&rp)||lp<=0||lp>65535||rp<=0||rp>65535||inet_pton(AF_INET,lip,&local.sin_addr)!=1||inet_pton(AF_INET,rip,&remote.sin_addr)!=1)return false;
    local.sin_port=htons(lp);remote.sin_port=htons(rp);
    if(history->tuple_valid&&(memcmp(&history->local,&local,sizeof(local))||memcmp(&history->remote,&remote,sizeof(remote))))return false;
    history->local=local;history->remote=remote;history->tuple_valid=true;return true;
}
static bool valid_observation(json_object *j,int64_t observed,struct follow_state *state){
    uint64_t now=clock_ns();if(observed<=0||(uint64_t)observed>now)return false;
    json_object *history;int64_t capture;
    if(json_object_object_get_ex(j,"checkpoint_history",&history)&&json_object_get_boolean(history)){
        return integer(j,"checkpoint_capture_ns",&capture)&&capture>=observed&&(uint64_t)capture<=now&&now-(uint64_t)capture<=500000000ULL;
    }
    json_object *cold=NULL;
    if(json_object_object_get_ex(j,"cold_replay",&cold)&&json_object_get_boolean(cold)){
        /* Cold reconstruction is never a promotable timer checkpoint. A
         * fresh <=500ms full TCP/BGP barrier must seal all peers afterward. */
        return !state->staged_capture_ns&&!state->transport_active&&now-(uint64_t)observed<=30000000000ULL;
    }
    return now-(uint64_t)observed<=3000000000ULL;
}
static json_object *written(json_object *j,struct peer *peer,struct follow_state *state){
    int64_t pid,id,observed,cookie,size;const char *hex=string(j,"wire_hex");json_object *poison;
    if(!consume_output)return error("output_consumption_disabled");
    if(!hex||!integer(j,"pid",&pid)||!integer(j,"record_id",&id)||!integer(j,"observed_monotonic_ns",&observed)||!integer(j,"socket_cookie",&cookie)||!integer(j,"wire_size",&size))return error("invalid_output_record");
    if(json_object_object_get_ex(j,"journal_failed",&poison)&&json_object_get_boolean(poison)){state->output_poisoned=true;return error("poisoned_source");}
    if(state->output_poisoned)return error("output_already_poisoned");
    if(pid<=0||id<=0||cookie<=0||(state->producer_pid&&pid!=state->producer_pid)||(uint64_t)id<=state->last_id)return error("replayed_or_wrong_producer");
    if(!valid_observation(j,observed,state))return error("expired_output");
    if(size<=0||size>16384||strlen(hex)!=(size_t)size*2)return error("invalid_output_size");
    size_t i=0;while(i<state->candidate_count&&state->candidates[i].cookie!=cookie)i++;
    if(i==state->candidate_count){if(i==array_size(state->candidates))return error("candidate_history_limit");state->candidate_count++;state->candidates[i].cookie=cookie;}
    struct candidate *history=&state->candidates[i];
    if(!bind_tuple(j,history)){state->output_poisoned=true;return error("source_tuple_changed");}
    /* Discard already compared bytes, retaining their absolute frontier. */
    if(history->matched>=65536 || history->written_size+(size_t)size>1048576){
        size_t left=history->written_size-history->matched;
        if(left)memmove(history->written,history->written+history->matched,left);
        history->retired+=history->matched;
        history->written_size=left;
        history->matched=0;
    }
    if(history->written_size+(size_t)size>1048576){state->output_poisoned=true;return error("output_history_limit");}
    unsigned char bytes[16384];
    for(int64_t n=0;n<size;n++){int a=hexval(hex[2*n]),b=hexval(hex[2*n+1]);if(a<0||b<0)return error("invalid_hex");bytes[n]=(a<<4)|b;}
    unsigned char *buffer=realloc(history->written,history->written_size+size);if(!buffer)return error("allocation_failed");
    memcpy(buffer+history->written_size,bytes,size);history->written=buffer;history->written_size+=size;
    state->producer_pid=pid;state->last_id=id;state->last_observed_ns=observed;state->output_records++;match_output(state);
    json_object *reply=status(peer,state);json_object_object_add(reply,"output_recorded",json_object_new_boolean(true));return reply;
}
/* Stage only. This API never assigns peer_connection.fd or exits repair.
 * The FD must be a newly restored socket in this standby's own namespace. */
static json_object *stage_transport(json_object *j,struct peer *peer,int *passed_fd,struct follow_state *state){
    if(!passed_fd||*passed_fd<0)return error("one_restored_fd_required");
    int fd=*passed_fd,domain=0,type=0,protocol=0,repair=0;socklen_t n=sizeof(int);
    if(getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&domain,&n)||domain!=AF_INET)return error("not_ipv4_socket");
    n=sizeof(int);if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n)||type!=SOCK_STREAM)return error("not_stream_socket");
    n=sizeof(int);if(getsockopt(fd,SOL_SOCKET,SO_PROTOCOL,&protocol,&n)||protocol!=IPPROTO_TCP)return error("not_tcp_socket");
    int nsfd=-1;frr_with_privs(&bgpd_privs){nsfd=ioctl(fd,SIOCGSKNS);}
    if(nsfd<0)return error("socket_namespace_unverifiable");
    struct stat own,other;int ns_ok=fstat(nsfd,&other)==0&&stat("/proc/self/ns/net",&own)==0&&own.st_ino==other.st_ino&&own.st_dev==other.st_dev;close(nsfd);
    if(!ns_ok)return error("socket_from_other_namespace");
    if(state->staged_fd>=0)return error("transport_already_staged");
    if(!consume_output||state->output_poisoned)return error("output_not_reconciled");
    int64_t pid,cookie,record,matched;
    if(!integer(j,"source_pid",&pid)||!integer(j,"source_socket_cookie",&cookie)||!integer(j,"last_record_id",&record)||!integer(j,"primary_output_matched",&matched))return error("barrier_identity_required");
    if(pid!=state->producer_pid||cookie!=state->source_cookie||record!=(int64_t)state->last_id)return error("stale_or_wrong_barrier");
    int64_t capture=0;
    if(!integer(j,"capture_mono_ns",&capture)||capture<(int64_t)state->last_observed_ns||(uint64_t)capture>clock_ns()||clock_ns()-(uint64_t)capture>500000000ULL)return error("checkpoint_barrier_too_old");
    struct peer_connection *c=peer->connection;struct candidate *history=NULL;
    for(size_t i=0;i<state->candidate_count;i++)if(state->candidates[i].cookie==state->source_cookie)history=&state->candidates[i];
    if(c->status!=Established||c->fd>=0||!history||!(history->retired+history->matched)||history->matched!=history->written_size||matched!=(int64_t)(history->retired+history->matched)||c->ibuf->count||!peer->bgp->mq||peer->bgp->mq->size)return error("native_state_or_output_not_ready");
    n=sizeof(repair);if(getsockopt(fd,IPPROTO_TCP,TCP_REPAIR,&repair,&n)||repair!=1)return error("restored_socket_not_fenced_in_repair");
    struct tcp_info info={0};n=sizeof(info);if(getsockopt(fd,IPPROTO_TCP,TCP_INFO,&info,&n)||info.tcpi_state!=TCP_ESTABLISHED)return error("socket_not_established");
    uint64_t actual_cookie=0;n=sizeof(actual_cookie);if(getsockopt(fd,SOL_SOCKET,SO_COOKIE,&actual_cookie,&n)||!actual_cookie||(actual_cookie==(uint64_t)state->source_cookie&&!getenv("CNLAB_NSR_DEVICE_ISOLATED")))return error("source_socket_survived");
    const char *lip=string(j,"local_ip"),*rip=string(j,"remote_ip");int64_t lp,rp;struct sockaddr_in local={0},remote={0};
    if(!lip||!rip||!integer(j,"local_port",&lp)||!integer(j,"remote_port",&rp)||lp<=0||lp>65535||rp<=0||rp>65535)return error("transport_tuple_required");
    struct in_addr laddr,raddr;
    if(inet_pton(AF_INET,lip,&laddr)!=1||inet_pton(AF_INET,rip,&raddr)!=1||strcmp(lip,getenv("CNLAB_NSR_BGP_LOCAL_IP"))||strcmp(rip,peer->host))return error("configured_endpoint_mismatch");
    n=sizeof(local);if(getsockname(fd,(struct sockaddr *)&local,&n))return error("local_tuple_unavailable");
    n=sizeof(remote);if(getpeername(fd,(struct sockaddr *)&remote,&n))return error("remote_tuple_unavailable");
    if(local.sin_addr.s_addr!=laddr.s_addr||remote.sin_addr.s_addr!=raddr.s_addr||ntohs(local.sin_port)!=lp||ntohs(remote.sin_port)!=rp)return error("restored_tuple_mismatch");
    if(!history->tuple_valid||memcmp(&local,&history->local,sizeof(local))||memcmp(&remote,&history->remote,sizeof(remote)))return error("not_observed_source_tuple");
    int64_t timer_capture,hold_remaining,holdtime,keepalive,last_write,last_update,keepalive_last;
    if(!integer(j,"keepalive_last_monotonic_us",&keepalive_last)||keepalive_last<=0||(uint64_t)keepalive_last>clock_ns()/1000)return error("invalid_keepalive_clock");
    if(peer->password||!integer(j,"bgp_timer_capture_ns",&timer_capture)||!integer(j,"hold_remaining_us",&hold_remaining)||!integer(j,"negotiated_holdtime",&holdtime)||!integer(j,"negotiated_keepalive",&keepalive)||!integer(j,"last_write_monotonic",&last_write)||!integer(j,"last_update_monotonic",&last_update)||timer_capture<capture||(uint64_t)timer_capture>clock_ns()||holdtime!=peer->v_holdtime||keepalive!=peer->v_keepalive||last_write<0||last_update<0)return error("invalid_bgp_timer_checkpoint");
    int64_t elapsed=(clock_ns()-(uint64_t)timer_capture)/1000;
    if(cnlab_bgp_restore_hold_timer(c,hold_remaining-elapsed-100))return error("expired_bgp_hold_timer");
    atomic_store_explicit(&peer->last_write,last_write,memory_order_relaxed);atomic_store_explicit(&peer->last_update,last_update,memory_order_relaxed);
    state->staged_keepalive_last_us=keepalive_last;state->staged_hold_deadline_ns=(uint64_t)timer_capture+(uint64_t)hold_remaining*1000;
    state->staged_fd=fd;state->staged_capture_ns=capture;*passed_fd=-1;json_object *reply=status(peer,state);json_object_object_add(reply,"transport_staged",json_object_new_boolean(true));return reply;
}
static json_object *activate_transport(json_object *j,struct peer *peer,struct follow_state *state){
    int64_t epoch;if(!integer(j,"epoch",&epoch))return error("epoch_required");
    if(state->transport_active)return error("already_active");
    if(!bulk_activation&&!owner_claim("bgpd",epoch,&bgpd_privs))return error("owner_grant_refused");
    if(!state->staged_hold_deadline_ns||clock_ns()>=state->staged_hold_deadline_ns)return error("staged_bgp_hold_timer_expired");
    if(!state->staged_capture_ns||clock_ns()-state->staged_capture_ns>500000000ULL)return error("staged_checkpoint_too_old");
    match_output(state);struct peer_connection *c=peer->connection;struct candidate *history=NULL;
    for(size_t i=0;i<state->candidate_count;i++)if(state->candidates[i].cookie==state->source_cookie)history=&state->candidates[i];
    if(state->staged_fd<0||state->output_poisoned||!history||history->matched!=history->written_size||c->status!=Established||c->fd>=0||c->ibuf->count||!peer->bgp->mq||peer->bgp->mq->size)return error("transport_or_native_state_not_ready");
    union sockunion source_local={0},source_remote={0};source_local.sin=history->local;source_remote.sin=history->remote;
    union sockunion *local=sockunion_dup(&source_local),*remote=sockunion_dup(&source_remote);
    if(!local||!remote){if(local)sockunion_free(local);if(remote)sockunion_free(remote);return error("endpoint_allocation_failed");}
    if(getenv("CNLAB_NSR_ABORT_ON_CLOSE")){
        struct linger linger={.l_onoff=1,.l_linger=0};
        if(setsockopt(state->staged_fd,SOL_SOCKET,SO_LINGER,&linger,sizeof(linger)))return error("socket_retirement_guard_failed");
    }
    int mode=-1,rc=-1;frr_with_privs(&bgpd_privs){rc=setsockopt(state->staged_fd,IPPROTO_TCP,TCP_REPAIR,&mode,sizeof(mode));}
    if(rc){sockunion_free(local);sockunion_free(remote);return error("repair_activation_failed");}
    if(c->su_local)sockunion_free(c->su_local);
    if(c->su_remote)sockunion_free(c->su_remote);
    c->su_local=local;c->su_remote=remote;
    c->dir=ntohs(history->local.sin_port)==179?CONNECTION_INCOMING:CONNECTION_OUTGOING;
    c->fd=state->staged_fd;state->staged_fd=-1;state->transport_active=true;state->native_event_mode=false;work_queue_unplug(peer->bgp->process_queue);
    unsetenv("CNLAB_NSR_BGP_FOLLOWER");bgp_reads_on(c);bgp_writes_on(c);struct timeval ka_last={.tv_sec=state->staged_keepalive_last_us/1000000,.tv_usec=state->staged_keepalive_last_us%1000000};cnlab_bgp_keepalive_resume(c,&ka_last);
    if(!bulk_activation){
        for(size_t i=0;i<state_count;i++)if(!states[i]->transport_active)return error("complete_activation_set_required");
        if(cnlab_bgp_start_owner_listener(getenv("CNLAB_NSR_BGP_LOCAL_IP")))return error("owner_listener_failed");
        if(!owner_ready("bgpd",epoch,&bgpd_privs))return error("owner_readiness_commit_failed");
    }
    uint64_t live_cookie=0;socklen_t cookie_len=sizeof(live_cookie);
    if(getsockopt(c->fd,SOL_SOCKET,SO_COOKIE,&live_cookie,&cookie_len)||!live_cookie)return error("adopted_cookie_unavailable");
    json_object *reply=status(peer,state);
    json_object_object_add(reply,"adopted_cookie",json_object_new_int64(live_cookie));
    json_object_object_add(reply,"adopted_pid",json_object_new_int64(getpid()));
    json_object_object_add(reply,"activated",json_object_new_boolean(true));json_object_object_add(reply,"epoch",json_object_new_int64(epoch));return reply;
}
static int event_gate(struct peer_connection *c,int kind,afi_t afi,safi_t safi){(void)afi;(void)safi;if(kind==3&&replaying_meta_event)return 0;struct follow_state *state=state_for(c->peer,false);return state&&state->native_event_mode&&consume_output&&c->fd<0&&!state->replaying_event;}
static json_object *apply_native_event(json_object *j,struct peer *peer,struct follow_state *state){
    int64_t pid,id,observed,cookie,kind;
    if(!integer(j,"pid",&pid)||!integer(j,"record_id",&id)||!integer(j,"observed_monotonic_ns",&observed)||!integer(j,"socket_cookie",&cookie)||!integer(j,"type",&kind)||kind<1||kind>4)return error("invalid_native_event");
    if(!valid_observation(j,observed,state))return error("expired_native_event");
    if(pid<=0||id<=0||(state->producer_pid&&pid!=state->producer_pid)||(uint64_t)id<=state->last_id)return error("replayed_or_wrong_producer");
    if(state->native_event_mode){
        if(cookie!=state->source_cookie||peer->connection->status!=Established||peer->connection->fd>=0)return error("foreign_socket_or_negotiation_not_ready");
        state->replaying_event=true;replaying_meta_event=kind==3;int rc=cnlab_bgp_replay_native_event(peer->connection,kind==4?2:kind,AFI_IP,SAFI_UNICAST);state->replaying_event=false;replaying_meta_event=false;
        if(rc)return error("native_event_replay_failed");
    }
    state->producer_pid=pid;state->last_id=id;state->last_observed_ns=observed;match_output(state);json_object *reply=status(peer,state);json_object_object_add(reply,"event_applied",json_object_new_boolean(true));return reply;
}
/* A cold cursor accounts for already verified KEEPALIVEs. It cannot
 * authorize a socket, alter routes, or substitute for a fresh checkpoint. */
static json_object *idle_cursor(json_object *j,struct peer *peer,struct follow_state *state){
    int64_t pid,id,cookie,observed,sent,received;
    json_object *cold=NULL;
    struct peer_connection *c=peer->connection;
    if(!json_object_object_get_ex(j,"cold_replay",&cold)||!json_object_get_boolean(cold)||
       !integer(j,"pid",&pid)||!integer(j,"record_id",&id)||
       !integer(j,"socket_cookie",&cookie)||!integer(j,"observed_monotonic_ns",&observed)||
       !integer(j,"sent",&sent)||!integer(j,"received",&received)||
       pid!=state->producer_pid||cookie!=state->source_cookie||id<1||
       (uint64_t)id<=state->last_id||sent<0||received<0||
       !state->native_event_mode||state->output_poisoned||c->fd>=0||
       state->staged_fd>=0||!valid_observation(j,observed,state)||
       !cnlab_idle_update_scan(c)||!c->obuf||c->obuf->count||!c->ibuf||
       c->ibuf->count||!peer->bgp->mq||peer->bgp->mq->size)
        return error("cold_idle_cursor_not_aligned");
    struct candidate *history=NULL;
    for(size_t i=0;i<state->candidate_count;i++)
        if(state->candidates[i].cookie==cookie)history=&state->candidates[i];
    if(!history||!history->tuple_valid||!bind_tuple(j,history)||
       history->matched!=history->written_size||
       (uint64_t)sent>((uint64_t)INT64_MAX-state->matched_total)/19)
        return error("cold_idle_cursor_output_not_aligned");
    uint64_t skipped=(uint64_t)sent*19;
    history->retired+=skipped;state->matched_total+=skipped;
    atomic_fetch_add_explicit(&peer->keepalive_in,received,memory_order_relaxed);
    atomic_fetch_add_explicit(&peer->keepalive_out,sent,memory_order_relaxed);
    state->last_id=id;state->last_observed_ns=observed;
    json_object *reply=status(peer,state);
    json_object_object_add(reply,"event_applied",json_object_new_boolean(true));
    return reply;
}
/* Compact read-only native bestpaths. Kernel FIB is checked independently
 * by the device agent; this never installs routes or substitutes protocol state. */
#include "native_rib.h"
static json_object *dispatch(json_object *j,struct event *event,int *passed_fd);
static json_object *dispatch_many(json_object *j,struct event *event,const char *operation){
    json_object *items=NULL,*result=json_object_new_object(),*rows=json_object_new_array();
    bool records=!strcmp(operation,"batch");
    if(!json_object_object_get_ex(j,records?"records":"peers",&items)||json_object_get_type(items)!=json_type_array||json_object_array_length(items)<1||json_object_array_length(items)>256){json_object_put(result);json_object_put(rows);return error("invalid_batch_bound");}
    int64_t epoch=0;bool activate=!strcmp(operation,"activate_all");
    if(activate){
        if(!integer(j,"epoch",&epoch)||epoch<1||(size_t)json_object_array_length(items)!=state_count){json_object_put(result);json_object_put(rows);return error("complete_activation_set_required");}
        for(size_t i=0;i<state_count;i++)if(states[i]->staged_fd<0||states[i]->transport_active||!states[i]->staged_capture_ns||clock_ns()-states[i]->staged_capture_ns>=500000000ULL){json_object_put(result);json_object_put(rows);return error("incomplete_or_stale_activation_set");}
        if(!owner_claim("bgpd",epoch,&bgpd_privs)){json_object_put(result);json_object_put(rows);return error("owner_grant_refused");}
        bulk_activation=true;
    }
    compact_status=true;slim_records=records;size_t total=json_object_array_length(items);const char *failure=NULL;
    for(size_t i=0;i<total;i++){
        json_object *entry=json_object_array_get_idx(items,i),*request=entry;int passed=-1;
        if(!records){
            if(json_object_get_type(entry)!=json_type_string){failure="invalid_batch_peer";break;}
            for(size_t k=0;k<i;k++)if(!strcmp(json_object_get_string(entry),json_object_get_string(json_object_array_get_idx(items,k))))failure="duplicate_batch_peer";
            if(failure)break;
            request=json_object_new_object();json_object_object_add(request,"peer",json_object_get(entry));
            json_object_object_add(request,"action",json_object_new_string(activate?"activate_transport":!strcmp(operation,"arm_all")?"native_event_mode":!strcmp(operation,"release_all")?"release_staged":"query"));
            if(activate)json_object_object_add(request,"epoch",json_object_new_int64(epoch));
        }
        json_object *reply=dispatch(request,event,&passed),*why=NULL;
        if(!records)json_object_put(request);
        if(json_object_object_get_ex(reply,"error",&why)&&strcmp(json_object_get_string(why),"foreign_socket_or_negotiation_not_ready")){
            json_object_object_add(result,"error",json_object_get(why));json_object_object_add(result,"failed_index",json_object_new_int64(i));json_object_put(reply);failure="native_batch_refused";break;
        }
        json_object *poison=NULL;if(records&&((json_object_object_get_ex(reply,"output_poisoned",&poison)&&json_object_get_boolean(poison))||(json_object_object_get_ex(reply,"native_output_overflow",&poison)&&json_object_get_boolean(poison)))){json_object_object_add(result,"error",json_object_new_string("native_output_mismatch_or_overflow"));json_object_object_add(result,"failed_index",json_object_new_int64(i));json_object_object_add(result,"failed_record",json_object_get(entry));json_object *detail=NULL;if(json_object_object_get_ex(reply,"output_mismatch",&detail))json_object_object_add(result,"output_mismatch",json_object_get(detail));json_object_put(reply);failure="native_output_mismatch_or_overflow";break;}
        if(records){json_object_put(reply);}else{json_object_object_add(reply,"peer",json_object_get(entry));json_object_array_add(rows,reply);}
    }
    compact_status=false;slim_records=false;bulk_activation=false;
    if(activate&&!failure&&cnlab_bgp_start_owner_listener(getenv("CNLAB_NSR_BGP_LOCAL_IP")))failure="owner_listener_failed";
    if(activate&&!failure&&!owner_ready("bgpd",epoch,&bgpd_privs))failure="owner_readiness_commit_failed";
    json_object_object_add(result,"ok",json_object_new_boolean(!failure));json_object_object_add(result,"count",json_object_new_int64(total));
    if(failure){json_object *existing;if(!json_object_object_get_ex(result,"error",&existing))json_object_object_add(result,"error",json_object_new_string(failure));}
    if(activate)json_object_object_add(result,"activated",json_object_new_boolean(!failure));
    json_object_object_add(result,"peers",rows);return result;
}
static json_object *dispatch(json_object *j,struct event *event,int *passed_fd){
    if(!j)return error("invalid_json");
    const char *operation=string(j,"action");
    if(operation&&!strcmp(operation,"settle_bootstrap")){
        struct bgp *bgp=bgp_get_default();struct peer_connection *connection=NULL;
        for(size_t i=0;i<state_count;i++){
            struct follow_state *s=states[i];
            if(s->transport_active||s->staged_capture_ns||!s->native_event_mode||
               s->output_poisoned)return error("cold_fenced_replica_required");
            if(s->active_peer->connection->status==Established)connection=s->active_peer->connection;
        }
        if(!connection||!bgp||!bgp->mq)return error("cold_instance_unavailable");
        /* Local zebra nexthop notifications during cold replay may enqueue
         * additional real bestpath work. Keep all outputs for byte comparison.
         * The caller separately verifies the source RIB and local kernel FIB. */
        replaying_meta_event=true;
        for(unsigned i=0;i<256&&bgp->mq->size;i++)
            cnlab_bgp_replay_native_event(connection,3,AFI_IP,SAFI_UNICAST);
        replaying_meta_event=false;
        json_object *reply=json_object_new_object();
        json_object_object_add(reply,"remaining",json_object_new_int64(bgp->mq->size));return reply;
    }
    if(operation&&!strcmp(operation,"rib_snapshot"))return native_rib();
    if(operation&&(!strcmp(operation,"batch")||!strcmp(operation,"query_all")||!strcmp(operation,"arm_all")||!strcmp(operation,"release_all")||!strcmp(operation,"activate_all")))return dispatch_many(j,event,operation);
    const char *peer_ip=string(j,"peer");
    if(!peer_ip)return error("missing_peer");
    union sockunion su;
    if(str2sockunion(peer_ip,&su)<0||su.sa.sa_family!=AF_INET)return error("invalid_peer");
    struct bgp *bgp=bgp_get_default();if(!bgp)return error("bgp_not_configured");
    struct peer *peer=peer_lookup(bgp,&su);if(!peer||!peer->connection)return error("peer_not_configured");
    struct follow_state *state=state_for(peer,true);if(!state)return error("peer_state_limit");
    const char *action=string(j,"action");if(action&&!strcmp(action,"query")){match_output(state);return status(peer,state);}
    if(action&&!strcmp(action,"native_event_mode")){
        if(state->transport_active||state->output_poisoned||peer->connection->obuf->count)return error("native_event_mode_not_ready");
        state->native_event_mode=true;work_queue_plug(peer->bgp->process_queue);json_object *reply=status(peer,state);json_object_object_add(reply,"mode_armed",json_object_new_boolean(true));return reply;
    }
    /* The source changed physical device while the wire session survived.
     * Accept its new kernel identity only at a fully reconciled cold replay
     * boundary, before a socket has been staged in this new follower. */
    if(action&&!strcmp(action,"bootstrap_rebind")){
        int64_t old_pid,old_cookie,old_last,new_pid,new_cookie;
        if(!integer(j,"old_pid",&old_pid)||!integer(j,"old_cookie",&old_cookie)||
           !integer(j,"old_last",&old_last)||!integer(j,"new_pid",&new_pid)||
           !integer(j,"new_cookie",&new_cookie)||new_pid<=0||new_cookie<=0||
           old_pid!=state->producer_pid||old_cookie!=state->source_cookie||
           old_last!=(int64_t)state->last_id||state->output_poisoned||
           state->staged_capture_ns||state->transport_active||state->staged_fd>=0||
           peer->connection->fd>=0||peer->connection->status!=Established||
           peer->connection->obuf->count||peer->connection->ibuf->count)
            return error("invalid_source_epoch_boundary");
        struct candidate *h=NULL;
        for(size_t i=0;i<state->candidate_count;i++){
            if(state->candidates[i].cookie==old_cookie)h=&state->candidates[i];
            else if(state->candidates[i].cookie==new_cookie)return error("ambiguous_new_cookie");
        }
        if(!h||!h->tuple_valid||!(h->retired+h->matched)||h->matched!=h->written_size||!bind_tuple(j,h))
            return error("unreconciled_epoch_boundary");
        h->cookie=new_cookie;state->producer_pid=new_pid;state->source_cookie=new_cookie;
        state->open_cookie=new_cookie;state->last_id=0;
        return status(peer,state);
    }
    if(action&&!strcmp(action,"release_staged")){
        if(state->transport_active)return error("already_active");
        if(state->staged_fd>=0){close(state->staged_fd);state->staged_fd=-1;}
        json_object *reply=status(peer,state);json_object_object_add(reply,"staged_released",json_object_new_boolean(true));return reply;
    }
    if(action&&!strcmp(action,"activate_transport"))return activate_transport(j,peer,state);
    if(action&&!strcmp(action,"stage_transport")){match_output(state);return stage_transport(j,peer,passed_fd,state);}
    json_object *poison;if(json_object_object_get_ex(j,"journal_failed",&poison)&&json_object_get_boolean(poison)){state->output_poisoned=true;return error("poisoned_source");}
    const char *incoming_schema=string(j,"schema");
    if(incoming_schema&&!strcmp(incoming_schema,"cnlab-native-idle-cursor-v1"))return idle_cursor(j,peer,state);
    if(incoming_schema&&!strcmp(incoming_schema,"cnlab-native-event-v1"))return apply_native_event(j,peer,state);
    if(incoming_schema&&!strcmp(incoming_schema,"cnlab-native-output-v1"))return written(j,peer,state);
    int64_t id,pid,observed,size,type;
    const char *schema=string(j,"schema"),*hex=string(j,"wire_hex");
    if(!schema||strcmp(schema,"cnlab-native-input-v1")||!hex||!integer(j,"record_id",&id)||!integer(j,"pid",&pid)||!integer(j,"observed_monotonic_ns",&observed)||!integer(j,"wire_size",&size)||!integer(j,"type",&type))return error("invalid_input_record");
    if(!valid_observation(j,observed,state))return error("expired_or_wrong_clock");
    if(id<=0||pid<=0||(state->producer_pid&&state->producer_pid!=pid)||(uint64_t)id<=state->last_id)return error("replayed_or_wrong_producer");
    if(size<19||size>65535||strlen(hex)!=(size_t)size*2||type<1||type>5)return error("invalid_bgp_frame_length");
    unsigned char *bytes=malloc(size);if(!bytes)return error("allocation_failed");
    for(int64_t i=0;i<size;i++){int a=hexval(hex[2*i]),b=hexval(hex[2*i+1]);if(a<0||b<0){free(bytes);return error("invalid_hex");}bytes[i]=(a<<4)|b;}
    bool marker=true;for(int i=0;i<16;i++)if(bytes[i]!=255)marker=false;
    if(!marker||((bytes[16]<<8)|bytes[17])!=size||bytes[18]!=type){free(bytes);return error("invalid_bgp_header");}
    struct peer_connection *c=peer->connection;
    int64_t cookie=0;if(!integer(j,"socket_cookie",&cookie)||cookie<=0){free(bytes);return error("socket_identity_required");}
    if(c->fd>=0){free(bytes);return error("real_transport_forbidden_in_shadow");}
    if(c->obuf&&c->obuf->count>256){free(bytes);return error("uncommitted_output_limit");}
    size_t candidate=0;while(candidate<state->candidate_count&&state->candidates[candidate].cookie!=cookie)candidate++;
    if(type==BGP_MSG_OPEN){
        int64_t capabilities;
        if(!integer(j,"capabilities",&capabilities)||capabilities<0){free(bytes);return error("source_open_capabilities_required");}
        if(size>4096||candidate==array_size(state->candidates)){free(bytes);return error("candidate_history_limit");}
        if(candidate==state->candidate_count)state->candidate_count++;
        state->candidates[candidate].cookie=cookie;if(!bind_tuple(j,&state->candidates[candidate])){free(bytes);state->output_poisoned=true;return error("source_tuple_changed");}state->candidates[candidate].size=size;state->candidates[candidate].observed=observed;
        state->candidates[candidate].open_capabilities=(uint64_t)capabilities;
        memcpy(state->candidates[candidate].bytes,bytes,size);free(bytes);
        state->producer_pid=pid;state->last_id=id;state->buffered_opens++;
        json_object *reply=status(peer,state);json_object_object_add(reply,"buffered_open",json_object_new_boolean(true));return reply;
    }
    if(cookie!=state->source_cookie||c->status<OpenSent||c->status==Clearing||c->status==Deleted){
        if(type!=BGP_MSG_KEEPALIVE||candidate==state->candidate_count){free(bytes);state->foreign_records++;return error("foreign_socket_or_negotiation_not_ready");}
        if(c->status==Clearing){free(bytes);return error("native_clearing_in_progress");}
        struct candidate *history=&state->candidates[candidate];
        if(clock_ns()-history->observed>3000000000ULL&&!valid_observation(j,history->observed,state)){free(bytes);return error("expired_open_history");}
        bgp_stop(c);bgp_fsm_change_status(c,Idle);
        event_cancel(&c->t_start);event_cancel(&c->t_connect);event_cancel(&c->t_delayopen);
        const char *local=getenv("CNLAB_NSR_BGP_LOCAL_IP");if(!local){free(bytes);return error("local_endpoint_required");}
        if(c->su_local)sockunion_free(c->su_local);
        if(c->su_remote)sockunion_free(c->su_remote);
        c->su_local=sockunion_str2su(local);c->su_remote=sockunion_str2su(peer_ip);
        if(!c->su_local||!c->su_remote){free(bytes);return error("endpoint_allocation_failed");}
        c->su_remote->sin.sin_port=htons(179);c->dir=CONNECTION_OUTGOING;
        peer->local_id=bgp->router_id;
        bgp_fsm_change_status(c,OpenSent);
        state->replaying_open=history;bgp_open_send(c);state->replaying_open=NULL;

        struct stream *opening=stream_new(history->size);stream_put(opening,history->bytes,history->size);
        frr_with_mutex(&c->io_mtx){stream_fifo_push(c->ibuf,opening);}
        frr_with_mutex(&bm->peer_connection_mtx){if(!peer_connection_fifo_member(&bm->connection_fifo,c))peer_connection_fifo_add_tail(&bm->connection_fifo,c);}
        bgp_process_packet(event);
        if(c->status!=OpenConfirm){free(bytes);return error("native_open_did_not_negotiate");}
        state->source_cookie=cookie;state->open_cookie=cookie;state->active_peer=peer;
    }
    struct stream *input=stream_new(size);stream_put(input,bytes,size);free(bytes);
    frr_with_mutex(&c->io_mtx){stream_fifo_push(c->ibuf,input);}
    frr_with_mutex(&bm->peer_connection_mtx){if(!peer_connection_fifo_member(&bm->connection_fifo,c))peer_connection_fifo_add_tail(&bm->connection_fifo,c);}
    /* Same main event loop and native dispatcher; response is after this
     * input dispatch, but it is NOT a cross-component/FIB commit ACK. */
    bgp_process_packet(event);
    state->producer_pid=pid;state->last_id=id;state->last_observed_ns=observed;state->applied++;

    match_output(state);
    json_object *reply=status(peer,state);json_object_object_add(reply,"dispatched",json_object_new_boolean(true));return reply;
}
/* A request is dispatched exactly once. Only its already-computed reply may
 * wait for writability; replaying stage_transport after a lost ACK is unsafe.
 * All callbacks stay on the native event loop and never block it. */
static void control_close(struct control *c){
    event_cancel(&c->event);event_cancel(&c->deadline);
    if(c->reply)json_object_put(c->reply);
    close(c->fd);free(c);
}
static void control_expired(struct event *event){
    struct control *c=EVENT_ARG(event);
    zlog_warn("cnlab local control expired: fd=%d phase=%s",c->fd,c->reply?"reply":"request");
    control_close(c);
}
static void control_write(struct event *event);
static void control_send(struct control *c){
    const char *text=json_object_to_json_string_ext(c->reply,JSON_C_TO_STRING_PLAIN);
    size_t size=strlen(text);ssize_t n=send(c->fd,text,size,MSG_NOSIGNAL|MSG_DONTWAIT);
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)){
        event_add_write(loop,control_write,c,c->fd,&c->event);return;
    }
    if(n!=(ssize_t)size){
        int saved=n<0?errno:0;
        zlog_warn("cnlab local control reply failed: fd=%d bytes=%zd expected=%zu errno=%d (%s)",
                  c->fd,n,size,saved,strerror(saved));
    }
    control_close(c);
}
static void control_write(struct event *event){control_send(EVENT_ARG(event));}
static void control_read(struct event *event){
    struct control *c=EVENT_ARG(event);char *data=malloc(160000);json_object *j=NULL,*reply;int passed_fd=-1;size_t fd_count=0;
    if(!data)reply=error("allocation_failed");else{
        char control[CMSG_SPACE(sizeof(int)*8)]={0};struct iovec iov={.iov_base=data,.iov_len=159999};
        struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
        ssize_t n=recvmsg(c->fd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)){
            free(data);event_add_read(loop,control_read,c,c->fd,&c->event);return;
        }
        if(n<=0){
            if(n<0)zlog_warn("cnlab local control request failed: fd=%d errno=%d (%s)",c->fd,errno,strerror(errno));
            free(data);control_close(c);return;
        }
        for(struct cmsghdr *cm=CMSG_FIRSTHDR(&msg);cm;cm=CMSG_NXTHDR(&msg,cm)){
            if(cm->cmsg_level==SOL_SOCKET&&cm->cmsg_type==SCM_RIGHTS&&cm->cmsg_len>=CMSG_LEN(0)){
                size_t count=(cm->cmsg_len-CMSG_LEN(0))/sizeof(int);int *fds=(int *)CMSG_DATA(cm);
                for(size_t i=0;i<count;i++){fd_count++;if(passed_fd<0)passed_fd=fds[i];else close(fds[i]);}
            }
        }
        if(n<159999&&!(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC))){data[n]=0;j=json_tokener_parse(data);}
        if(fd_count>1)reply=error("exactly_one_fd_required");else reply=dispatch(j,event,&passed_fd);
    }
    if(passed_fd>=0)close(passed_fd);
    if(j)json_object_put(j);
    free(data);c->reply=reply;control_send(c);
}
static void accept_control(struct event *event){
    (void)event;event_add_read(loop,accept_control,NULL,listener,&accept_event);
    int fd=accept4(listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);if(fd<0)return;
    int buffer=1024*1024;setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer));
    struct control *c=calloc(1,sizeof(*c));if(!c){close(fd);return;}c->fd=fd;
    event_add_timer_msec(loop,control_expired,c,200,&c->deadline);
    event_add_read(loop,control_read,c,fd,&c->event);
}
static int late_init(struct event_loop *master){loop=master;if(consume_output)event_add_timer_msec(loop,match_tick,NULL,10,&match_event);event_add_read(loop,accept_control,NULL,listener,&accept_event);return 0;}
static int module_init(void){
    const char *role=getenv("CNLAB_NSR_BGP_FOLLOWER"),*path=getenv("CNLAB_NSR_BGP_FOLLOW_SOCK");struct sockaddr_un addr={.sun_family=AF_UNIX};
    if(!role||strcmp(role,"1")||!path||strncmp(path,"/run/frr-nsr/",13)||strlen(path)>=sizeof(addr.sun_path))return -1;
    consume_output=getenv("CNLAB_NSR_BGP_CONSUME_OUTPUT")&& !strcmp(getenv("CNLAB_NSR_BGP_CONSUME_OUTPUT"),"1");
    strlcpy(addr.sun_path,path,sizeof(addr.sun_path));listener=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if(listener<0||bind(listener,(struct sockaddr *)&addr,sizeof(addr))||listen(listener,8))return -1;
    chmod(path,0600);hook_register(peer_status_changed,observe_shadow_transition);hook_register(cnlab_bgp_open_restart_bit,replay_open_restart_bit);hook_register(cnlab_bgp_native_event_gate,event_gate);hook_register(frr_late_init,late_init);return 0;
}
FRR_MODULE_SETUP(.name="cnlab_bgpd_native_follow",.version=FRR_VERSION,.description="Native BGP shadow with guarded transport activation",.init=module_init,);
