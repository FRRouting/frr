/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Native Linux TCP state export primitive; no CRIU dependency.
 * Call only while application IO is quiesced and packet output is fenced. This does NOT implement the
 * cross-daemon commit/send gate and is not a promotable NSR checkpoint.
 * Linux queue identifiers are enums: RECV=1, SEND=2. Do not override them
 * with #ifndef macros (the historical repair helper had them reversed).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "tcp_snapshot.h"

static uint64_t now_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static int opt(int fd,int name,void *buf,socklen_t len) {
    return getsockopt(fd,SOL_TCP,name,buf,&len);
}
static int select_queue(int fd,int q) {
    return setsockopt(fd,SOL_TCP,TCP_REPAIR_QUEUE,&q,sizeof(q));
}
static int peek_queue(int fd,int q,int n,unsigned char **dest) {
    *dest=NULL;
    if (n<0 || n>1024*1024) { errno=EOVERFLOW;return -1; }
    if (select_queue(fd,q))return -1;
    if (!n)return 0;
    *dest=malloc(n);if(!*dest)return -1;
    ssize_t got=recv(fd,*dest,n,MSG_PEEK|MSG_DONTWAIT|MSG_WAITALL);
    if (got!=n) {if(got>=0)errno=EIO;return -1;}
    return 0;
}
void tcp_snapshot_free(struct tcp_snapshot *s) {
    free(s->send_data);free(s->recv_data);
    s->send_data=s->recv_data=NULL;
}
static int snapshot_export(int fd,struct tcp_snapshot *s,int hold) {
    memset(s,0,sizeof(*s));
    int mode=0; socklen_t len=sizeof(mode);
    if(getsockopt(fd,SOL_TCP,TCP_REPAIR,&mode,&len))return -1;
    if(mode) {errno=EBUSY;return -1;}
    len=sizeof(s->local);
    if(getsockname(fd,(struct sockaddr *)&s->local,&len))return -1;
    len=sizeof(s->remote);
    if(getpeername(fd,(struct sockaddr *)&s->remote,&len))return -1;
    if(s->local.sin_family!=AF_INET || s->remote.sin_family!=AF_INET) {errno=EAFNOSUPPORT;return -1;}
    uint64_t start=now_ns();mode=1;
    if(setsockopt(fd,SOL_TCP,TCP_REPAIR,&mode,sizeof(mode)))return -1;
    int rc=-1, saved;
    if(opt(fd,TCP_INFO,&s->info,sizeof(s->info)))goto done;
    if(s->info.tcpi_state!=TCP_ESTABLISHED){errno=ENOTCONN;goto done;}
    if(ioctl(fd,SIOCOUTQ,&s->outq)||ioctl(fd,SIOCOUTQNSD,&s->unsent)||ioctl(fd,FIONREAD,&s->unread))goto done;
    if(opt(fd,TCP_MAXSEG,&s->mss,sizeof(s->mss)))goto done;
    if(opt(fd,TCP_CORK,&s->cork,sizeof(s->cork)) || opt(fd,TCP_NODELAY,&s->nodelay,sizeof(s->nodelay)) || opt(fd,TCP_USER_TIMEOUT,&s->user_timeout,sizeof(s->user_timeout)))goto done;
    len=sizeof(s->sndbuf);
    if(getsockopt(fd,SOL_SOCKET,SO_SNDBUF,&s->sndbuf,&len))goto done;
    len=sizeof(s->rcvbuf);
    if(getsockopt(fd,SOL_SOCKET,SO_RCVBUF,&s->rcvbuf,&len))goto done;
    s->status_flags=fcntl(fd,F_GETFL);if(s->status_flags<0)goto done;
    s->capture_mono_ns=now_ns();
    if(opt(fd,TCP_REPAIR_WINDOW,&s->window,sizeof(s->window)))goto done;
    if(s->info.tcpi_options & TCPI_OPT_TIMESTAMPS)
        if(opt(fd,TCP_TIMESTAMP,&s->timestamp,sizeof(s->timestamp)))goto done;
    if(peek_queue(fd,TCP_SEND_QUEUE,s->outq,&s->send_data))goto done;
    if(opt(fd,TCP_QUEUE_SEQ,&s->send_end,sizeof(s->send_end)))goto done;
    if(peek_queue(fd,TCP_RECV_QUEUE,s->unread,&s->recv_data))goto done;
    if(opt(fd,TCP_QUEUE_SEQ,&s->recv_end,sizeof(s->recv_end)))goto done;
    if(s->unsent>s->outq){errno=EPROTO;goto done;}
    /* recv(MSG_PEEK) still calls tcp_cleanup_rbuf in Linux5.4 and can
     * update the receive window. Restore the captured window after peeking.
     * A caller-provided output fence is required to suppress any such ACK. */
    if(setsockopt(fd,SOL_TCP,TCP_REPAIR_WINDOW,&s->window,sizeof(s->window)))goto done;
    rc=0;
done:
    saved=errno;
    if(select_queue(fd,TCP_NO_QUEUE)) {saved=errno;rc=-1;}
    if(!hold || rc) {
        /* Linux5.4 TCP_REPAIR_OFF_NO_WP: export must not emit window probes. */
        mode=-1;
        if(setsockopt(fd,SOL_TCP,TCP_REPAIR,&mode,sizeof(mode))){saved=errno;rc=-1;}
    }
    s->pause_ns=now_ns()-start;
    if(rc)tcp_snapshot_free(s);
    errno=saved;return rc;
}

int tcp_snapshot_export(int fd,struct tcp_snapshot *s) {
    return snapshot_export(fd,s,0);
}
int tcp_snapshot_export_hold(int fd,struct tcp_snapshot *s) {
    return snapshot_export(fd,s,1);
}
static int set(int fd,int optname,const void *value,socklen_t len) {
    return setsockopt(fd,SOL_TCP,optname,value,len);
}
static int inject(int fd,int queue,const unsigned char *bytes,int count) {
    if(select_queue(fd,queue))return -1;
    int done=0;
    while(done<count) {
        ssize_t n=send(fd,bytes+done,count-done,MSG_DONTWAIT|MSG_NOSIGNAL);
        if(n<=0){if(!n)errno=EIO;return -1;}
        done+=n;
    }
    return 0;
}
static int snapshot_supported(const struct tcp_snapshot *s) {
    if(s->local.sin_family!=AF_INET || s->remote.sin_family!=AF_INET ||
       s->info.tcpi_state!=TCP_ESTABLISHED || s->outq<0 || s->outq>1024*1024 ||
       s->unread<0 || s->unread>1024*1024 || s->unsent<0 || s->unsent>s->outq ||
       (s->outq && !s->send_data) || (s->unread && !s->recv_data) ||
       s->mss<=0 || s->sndbuf<2048 || s->rcvbuf<2048 ||
       s->info.tcpi_sacked || (s->info.tcpi_options & ~(TCPI_OPT_TIMESTAMPS|TCPI_OPT_SACK|TCPI_OPT_WSCALE))) {
        errno=ENOTSUP;return -1;
    }
    return 0;
}
int tcp_snapshot_import_fenced(const struct tcp_snapshot *s,uint64_t *duration_ns) {
    if(snapshot_supported(s))return -1;
    uint64_t start=now_ns();
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0),one=1;
    if(fd<0)return -1;
    int saved;
    if(set(fd,TCP_REPAIR,&one,sizeof(one)))goto fail;
    int snd=s->sndbuf/2,rcv=s->rcvbuf/2;
    if(setsockopt(fd,SOL_SOCKET,SO_SNDBUFFORCE,&snd,sizeof(snd)) ||
       setsockopt(fd,SOL_SOCKET,SO_RCVBUFFORCE,&rcv,sizeof(rcv)))goto fail;
    if(bind(fd,(const struct sockaddr *)&s->local,sizeof(s->local)))goto fail;
    uint32_t seq=s->recv_end-(uint32_t)s->unread;
    if(select_queue(fd,TCP_RECV_QUEUE)||set(fd,TCP_QUEUE_SEQ,&seq,sizeof(seq)))goto fail;
    seq=s->send_end-(uint32_t)s->outq;
    if(select_queue(fd,TCP_SEND_QUEUE)||set(fd,TCP_QUEUE_SEQ,&seq,sizeof(seq)))goto fail;
    if(connect(fd,(const struct sockaddr *)&s->remote,sizeof(s->remote)))goto fail;
    struct tcp_repair_opt options[4];unsigned count=0;
    options[count++]=(struct tcp_repair_opt){TCPOPT_MAXSEG,(uint32_t)s->mss};
    if(s->info.tcpi_options & TCPI_OPT_WSCALE)
        options[count++]=(struct tcp_repair_opt){TCPOPT_WINDOW,(uint32_t)s->info.tcpi_snd_wscale|((uint32_t)s->info.tcpi_rcv_wscale<<16)};
    if(s->info.tcpi_options & TCPI_OPT_SACK)
        options[count++]=(struct tcp_repair_opt){TCPOPT_SACK_PERMITTED,0};
    if(s->info.tcpi_options & TCPI_OPT_TIMESTAMPS)
        options[count++]=(struct tcp_repair_opt){TCPOPT_TIMESTAMP,0};
    if(set(fd,TCP_REPAIR_OPTIONS,options,count*sizeof(options[0])))goto fail;
    if(s->info.tcpi_options & TCPI_OPT_TIMESTAMPS) {
        uint32_t stamp=s->timestamp+(uint32_t)((now_ns()-s->capture_mono_ns)/1000000);
        if(set(fd,TCP_TIMESTAMP,&stamp,sizeof(stamp)))goto fail;
    }
    if(inject(fd,TCP_RECV_QUEUE,s->recv_data,s->unread))goto fail;
    if(set(fd,TCP_REPAIR_WINDOW,&s->window,sizeof(s->window)))goto fail;
    if(set(fd,TCP_NODELAY,&one,sizeof(one)))goto fail;
    /* Inject only previously-transmitted bytes in repair mode. The kernel
     * marks these SKBs repaired/sent without putting them on the wire. */
    if(inject(fd,TCP_SEND_QUEUE,s->send_data,s->outq-s->unsent))goto fail;
    if(set(fd,TCP_NODELAY,&s->nodelay,sizeof(s->nodelay)) ||
       set(fd,TCP_CORK,&s->cork,sizeof(s->cork)) ||
       set(fd,TCP_USER_TIMEOUT,&s->user_timeout,sizeof(s->user_timeout)))goto fail;
    if(s->unsent) {
        /* New unsent bytes must not acquire TCPCB_REPAIRED. Briefly use
         * normal send under a ZERO send window and a physically fenced port,
         * then return to repair before restoring the original window. */
        struct tcp_repair_window blocked=s->window;blocked.snd_wnd=0;
        if(set(fd,TCP_REPAIR_WINDOW,&blocked,sizeof(blocked)))goto fail;
        int off_no_probe=-1;
        if(set(fd,TCP_REPAIR,&off_no_probe,sizeof(off_no_probe)))goto fail;
        int done=0;
        while(done<s->unsent) {
            ssize_t n=send(fd,s->send_data+s->outq-s->unsent+done,s->unsent-done,MSG_DONTWAIT|MSG_MORE|MSG_NOSIGNAL);
            if(n<=0){if(!n)errno=EIO;goto fail;}done+=n;
        }
        if(set(fd,TCP_REPAIR,&one,sizeof(one)))goto fail;
    }
    if(set(fd,TCP_REPAIR_WINDOW,&s->window,sizeof(s->window)))goto fail;
    /* Verify the actual kernel queues, options and windows before granting
     * the caller a still-fenced/still-repaired FD. No JSON self-assertion. */
    struct tcp_snapshot actual={0};
    if(ioctl(fd,SIOCOUTQ,&actual.outq)||ioctl(fd,SIOCOUTQNSD,&actual.unsent)||ioctl(fd,FIONREAD,&actual.unread))goto fail;
    if(peek_queue(fd,TCP_SEND_QUEUE,actual.outq,&actual.send_data))goto actual_fail;
    if(opt(fd,TCP_QUEUE_SEQ,&actual.send_end,sizeof(actual.send_end)))goto actual_fail;
    if(peek_queue(fd,TCP_RECV_QUEUE,actual.unread,&actual.recv_data))goto actual_fail;
    if(opt(fd,TCP_QUEUE_SEQ,&actual.recv_end,sizeof(actual.recv_end)))goto actual_fail;
    /* Peeking is not observationally pure: reset the window after bytes
     * have been verified, then perform only non-mutating getsockopt checks. */
    if(set(fd,TCP_REPAIR_WINDOW,&s->window,sizeof(s->window)))goto actual_fail;
    if(opt(fd,TCP_REPAIR_WINDOW,&actual.window,sizeof(actual.window)) || opt(fd,TCP_INFO,&actual.info,sizeof(actual.info)) ||
       opt(fd,TCP_MAXSEG,&actual.mss,sizeof(actual.mss)))goto actual_fail;
    if(actual.outq!=s->outq || actual.unsent!=s->unsent || actual.unread!=s->unread ||
       actual.send_end!=s->send_end || actual.recv_end!=s->recv_end ||
       memcmp(&actual.window,&s->window,sizeof(s->window)) ||
       actual.mss!=s->mss || actual.info.tcpi_options!=s->info.tcpi_options ||
       actual.info.tcpi_snd_wscale!=s->info.tcpi_snd_wscale || actual.info.tcpi_rcv_wscale!=s->info.tcpi_rcv_wscale ||
       (s->outq && memcmp(actual.send_data,s->send_data,s->outq)) ||
       (s->unread && memcmp(actual.recv_data,s->recv_data,s->unread))) {
        fprintf(stderr,"readback mismatch: outq=%d/%d unsent=%d/%d unread=%d/%d snd=%u/%u rcv=%u/%u mss=%d/%d opts=%u/%u scale=%u,%u/%u,%u window_cmp=%d send_cmp=%d recv_cmp=%d\n",actual.outq,s->outq,actual.unsent,s->unsent,actual.unread,s->unread,actual.send_end,s->send_end,actual.recv_end,s->recv_end,actual.mss,s->mss,actual.info.tcpi_options,s->info.tcpi_options,actual.info.tcpi_snd_wscale,actual.info.tcpi_rcv_wscale,s->info.tcpi_snd_wscale,s->info.tcpi_rcv_wscale,memcmp(&actual.window,&s->window,sizeof(s->window)),actual.outq==s->outq&&s->outq?memcmp(actual.send_data,s->send_data,s->outq):0,actual.unread==s->unread&&s->unread?memcmp(actual.recv_data,s->recv_data,s->unread):0);
        fprintf(stderr,"window actual wl1=%u snd=%u max=%u rcv=%u wup=%u expected wl1=%u snd=%u max=%u rcv=%u wup=%u\n",actual.window.snd_wl1,actual.window.snd_wnd,actual.window.max_window,actual.window.rcv_wnd,actual.window.rcv_wup,s->window.snd_wl1,s->window.snd_wnd,s->window.max_window,s->window.rcv_wnd,s->window.rcv_wup);
        errno=EPROTO;goto actual_fail;
    }
    tcp_snapshot_free(&actual);
    if(select_queue(fd,TCP_NO_QUEUE))goto fail;
    if(fcntl(fd,F_SETFL,s->status_flags))goto fail;
    if(duration_ns)*duration_ns=now_ns()-start;
    return fd;
actual_fail:
    saved=errno;tcp_snapshot_free(&actual);errno=saved;
fail:
    saved=errno;
    /* A failed partial import must close silently while still in repair. */
    set(fd,TCP_REPAIR,&one,sizeof(one));close(fd);errno=saved;return -1;
}
int tcp_snapshot_activate(int fd) {
    int mode=-1;
    if(select_queue(fd,TCP_NO_QUEUE))return -1;
    return set(fd,TCP_REPAIR,&mode,sizeof(mode));
}
#ifdef TCP_SNAPSHOT_SELFTEST
static void must(int okay,const char *what){if(!okay){perror(what);exit(1);}}
int main(void) {
    int l=socket(AF_INET,SOCK_STREAM,0),c=socket(AF_INET,SOCK_STREAM,0);
    must(l>=0 && c>=0,"socket");
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(179)};
    inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
    must(bind(l,(struct sockaddr *)&a,sizeof(a))==0,"bind isolated TCP179");
    must(listen(l,1)==0,"listen");
    must(connect(c,(struct sockaddr *)&a,sizeof(a))==0,"connect");
    int p=accept(l,NULL,NULL);must(p>=0,"accept");
    const char incoming[]="unread-input";const char outgoing[]="unsent-output";
    must(send(p,incoming,sizeof(incoming)-1,0)==sizeof(incoming)-1,"send input");
    int n=0;for(int i=0;i<1000;i++){must(ioctl(c,FIONREAD,&n)==0,"FIONREAD");if(n==(int)sizeof(incoming)-1)break;usleep(100);}
    must(n==(int)sizeof(incoming)-1,"input queued");
    int cork=1;must(setsockopt(c,SOL_TCP,TCP_CORK,&cork,sizeof(cork))==0,"cork");
    must(send(c,outgoing,sizeof(outgoing)-1,0)==sizeof(outgoing)-1,"queue unsent");
    struct tcp_snapshot s;
    must(tcp_snapshot_export(c,&s)==0,"export nonempty queues");
    must(s.unread==(int)sizeof(incoming)-1,"unread size");
    must(s.outq==(int)sizeof(outgoing)-1 && s.unsent==s.outq,"send queue size");
    must(!memcmp(s.recv_data,incoming,s.unread),"receive bytes");
    must(!memcmp(s.send_data,outgoing,s.outq),"send bytes");
    must(TCP_RECV_QUEUE==1 && TCP_SEND_QUEUE==2,"Linux queue enum values");
    printf("{\"test\":\"native_tcp_export\",\"recv_bytes\":%d,\"send_bytes\":%d,\"unsent\":%d,\"send_end\":%u,\"recv_end\":%u,\"window\":{\"snd_wnd\":%u,\"rcv_wnd\":%u},\"first_pause_ns\":%llu,",s.unread,s.outq,s.unsent,s.send_end,s.recv_end,s.window.snd_wnd,s.window.rcv_wnd,(unsigned long long)s.pause_ns);
    tcp_snapshot_free(&s);
    cork=0;must(setsockopt(c,SOL_TCP,TCP_CORK,&cork,sizeof(cork))==0,"uncork");
    char b[64];must(recv(p,b,sizeof(b),0)==(ssize_t)sizeof(outgoing)-1,"original socket still sends");
    must(recv(c,b,sizeof(b),0)==(ssize_t)sizeof(incoming)-1,"original socket still receives");
    uint64_t max=0,total=0;
    for(int i=0;i<1000;i++){
        must(tcp_snapshot_export(c,&s)==0,"repeated native export");
        if(s.pause_ns>max)
            max=s.pause_ns;
        total+=s.pause_ns;
        tcp_snapshot_free(&s);
    }
    printf("\"empty_queue_exports\":1000,\"mean_pause_ns\":%llu,\"max_pause_ns\":%llu,\"promotable_checkpoint\":false,\"nsr_acceptance\":false}\n",(unsigned long long)(total/1000),(unsigned long long)max);
    close(p);close(c);close(l);return 0;
}
#endif
