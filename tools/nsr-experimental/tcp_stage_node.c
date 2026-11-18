/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Kernel TCP import integration fixture. Arbitrary test payload, NOT BGP.
 * All peer sockets are created by this process inside an isolated netns.
 * No FD is shared with the controller; checkpoint is preloaded before fault.
 */
#define _GNU_SOURCE
#include "tcp_snapshot.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sys/un.h>
static void must(int ok,const char *msg){if(!ok){perror(msg);exit(1);}}
static uint64_t hashbytes(uint64_t h,const void *data,size_t size){const unsigned char *b=data;while(size--){h^=*b++;h*=1099511628211ULL;}return h;}
struct image {uint64_t magic;uint32_t version,abi;struct tcp_snapshot s;uint64_t checksum;};
static struct tcp_snapshot load_stream(FILE *f){
    struct image d;must(f!=NULL,"load image");
    must(fread(&d,1,sizeof(d),f)==sizeof(d),"short image");
    must(d.magic==0x434e4c5443503031ULL && d.version==1 && d.abi==sizeof(d),"image version/ABI");
    must(!d.s.send_data && !d.s.recv_data && d.s.outq>=0 && d.s.outq<=1024*1024 && d.s.unread>=0 && d.s.unread<=1024*1024 && d.s.unsent>=0 && d.s.unsent<=d.s.outq,"image lengths");
    uint64_t expected=d.checksum;d.checksum=0;
    uint64_t h=hashbytes(1469598103934665603ULL,&d,sizeof(d));
    struct tcp_snapshot s=d.s;
    s.send_data=malloc(s.outq?s.outq:1);s.recv_data=malloc(s.unread?s.unread:1);must(s.send_data && s.recv_data,"image malloc");
    must(fread(s.send_data,1,s.outq,f)==(size_t)s.outq && fread(s.recv_data,1,s.unread,f)==(size_t)s.unread,"short image queues");
    must(fgetc(f)==EOF,"unexpected image trailer");fclose(f);
    h=hashbytes(h,s.send_data,s.outq);h=hashbytes(h,s.recv_data,s.unread);must(h==expected,"image checksum");return s;
}
static struct tcp_snapshot load_image(const char *path){return load_stream(fopen(path,"rb"));}
int main(int argc,char **argv){
    if(argc==3&&!strcmp(argv[1],"--inspect")){
        struct tcp_snapshot s=load_image(argv[2]);char local[INET_ADDRSTRLEN],remote[INET_ADDRSTRLEN];inet_ntop(AF_INET,&s.local.sin_addr,local,sizeof(local));inet_ntop(AF_INET,&s.remote.sin_addr,remote,sizeof(remote));
        printf("{\"local_ip\":\"%s\",\"local_port\":%u,\"remote_ip\":\"%s\",\"remote_port\":%u,\"send_end\":%u,\"recv_end\":%u,\"outq\":%d,\"unsent\":%d,\"unread\":%d,\"capture_mono_ns\":%llu,\"mss\":%d,\"tcp_state\":%u,\"options\":%u,\"sacked\":%u,\"send_hex\":\"",local,ntohs(s.local.sin_port),remote,ntohs(s.remote.sin_port),s.send_end,s.recv_end,s.outq,s.unsent,s.unread,(unsigned long long)s.capture_mono_ns,s.mss,s.info.tcpi_state,s.info.tcpi_options,s.info.tcpi_sacked);
        for(int i=0;i<s.outq;i++)printf("%02x",s.send_data[i]);
        printf("\",\"recv_hex\":\"");
        for(int i=0;i<s.unread;i++)printf("%02x",s.recv_data[i]);
        puts("\"}");tcp_snapshot_free(&s);return 0;
    }
    must(argc==4||argc==5,"image, control socket, request JSON, optional cross-host age upper ns");
    struct tcp_snapshot snapshot=load_image(argv[1]);
    if(argc==5){
        /* The image remains byte-identical and checksummed on disk. Its
         * source clock is not a deadline on this host. The trusted local
         * agent supplies a conservatively bounded elapsed duration. */
        char *end=NULL;errno=0;unsigned long long elapsed=strtoull(argv[4],&end,10);
        must(!errno&&end&&*end==0&&argv[4][0]>='0'&&argv[4][0]<='9'&&elapsed<=500000000ULL,"cross-host elapsed bound");
        struct timespec now;must(clock_gettime(CLOCK_MONOTONIC,&now)==0,"local monotonic");
        uint64_t local=(uint64_t)now.tv_sec*1000000000+now.tv_nsec;must(local>=elapsed,"local clock bound");
        snapshot.capture_mono_ns=local-elapsed;
    }
    uint64_t duration=0;int fd=tcp_snapshot_import_fenced(&snapshot,&duration);must(fd>=0,"import fenced TCP");tcp_snapshot_free(&snapshot);
    FILE *file=fopen(argv[3],"rb");must(file!=NULL,"request file");char request[8192];size_t n=fread(request,1,sizeof(request),file);must(n>0&&n<sizeof(request)&&fgetc(file)==EOF,"request bound");fclose(file);
    struct sockaddr_un address={.sun_family=AF_UNIX};must(strlen(argv[2])<sizeof(address.sun_path),"socket path bound");strcpy(address.sun_path,argv[2]);int control=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);must(control>=0&&connect(control,(struct sockaddr *)&address,sizeof(address))==0,"standby control connect");
    struct iovec iov={.iov_base=request,.iov_len=n};char ancillary[CMSG_SPACE(sizeof(int))];struct msghdr message={.msg_iov=&iov,.msg_iovlen=1,.msg_control=ancillary,.msg_controllen=sizeof(ancillary)};struct cmsghdr *cm=CMSG_FIRSTHDR(&message);cm->cmsg_level=SOL_SOCKET;cm->cmsg_type=SCM_RIGHTS;cm->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(cm),&fd,sizeof(fd));must(sendmsg(control,&message,MSG_NOSIGNAL)==(ssize_t)n,"SCM_RIGHTS send");
    char reply[160000];ssize_t got=recv(control,reply,sizeof(reply)-1,0);must(got>0,"stage reply");reply[got]=0;puts(reply);fflush(stdout);close(control);close(fd);return 0;
}
