/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Holds genuine kernel TCP packets in NFQUEUE until a replica checkpoint
 * covers both their sequence range and ACK. Never builds a TCP packet.
 * Must run inside the isolated primary namespace and die with that instance. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#define LIMIT 4096
struct packet {uint32_t id,end,ack;uint8_t flags;};
static struct packet pending[LIMIT];static size_t count;
static uint32_t input_ids[LIMIT];static size_t input_count;static bool input_frozen;
static uint64_t held,released;static bool poisoned,committed;static uint32_t send_end,recv_end;
static struct in_addr local,remote;static uint16_t local_port,remote_port;static struct nfq_q_handle *queue;
static int beforeeq(uint32_t a,uint32_t b){return (int32_t)(a-b)<=0;}
static bool covered(struct packet *p){return committed&&!(p->flags&(TH_SYN|TH_FIN|TH_RST))&&beforeeq(p->end,send_end)&&(!(p->flags&TH_ACK)||beforeeq(p->ack,recv_end));}
static void flush(void){
    if(poisoned)return;
    size_t keep=0;
    for(size_t i=0;i<count;i++){
        if(covered(&pending[i])){if(nfq_set_verdict(queue,pending[i].id,NF_ACCEPT,0,NULL)<0){poisoned=true;pending[keep++]=pending[i];}else released++;}
        else pending[keep++]=pending[i];
    }
    count=keep;
}
static int receive_packet(struct nfq_q_handle *q,struct nfgenmsg *msg,struct nfq_data *data,void *arg){
    (void)msg;(void)arg;struct nfqnl_msg_packet_hdr *header=nfq_get_msg_packet_hdr(data);if(!header){poisoned=true;return 0;}uint32_t id=ntohl(header->packet_id);
    unsigned char *bytes=NULL;int length=nfq_get_payload(data,&bytes);
    if(length<(int)sizeof(struct iphdr)){poisoned=true;return nfq_set_verdict(q,id,NF_DROP,0,NULL);}
    struct iphdr *ip=(struct iphdr *)bytes;size_t ih=ip->ihl*4,total=ntohs(ip->tot_len);
    if(ip->version!=4||ip->protocol!=IPPROTO_TCP||ih<20||total>(size_t)length||total<ih+20||(ntohs(ip->frag_off)&0x3fff)){poisoned=true;return nfq_set_verdict(q,id,NF_DROP,0,NULL);}
    struct tcphdr *tcp=(struct tcphdr *)(bytes+ih);size_t th=tcp->doff*4;
    if(th<20||total<ih+th){poisoned=true;return nfq_set_verdict(q,id,NF_DROP,0,NULL);}
    if(ip->saddr==remote.s_addr&&ip->daddr==local.s_addr&&tcp->source==remote_port&&tcp->dest==local_port){
        if(!input_frozen)return nfq_set_verdict(q,id,NF_ACCEPT,0,NULL);
        if(input_count==LIMIT){poisoned=true;return nfq_set_verdict(q,id,NF_DROP,0,NULL);}
        input_ids[input_count++]=id;return 0;
    }
    if(ip->saddr!=local.s_addr||ip->daddr!=remote.s_addr||tcp->source!=local_port||tcp->dest!=remote_port){poisoned=true;return nfq_set_verdict(q,id,NF_DROP,0,NULL);}
    struct packet p={.id=id,.end=ntohl(tcp->seq)+(uint32_t)(total-ih-th),.ack=ntohl(tcp->ack_seq),.flags=bytes[ih+13]};
    if(p.flags&(TH_SYN|TH_FIN|TH_RST))poisoned=true;
    if(covered(&p)&&!poisoned){released++;return nfq_set_verdict(q,id,NF_ACCEPT,0,NULL);}
    held++;if(count==LIMIT){poisoned=true;return nfq_set_verdict(q,id,NF_DROP,0,NULL);}pending[count++]=p;return 0;
}
static bool number(json_object *j,const char *key,int64_t *v){json_object *o;if(!j||!json_object_object_get_ex(j,key,&o)||json_object_get_type(o)!=json_type_int)return false;*v=json_object_get_int64(o);return true;}
static void control(int listener){
    int fd=accept4(listener,NULL,NULL,SOCK_CLOEXEC);if(fd<0)return;struct timeval timeout={.tv_sec=0,.tv_usec=200000};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));char bytes[8192];ssize_t n=recv(fd,bytes,sizeof(bytes)-1,0);json_object *j=NULL,*reply=json_object_new_object(),*action=NULL;
    if(n>0){bytes[n]=0;j=json_tokener_parse(bytes);}const char *error=NULL;bool success=false;
    if(j&&json_object_object_get_ex(j,"action",&action)&&!strcmp(json_object_get_string(action),"commit")){
        int64_t tx,rx;
        if(poisoned)error="gate_poisoned";
        else if(!number(j,"send_end",&tx)||!number(j,"recv_end",&rx)||tx<0||tx>UINT32_MAX||rx<0||rx>UINT32_MAX)error="invalid_checkpoint_sequences";
        else if(committed&&(!beforeeq(send_end,(uint32_t)tx)||!beforeeq(recv_end,(uint32_t)rx)))error="checkpoint_rewind";
        else{send_end=tx;recv_end=rx;committed=true;flush();success=!poisoned;}
    }else if(j&&action&&!strcmp(json_object_get_string(action),"freeze_input")){input_frozen=true;success=!poisoned;}
    else if(j&&action&&!strcmp(json_object_get_string(action),"resume_input")){
        for(size_t i=0;i<input_count;i++)if(nfq_set_verdict(queue,input_ids[i],NF_ACCEPT,0,NULL)<0)poisoned=true;
        input_count=0;input_frozen=false;success=!poisoned;
    }else if(j&&action&&!strcmp(json_object_get_string(action),"query"))success=true;
    else error="unknown_action";
    json_object_object_add(reply,"ok",json_object_new_boolean(success));json_object_object_add(reply,"poisoned",json_object_new_boolean(poisoned));json_object_object_add(reply,"held",json_object_new_int64(held));json_object_object_add(reply,"released",json_object_new_int64(released));json_object_object_add(reply,"input_pending",json_object_new_int64(input_count));json_object_object_add(reply,"input_frozen",json_object_new_boolean(input_frozen));json_object_object_add(reply,"pending",json_object_new_int64(count));json_object_object_add(reply,"send_end",json_object_new_int64(send_end));json_object_object_add(reply,"recv_end",json_object_new_int64(recv_end));if(error)json_object_object_add(reply,"error",json_object_new_string(error));
    const char *text=json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN);send(fd,text,strlen(text),MSG_NOSIGNAL);close(fd);json_object_put(reply);if(j)json_object_put(j);
}
int main(int argc,char **argv){
    if(argc!=6){fprintf(stderr,"usage: gate control.sock local_ip local_port remote_ip remote_port\n");return 2;}
    if(strncmp(argv[1],"/run/frr-nsr/",13)||strlen(argv[1])>=108||inet_pton(AF_INET,argv[2],&local)!=1||inet_pton(AF_INET,argv[4],&remote)!=1)return 2;
    long lp=strtol(argv[3],NULL,10),rp=strtol(argv[5],NULL,10);if(lp<=0||lp>65535||rp<=0||rp>65535)return 2;local_port=htons(lp);remote_port=htons(rp);
    struct nfq_handle *handle=nfq_open();if(!handle){perror("nfq_open");return 1;}
    if(nfq_bind_pf(handle,AF_INET)<0){perror("nfq_bind_pf");return 1;}
    queue=nfq_create_queue(handle,141,receive_packet,NULL);if(!queue){perror("nfq_create_queue");return 1;}
    if(nfq_set_mode(queue,NFQNL_COPY_PACKET,65535)<0||nfq_set_queue_maxlen(queue,LIMIT)<0){perror("nfq_config");return 1;}
    int listener=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,argv[1]);if(listener<0||bind(listener,(struct sockaddr *)&address,sizeof(address))||listen(listener,8)){perror("gate control");return 1;}chmod(argv[1],0600);
    int netlink=nfq_fd(handle);char buffer[131072];printf("READY\n");fflush(stdout);
    struct pollfd fds[2]={{.fd=netlink,.events=POLLIN},{.fd=listener,.events=POLLIN}};
    for(;;){if(poll(fds,2,1000)<0){if(errno==EINTR)continue;perror("poll");return 1;}
        if(fds[0].revents&POLLIN){ssize_t n=recv(netlink,buffer,sizeof(buffer),MSG_DONTWAIT);if(n<0){if(errno==ENOBUFS)poisoned=true;else if(errno!=EAGAIN){perror("netlink recv");return 1;}}else if(nfq_handle_packet(handle,buffer,n)<0)poisoned=true;}
        if(fds[1].revents&POLLIN)control(listener);
    }
}
