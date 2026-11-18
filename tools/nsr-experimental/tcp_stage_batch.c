/* SPDX-License-Identifier: GPL-2.0-or-later */
/* One device-local worker imports all independent TCP sockets. No source FD. */
#define main cnlab_stage_single_main
#include "tcp_stage_node.c"
#undef main
#include <json-c/json.h>
#include <stdbool.h>
static int digit(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
static json_object *item(json_object *j,const char *name){json_object *v=NULL;must(json_object_object_get_ex(j,name,&v),name);return v;}
static json_object *rpc(const char *path,json_object *request,int fd){
 struct sockaddr_un address={.sun_family=AF_UNIX};must(strlen(path)<sizeof(address.sun_path),"local path bound");strcpy(address.sun_path,path);
 int control=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);must(control>=0,"control socket");struct timeval deadline={.tv_usec=200000};setsockopt(control,SOL_SOCKET,SO_RCVTIMEO,&deadline,sizeof(deadline));must(connect(control,(struct sockaddr *)&address,sizeof(address))==0,"control connect");
 const char *text=json_object_to_json_string_ext(request,JSON_C_TO_STRING_PLAIN);struct iovec io={.iov_base=(void *)text,.iov_len=strlen(text)};char ancillary[CMSG_SPACE(sizeof(int))];struct msghdr msg={.msg_iov=&io,.msg_iovlen=1};
 if(fd>=0){msg.msg_control=ancillary;msg.msg_controllen=sizeof(ancillary);struct cmsghdr *cm=CMSG_FIRSTHDR(&msg);cm->cmsg_level=SOL_SOCKET;cm->cmsg_type=SCM_RIGHTS;cm->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(cm),&fd,sizeof(fd));}
 must(sendmsg(control,&msg,MSG_NOSIGNAL)==(ssize_t)strlen(text),"local stage request");
 char reply[160000];struct iovec result_io={.iov_base=reply,.iov_len=sizeof(reply)-1};
 struct msghdr result_msg={.msg_iov=&result_io,.msg_iovlen=1};ssize_t n;
 do {n=recvmsg(control,&result_msg,0);} while(n<0&&errno==EINTR);
 if(n<=0||n>=(ssize_t)sizeof(reply)-1||(result_msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC))){
  int saved=n<0?errno:0;json_object *peer=NULL;json_object_object_get_ex(request,"peer",&peer);
  fprintf(stderr,"local stage reply failed: peer=%s bytes=%zd flags=%d errno=%d (%s) reason=%s\n",
          peer?json_object_get_string(peer):"unknown",n,result_msg.msg_flags,saved,strerror(saved),
          n==0?"peer_closed_without_reply":n<0?"receive_error":"truncated_reply");exit(1);
 }
 reply[n]=0;close(control);json_object *result=json_tokener_parse(reply);must(result!=NULL,"stage JSON");return result;
}
int main(int argc,char **argv){
 must(argc==3,"batch JSON file, local bgpd socket required");json_object *bundle=json_object_from_file(argv[1]);must(bundle!=NULL,"batch JSON");json_object *sessions=item(bundle,"sessions"),*rows=json_object_new_array();int count=json_object_array_length(sessions);must(count>0&&count<=256,"session count");
 for(int i=0;i<count;i++){
  json_object *row=json_object_array_get_idx(sessions,i),*barrier=item(row,"barrier");const char *hex=json_object_get_string(item(row,"image_hex"));size_t size=strlen(hex);must(size>0&&size%2==0&&size<=4*1024*1024,"image hex bound");
  unsigned char *bytes=malloc(size/2);must(bytes!=NULL,"private image memory");
  for(size_t k=0;k<size;k+=2){int a=digit(hex[k]),b=digit(hex[k+1]);must(a>=0&&b>=0,"image hex");bytes[k/2]=(a<<4)|b;}FILE *stream=fmemopen(bytes,size/2,"rb");must(stream!=NULL,"private image stream");
  struct tcp_snapshot snapshot=load_stream(stream);free(bytes);uint64_t capture=json_object_get_int64(item(barrier,"capture_mono_ns"));struct timespec now;must(clock_gettime(CLOCK_MONOTONIC,&now)==0,"clock");uint64_t local=(uint64_t)now.tv_sec*1000000000+now.tv_nsec;must(capture<=local&&local-capture<500000000ULL,"stale batch image");snapshot.capture_mono_ns=capture;
  uint64_t duration=0;int fd=tcp_snapshot_import_fenced(&snapshot,&duration);tcp_snapshot_free(&snapshot);must(fd>=0,"independent TCP import");
  json_object *reply=rpc(argv[2],barrier,fd);close(fd);must(json_object_get_boolean(item(reply,"transport_staged")),"native stage refused");json_object_object_add(reply,"peer",json_object_get(item(barrier,"peer")));json_object_array_add(rows,reply);
 }
 json_object *reply=json_object_new_object();json_object_object_add(reply,"transport_staged",json_object_new_boolean(true));json_object_object_add(reply,"count",json_object_new_int(count));json_object_object_add(reply,"peers",rows);puts(json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN));json_object_put(reply);json_object_put(bundle);return 0;
}
