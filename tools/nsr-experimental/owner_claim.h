/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CNLAB_OWNER_CLAIM_H
#define CNLAB_OWNER_CLAIM_H
/* Same-host authorization via registered process credentials + pidfd proof.
 * The physical egress gate must stay closed until every component claimed. */
static bool owner_action(const char *component,int64_t epoch,struct zebra_privs_t *privs,const char *action){
    const char *path=getenv("CNLAB_NSR_ARBITER_SOCK");struct sockaddr_un address={.sun_family=AF_UNIX};
    if(epoch<1||!path||strncmp(path,"/run/frr-nsr/",13)||strlen(path)>=sizeof(address.sun_path))return false;
    strlcpy(address.sun_path,path,sizeof(address.sun_path));int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);if(fd<0)return false;
    struct timeval timeout={.tv_sec=0,.tv_usec=200000};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    int rc=-1;frr_with_privs(privs){rc=connect(fd,(struct sockaddr *)&address,sizeof(address));}
    if(rc){close(fd);return false;}
    char request[128],reply[1024];int size=snprintf(request,sizeof(request),"{\"action\":\"%s\",\"component\":\"%s\",\"epoch\":%lld}",action,component,(long long)epoch);
    if(send(fd,request,size,MSG_NOSIGNAL)!=size){close(fd);return false;}
    ssize_t n=recv(fd,reply,sizeof(reply)-1,0);close(fd);if(n<=0)return false;reply[n]=0;
    json_object *j=json_tokener_parse(reply),*granted,*value;bool allowed=j&&json_object_object_get_ex(j,"granted",&granted)&&json_object_get_boolean(granted)&&json_object_object_get_ex(j,"epoch",&value)&&json_object_get_int64(value)==epoch;
    if(j)json_object_put(j);
    return allowed;
}
static bool owner_claim(const char *component,int64_t epoch,struct zebra_privs_t *privs){return owner_action(component,epoch,privs,"claim");}
static bool owner_ready(const char *component,int64_t epoch,struct zebra_privs_t *privs){return owner_action(component,epoch,privs,"ready");}
#endif
