/**Copyright(c)2015-16DavidLamparter,forNetDEF,Inc.**ThisfileispartofQuagga**Qua
ggaisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGenera
lPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(atyourop
tion)any*laterversion.**Quaggaisdistributedinthehopethatitwillbeuseful,but*WITHO
UTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTIC
ULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceived
acopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,w
ritetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-130
1USA*/#include<zebra.h>#include"thread.h"#include"memory.h"#include"hash.h"#incl
ude"log.h"#include"qobj.h"#include"jhash.h"staticpthread_rwlock_tnodes_lock;stat
icstructhash*nodes=NULL;staticunsignedintqobj_key(void*data){structqobj_node*nod
e=data;return(unsignedint)node->nid;}staticintqobj_cmp(constvoid*a,constvoid*b){
conststructqobj_node*na=a,*nb=b;returnna->nid==nb->nid;}voidqobj_reg(structqobj_
node*node,structqobj_nodetype*type){node->type=type;pthread_rwlock_wrlock(&nodes
_lock);do{node->nid=(uint64_t)random();node->nid^=(uint64_t)random()<<32;}while(
!node->nid||hash_get(nodes,node,hash_alloc_intern)!=node);pthread_rwlock_unlock(
&nodes_lock);}voidqobj_unreg(structqobj_node*node){pthread_rwlock_wrlock(&nodes_
lock);hash_release(nodes,node);pthread_rwlock_unlock(&nodes_lock);}structqobj_no
de*qobj_get(uint64_tid){structqobj_nodedummy={.nid=id},*rv;pthread_rwlock_rdlock
(&nodes_lock);rv=hash_lookup(nodes,&dummy);pthread_rwlock_unlock(&nodes_lock);re
turnrv;}void*qobj_get_typed(uint64_tid,structqobj_nodetype*type){structqobj_node
dummy={.nid=id};structqobj_node*node;void*rv;pthread_rwlock_rdlock(&nodes_lock);
node=hash_lookup(nodes,&dummy);/*note:weexplicitlyholdthelockuntilafterwehaveche
ckedthe*type.*ifthecallerholdsalockthatforexamplepreventsthedeletionof*route-map
s,wecanstillraceagainstadeleteofsomethingthat*isn't*aroute-map.*/if(!node||node-
>type!=type)rv=NULL;elserv=(char*)node-node->type->node_member_offset;pthread_rw
lock_unlock(&nodes_lock);returnrv;}voidqobj_init(void){if(!nodes){pthread_rwlock
_init(&nodes_lock,NULL);nodes=hash_create_size(16,qobj_key,qobj_cmp,"QOBJHash");
}}voidqobj_finish(void){hash_clean(nodes,NULL);hash_free(nodes);nodes=NULL;pthre
ad_rwlock_destroy(&nodes_lock);}