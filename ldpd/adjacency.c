/*$OpenBSD$*//**Copyright(c)2013,2015RenatoWestphal<renato@openbsd.org>*Copyrigh
t(c)2009MicheleMarchetto<michele@openbsd.org>*Copyright(c)2005ClaudioJeker<claud
io@openbsd.org>*Copyright(c)2004,2005,2008EsbenNorby<norby@openbsd.org>**Permiss
iontouse,copy,modify,anddistributethissoftwareforany*purposewithorwithoutfeeishe
rebygranted,providedthattheabove*copyrightnoticeandthispermissionnoticeappearina
llcopies.**THESOFTWAREISPROVIDED"ASIS"ANDTHEAUTHORDISCLAIMSALLWARRANTIES*WITHREG
ARDTOTHISSOFTWAREINCLUDINGALLIMPLIEDWARRANTIESOF*MERCHANTABILITYANDFITNESS.INNOE
VENTSHALLTHEAUTHORBELIABLEFOR*ANYSPECIAL,DIRECT,INDIRECT,ORCONSEQUENTIALDAMAGESO
RANYDAMAGES*WHATSOEVERRESULTINGFROMLOSSOFUSE,DATAORPROFITS,WHETHERINAN*ACTIONOFC
ONTRACT,NEGLIGENCEOROTHERTORTIOUSACTION,ARISINGOUTOF*ORINCONNECTIONWITHTHEUSEORP
ERFORMANCEOFTHISSOFTWARE.*/#include<zebra.h>#include"ldpd.h"#include"ldpe.h"#inc
lude"log.h"static__inlineintadj_compare(conststructadj*,conststructadj*);statici
ntadj_itimer(structthread*);static__inlineinttnbr_compare(conststructtnbr*,const
structtnbr*);staticvoidtnbr_del(structldpd_conf*,structtnbr*);staticvoidtnbr_sta
rt(structtnbr*);staticvoidtnbr_stop(structtnbr*);staticinttnbr_hello_timer(struc
tthread*);staticvoidtnbr_start_hello_timer(structtnbr*);staticvoidtnbr_stop_hell
o_timer(structtnbr*);RB_GENERATE(global_adj_head,adj,global_entry,adj_compare)RB
_GENERATE(nbr_adj_head,adj,nbr_entry,adj_compare)RB_GENERATE(ia_adj_head,adj,ia_
entry,adj_compare)RB_GENERATE(tnbr_head,tnbr,entry,tnbr_compare)static__inlinein
tadj_compare(conststructadj*a,conststructadj*b){if(adj_get_af(a)<adj_get_af(b))r
eturn(-1);if(adj_get_af(a)>adj_get_af(b))return(1);if(ntohl(a->lsr_id.s_addr)<nt
ohl(b->lsr_id.s_addr))return(-1);if(ntohl(a->lsr_id.s_addr)>ntohl(b->lsr_id.s_ad
dr))return(1);if(a->source.type<b->source.type)return(-1);if(a->source.type>b->s
ource.type)return(1);switch(a->source.type){caseHELLO_LINK:if(if_cmp_name_func((
char*)a->source.link.ia->iface->name,(char*)b->source.link.ia->iface->name)<0)re
turn(-1);if(if_cmp_name_func((char*)a->source.link.ia->iface->name,(char*)b->sou
rce.link.ia->iface->name)>0)return(1);return(ldp_addrcmp(a->source.link.ia->af,&
a->source.link.src_addr,&b->source.link.src_addr));caseHELLO_TARGETED:return(ldp
_addrcmp(a->source.target->af,&a->source.target->addr,&b->source.target->addr));
default:fatalx("adj_compare:unknownhellotype");}return(0);}structadj*adj_new(str
uctin_addrlsr_id,structhello_source*source,unionldpd_addr*addr){structadj*adj;lo
g_debug("%s:lsr-id%s,%s",__func__,inet_ntoa(lsr_id),log_hello_src(source));if((a
dj=calloc(1,sizeof(*adj)))==NULL)fatal(__func__);adj->lsr_id=lsr_id;adj->nbr=NUL
L;adj->source=*source;adj->trans_addr=*addr;RB_INSERT(global_adj_head,&global.ad
j_tree,adj);switch(source->type){caseHELLO_LINK:RB_INSERT(ia_adj_head,&source->l
ink.ia->adj_tree,adj);break;caseHELLO_TARGETED:source->target->adj=adj;break;}re
turn(adj);}voidadj_del(structadj*adj,uint32_tnotif_status){structnbr*nbr=adj->nb
r;log_debug("%s:lsr-id%s,%s(%s)",__func__,inet_ntoa(adj->lsr_id),log_hello_src(&
adj->source),af_name(adj_get_af(adj)));adj_stop_itimer(adj);RB_REMOVE(global_adj
_head,&global.adj_tree,adj);if(nbr)RB_REMOVE(nbr_adj_head,&nbr->adj_tree,adj);sw
itch(adj->source.type){caseHELLO_LINK:RB_REMOVE(ia_adj_head,&adj->source.link.ia
->adj_tree,adj);break;caseHELLO_TARGETED:adj->source.target->adj=NULL;break;}fre
e(adj);/**Iftheneighborstillexistsbutnoneofitsremaining*adjacencies(ifany)arefro
mthepreferredaddress-family,*thendeleteit.*/if(nbr&&nbr_adj_count(nbr,nbr->af)==
0){session_shutdown(nbr,notif_status,0,0);nbr_del(nbr);}}structadj*adj_find(stru
ctin_addrlsr_id,structhello_source*source){structadjadj;adj.lsr_id=lsr_id;adj.so
urce=*source;return(RB_FIND(global_adj_head,&global.adj_tree,&adj));}intadj_get_
af(conststructadj*adj){switch(adj->source.type){caseHELLO_LINK:return(adj->sourc
e.link.ia->af);caseHELLO_TARGETED:return(adj->source.target->af);default:fatalx(
"adj_get_af:unknownhellotype");}}/*adjacencytimers*//*ARGSUSED*/staticintadj_iti
mer(structthread*thread){structadj*adj=THREAD_ARG(thread);adj->inactivity_timer=
NULL;log_debug("%s:lsr-id%s",__func__,inet_ntoa(adj->lsr_id));if(adj->source.typ
e==HELLO_TARGETED){if(!(adj->source.target->flags&F_TNBR_CONFIGURED)&&adj->sourc
e.target->pw_count==0){/*removedynamictargetedneighbor*/tnbr_del(leconf,adj->sou
rce.target);return(0);}}adj_del(adj,S_HOLDTIME_EXP);return(0);}voidadj_start_iti
mer(structadj*adj){THREAD_TIMER_OFF(adj->inactivity_timer);adj->inactivity_timer
=NULL;thread_add_timer(master,adj_itimer,adj,adj->holdtime,&adj->inactivity_time
r);}voidadj_stop_itimer(structadj*adj){THREAD_TIMER_OFF(adj->inactivity_timer);}
/*targetedneighbors*/static__inlineinttnbr_compare(conststructtnbr*a,conststruct
tnbr*b){if(a->af<b->af)return(-1);if(a->af>b->af)return(1);return(ldp_addrcmp(a-
>af,&a->addr,&b->addr));}structtnbr*tnbr_new(intaf,unionldpd_addr*addr){structtn
br*tnbr;if((tnbr=calloc(1,sizeof(*tnbr)))==NULL)fatal(__func__);tnbr->af=af;tnbr
->addr=*addr;tnbr->state=TNBR_STA_DOWN;return(tnbr);}staticvoidtnbr_del(structld
pd_conf*xconf,structtnbr*tnbr){tnbr_stop(tnbr);RB_REMOVE(tnbr_head,&xconf->tnbr_
tree,tnbr);free(tnbr);}structtnbr*tnbr_find(structldpd_conf*xconf,intaf,unionldp
d_addr*addr){structtnbrtnbr;tnbr.af=af;tnbr.addr=*addr;return(RB_FIND(tnbr_head,
&xconf->tnbr_tree,&tnbr));}structtnbr*tnbr_check(structldpd_conf*xconf,structtnb
r*tnbr){if(!(tnbr->flags&(F_TNBR_CONFIGURED|F_TNBR_DYNAMIC))&&tnbr->pw_count==0)
{tnbr_del(xconf,tnbr);return(NULL);}return(tnbr);}staticvoidtnbr_start(structtnb
r*tnbr){send_hello(HELLO_TARGETED,NULL,tnbr);tnbr_start_hello_timer(tnbr);tnbr->
state=TNBR_STA_ACTIVE;}staticvoidtnbr_stop(structtnbr*tnbr){tnbr_stop_hello_time
r(tnbr);if(tnbr->adj)adj_del(tnbr->adj,S_SHUTDOWN);tnbr->state=TNBR_STA_DOWN;}vo
idtnbr_update(structtnbr*tnbr){intsocket_ok,rtr_id_ok;if((ldp_af_global_get(&glo
bal,tnbr->af))->ldp_edisc_socket!=-1)socket_ok=1;elsesocket_ok=0;if(ldp_rtr_id_g
et(leconf)!=INADDR_ANY)rtr_id_ok=1;elsertr_id_ok=0;if(tnbr->state==TNBR_STA_DOWN
){if(!socket_ok||!rtr_id_ok)return;tnbr_start(tnbr);}elseif(tnbr->state==TNBR_ST
A_ACTIVE){if(socket_ok&&rtr_id_ok)return;tnbr_stop(tnbr);}}voidtnbr_update_all(i
ntaf){structtnbr*tnbr;/*updatetargetedneighbors*/RB_FOREACH(tnbr,tnbr_head,&leco
nf->tnbr_tree)if(tnbr->af==af||af==AF_UNSPEC)tnbr_update(tnbr);}uint16_ttnbr_get
_hello_holdtime(structtnbr*tnbr){if((ldp_af_conf_get(leconf,tnbr->af))->thello_h
oldtime!=0)return((ldp_af_conf_get(leconf,tnbr->af))->thello_holdtime);return(le
conf->thello_holdtime);}uint16_ttnbr_get_hello_interval(structtnbr*tnbr){if((ldp
_af_conf_get(leconf,tnbr->af))->thello_interval!=0)return((ldp_af_conf_get(lecon
f,tnbr->af))->thello_interval);return(leconf->thello_interval);}/*targetneighbor
stimers*//*ARGSUSED*/staticinttnbr_hello_timer(structthread*thread){structtnbr*t
nbr=THREAD_ARG(thread);tnbr->hello_timer=NULL;send_hello(HELLO_TARGETED,NULL,tnb
r);tnbr_start_hello_timer(tnbr);return(0);}staticvoidtnbr_start_hello_timer(stru
cttnbr*tnbr){THREAD_TIMER_OFF(tnbr->hello_timer);tnbr->hello_timer=NULL;thread_a
dd_timer(master,tnbr_hello_timer,tnbr,tnbr_get_hello_interval(tnbr),&tnbr->hello
_timer);}staticvoidtnbr_stop_hello_timer(structtnbr*tnbr){THREAD_TIMER_OFF(tnbr-
>hello_timer);}structctl_adj*adj_to_ctl(structadj*adj){staticstructctl_adjactl;a
ctl.af=adj_get_af(adj);actl.id=adj->lsr_id;actl.type=adj->source.type;switch(adj
->source.type){caseHELLO_LINK:memcpy(actl.ifname,adj->source.link.ia->iface->nam
e,sizeof(actl.ifname));actl.src_addr=adj->source.link.src_addr;break;caseHELLO_T
ARGETED:actl.src_addr=adj->source.target->addr;break;}actl.holdtime=adj->holdtim
e;actl.holdtime_remaining=thread_timer_remain_second(adj->inactivity_timer);actl
.trans_addr=adj->trans_addr;actl.ds_tlv=adj->ds_tlv;return(&actl);}