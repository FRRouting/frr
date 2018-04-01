/*$OpenBSD$*//**Copyright(c)2013,2016RenatoWestphal<renato@openbsd.org>*Copyrigh
t(c)2005ClaudioJeker<claudio@openbsd.org>*Copyright(c)2004,2008EsbenNorby<norby@
openbsd.org>*Copyright(c)2003,2004HenningBrauer<henning@openbsd.org>**Permission
touse,copy,modify,anddistributethissoftwareforany*purposewithorwithoutfeeishereb
ygranted,providedthattheabove*copyrightnoticeandthispermissionnoticeappearinallc
opies.**THESOFTWAREISPROVIDED"ASIS"ANDTHEAUTHORDISCLAIMSALLWARRANTIES*WITHREGARD
TOTHISSOFTWAREINCLUDINGALLIMPLIEDWARRANTIESOF*MERCHANTABILITYANDFITNESS.INNOEVEN
TSHALLTHEAUTHORBELIABLEFOR*ANYSPECIAL,DIRECT,INDIRECT,ORCONSEQUENTIALDAMAGESORAN
YDAMAGES*WHATSOEVERRESULTINGFROMLOSSOFUSE,DATAORPROFITS,WHETHERINAN*ACTIONOFCONT
RACT,NEGLIGENCEOROTHERTORTIOUSACTION,ARISINGOUTOF*ORINCONNECTIONWITHTHEUSEORPERF
ORMANCEOFTHISSOFTWARE.*/#include<zebra.h>#include"ldpd.h"#include"ldpe.h"#includ
e"lde.h"#include"control.h"#include"log.h"#include"ldp_debug.h"#include<lib/log.
h>#include"memory.h"#include"privs.h"#include"sigevent.h"staticvoidldpe_shutdown
(void);staticintldpe_dispatch_main(structthread*);staticintldpe_dispatch_lde(str
uctthread*);#ifdef__OpenBSD__staticintldpe_dispatch_pfkey(structthread*);#endifs
taticvoidldpe_setup_sockets(int,int,int,int);staticvoidldpe_close_sockets(int);s
taticvoidldpe_iface_af_ctl(structctl_conn*,int,unsignedint);structldpd_conf*leco
nf;#ifdef__OpenBSD__structldpd_sysdepsysdep;#endifstaticstructimsgev*iev_main,*i
ev_main_sync;staticstructimsgev*iev_lde;#ifdef__OpenBSD__staticstructthread*pfke
y_ev;#endif/*Masterofthreads.*/structthread_master*master;/*ldpeprivileges*/stat
iczebra_capabilities_t_caps_p[]={ZCAP_BIND,ZCAP_NET_ADMIN};structzebra_privs_tld
pe_privs={#ifdefined(VTY_GROUP).vty_group=VTY_GROUP,#endif.caps_p=_caps_p,.cap_n
um_p=array_size(_caps_p),.cap_num_i=0};/*SIGINT/SIGTERMhandler.*/staticvoidsigin
t(void){ldpe_shutdown();}staticstructquagga_signal_tldpe_signals[]={{.signal=SIG
HUP,/*ignore*/},{.signal=SIGINT,.handler=&sigint,},{.signal=SIGTERM,.handler=&si
gint,},};/*labeldistributionprotocolengine*/voidldpe(void){structthreadthread;#i
fdefHAVE_SETPROCTITLEsetproctitle("ldpengine");#endifldpd_process=PROC_LDP_ENGIN
E;log_procname=log_procnames[ldpd_process];master=thread_master_create(NULL);/*s
etupsignalhandler*/signal_init(master,array_size(ldpe_signals),ldpe_signals);/*s
etuppipesandeventhandlerstotheparentprocess*/if((iev_main=calloc(1,sizeof(struct
imsgev)))==NULL)fatal(NULL);imsg_init(&iev_main->ibuf,LDPD_FD_ASYNC);iev_main->h
andler_read=ldpe_dispatch_main;iev_main->ev_read=NULL;thread_add_read(master,iev
_main->handler_read,iev_main,iev_main->ibuf.fd,&iev_main->ev_read);iev_main->han
dler_write=ldp_write_handler;if((iev_main_sync=calloc(1,sizeof(structimsgev)))==
NULL)fatal(NULL);imsg_init(&iev_main_sync->ibuf,LDPD_FD_SYNC);/*createbaseconfig
uration*/leconf=config_new_empty();/*Fetchnextactivethread.*/while(thread_fetch(
master,&thread))thread_call(&thread);}voidldpe_init(structldpd_init*init){/*drop
privileges*/ldpe_privs.user=init->user;ldpe_privs.group=init->group;zprivs_prein
it(&ldpe_privs);zprivs_init(&ldpe_privs);/*listenonldpdcontrolsocket*/strlcpy(ct
l_sock_path,init->ctl_sock_path,sizeof(ctl_sock_path));if(control_init(ctl_sock_
path)==-1)fatalx("controlsocketsetupfailed");TAILQ_INIT(&ctl_conns);control_list
en();LIST_INIT(&global.addr_list);RB_INIT(global_adj_head,&global.adj_tree);TAIL
Q_INIT(&global.pending_conns);if(inet_pton(AF_INET,AllRouters_v4,&global.mcast_a
ddr_v4)!=1)fatal("inet_pton");if(inet_pton(AF_INET6,AllRouters_v6,&global.mcast_
addr_v6)!=1)fatal("inet_pton");#ifdef__OpenBSD__global.pfkeysock=pfkey_init();if
(sysdep.no_pfkey==0){pfkey_ev=NULL;thread_add_read(master,ldpe_dispatch_pfkey,NU
LL,global.pfkeysock,&pfkey_ev);}#endif/*marksocketsasclosed*/global.ipv4.ldp_dis
c_socket=-1;global.ipv4.ldp_edisc_socket=-1;global.ipv4.ldp_session_socket=-1;gl
obal.ipv6.ldp_disc_socket=-1;global.ipv6.ldp_edisc_socket=-1;global.ipv6.ldp_ses
sion_socket=-1;if((pkt_ptr=calloc(1,IBUF_READ_SIZE))==NULL)fatal(__func__);accep
t_init();}staticvoidldpe_shutdown(void){structif_addr*if_addr;structadj*adj;/*cl
osepipes*/if(iev_lde){msgbuf_clear(&iev_lde->ibuf.w);close(iev_lde->ibuf.fd);iev
_lde->ibuf.fd=-1;}msgbuf_clear(&iev_main->ibuf.w);close(iev_main->ibuf.fd);iev_m
ain->ibuf.fd=-1;msgbuf_clear(&iev_main_sync->ibuf.w);close(iev_main_sync->ibuf.f
d);iev_main_sync->ibuf.fd=-1;control_cleanup(ctl_sock_path);config_clear(leconf)
;#ifdef__OpenBSD__if(sysdep.no_pfkey==0){THREAD_READ_OFF(pfkey_ev);close(global.
pfkeysock);}#endifldpe_close_sockets(AF_INET);ldpe_close_sockets(AF_INET6);/*rem
oveaddressesfromgloballist*/while((if_addr=LIST_FIRST(&global.addr_list))!=NULL)
{LIST_REMOVE(if_addr,entry);assert(if_addr!=LIST_FIRST(&global.addr_list));free(
if_addr);}while(!RB_EMPTY(global_adj_head,&global.adj_tree)){adj=RB_ROOT(global_
adj_head,&global.adj_tree);adj_del(adj,S_SHUTDOWN);}/*cleanup*/if(iev_lde)free(i
ev_lde);free(iev_main);free(iev_main_sync);free(pkt_ptr);log_info("ldpengineexit
ing");exit(0);}/*imesg*/intldpe_imsg_compose_parent(inttype,pid_tpid,void*data,u
int16_tdatalen){if(iev_main->ibuf.fd==-1)return(0);return(imsg_compose_event(iev
_main,type,0,pid,-1,data,datalen));}voidldpe_imsg_compose_parent_sync(inttype,pi
d_tpid,void*data,uint16_tdatalen){if(iev_main_sync->ibuf.fd==-1)return;imsg_comp
ose_event(iev_main_sync,type,0,pid,-1,data,datalen);imsg_flush(&iev_main_sync->i
buf);}intldpe_imsg_compose_lde(inttype,uint32_tpeerid,pid_tpid,void*data,uint16_
tdatalen){if(iev_lde->ibuf.fd==-1)return(0);return(imsg_compose_event(iev_lde,ty
pe,peerid,pid,-1,data,datalen));}/*ARGSUSED*/staticintldpe_dispatch_main(structt
hread*thread){staticstructldpd_conf*nconf;structiface*niface;structtnbr*ntnbr;st
ructnbr_params*nnbrp;staticstructl2vpn*l2vpn,*nl2vpn;structl2vpn_if*lif,*nlif;st
ructl2vpn_pw*pw,*npw;structimsgimsg;intfd;structimsgev*iev=THREAD_ARG(thread);st
ructimsgbuf*ibuf=&iev->ibuf;structiface*iface=NULL;structkif*kif;intaf;enumsocke
t_type*socket_type;staticintdisc_socket=-1;staticintedisc_socket=-1;staticintses
sion_socket=-1;structnbr*nbr;#ifdef__OpenBSD__structnbr_params*nbrp;#endifintn,s
hut=0;iev->ev_read=NULL;if((n=imsg_read(ibuf))==-1&&errno!=EAGAIN)fatal("imsg_re
aderror");if(n==0)/*connectionclosed*/shut=1;for(;;){if((n=imsg_get(ibuf,&imsg))
==-1)fatal("ldpe_dispatch_main:imsg_geterror");if(n==0)break;switch(imsg.hdr.typ
e){caseIMSG_IFSTATUS:if(imsg.hdr.len!=IMSG_HEADER_SIZE+sizeof(structkif))fatalx(
"IFSTATUSimsgwithwronglen");kif=imsg.data;iface=if_lookup_name(leconf,kif->ifnam
e);if(iface){if_update_info(iface,kif);ldp_if_update(iface,AF_UNSPEC);break;}RB_
FOREACH(l2vpn,l2vpn_head,&leconf->l2vpn_tree){lif=l2vpn_if_find(l2vpn,kif->ifnam
e);if(lif){l2vpn_if_update_info(lif,kif);l2vpn_if_update(lif);break;}pw=l2vpn_pw
_find(l2vpn,kif->ifname);if(pw){l2vpn_pw_update_info(pw,kif);break;}}break;caseI
MSG_NEWADDR:if(imsg.hdr.len!=IMSG_HEADER_SIZE+sizeof(structkaddr))fatalx("NEWADD
Rimsgwithwronglen");if_addr_add(imsg.data);break;caseIMSG_DELADDR:if(imsg.hdr.le
n!=IMSG_HEADER_SIZE+sizeof(structkaddr))fatalx("DELADDRimsgwithwronglen");if_add
r_del(imsg.data);break;caseIMSG_SOCKET_IPC:if(iev_lde){log_warnx("%s:receivedune
xpectedimsgfd""tolde",__func__);break;}if((fd=imsg.fd)==-1){log_warnx("%s:expect
edtoreceiveimsgfdto""ldebutdidn'treceiveany",__func__);break;}if((iev_lde=malloc
(sizeof(structimsgev)))==NULL)fatal(NULL);imsg_init(&iev_lde->ibuf,fd);iev_lde->
handler_read=ldpe_dispatch_lde;iev_lde->ev_read=NULL;thread_add_read(master,iev_
lde->handler_read,iev_lde,iev_lde->ibuf.fd,&iev_lde->ev_read);iev_lde->handler_w
rite=ldp_write_handler;iev_lde->ev_write=NULL;break;caseIMSG_INIT:if(imsg.hdr.le
n!=IMSG_HEADER_SIZE+sizeof(structldpd_init))fatalx("INITimsgwithwronglen");memcp
y(&init,imsg.data,sizeof(init));ldpe_init(&init);break;caseIMSG_CLOSE_SOCKETS:af
=imsg.hdr.peerid;RB_FOREACH(nbr,nbr_id_head,&nbrs_by_id){if(nbr->af!=af)continue
;session_shutdown(nbr,S_SHUTDOWN,0,0);#ifdef__OpenBSD__pfkey_remove(nbr);#endifn
br->auth.method=AUTH_NONE;}ldpe_close_sockets(af);if_update_all(af);tnbr_update_
all(af);disc_socket=-1;edisc_socket=-1;session_socket=-1;if((ldp_af_conf_get(lec
onf,af))->flags&F_LDPD_AF_ENABLED)ldpe_imsg_compose_parent(IMSG_REQUEST_SOCKETS,
af,NULL,0);break;caseIMSG_SOCKET_NET:if(imsg.hdr.len!=IMSG_HEADER_SIZE+sizeof(en
umsocket_type))fatalx("SOCKET_NETimsgwithwronglen");socket_type=imsg.data;switch
(*socket_type){caseLDP_SOCKET_DISC:disc_socket=imsg.fd;break;caseLDP_SOCKET_EDIS
C:edisc_socket=imsg.fd;break;caseLDP_SOCKET_SESSION:session_socket=imsg.fd;break
;}break;caseIMSG_SETUP_SOCKETS:af=imsg.hdr.peerid;if(disc_socket==-1||edisc_sock
et==-1||session_socket==-1){if(disc_socket!=-1)close(disc_socket);if(edisc_socke
t!=-1)close(edisc_socket);if(session_socket!=-1)close(session_socket);break;}ldp
e_setup_sockets(af,disc_socket,edisc_socket,session_socket);if_update_all(af);tn
br_update_all(af);RB_FOREACH(nbr,nbr_id_head,&nbrs_by_id){if(nbr->af!=af)continu
e;nbr->laddr=(ldp_af_conf_get(leconf,af))->trans_addr;#ifdef__OpenBSD__nbrp=nbr_
params_find(leconf,nbr->id);if(nbrp){nbr->auth.method=nbrp->auth.method;if(pfkey
_establish(nbr,nbrp)==-1)fatalx("pfkeysetupfailed");}#endifif(nbr_session_active
_role(nbr))nbr_establish_connection(nbr);}break;caseIMSG_RTRID_UPDATE:memcpy(&gl
obal.rtr_id,imsg.data,sizeof(global.rtr_id));if(leconf->rtr_id.s_addr==INADDR_AN
Y){ldpe_reset_nbrs(AF_UNSPEC);}if_update_all(AF_UNSPEC);tnbr_update_all(AF_UNSPE
C);break;caseIMSG_RECONF_CONF:if((nconf=malloc(sizeof(structldpd_conf)))==NULL)f
atal(NULL);memcpy(nconf,imsg.data,sizeof(structldpd_conf));RB_INIT(iface_head,&n
conf->iface_tree);RB_INIT(tnbr_head,&nconf->tnbr_tree);RB_INIT(nbrp_head,&nconf-
>nbrp_tree);RB_INIT(l2vpn_head,&nconf->l2vpn_tree);break;caseIMSG_RECONF_IFACE:i
f((niface=malloc(sizeof(structiface)))==NULL)fatal(NULL);memcpy(niface,imsg.data
,sizeof(structiface));RB_INSERT(iface_head,&nconf->iface_tree,niface);break;case
IMSG_RECONF_TNBR:if((ntnbr=malloc(sizeof(structtnbr)))==NULL)fatal(NULL);memcpy(
ntnbr,imsg.data,sizeof(structtnbr));RB_INSERT(tnbr_head,&nconf->tnbr_tree,ntnbr)
;break;caseIMSG_RECONF_NBRP:if((nnbrp=malloc(sizeof(structnbr_params)))==NULL)fa
tal(NULL);memcpy(nnbrp,imsg.data,sizeof(structnbr_params));RB_INSERT(nbrp_head,&
nconf->nbrp_tree,nnbrp);break;caseIMSG_RECONF_L2VPN:if((nl2vpn=malloc(sizeof(str
uctl2vpn)))==NULL)fatal(NULL);memcpy(nl2vpn,imsg.data,sizeof(structl2vpn));RB_IN
IT(l2vpn_if_head,&nl2vpn->if_tree);RB_INIT(l2vpn_pw_head,&nl2vpn->pw_tree);RB_IN
IT(l2vpn_pw_head,&nl2vpn->pw_inactive_tree);RB_INSERT(l2vpn_head,&nconf->l2vpn_t
ree,nl2vpn);break;caseIMSG_RECONF_L2VPN_IF:if((nlif=malloc(sizeof(structl2vpn_if
)))==NULL)fatal(NULL);memcpy(nlif,imsg.data,sizeof(structl2vpn_if));RB_INSERT(l2
vpn_if_head,&nl2vpn->if_tree,nlif);break;caseIMSG_RECONF_L2VPN_PW:if((npw=malloc
(sizeof(structl2vpn_pw)))==NULL)fatal(NULL);memcpy(npw,imsg.data,sizeof(structl2
vpn_pw));RB_INSERT(l2vpn_pw_head,&nl2vpn->pw_tree,npw);break;caseIMSG_RECONF_L2V
PN_IPW:if((npw=malloc(sizeof(structl2vpn_pw)))==NULL)fatal(NULL);memcpy(npw,imsg
.data,sizeof(structl2vpn_pw));RB_INSERT(l2vpn_pw_head,&nl2vpn->pw_inactive_tree,
npw);break;caseIMSG_RECONF_END:merge_config(leconf,nconf);ldp_clear_config(nconf
);nconf=NULL;global.conf_seqnum++;break;caseIMSG_CTL_END:control_imsg_relay(&ims
g);break;caseIMSG_DEBUG_UPDATE:if(imsg.hdr.len!=IMSG_HEADER_SIZE+sizeof(ldp_debu
g)){log_warnx("%s:wrongimsglen",__func__);break;}memcpy(&ldp_debug,imsg.data,siz
eof(ldp_debug));break;default:log_debug("ldpe_dispatch_main:errorhandlingimsg%d"
,imsg.hdr.type);break;}imsg_free(&imsg);}if(!shut)imsg_event_add(iev);else{/*thi
spipeisdead,soremovetheeventhandlersandexit*/THREAD_READ_OFF(iev->ev_read);THREA
D_WRITE_OFF(iev->ev_write);ldpe_shutdown();}return(0);}/*ARGSUSED*/staticintldpe
_dispatch_lde(structthread*thread){structimsgev*iev=THREAD_ARG(thread);structims
gbuf*ibuf=&iev->ibuf;structimsgimsg;structmap*map;structnotify_msg*nm;structnbr*
nbr;intn,shut=0;iev->ev_read=NULL;if((n=imsg_read(ibuf))==-1&&errno!=EAGAIN)fata
l("imsg_readerror");if(n==0)/*connectionclosed*/shut=1;for(;;){if((n=imsg_get(ib
uf,&imsg))==-1)fatal("ldpe_dispatch_lde:imsg_geterror");if(n==0)break;switch(ims
g.hdr.type){caseIMSG_MAPPING_ADD:caseIMSG_RELEASE_ADD:caseIMSG_REQUEST_ADD:caseI
MSG_WITHDRAW_ADD:if(imsg.hdr.len-IMSG_HEADER_SIZE!=sizeof(structmap))fatalx("inv
alidsizeofmaprequest");map=imsg.data;nbr=nbr_find_peerid(imsg.hdr.peerid);if(nbr
==NULL){log_debug("ldpe_dispatch_lde:cannotfind""neighbor");break;}if(nbr->state
!=NBR_STA_OPER)break;switch(imsg.hdr.type){caseIMSG_MAPPING_ADD:mapping_list_add
(&nbr->mapping_list,map);break;caseIMSG_RELEASE_ADD:mapping_list_add(&nbr->relea
se_list,map);break;caseIMSG_REQUEST_ADD:mapping_list_add(&nbr->request_list,map)
;break;caseIMSG_WITHDRAW_ADD:mapping_list_add(&nbr->withdraw_list,map);break;}br
eak;caseIMSG_MAPPING_ADD_END:caseIMSG_RELEASE_ADD_END:caseIMSG_REQUEST_ADD_END:c
aseIMSG_WITHDRAW_ADD_END:nbr=nbr_find_peerid(imsg.hdr.peerid);if(nbr==NULL){log_
debug("ldpe_dispatch_lde:cannotfind""neighbor");break;}if(nbr->state!=NBR_STA_OP
ER)break;switch(imsg.hdr.type){caseIMSG_MAPPING_ADD_END:send_labelmessage(nbr,MS
G_TYPE_LABELMAPPING,&nbr->mapping_list);break;caseIMSG_RELEASE_ADD_END:send_labe
lmessage(nbr,MSG_TYPE_LABELRELEASE,&nbr->release_list);break;caseIMSG_REQUEST_AD
D_END:send_labelmessage(nbr,MSG_TYPE_LABELREQUEST,&nbr->request_list);break;case
IMSG_WITHDRAW_ADD_END:send_labelmessage(nbr,MSG_TYPE_LABELWITHDRAW,&nbr->withdra
w_list);break;}break;caseIMSG_NOTIFICATION_SEND:if(imsg.hdr.len-IMSG_HEADER_SIZE
!=sizeof(structnotify_msg))fatalx("invalidsizeofOErequest");nm=imsg.data;nbr=nbr
_find_peerid(imsg.hdr.peerid);if(nbr==NULL){log_debug("ldpe_dispatch_lde:cannotf
ind""neighbor");break;}if(nbr->state!=NBR_STA_OPER)break;send_notification_full(
nbr->tcp,nm);break;caseIMSG_CTL_END:caseIMSG_CTL_SHOW_LIB_BEGIN:caseIMSG_CTL_SHO
W_LIB_RCVD:caseIMSG_CTL_SHOW_LIB_SENT:caseIMSG_CTL_SHOW_LIB_END:caseIMSG_CTL_SHO
W_L2VPN_PW:caseIMSG_CTL_SHOW_L2VPN_BINDING:control_imsg_relay(&imsg);break;defau
lt:log_debug("ldpe_dispatch_lde:errorhandlingimsg%d",imsg.hdr.type);break;}imsg_
free(&imsg);}if(!shut)imsg_event_add(iev);else{/*thispipeisdead,soremovetheevent
handlersandexit*/THREAD_READ_OFF(iev->ev_read);THREAD_WRITE_OFF(iev->ev_write);l
dpe_shutdown();}return(0);}#ifdef__OpenBSD__/*ARGSUSED*/staticintldpe_dispatch_p
fkey(structthread*thread){intfd=THREAD_FD(thread);pfkey_ev=NULL;thread_add_read(
master,ldpe_dispatch_pfkey,NULL,global.pfkeysock,&pfkey_ev);if(pfkey_read(fd,NUL
L)==-1)fatal("pfkey_readfailed,exiting...");return(0);}#endif/*__OpenBSD__*/stat
icvoidldpe_setup_sockets(intaf,intdisc_socket,intedisc_socket,intsession_socket)
{structldpd_af_global*af_global;af_global=ldp_af_global_get(&global,af);/*discov
erysocket*/af_global->ldp_disc_socket=disc_socket;af_global->disc_ev=NULL;thread
_add_read(master,disc_recv_packet,&af_global->disc_ev,af_global->ldp_disc_socket
,&af_global->disc_ev);/*extendeddiscoverysocket*/af_global->ldp_edisc_socket=edi
sc_socket;af_global->edisc_ev=NULL;thread_add_read(master,disc_recv_packet,&af_g
lobal->edisc_ev,af_global->ldp_edisc_socket,&af_global->edisc_ev);/*sessionsocke
t*/af_global->ldp_session_socket=session_socket;accept_add(af_global->ldp_sessio
n_socket,session_accept,NULL);}staticvoidldpe_close_sockets(intaf){structldpd_af
_global*af_global;af_global=ldp_af_global_get(&global,af);/*discoverysocket*/THR
EAD_READ_OFF(af_global->disc_ev);if(af_global->ldp_disc_socket!=-1){close(af_glo
bal->ldp_disc_socket);af_global->ldp_disc_socket=-1;}/*extendeddiscoverysocket*/
THREAD_READ_OFF(af_global->edisc_ev);if(af_global->ldp_edisc_socket!=-1){close(a
f_global->ldp_edisc_socket);af_global->ldp_edisc_socket=-1;}/*sessionsocket*/if(
af_global->ldp_session_socket!=-1){accept_del(af_global->ldp_session_socket);clo
se(af_global->ldp_session_socket);af_global->ldp_session_socket=-1;}}intldpe_acl
_check(char*acl_name,intaf,unionldpd_addr*addr,uint8_tprefixlen){returnldp_acl_r
equest(iev_main_sync,acl_name,af,addr,prefixlen);}voidldpe_reset_nbrs(intaf){str
uctnbr*nbr;RB_FOREACH(nbr,nbr_id_head,&nbrs_by_id){if(af==AF_UNSPEC||nbr->af==af
)session_shutdown(nbr,S_SHUTDOWN,0,0);}}voidldpe_reset_ds_nbrs(void){structnbr*n
br;RB_FOREACH(nbr,nbr_id_head,&nbrs_by_id){if(nbr->ds_tlv)session_shutdown(nbr,S
_SHUTDOWN,0,0);}}voidldpe_remove_dynamic_tnbrs(intaf){structtnbr*tnbr,*safe;RB_F
OREACH_SAFE(tnbr,tnbr_head,&leconf->tnbr_tree,safe){if(tnbr->af!=af)continue;tnb
r->flags&=~F_TNBR_DYNAMIC;tnbr_check(leconf,tnbr);}}voidldpe_stop_init_backoff(i
ntaf){structnbr*nbr;RB_FOREACH(nbr,nbr_id_head,&nbrs_by_id){if(nbr->af==af&&nbr_
pending_idtimer(nbr)){nbr_stop_idtimer(nbr);nbr_establish_connection(nbr);}}}sta
ticvoidldpe_iface_af_ctl(structctl_conn*c,intaf,unsignedintidx){structiface*ifac
e;structiface_af*ia;structctl_iface*ictl;RB_FOREACH(iface,iface_head,&leconf->if
ace_tree){if(idx==0||idx==iface->ifindex){ia=iface_af_get(iface,af);if(!ia->enab
led)continue;ictl=if_to_ctl(ia);imsg_compose_event(&c->iev,IMSG_CTL_SHOW_INTERFA
CE,0,0,-1,ictl,sizeof(structctl_iface));}}}voidldpe_iface_ctl(structctl_conn*c,u
nsignedintidx){ldpe_iface_af_ctl(c,AF_INET,idx);ldpe_iface_af_ctl(c,AF_INET6,idx
);}voidldpe_adj_ctl(structctl_conn*c){structadj*adj;structctl_adj*actl;RB_FOREAC
H(adj,global_adj_head,&global.adj_tree){actl=adj_to_ctl(adj);imsg_compose_event(
&c->iev,IMSG_CTL_SHOW_DISCOVERY,0,0,-1,actl,sizeof(structctl_adj));}imsg_compose
_event(&c->iev,IMSG_CTL_END,0,0,-1,NULL,0);}voidldpe_adj_detail_ctl(structctl_co
nn*c){structiface*iface;structtnbr*tnbr;structadj*adj;structctl_adj*actl;structc
tl_disc_ifictl;structctl_disc_tnbrtctl;imsg_compose_event(&c->iev,IMSG_CTL_SHOW_
DISCOVERY,0,0,-1,NULL,0);RB_FOREACH(iface,iface_head,&leconf->iface_tree){memset
(&ictl,0,sizeof(ictl));ictl.active_v4=(iface->ipv4.state==IF_STA_ACTIVE);ictl.ac
tive_v6=(iface->ipv6.state==IF_STA_ACTIVE);if(!ictl.active_v4&&!ictl.active_v6)c
ontinue;strlcpy(ictl.name,iface->name,sizeof(ictl.name));if(RB_EMPTY(ia_adj_head
,&iface->ipv4.adj_tree)&&RB_EMPTY(ia_adj_head,&iface->ipv6.adj_tree))ictl.no_adj
=1;imsg_compose_event(&c->iev,IMSG_CTL_SHOW_DISC_IFACE,0,0,-1,&ictl,sizeof(ictl)
);RB_FOREACH(adj,ia_adj_head,&iface->ipv4.adj_tree){actl=adj_to_ctl(adj);imsg_co
mpose_event(&c->iev,IMSG_CTL_SHOW_DISC_ADJ,0,0,-1,actl,sizeof(structctl_adj));}R
B_FOREACH(adj,ia_adj_head,&iface->ipv6.adj_tree){actl=adj_to_ctl(adj);imsg_compo
se_event(&c->iev,IMSG_CTL_SHOW_DISC_ADJ,0,0,-1,actl,sizeof(structctl_adj));}}RB_
FOREACH(tnbr,tnbr_head,&leconf->tnbr_tree){memset(&tctl,0,sizeof(tctl));tctl.af=
tnbr->af;tctl.addr=tnbr->addr;if(tnbr->adj==NULL)tctl.no_adj=1;imsg_compose_even
t(&c->iev,IMSG_CTL_SHOW_DISC_TNBR,0,0,-1,&tctl,sizeof(tctl));if(tnbr->adj==NULL)
continue;actl=adj_to_ctl(tnbr->adj);imsg_compose_event(&c->iev,IMSG_CTL_SHOW_DIS
C_ADJ,0,0,-1,actl,sizeof(structctl_adj));}imsg_compose_event(&c->iev,IMSG_CTL_EN
D,0,0,-1,NULL,0);}voidldpe_nbr_ctl(structctl_conn*c){structadj*adj;structctl_adj
*actl;structnbr*nbr;structctl_nbr*nctl;RB_FOREACH(nbr,nbr_addr_head,&nbrs_by_add
r){if(nbr->state==NBR_STA_PRESENT)continue;nctl=nbr_to_ctl(nbr);imsg_compose_eve
nt(&c->iev,IMSG_CTL_SHOW_NBR,0,0,-1,nctl,sizeof(structctl_nbr));RB_FOREACH(adj,n
br_adj_head,&nbr->adj_tree){actl=adj_to_ctl(adj);imsg_compose_event(&c->iev,IMSG
_CTL_SHOW_NBR_DISC,0,0,-1,actl,sizeof(structctl_adj));}imsg_compose_event(&c->ie
v,IMSG_CTL_SHOW_NBR_END,0,0,-1,NULL,0);}imsg_compose_event(&c->iev,IMSG_CTL_END,
0,0,-1,NULL,0);}voidmapping_list_add(structmapping_head*mh,structmap*map){struct
mapping_entry*me;me=calloc(1,sizeof(*me));if(me==NULL)fatal(__func__);me->map=*m
ap;TAILQ_INSERT_TAIL(mh,me,entry);}voidmapping_list_clr(structmapping_head*mh){s
tructmapping_entry*me;while((me=TAILQ_FIRST(mh))!=NULL){TAILQ_REMOVE(mh,me,entry
);assert(me!=TAILQ_FIRST(mh));free(me);}}