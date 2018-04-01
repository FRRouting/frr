/*NHRPdaemonmainfunctions*Copyright(c)2014-2015TimoTeräs**Thisfileisfreesoftware
:youmaycopy,redistributeand/ormodify*itunderthetermsoftheGNUGeneralPublicLicense
aspublishedby*theFreeSoftwareFoundation,eitherversion2oftheLicense,or*(atyouropt
ion)anylaterversion.*/#include<unistd.h>#include"zebra.h"#include"privs.h"#inclu
de"getopt.h"#include"thread.h"#include"sigevent.h"#include"version.h"#include"lo
g.h"#include"memory.h"#include"memory_vty.h"#include"command.h"#include"libfrr.h
"#include"nhrpd.h"#include"netlink.h"DEFINE_MGROUP(NHRPD,"NHRP")unsignedintdebug
_flags=0;structthread_master*master;structtimevalcurrent_time;/*nhrpdoptions.*/s
tructoptionlongopts[]={{0}};/*nhrpdprivileges*/staticzebra_capabilities_t_caps_p
[]={ZCAP_NET_RAW,ZCAP_NET_ADMIN,ZCAP_DAC_OVERRIDE,/*fornowneededtowriteto/proc/s
ys/net/ipv4/<if>/send_redirect*/};structzebra_privs_tnhrpd_privs={#ifdefined(FRR
_USER)&&defined(FRR_GROUP).user=FRR_USER,.group=FRR_GROUP,#endif#ifdefVTY_GROUP.
vty_group=VTY_GROUP,#endif.caps_p=_caps_p,.cap_num_p=ZEBRA_NUM_OF(_caps_p),};sta
ticvoidparse_arguments(intargc,char**argv){intopt;while(1){opt=frr_getopt(argc,a
rgv,0);if(opt<0)break;switch(opt){case0:break;default:frr_help_exit(1);break;}}}
staticvoidnhrp_sigusr1(void){zlog_rotate();}staticvoidnhrp_request_stop(void){de
bugf(NHRP_DEBUG_COMMON,"Exiting...");frr_early_fini();nhrp_shortcut_terminate();
nhrp_nhs_terminate();nhrp_zebra_terminate();vici_terminate();evmgr_terminate();n
hrp_vc_terminate();vrf_terminate();debugf(NHRP_DEBUG_COMMON,"Done.");frr_fini();
exit(0);}staticstructquagga_signal_tsighandlers[]={{.signal=SIGUSR1,.handler=&nh
rp_sigusr1,},{.signal=SIGINT,.handler=&nhrp_request_stop,},{.signal=SIGTERM,.han
dler=&nhrp_request_stop,},};FRR_DAEMON_INFO(nhrpd,NHRP,.vty_port=NHRP_VTY_PORT,.
proghelp="ImplementationoftheNHRProutingprotocol.",.signals=sighandlers,.n_signa
ls=array_size(sighandlers),.privs=&nhrpd_privs,)intmain(intargc,char**argv){frr_
preinit(&nhrpd_di,argc,argv);frr_opt_add("",longopts,"");parse_arguments(argc,ar
gv);/*Libraryinits.*/master=frr_init();vrf_init(NULL,NULL,NULL,NULL);nhrp_interf
ace_init();resolver_init();/*Runwithelevatedcapabilities,asforallnetlinkactivity
*weneedprivilegesanyway.*/nhrpd_privs.change(ZPRIVS_RAISE);netlink_init();evmgr_
init();nhrp_vc_init();nhrp_packet_init();vici_init();nhrp_zebra_init();nhrp_shor
tcut_init();nhrp_config_init();frr_config_fork();frr_run(master);return0;}