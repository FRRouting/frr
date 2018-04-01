/**LogicalRouterfunctions.*Copyright(C)20186WINDS.A.**Thisprogramisfreesoftware;
youcanredistributeitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseaspu
blishedbytheFree*SoftwareFoundation;eitherversion2oftheLicense,or(atyouroption)*
anylaterversion.**Thisprogramisdistributedinthehopethatitwillbeuseful,butWITHOUT
*ANYWARRANTY;withouteventheimpliedwarrantyofMERCHANTABILITYor*FITNESSFORAPARTICU
LARPURPOSE.SeetheGNUGeneralPublicLicensefor*moredetails.**Youshouldhavereceiveda
copyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,wr
itetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301
USA*/#include<zebra.h>#include"ns.h"#include"log.h"#include"memory.h"#include"co
mmand.h"#include"vty.h"#include"logicalrouter.h"/*Commentthatuselessdefinetoavoi
dcompilationerror*inordertouseit,onecouldprovidethekindofNETNStoNSbackend*sothat
theallocationwillmatchthelogicalrouter*DEFINE_MTYPE_STATIC(LIB,LOGICALROUTER,"Lo
gicalRouterContext")*/DEFINE_MTYPE_STATIC(LIB,LOGICALROUTER_NAME,"LogicalRouterN
ame")/*LogicalRouternodehasnointerface.*/staticstructcmd_nodelogicalrouter_node=
{LOGICALROUTER_NODE,"",1};staticintlogicalrouter_backend;/*GetaNS.Ifnotfound,cre
ateone.*/staticstructns*logicalrouter_get(ns_id_tns_id){structns*ns;ns=ns_lookup
(ns_id);if(ns)return(ns);ns=ns_get_created(ns,NULL,ns_id);returnns;}staticintlog
icalrouter_is_backend_netns(void){return(logicalrouter_backend==LOGICALROUTER_BA
CKEND_NETNS);}DEFUN_NOSH(logicalrouter,logicalrouter_cmd,"logical-router(1-65535
)nsNAME","Enablealogical-router\n""Specifythelogical-routerindentifier\n""TheNam
eSpace\n""Thefilenamein"NS_RUN_DIR",orafullpathname\n"){intidx_number=1;intidx_n
ame=3;ns_id_tns_id;structns*ns=NULL;char*pathname=ns_netns_pathname(vty,argv[idx
_name]->arg);if(!pathname)returnCMD_WARNING_CONFIG_FAILED;ns_id=strtoul(argv[idx
_number]->arg,NULL,10);ns=logicalrouter_get(ns_id);if(ns->name&&strcmp(ns->name,
pathname)!=0){vty_out(vty,"NS%uisalreadyconfiguredwithNETNS%s\n",ns->ns_id,ns->n
ame);returnCMD_WARNING;}if(!ns->name)ns->name=XSTRDUP(MTYPE_LOGICALROUTER_NAME,p
athname);if(!ns_enable(ns,NULL)){vty_out(vty,"CannotassociateNS%uwithNETNS%s\n",
ns->ns_id,ns->name);returnCMD_WARNING_CONFIG_FAILED;}returnCMD_SUCCESS;}DEFUN(no
_logicalrouter,no_logicalrouter_cmd,"nological-router(1-65535)nsNAME",NO_STR"Ena
bleaLogical-Router\n""SpecifytheLogical-Routeridentifier\n""TheNameSpace\n""Thef
ilenamein"NS_RUN_DIR",orafullpathname\n"){intidx_number=2;intidx_name=4;ns_id_tn
s_id;structns*ns=NULL;char*pathname=ns_netns_pathname(vty,argv[idx_name]->arg);i
f(!pathname)returnCMD_WARNING_CONFIG_FAILED;ns_id=strtoul(argv[idx_number]->arg,
NULL,10);ns=ns_lookup(ns_id);if(!ns){vty_out(vty,"NS%uisnotfound\n",ns_id);retur
nCMD_SUCCESS;}if(ns->name&&strcmp(ns->name,pathname)!=0){vty_out(vty,"IncorrectN
ETNSfilename\n");returnCMD_WARNING_CONFIG_FAILED;}ns_disable(ns);if(ns->name){XF
REE(MTYPE_LOGICALROUTER_NAME,ns->name);ns->name=NULL;}returnCMD_SUCCESS;}/*Initi
alizeNSmodule.*/voidlogicalrouter_init(int(*writefunc)(structvty*vty)){if(ns_hav
e_netns()&&logicalrouter_is_backend_netns()){/*InstallLogicalRoutercommands.*/in
stall_node(&logicalrouter_node,writefunc);install_element(CONFIG_NODE,&logicalro
uter_cmd);install_element(CONFIG_NODE,&no_logicalrouter_cmd);}}voidlogicalrouter
_terminate(void){ns_terminate();}voidlogicalrouter_configure_backend(intbackend_
netns){logicalrouter_backend=backend_netns;}