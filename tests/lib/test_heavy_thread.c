/**ThisfileispartofQuagga.**Quaggaisfreesoftware;youcanredistributeitand/ormodif
yit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFounda
tion;eitherversion2,or(atyouroption)any*laterversion.**Quaggaisdistributedintheh
opethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MER
CHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformore
details.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthispr
ogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinS
t,FifthFloor,Boston,MA02110-1301USA*//*Thisprogrammeshowstheeffectsof'heavy'long
-runningfunctions*onthecooperativethreadingmodel,asdemonstratedbyheavy.c,andhow*
theycanbemitigatedusingabackgroundthread.**Runitwithaconfigfilecontaining'passwo
rdwhatever',telnettoit*(itdefaultstoport4000)andenterthe'clearfoostring'command.
*thentypewhateverandobservethat,unlikeheavy.c,thevtyinterface*remainsresponsive.
*/#include<zebra.h>#include<math.h>#include"thread.h"#include"vty.h"#include"com
mand.h"#include"memory.h"#include"log.h"#include"tests.h"externstructthread_mast
er*master;enum{ITERS_FIRST=0,ITERS_ERR=100,ITERS_LATER=400,ITERS_PRINT=10,ITERS_
MAX=1000,};structwork_state{structvty*vty;char*str;inti;};staticvoidslow_func(st
ructvty*vty,constchar*str,constinti){doublex=1;intj;for(j=0;j<300;j++)x+=sin(x)*
j;if((i%ITERS_LATER)==0)printf("%s:%d,temporaryerror,savethissomehowanddoitlater
..\n",__func__,i);if((i%ITERS_ERR)==0)printf("%s:harderror\n",__func__);if((i%IT
ERS_PRINT)==0)printf("%sdid%d,x=%g\n",str,i,x);}staticintclear_something(structt
hread*thread){structwork_state*ws=THREAD_ARG(thread);/*thiscouldbelikeiteratingt
hrough150kofroute_table*orworse,iteratingthroughalistofpeers,tobgp_stopthemwith*
eachhaving150kroutetablestoprocess...*/while(ws->i<ITERS_MAX){slow_func(ws->vty,
ws->str,ws->i);ws->i++;if(thread_should_yield(thread)){thread_add_timer_msec(mas
ter,clear_something,ws,0,NULL);return0;}}/*Alldone!*/XFREE(MTYPE_TMP,ws->str);XF
REE(MTYPE_TMP,ws);return0;}DEFUN(clear_foo,clear_foo_cmd,"clearfooLINE...","clea
rcommand\n""arbitrarystring\n"){char*str;structwork_state*ws;if(!argc){vty_out(v
ty,"%%stringargumentrequired\n");returnCMD_WARNING;}str=argv_concat(argv,argc,0)
;if((ws=XMALLOC(MTYPE_TMP,sizeof(*ws)))==NULL){zlog_err("%s:unabletoallocatework
_state",__func__);returnCMD_WARNING;}if(!(ws->str=XSTRDUP(MTYPE_TMP,str))){zlog_
err("%s:unabletoxstrdup",__func__);XFREE(MTYPE_TMP,ws);returnCMD_WARNING;}ws->vt
y=vty;ws->i=ITERS_FIRST;thread_add_timer_msec(master,clear_something,ws,0,NULL);
returnCMD_SUCCESS;}voidtest_init(){install_element(VIEW_NODE,&clear_foo_cmd);}