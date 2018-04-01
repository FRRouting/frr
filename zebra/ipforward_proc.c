/**Fetchipforwardvaluebyreading/procfilesystem.*Copyright(C)1997KunihiroIshiguro
**ThisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormo
difyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFou
ndation;eitherversion2,or(atyouroption)any*laterversion.**GNUZebraisdistributedi
nthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyo
f*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicensefo
rmoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*witht
hisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51Fran
klinSt,FifthFloor,Boston,MA02110-1301USA*/#include<zebra.h>#ifdefGNU_LINUX#inclu
de"log.h"#include"privs.h"#include"zebra/ipforward.h"externstructzebra_privs_tzs
erv_privs;charproc_net_snmp[]="/proc/net/snmp";staticvoiddropline(FILE*fp){intc;
while((c=getc(fp))!='\n');}intipforward(void){intret=0;FILE*fp;intipforwarding=0
;charbuf[10];fp=fopen(proc_net_snmp,"r");if(fp==NULL)return-1;/*Wedon'tcareabout
thefirstline.*/dropline(fp);/*Getip_statistics.IpForwarding:1=>ipforwardingenabl
ed2=>ipforwardingoff.*/if(fgets(buf,6,fp))ret=sscanf(buf,"Ip:%d",&ipforwarding);
fclose(fp);if(ret==1&&ipforwarding==1)return1;return0;}/*charproc_ipv4_forwardin
g[]="/proc/sys/net/ipv4/conf/all/forwarding";*/charproc_ipv4_forwarding[]="/proc
/sys/net/ipv4/ip_forward";intipforward_on(void){FILE*fp;if(zserv_privs.change(ZP
RIVS_RAISE))zlog_err("Can'traiseprivileges,%s",safe_strerror(errno));fp=fopen(pr
oc_ipv4_forwarding,"w");if(fp==NULL){if(zserv_privs.change(ZPRIVS_LOWER))zlog_er
r("Can'tlowerprivileges,%s",safe_strerror(errno));return-1;}fprintf(fp,"1\n");fc
lose(fp);if(zserv_privs.change(ZPRIVS_LOWER))zlog_err("Can'tlowerprivileges,%s",
safe_strerror(errno));returnipforward();}intipforward_off(void){FILE*fp;if(zserv
_privs.change(ZPRIVS_RAISE))zlog_err("Can'traiseprivileges,%s",safe_strerror(err
no));fp=fopen(proc_ipv4_forwarding,"w");if(fp==NULL){if(zserv_privs.change(ZPRIV
S_LOWER))zlog_err("Can'tlowerprivileges,%s",safe_strerror(errno));return-1;}fpri
ntf(fp,"0\n");fclose(fp);if(zserv_privs.change(ZPRIVS_LOWER))zlog_err("Can'tlowe
rprivileges,%s",safe_strerror(errno));returnipforward();}charproc_ipv6_forwardin
g[]="/proc/sys/net/ipv6/conf/all/forwarding";intipforward_ipv6(void){intret=0;FI
LE*fp;charbuf[5];intipforwarding=0;fp=fopen(proc_ipv6_forwarding,"r");if(fp==NUL
L)return-1;if(fgets(buf,2,fp))ret=sscanf(buf,"%d",&ipforwarding);fclose(fp);if(r
et!=1)return0;returnipforwarding;}intipforward_ipv6_on(void){FILE*fp;if(zserv_pr
ivs.change(ZPRIVS_RAISE))zlog_err("Can'traiseprivileges,%s",safe_strerror(errno)
);fp=fopen(proc_ipv6_forwarding,"w");if(fp==NULL){if(zserv_privs.change(ZPRIVS_L
OWER))zlog_err("Can'tlowerprivileges,%s",safe_strerror(errno));return-1;}fprintf
(fp,"1\n");fclose(fp);if(zserv_privs.change(ZPRIVS_LOWER))zlog_err("Can'tlowerpr
ivileges,%s",safe_strerror(errno));returnipforward_ipv6();}intipforward_ipv6_off
(void){FILE*fp;if(zserv_privs.change(ZPRIVS_RAISE))zlog_err("Can'traiseprivilege
s,%s",safe_strerror(errno));fp=fopen(proc_ipv6_forwarding,"w");if(fp==NULL){if(z
serv_privs.change(ZPRIVS_LOWER))zlog_err("Can'tlowerprivileges,%s",safe_strerror
(errno));return-1;}fprintf(fp,"0\n");fclose(fp);if(zserv_privs.change(ZPRIVS_LOW
ER))zlog_err("Can'tlowerprivileges,%s",safe_strerror(errno));returnipforward_ipv
6();}#endif/*GNU_LINUX*/