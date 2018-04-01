/*lib/systemdCode*Copyright(C)2016CumulusNetworks,Inc.*DonaldSharp**Thisfileispa
rtofQuagga.**Quaggaisfreesoftware;youcanredistributeitand/ormodifyit*undertheter
msoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eithervers
ion2,or(atyouroption)any*laterversion.**Quaggaisdistributedinthehopethatitwillbe
useful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorF
ITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Yoush
ouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefil
eCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Bo
ston,MA02110-1301USA*/#include<zebra.h>#include"thread.h"#include"systemd.h"#ifd
efinedHAVE_SYSTEMD#include<systemd/sd-daemon.h>#endif/**Wrapperthissillinessifwe
*don'thavesystemd*/voidsystemd_send_information(constchar*info){#ifdefinedHAVE_S
YSTEMDsd_notify(0,info);#elsereturn;#endif}/**Areturnof0meansthatwearenotwatchdo
ged*/staticintsystemd_get_watchdog_time(intthe_process){#ifdefinedHAVE_SYSTEMDui
nt64_tusec;char*watchdog=NULL;intret;ret=sd_watchdog_enabled(0,&usec);/**Ifretur
nis0->wedon'twantwatchdog*ifreturnis<0,somesortoffailureoccurred*/if(ret<0)retur
n0;/**systemdcanreturnthatthisprocess*isnottheexpectedsenderofthewatchdogtimer*I
fwesetthe_process=0thenweexpectto*beabletosendthewatchdogtosystemd*irrelevantoft
hepidofthisprocess.*/if(ret==0&&the_process)return0;if(ret==0&&!the_process){wat
chdog=getenv("WATCHDOG_USEC");if(!watchdog)return0;usec=atol(watchdog);}return(u
sec/1000000)/3;#elsereturn0;#endif}voidsystemd_send_stopping(void){systemd_send_
information("STOPPING=1");}/**Howmanysecondsshouldwewaitbetweenwatchdogsends*/in
twsecs=0;structthread_master*systemd_master=NULL;staticintsystemd_send_watchdog(
structthread*t){systemd_send_information("WATCHDOG=1");thread_add_timer(systemd_
master,systemd_send_watchdog,NULL,wsecs,NULL);return1;}voidsystemd_send_started(
structthread_master*m,intthe_process){assert(m!=NULL);wsecs=systemd_get_watchdog
_time(the_process);systemd_master=m;systemd_send_information("READY=1");if(wsecs
!=0)thread_add_timer(m,systemd_send_watchdog,m,wsecs,NULL);}