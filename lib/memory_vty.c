/**MemoryanddynamicmoduleVTYroutine**Copyright(C)1998KunihiroIshiguro*Copyright(
C)2016-2017DavidLamparterforNetDEF,Inc.**Thisprogramisfreesoftware;youcanredistr
ibuteitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbytheF
ree*SoftwareFoundation;eitherversion2oftheLicense,or(atyouroption)*anylaterversi
on.**Thisprogramisdistributedinthehopethatitwillbeuseful,butWITHOUT*ANYWARRANTY;
withouteventheimpliedwarrantyofMERCHANTABILITYor*FITNESSFORAPARTICULARPURPOSE.Se
etheGNUGeneralPublicLicensefor*moredetails.**YoushouldhavereceivedacopyoftheGNUG
eneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,writetotheFreeS
oftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#include
<zebra.h>/*malloc.hisgenerallyobsolete,howeverGNULibcmallinfowantsit.*/#if(defin
ed(GNU_LINUX)&&defined(HAVE_MALLINFO))#include<malloc.h>#endif/*HAVE_MALLINFO*/#
include<dlfcn.h>#include<link.h>#include"log.h"#include"memory.h"#include"module
.h"#include"memory_vty.h"/*Lookingupmemorystatusfromvtyinterface.*/#include"vect
or.h"#include"vty.h"#include"command.h"#ifdefHAVE_MALLINFOstaticintshow_memory_m
allinfo(structvty*vty){structmallinfominfo=mallinfo();charbuf[MTYPE_MEMSTR_LEN];
vty_out(vty,"Systemallocatorstatistics:\n");vty_out(vty,"Totalheapallocated:%s\n
",mtype_memstr(buf,MTYPE_MEMSTR_LEN,minfo.arena));vty_out(vty,"Holdingblockheade
rs:%s\n",mtype_memstr(buf,MTYPE_MEMSTR_LEN,minfo.hblkhd));vty_out(vty,"Usedsmall
blocks:%s\n",mtype_memstr(buf,MTYPE_MEMSTR_LEN,minfo.usmblks));vty_out(vty,"Used
ordinaryblocks:%s\n",mtype_memstr(buf,MTYPE_MEMSTR_LEN,minfo.uordblks));vty_out(
vty,"Freesmallblocks:%s\n",mtype_memstr(buf,MTYPE_MEMSTR_LEN,minfo.fsmblks));vty
_out(vty,"Freeordinaryblocks:%s\n",mtype_memstr(buf,MTYPE_MEMSTR_LEN,minfo.fordb
lks));vty_out(vty,"Ordinaryblocks:%ld\n",(unsignedlong)minfo.ordblks);vty_out(vt
y,"Smallblocks:%ld\n",(unsignedlong)minfo.smblks);vty_out(vty,"Holdingblocks:%ld
\n",(unsignedlong)minfo.hblks);vty_out(vty,"(seesystemdocumentationfor'mallinfo'
formeaning)\n");return1;}#endif/*HAVE_MALLINFO*/staticintqmem_walker(void*arg,st
ructmemgroup*mg,structmemtype*mt){structvty*vty=arg;if(!mt)vty_out(vty,"---qmem%
s---\n",mg->name);else{if(mt->n_alloc!=0){charsize[32];snprintf(size,sizeof(size
),"%6zu",mt->size);vty_out(vty,"%-30s:%10zu%s\n",mt->name,mt->n_alloc,mt->size==
0?"":mt->size==SIZE_VAR?"(variablysized)":size);}}return0;}DEFUN(show_memory,sho
w_memory_cmd,"showmemory","Showrunningsysteminformation\n""Memorystatistics\n"){
#ifdefHAVE_MALLINFOshow_memory_mallinfo(vty);#endif/*HAVE_MALLINFO*/qmem_walk(qm
em_walker,vty);returnCMD_SUCCESS;}DEFUN(show_modules,show_modules_cmd,"showmodul
es","Showrunningsysteminformation\n""Loadedmodules\n"){structfrrmod_runtime*plug
=frrmod_list;vty_out(vty,"%-12s%-25s%s\n\n","ModuleName","Version","Description"
);while(plug){conststructfrrmod_info*i=plug->info;vty_out(vty,"%-12s%-25s%s\n",i
->name,i->version,i->description);if(plug->dl_handle){#ifdefHAVE_DLINFO_ORIGINch
arorigin[MAXPATHLEN]="";dlinfo(plug->dl_handle,RTLD_DI_ORIGIN,&origin);#ifdefHAV
E_DLINFO_LINKMAPconstchar*name;structlink_map*lm=NULL;dlinfo(plug->dl_handle,RTL
D_DI_LINKMAP,&lm);if(lm){name=strrchr(lm->l_name,'/');name=name?name+1:lm->l_nam
e;vty_out(vty,"\tfrom:%s/%s\n",origin,name);}#elsevty_out(vty,"\tfrom:%s\n",orig
in,plug->load_name);#endif#elsevty_out(vty,"\tfrom:%s\n",plug->load_name);#endif
}plug=plug->next;}returnCMD_SUCCESS;}voidmemory_init(void){install_element(VIEW_
NODE,&show_memory_cmd);install_element(VIEW_NODE,&show_modules_cmd);}/*Statsquer
yingfromusers*//*Returnapointertoahumanfriendlystringdescribing*thebytecountpass
edin.E.g:*"0bytes","2048bytes","110kB","500MiB","11GiB",etc.*Upto4significantfig
ureswillbegiven.*ThepointerreturnedmaybeNULL(indicatinganerror)*orpointtothegive
nbuffer,orpointtostaticstorage.*/constchar*mtype_memstr(char*buf,size_tlen,unsig
nedlongbytes){unsignedintm,k;/*easycases*/if(!bytes)return"0bytes";if(bytes==1)r
eturn"1byte";/**Whenwepassthe2gbbarriermallinfo()cannolongerreport*correctdataso
itjustdoessomethingodd...*ReportinglikeTerrabytesofdata.Whichmakesusers...*edgy.
.yesedgythat'sthetermforit.*Solet'sjustgiveupgracefully*/if(bytes>0x7fffffff)ret
urn">2GB";m=bytes>>20;k=bytes>>10;if(m>10){if(bytes&(1<<19))m++;snprintf(buf,len
,"%dMiB",m);}elseif(k>10){if(bytes&(1<<9))k++;snprintf(buf,len,"%dKiB",k);}elses
nprintf(buf,len,"%ldbytes",bytes);returnbuf;}