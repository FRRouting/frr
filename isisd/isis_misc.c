/**IS-ISRout(e)ingprotocol-isis_misc.h*Miscellanousroutines**Copyright(C)2001,20
02SampoSaaristo*TampereUniversityofTechnology*InstituteofCommunicationsEngineeri
ng**Thisprogramisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsof
theGNUGeneralPublicLicenseaspublishedbytheFree*SoftwareFoundation;eitherversion2
oftheLicense,or(atyouroption)*anylaterversion.**Thisprogramisdistributedinthehop
ethatitwillbeuseful,butWITHOUT*ANYWARRANTY;withouteventheimpliedwarrantyofMERCHA
NTABILITYor*FITNESSFORAPARTICULARPURPOSE.SeetheGNUGeneralPublicLicensefor*morede
tails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprog
ram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,
FifthFloor,Boston,MA02110-1301USA*/#include<zebra.h>#include"stream.h"#include"v
ty.h"#include"hash.h"#include"if.h"#include"command.h"#include"log_int.h"#includ
e"isisd/dict.h"#include"isisd/isis_constants.h"#include"isisd/isis_common.h"#inc
lude"isisd/isis_flags.h"#include"isisd/isis_circuit.h"#include"isisd/isis_csm.h"
#include"isisd/isisd.h"#include"isisd/isis_misc.h"#include"isisd/isis_lsp.h"#inc
lude"isisd/isis_constants.h"#include"isisd/isis_adjacency.h"#include"isisd/isis_
dynhn.h"/*staticlyassignedvarsforprintingpurposes*/structin_addrnew_prefix;/*len
ofxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xx*//*+placefor#0termination*/
charisonet[51];/*lenofxxYxxMxWxdxxhxxmxxs+placefor#0termination*/chardatestring[
20];charnlpidstring[30];/**Thisconvertstheisonettoitsprintableformat*/constchar*
isonet_print(constuint8_t*from,intlen){inti=0;char*pos=isonet;if(!from)return"un
known";while(i<len){if(i&1){sprintf(pos,"%02x",*(from+i));pos+=2;}else{if(i==(le
n-1)){/*Nodotattheendofaddress*/sprintf(pos,"%02x",*(from+i));pos+=2;}else{sprin
tf(pos,"%02x.",*(from+i));pos+=3;}}i++;}*(pos)='\0';returnisonet;}/**Returns0one
rror,lengthofbuffonok*extractdotfromthedottedstr,andinsertallthenumberinabuff*/i
ntdotformat2buff(uint8_t*buff,constchar*dotted){intdotlen,len=0;constchar*pos=do
tted;uint8_tnumber[3];intnextdotpos=2;number[2]='\0';dotlen=strlen(dotted);if(do
tlen>50){/*thiscan'tbeanisonet,itstoolong*/return0;}while((pos-dotted)<dotlen&&l
en<20){if(*pos=='.'){/*weexpectthe.at2,andthanevery5*/if((pos-dotted)!=nextdotpo
s){len=0;break;}nextdotpos+=5;pos++;continue;}/*wemusthaveatleasttwocharslefther
e*/if(dotlen-(pos-dotted)<2){len=0;break;}if((isxdigit((int)*pos))&&(isxdigit((i
nt)*(pos+1)))){memcpy(number,pos,2);pos+=2;}else{len=0;break;}*(buff+len)=(char)
strtol((char*)number,NULL,16);len++;}returnlen;}/**conversionofXXXX.XXXX.XXXXtom
emory*/intsysid2buff(uint8_t*buff,constchar*dotted){intlen=0;constchar*pos=dotte
d;uint8_tnumber[3];number[2]='\0';//surelynotasysid_stringifnot14lengthif(strlen
(dotted)!=14){return0;}while(len<ISIS_SYS_ID_LEN){if(*pos=='.'){/*the.isnotposit
ionedcorrectly*/if(((pos-dotted)!=4)&&((pos-dotted)!=9)){len=0;break;}pos++;cont
inue;}if((isxdigit((int)*pos))&&(isxdigit((int)*(pos+1)))){memcpy(number,pos,2);
pos+=2;}else{len=0;break;}*(buff+len)=(char)strtol((char*)number,NULL,16);len++;
}returnlen;}constchar*nlpid2str(uint8_tnlpid){staticcharbuf[4];switch(nlpid){cas
eNLPID_IP:return"IPv4";caseNLPID_IPV6:return"IPv6";caseNLPID_SNAP:return"SNAP";c
aseNLPID_CLNP:return"CLNP";caseNLPID_ESIS:return"ES-IS";default:snprintf(buf,siz
eof(buf),"%"PRIu8,nlpid);returnbuf;}}/**convertsthenlpidsstruct(filledbyTLV#129)
*intoastring*/char*nlpid2string(structnlpids*nlpids){char*pos=nlpidstring;inti;f
or(i=0;i<nlpids->count;i++){pos+=sprintf(pos,"%s",nlpid2str(nlpids->nlpids[i]));
if(nlpids->count-i>1)pos+=sprintf(pos,",");}*(pos)='\0';returnnlpidstring;}/**Re
turns0onerror,IS-ISCircuitTypeonok*/intstring2circuit_t(constchar*str){if(!str)r
eturn0;if(!strcmp(str,"level-1"))returnIS_LEVEL_1;if(!strcmp(str,"level-2-only")
||!strcmp(str,"level-2"))returnIS_LEVEL_2;if(!strcmp(str,"level-1-2"))returnIS_L
EVEL_1_AND_2;return0;}constchar*circuit_state2string(intstate){switch(state){cas
eC_STATE_INIT:return"Init";caseC_STATE_CONF:return"Config";caseC_STATE_UP:return
"Up";default:return"Unknown";}returnNULL;}constchar*circuit_type2string(inttype)
{switch(type){caseCIRCUIT_T_P2P:return"p2p";caseCIRCUIT_T_BROADCAST:return"lan";
caseCIRCUIT_T_LOOPBACK:return"loopback";default:return"Unknown";}returnNULL;}con
stchar*circuit_t2string(intcircuit_t){switch(circuit_t){caseIS_LEVEL_1:return"L1
";caseIS_LEVEL_2:return"L2";caseIS_LEVEL_1_AND_2:return"L1L2";default:return"??"
;}returnNULL;/*notreached*/}constchar*syst2string(inttype){switch(type){caseISIS
_SYSTYPE_ES:return"ES";caseISIS_SYSTYPE_IS:return"IS";caseISIS_SYSTYPE_L1_IS:ret
urn"1";caseISIS_SYSTYPE_L2_IS:return"2";default:return"??";}returnNULL;/*notreac
hed*/}/**Printfunctions-weprinttostaticvars*/constchar*snpa_print(constuint8_t*f
rom){returnisis_format_id(from,ISIS_SYS_ID_LEN);}constchar*sysid_print(constuint
8_t*from){returnisis_format_id(from,ISIS_SYS_ID_LEN);}constchar*rawlspid_print(c
onstuint8_t*from){returnisis_format_id(from,8);}#defineFORMAT_ID_SIZEsizeof("000
0.0000.0000.00-00")constchar*isis_format_id(constuint8_t*id,size_tlen){#defineFO
RMAT_BUF_COUNT4staticcharbuf_ring[FORMAT_BUF_COUNT][FORMAT_ID_SIZE];staticsize_t
cur_buf=0;char*rv;cur_buf++;if(cur_buf>=FORMAT_BUF_COUNT)cur_buf=0;rv=buf_ring[c
ur_buf];if(!id){snprintf(rv,FORMAT_ID_SIZE,"unknown");returnrv;}if(len<6){snprin
tf(rv,FORMAT_ID_SIZE,"ShortID");returnrv;}snprintf(rv,FORMAT_ID_SIZE,"%02x%02x.%
02x%02x.%02x%02x",id[0],id[1],id[2],id[3],id[4],id[5]);if(len>6)snprintf(rv+14,F
ORMAT_ID_SIZE-14,".%02x",id[6]);if(len>7)snprintf(rv+17,FORMAT_ID_SIZE-17,"-%02x
",id[7]);returnrv;}constchar*time2string(uint32_ttime){char*pos=datestring;uint3
2_trest;if(time==0)return"-";if(time/SECS_PER_YEAR)pos+=sprintf(pos,"%uY",time/S
ECS_PER_YEAR);rest=time%SECS_PER_YEAR;if(rest/SECS_PER_MONTH)pos+=sprintf(pos,"%
uM",rest/SECS_PER_MONTH);rest=rest%SECS_PER_MONTH;if(rest/SECS_PER_WEEK)pos+=spr
intf(pos,"%uw",rest/SECS_PER_WEEK);rest=rest%SECS_PER_WEEK;if(rest/SECS_PER_DAY)
pos+=sprintf(pos,"%ud",rest/SECS_PER_DAY);rest=rest%SECS_PER_DAY;if(rest/SECS_PE
R_HOUR)pos+=sprintf(pos,"%uh",rest/SECS_PER_HOUR);rest=rest%SECS_PER_HOUR;if(res
t/SECS_PER_MINUTE)pos+=sprintf(pos,"%um",rest/SECS_PER_MINUTE);rest=rest%SECS_PE
R_MINUTE;if(rest)pos+=sprintf(pos,"%us",rest);*(pos)=0;returndatestring;}/**rout
inetodecrementatimerbyarandom*number**firstargumentisthetimerandthesecondis*thej
itter*/unsignedlongisis_jitter(unsignedlongtimer,unsignedlongjitter){intj,k;if(j
itter>=100)returntimer;if(timer==1)returntimer;/**randomizingjustthepercentvalue
provides*nogoodrandomnumbers-hencethespread*toRANDOM_SPREAD(100000),whichisokas*
mostIS-IStimersarenolongerthan16bit*/j=1+(int)((RANDOM_SPREAD*random())/(RAND_MA
X+1.0));k=timer-(timer*(100-jitter))/100;timer=timer-(k*j/RANDOM_SPREAD);returnt
imer;}structin_addrnewprefix2inaddr(uint8_t*prefix_start,uint8_tprefix_masklen){
memset(&new_prefix,0,sizeof(new_prefix));memcpy(&new_prefix,prefix_start,(prefix
_masklen&0x3F)?((((prefix_masklen&0x3F)-1)>>3)+1):0);returnnew_prefix;}/**Return
sthedynamichostnameassociatedwiththepassedsystemID.*Ifnodynamichostnamefoundthen
returnsformattedsystemID.*/constchar*print_sys_hostname(constuint8_t*sysid){stru
ctisis_dynhn*dyn;if(!sysid)return"nullsysid";/*ForoursystemIDreturnourhostname*/
if(memcmp(sysid,isis->sysid,ISIS_SYS_ID_LEN)==0)returncmd_hostname_get();dyn=dyn
hn_find_by_id(sysid);if(dyn)returndyn->hostname;returnsysid_print(sysid);}/**Thi
sfunctionisagenericutilitythatlogsdataofgivenlength.*Movethistoasharedlibsothata
nyprotocolcanuseit.*/voidzlog_dump_data(void*data,intlen){inti;unsignedchar*p;un
signedcharc;charbytestr[4];charaddrstr[10];charhexstr[16*3+5];charcharstr[16*1+5
];p=data;memset(bytestr,0,sizeof(bytestr));memset(addrstr,0,sizeof(addrstr));mem
set(hexstr,0,sizeof(hexstr));memset(charstr,0,sizeof(charstr));for(i=1;i<=len;i+
+){c=*p;if(isalnum(c)==0)c='.';/*storeaddressforthisline*/if((i%16)==1)snprintf(
addrstr,sizeof(addrstr),"%p",p);/*storehexstr(forleftside)*/snprintf(bytestr,siz
eof(bytestr),"%02X",*p);strncat(hexstr,bytestr,sizeof(hexstr)-strlen(hexstr)-1);
/*storecharstr(forrightside)*/snprintf(bytestr,sizeof(bytestr),"%c",c);strncat(c
harstr,bytestr,sizeof(charstr)-strlen(charstr)-1);if((i%16)==0){/*linecompleted*
/zlog_debug("[%8.8s]%-50.50s%s",addrstr,hexstr,charstr);hexstr[0]=0;charstr[0]=0
;}elseif((i%8)==0){/*halfline:addwhitespaces*/strncat(hexstr,"",sizeof(hexstr)-s
trlen(hexstr)-1);strncat(charstr,"",sizeof(charstr)-strlen(charstr)-1);}p++;/*ne
xtbyte*/}/*printrestofbufferifnotempty*/if(strlen(hexstr)>0)zlog_debug("[%8.8s]%
-50.50s%s",addrstr,hexstr,charstr);return;}staticchar*qasprintf(constchar*format
,va_listap){va_listaq;va_copy(aq,ap);intsize=0;char*p=NULL;size=vsnprintf(p,size
,format,ap);if(size<0){va_end(aq);returnNULL;}size++;p=XMALLOC(MTYPE_TMP,size);s
ize=vsnprintf(p,size,format,aq);va_end(aq);if(size<0){XFREE(MTYPE_TMP,p);returnN
ULL;}returnp;}voidlog_multiline(intpriority,constchar*prefix,constchar*format,..
.){va_listap;char*p;va_start(ap,format);p=qasprintf(format,ap);va_end(ap);if(!p)
return;char*saveptr=NULL;for(char*line=strtok_r(p,"\n",&saveptr);line;line=strto
k_r(NULL,"\n",&saveptr)){zlog(priority,"%s%s",prefix,line);}XFREE(MTYPE_TMP,p);}
voidvty_multiline(structvty*vty,constchar*prefix,constchar*format,...){va_listap
;char*p;va_start(ap,format);p=qasprintf(format,ap);va_end(ap);if(!p)return;char*
saveptr=NULL;for(char*line=strtok_r(p,"\n",&saveptr);line;line=strtok_r(NULL,"\n
",&saveptr)){vty_out(vty,"%s%s\n",prefix,line);}XFREE(MTYPE_TMP,p);}voidvty_out_
timestr(structvty*vty,time_tuptime){structtm*tm;time_tdifftime=time(NULL);diffti
me-=uptime;tm=gmtime(&difftime);if(difftime<ONE_DAY_SECOND)vty_out(vty,"%02d:%02
d:%02d",tm->tm_hour,tm->tm_min,tm->tm_sec);elseif(difftime<ONE_WEEK_SECOND)vty_o
ut(vty,"%dd%02dh%02dm",tm->tm_yday,tm->tm_hour,tm->tm_min);elsevty_out(vty,"%02d
w%dd%02dh",tm->tm_yday/7,tm->tm_yday-((tm->tm_yday/7)*7),tm->tm_hour);vty_out(vt
y,"ago");}