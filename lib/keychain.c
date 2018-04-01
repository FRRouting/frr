/*key-chainforauthentication.*Copyright(C)2000KunihiroIshiguro**Thisfileispartof
GNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormodify*itundertheter
msoftheGNUGeneralPublicLicenseaspublished*bytheFreeSoftwareFoundation;eithervers
ion2,or(atyour*option)anylaterversion.**GNUZebraisdistributedinthehopethatitwill
beuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYo
rFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**You
shouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethef
ileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,
Boston,MA02110-1301USA*/#include<zebra.h>#include"command.h"#include"memory.h"#i
nclude"linklist.h"#include"keychain.h"DEFINE_MTYPE_STATIC(LIB,KEY,"Key")DEFINE_M
TYPE_STATIC(LIB,KEYCHAIN,"Keychain")DEFINE_QOBJ_TYPE(keychain)DEFINE_QOBJ_TYPE(k
ey)/*Masterlistofkeychain.*/structlist*keychain_list;staticstructkeychain*keycha
in_new(void){structkeychain*keychain;keychain=XCALLOC(MTYPE_KEYCHAIN,sizeof(stru
ctkeychain));QOBJ_REG(keychain,keychain);returnkeychain;}staticvoidkeychain_free
(structkeychain*keychain){QOBJ_UNREG(keychain);XFREE(MTYPE_KEYCHAIN,keychain);}s
taticstructkey*key_new(void){structkey*key=XCALLOC(MTYPE_KEY,sizeof(structkey));
QOBJ_REG(key,key);returnkey;}staticvoidkey_free(structkey*key){QOBJ_UNREG(key);X
FREE(MTYPE_KEY,key);}structkeychain*keychain_lookup(constchar*name){structlistno
de*node;structkeychain*keychain;if(name==NULL)returnNULL;for(ALL_LIST_ELEMENTS_R
O(keychain_list,node,keychain)){if(strcmp(keychain->name,name)==0)returnkeychain
;}returnNULL;}staticintkey_cmp_func(void*arg1,void*arg2){conststructkey*k1=arg1;
conststructkey*k2=arg2;if(k1->index>k2->index)return1;if(k1->index<k2->index)ret
urn-1;return0;}staticvoidkey_delete_func(structkey*key){if(key->string)free(key-
>string);key_free(key);}staticstructkeychain*keychain_get(constchar*name){struct
keychain*keychain;keychain=keychain_lookup(name);if(keychain)returnkeychain;keyc
hain=keychain_new();keychain->name=XSTRDUP(MTYPE_KEYCHAIN,name);keychain->key=li
st_new();keychain->key->cmp=(int(*)(void*,void*))key_cmp_func;keychain->key->del
=(void(*)(void*))key_delete_func;listnode_add(keychain_list,keychain);returnkeyc
hain;}staticvoidkeychain_delete(structkeychain*keychain){if(keychain->name)XFREE
(MTYPE_KEYCHAIN,keychain->name);list_delete_and_null(&keychain->key);listnode_de
lete(keychain_list,keychain);keychain_free(keychain);}staticstructkey*key_lookup
(conststructkeychain*keychain,uint32_tindex){structlistnode*node;structkey*key;f
or(ALL_LIST_ELEMENTS_RO(keychain->key,node,key)){if(key->index==index)returnkey;
}returnNULL;}structkey*key_lookup_for_accept(conststructkeychain*keychain,uint32
_tindex){structlistnode*node;structkey*key;time_tnow;now=time(NULL);for(ALL_LIST
_ELEMENTS_RO(keychain->key,node,key)){if(key->index>=index){if(key->accept.start
==0)returnkey;if(key->accept.start<=now)if(key->accept.end>=now||key->accept.end
==-1)returnkey;}}returnNULL;}structkey*key_match_for_accept(conststructkeychain*
keychain,constchar*auth_str){structlistnode*node;structkey*key;time_tnow;now=tim
e(NULL);for(ALL_LIST_ELEMENTS_RO(keychain->key,node,key)){if(key->accept.start==
0||(key->accept.start<=now&&(key->accept.end>=now||key->accept.end==-1)))if(strn
cmp(key->string,auth_str,16)==0)returnkey;}returnNULL;}structkey*key_lookup_for_
send(conststructkeychain*keychain){structlistnode*node;structkey*key;time_tnow;n
ow=time(NULL);for(ALL_LIST_ELEMENTS_RO(keychain->key,node,key)){if(key->send.sta
rt==0)returnkey;if(key->send.start<=now)if(key->send.end>=now||key->send.end==-1
)returnkey;}returnNULL;}staticstructkey*key_get(conststructkeychain*keychain,uin
t32_tindex){structkey*key;key=key_lookup(keychain,index);if(key)returnkey;key=ke
y_new();key->index=index;listnode_add_sort(keychain->key,key);returnkey;}staticv
oidkey_delete(structkeychain*keychain,structkey*key){listnode_delete(keychain->k
ey,key);if(key->string)XFREE(MTYPE_KEY,key->string);key_free(key);}DEFUN_NOSH(ke
y_chain,key_chain_cmd,"keychainWORD","Authenticationkeymanagement\n""Key-chainma
nagement\n""Key-chainname\n"){intidx_word=2;structkeychain*keychain;keychain=key
chain_get(argv[idx_word]->arg);VTY_PUSH_CONTEXT(KEYCHAIN_NODE,keychain);returnCM
D_SUCCESS;}DEFUN(no_key_chain,no_key_chain_cmd,"nokeychainWORD",NO_STR"Authentic
ationkeymanagement\n""Key-chainmanagement\n""Key-chainname\n"){intidx_word=3;str
uctkeychain*keychain;keychain=keychain_lookup(argv[idx_word]->arg);if(!keychain)
{vty_out(vty,"Can'tfindkeychain%s\n",argv[idx_word]->arg);returnCMD_WARNING_CONF
IG_FAILED;}keychain_delete(keychain);returnCMD_SUCCESS;}DEFUN_NOSH(key,key_cmd,"
key(0-2147483647)","Configureakey\n""Keyidentifiernumber\n"){intidx_number=1;VTY
_DECLVAR_CONTEXT(keychain,keychain);structkey*key;uint32_tindex;index=strtoul(ar
gv[idx_number]->arg,NULL,10);key=key_get(keychain,index);VTY_PUSH_CONTEXT_SUB(KE
YCHAIN_KEY_NODE,key);returnCMD_SUCCESS;}DEFUN(no_key,no_key_cmd,"nokey(0-2147483
647)",NO_STR"Deleteakey\n""Keyidentifiernumber\n"){intidx_number=2;VTY_DECLVAR_C
ONTEXT(keychain,keychain);structkey*key;uint32_tindex;index=strtoul(argv[idx_num
ber]->arg,NULL,10);key=key_lookup(keychain,index);if(!key){vty_out(vty,"Can'tfin
dkey%d\n",index);returnCMD_WARNING_CONFIG_FAILED;}key_delete(keychain,key);vty->
node=KEYCHAIN_NODE;returnCMD_SUCCESS;}DEFUN(key_string,key_string_cmd,"key-strin
gLINE","Setkeystring\n""Thekey\n"){intidx_line=1;VTY_DECLVAR_CONTEXT_SUB(key,key
);if(key->string)XFREE(MTYPE_KEY,key->string);key->string=XSTRDUP(MTYPE_KEY,argv
[idx_line]->arg);returnCMD_SUCCESS;}DEFUN(no_key_string,no_key_string_cmd,"nokey
-string[LINE]",NO_STR"Unsetkeystring\n""Thekey\n"){VTY_DECLVAR_CONTEXT_SUB(key,k
ey);if(key->string){XFREE(MTYPE_KEY,key->string);key->string=NULL;}returnCMD_SUC
CESS;}/*ConvertHH:MM:SSMONDAYYEARtotime_tvalue.-1isreturnedwhengivenstringismalf
ormed.*/statictime_tkey_str2time(constchar*time_str,constchar*day_str,constchar*
month_str,constchar*year_str){inti=0;char*colon;structtmtm;time_ttime;unsignedin
tsec,min,hour;unsignedintday,month,year;constchar*month_name[]={"January","Febru
ary","March","April","May","June","July","August","September","October","Novembe
r","December",NULL};#define_GET_LONG_RANGE(V,STR,MMCOND)\{\unsignedlongtmpl;\cha
r*endptr=NULL;\tmpl=strtoul((STR),&endptr,10);\if(*endptr!='\0'||tmpl==ULONG_MAX
)\return-1;\if(MMCOND)\return-1;\(V)=tmpl;\}#defineGET_LONG_RANGE(V,STR,MIN,MAX)
\_GET_LONG_RANGE(V,STR,tmpl<(MIN)||tmpl>(MAX))#defineGET_LONG_RANGE0(V,STR,MAX)_
GET_LONG_RANGE(V,STR,tmpl>(MAX))/*Checkhourfieldoftime_str.*/colon=strchr(time_s
tr,':');if(colon==NULL)return-1;*colon='\0';/*Hourmustbebetween0and23.*/GET_LONG
_RANGE0(hour,time_str,23);/*Checkminfieldoftime_str.*/time_str=colon+1;colon=str
chr(time_str,':');if(*time_str=='\0'||colon==NULL)return-1;*colon='\0';/*Minmust
bebetween0and59.*/GET_LONG_RANGE0(min,time_str,59);/*Checksecfieldoftime_str.*/t
ime_str=colon+1;if(*time_str=='\0')return-1;/*Secmustbebetween0and59.*/GET_LONG_
RANGE0(sec,time_str,59);/*Checkday_str.Daymustbe<1-31>.*/GET_LONG_RANGE(day,day_
str,1,31);/*Checkmonth_str.Monthmustmatchmonth_name.*/month=0;if(strlen(month_st
r)>=3)for(i=0;month_name[i];i++)if(strncmp(month_str,month_name[i],strlen(month_
str))==0){month=i;break;}if(!month_name[i])return-1;/*Checkyear_str.Yearmustbe<1
993-2035>.*/GET_LONG_RANGE(year,year_str,1993,2035);memset(&tm,0,sizeof(structtm
));tm.tm_sec=sec;tm.tm_min=min;tm.tm_hour=hour;tm.tm_mon=month;tm.tm_mday=day;tm
.tm_year=year-1900;time=mktime(&tm);returntime;#undefGET_LONG_RANGE}staticintkey
_lifetime_set(structvty*vty,structkey_range*krange,constchar*stime_str,constchar
*sday_str,constchar*smonth_str,constchar*syear_str,constchar*etime_str,constchar
*eday_str,constchar*emonth_str,constchar*eyear_str){time_ttime_start;time_ttime_
end;time_start=key_str2time(stime_str,sday_str,smonth_str,syear_str);if(time_sta
rt<0){vty_out(vty,"Malformedtimevalue\n");returnCMD_WARNING_CONFIG_FAILED;}time_
end=key_str2time(etime_str,eday_str,emonth_str,eyear_str);if(time_end<0){vty_out
(vty,"Malformedtimevalue\n");returnCMD_WARNING_CONFIG_FAILED;}if(time_end<=time_
start){vty_out(vty,"Expiretimeisnotlaterthanstarttime\n");returnCMD_WARNING_CONF
IG_FAILED;}krange->start=time_start;krange->end=time_end;returnCMD_SUCCESS;}stat
icintkey_lifetime_duration_set(structvty*vty,structkey_range*krange,constchar*st
ime_str,constchar*sday_str,constchar*smonth_str,constchar*syear_str,constchar*du
ration_str){time_ttime_start;uint32_tduration;time_start=key_str2time(stime_str,
sday_str,smonth_str,syear_str);if(time_start<0){vty_out(vty,"Malformedtimevalue\
n");returnCMD_WARNING_CONFIG_FAILED;}krange->start=time_start;duration=strtoul(d
uration_str,NULL,10);krange->duration=1;krange->end=time_start+duration;returnCM
D_SUCCESS;}staticintkey_lifetime_infinite_set(structvty*vty,structkey_range*kran
ge,constchar*stime_str,constchar*sday_str,constchar*smonth_str,constchar*syear_s
tr){time_ttime_start;time_start=key_str2time(stime_str,sday_str,smonth_str,syear
_str);if(time_start<0){vty_out(vty,"Malformedtimevalue\n");returnCMD_WARNING_CON
FIG_FAILED;}krange->start=time_start;krange->end=-1;returnCMD_SUCCESS;}DEFUN(acc
ept_lifetime_day_month_day_month,accept_lifetime_day_month_day_month_cmd,"accept
-lifetimeHH:MM:SS(1-31)MONTH(1993-2035)HH:MM:SS(1-31)MONTH(1993-2035)","Setaccep
tlifetimeofthekey\n""Timetostart\n""Dayofthmonthtostart\n""Monthoftheyeartostart
\n""Yeartostart\n""Timetoexpire\n""Dayofthmonthtoexpire\n""Monthoftheyeartoexpir
e\n""Yeartoexpire\n"){intidx_hhmmss=1;intidx_number=2;intidx_month=3;intidx_numb
er_2=4;intidx_hhmmss_2=5;intidx_number_3=6;intidx_month_2=7;intidx_number_4=8;VT
Y_DECLVAR_CONTEXT_SUB(key,key);returnkey_lifetime_set(vty,&key->accept,argv[idx_
hhmmss]->arg,argv[idx_number]->arg,argv[idx_month]->arg,argv[idx_number_2]->arg,
argv[idx_hhmmss_2]->arg,argv[idx_number_3]->arg,argv[idx_month_2]->arg,argv[idx_
number_4]->arg);}DEFUN(accept_lifetime_day_month_month_day,accept_lifetime_day_m
onth_month_day_cmd,"accept-lifetimeHH:MM:SS(1-31)MONTH(1993-2035)HH:MM:SSMONTH(1
-31)(1993-2035)","Setacceptlifetimeofthekey\n""Timetostart\n""Dayofthmonthtostar
t\n""Monthoftheyeartostart\n""Yeartostart\n""Timetoexpire\n""Monthoftheyeartoexp
ire\n""Dayofthmonthtoexpire\n""Yeartoexpire\n"){intidx_hhmmss=1;intidx_number=2;
intidx_month=3;intidx_number_2=4;intidx_hhmmss_2=5;intidx_month_2=6;intidx_numbe
r_3=7;intidx_number_4=8;VTY_DECLVAR_CONTEXT_SUB(key,key);returnkey_lifetime_set(
vty,&key->accept,argv[idx_hhmmss]->arg,argv[idx_number]->arg,argv[idx_month]->ar
g,argv[idx_number_2]->arg,argv[idx_hhmmss_2]->arg,argv[idx_number_3]->arg,argv[i
dx_month_2]->arg,argv[idx_number_4]->arg);}DEFUN(accept_lifetime_month_day_day_m
onth,accept_lifetime_month_day_day_month_cmd,"accept-lifetimeHH:MM:SSMONTH(1-31)
(1993-2035)HH:MM:SS(1-31)MONTH(1993-2035)","Setacceptlifetimeofthekey\n""Timetos
tart\n""Monthoftheyeartostart\n""Dayofthmonthtostart\n""Yeartostart\n""Timetoexp
ire\n""Dayofthmonthtoexpire\n""Monthoftheyeartoexpire\n""Yeartoexpire\n"){intidx
_hhmmss=1;intidx_month=2;intidx_number=3;intidx_number_2=4;intidx_hhmmss_2=5;int
idx_number_3=6;intidx_month_2=7;intidx_number_4=8;VTY_DECLVAR_CONTEXT_SUB(key,ke
y);returnkey_lifetime_set(vty,&key->accept,argv[idx_hhmmss]->arg,argv[idx_number
]->arg,argv[idx_month]->arg,argv[idx_number_2]->arg,argv[idx_hhmmss_2]->arg,argv
[idx_number_3]->arg,argv[idx_month_2]->arg,argv[idx_number_4]->arg);}DEFUN(accep
t_lifetime_month_day_month_day,accept_lifetime_month_day_month_day_cmd,"accept-l
ifetimeHH:MM:SSMONTH(1-31)(1993-2035)HH:MM:SSMONTH(1-31)(1993-2035)","Setacceptl
ifetimeofthekey\n""Timetostart\n""Monthoftheyeartostart\n""Dayofthmonthtostart\n
""Yeartostart\n""Timetoexpire\n""Monthoftheyeartoexpire\n""Dayofthmonthtoexpire\
n""Yeartoexpire\n"){intidx_hhmmss=1;intidx_month=2;intidx_number=3;intidx_number
_2=4;intidx_hhmmss_2=5;intidx_month_2=6;intidx_number_3=7;intidx_number_4=8;VTY_
DECLVAR_CONTEXT_SUB(key,key);returnkey_lifetime_set(vty,&key->accept,argv[idx_hh
mmss]->arg,argv[idx_number]->arg,argv[idx_month]->arg,argv[idx_number_2]->arg,ar
gv[idx_hhmmss_2]->arg,argv[idx_number_3]->arg,argv[idx_month_2]->arg,argv[idx_nu
mber_4]->arg);}DEFUN(accept_lifetime_infinite_day_month,accept_lifetime_infinite
_day_month_cmd,"accept-lifetimeHH:MM:SS(1-31)MONTH(1993-2035)infinite","Setaccep
tlifetimeofthekey\n""Timetostart\n""Dayofthmonthtostart\n""Monthoftheyeartostart
\n""Yeartostart\n""Neverexpires\n"){intidx_hhmmss=1;intidx_number=2;intidx_month
=3;intidx_number_2=4;VTY_DECLVAR_CONTEXT_SUB(key,key);returnkey_lifetime_infinit
e_set(vty,&key->accept,argv[idx_hhmmss]->arg,argv[idx_number]->arg,argv[idx_mont
h]->arg,argv[idx_number_2]->arg);}DEFUN(accept_lifetime_infinite_month_day,accep
t_lifetime_infinite_month_day_cmd,"accept-lifetimeHH:MM:SSMONTH(1-31)(1993-2035)
infinite","Setacceptlifetimeofthekey\n""Timetostart\n""Monthoftheyeartostart\n""
Dayofthmonthtostart\n""Yeartostart\n""Neverexpires\n"){intidx_hhmmss=1;intidx_mo
nth=2;intidx_number=3;intidx_number_2=4;VTY_DECLVAR_CONTEXT_SUB(key,key);returnk
ey_lifetime_infinite_set(vty,&key->accept,argv[idx_hhmmss]->arg,argv[idx_number]
->arg,argv[idx_month]->arg,argv[idx_number_2]->arg);}DEFUN(accept_lifetime_durat
ion_day_month,accept_lifetime_duration_day_month_cmd,"accept-lifetimeHH:MM:SS(1-
31)MONTH(1993-2035)duration(1-2147483646)","Setacceptlifetimeofthekey\n""Timetos
tart\n""Dayofthmonthtostart\n""Monthoftheyeartostart\n""Yeartostart\n""Durationo
fthekey\n""Durationseconds\n"){intidx_hhmmss=1;intidx_number=2;intidx_month=3;in
tidx_number_2=4;intidx_number_3=6;VTY_DECLVAR_CONTEXT_SUB(key,key);returnkey_lif
etime_duration_set(vty,&key->accept,argv[idx_hhmmss]->arg,argv[idx_number]->arg,
argv[idx_month]->arg,argv[idx_number_2]->arg,argv[idx_number_3]->arg);}DEFUN(acc
ept_lifetime_duration_month_day,accept_lifetime_duration_month_day_cmd,"accept-l
ifetimeHH:MM:SSMONTH(1-31)(1993-2035)duration(1-2147483646)","Setacceptlifetimeo
fthekey\n""Timetostart\n""Monthoftheyeartostart\n""Dayofthmonthtostart\n""Yearto
start\n""Durationofthekey\n""Durationseconds\n"){intidx_hhmmss=1;intidx_month=2;
intidx_number=3;intidx_number_2=4;intidx_number_3=6;VTY_DECLVAR_CONTEXT_SUB(key,
key);returnkey_lifetime_duration_set(vty,&key->accept,argv[idx_hhmmss]->arg,argv
[idx_number]->arg,argv[idx_month]->arg,argv[idx_number_2]->arg,argv[idx_number_3
]->arg);}DEFUN(no_accept_lifetime,no_accept_lifetime_cmd,"noaccept-lifetime",NO_
STR"Unsetaccept-lifetime\n"){VTY_DECLVAR_CONTEXT_SUB(key,key);if(key->accept.sta
rt)key->accept.start=0;if(key->accept.end)key->accept.end=0;if(key->accept.durat
ion)key->accept.duration=0;returnCMD_SUCCESS;}DEFUN(send_lifetime_day_month_day_
month,send_lifetime_day_month_day_month_cmd,"send-lifetimeHH:MM:SS(1-31)MONTH(19
93-2035)HH:MM:SS(1-31)MONTH(1993-2035)","Setsendlifetimeofthekey\n""Timetostart\
n""Dayofthmonthtostart\n""Monthoftheyeartostart\n""Yeartostart\n""Timetoexpire\n
""Dayofthmonthtoexpire\n""Monthoftheyeartoexpire\n""Yeartoexpire\n"){intidx_hhmm
ss=1;intidx_number=2;intidx_month=3;intidx_number_2=4;intidx_hhmmss_2=5;intidx_n
umber_3=6;intidx_month_2=7;intidx_number_4=8;VTY_DECLVAR_CONTEXT_SUB(key,key);re
turnkey_lifetime_set(vty,&key->send,argv[idx_hhmmss]->arg,argv[idx_number]->arg,
argv[idx_month]->arg,argv[idx_number_2]->arg,argv[idx_hhmmss_2]->arg,argv[idx_nu
mber_3]->arg,argv[idx_month_2]->arg,argv[idx_number_4]->arg);}DEFUN(send_lifetim
e_day_month_month_day,send_lifetime_day_month_month_day_cmd,"send-lifetimeHH:MM:
SS(1-31)MONTH(1993-2035)HH:MM:SSMONTH(1-31)(1993-2035)","Setsendlifetimeofthekey
\n""Timetostart\n""Dayofthmonthtostart\n""Monthoftheyeartostart\n""Yeartostart\n
""Timetoexpire\n""Monthoftheyeartoexpire\n""Dayofthmonthtoexpire\n""Yeartoexpire
\n"){intidx_hhmmss=1;intidx_number=2;intidx_month=3;intidx_number_2=4;intidx_hhm
mss_2=5;intidx_month_2=6;intidx_number_3=7;intidx_number_4=8;VTY_DECLVAR_CONTEXT
_SUB(key,key);returnkey_lifetime_set(vty,&key->send,argv[idx_hhmmss]->arg,argv[i
dx_number]->arg,argv[idx_month]->arg,argv[idx_number_2]->arg,argv[idx_hhmmss_2]-
>arg,argv[idx_number_3]->arg,argv[idx_month_2]->arg,argv[idx_number_4]->arg);}DE
FUN(send_lifetime_month_day_day_month,send_lifetime_month_day_day_month_cmd,"sen
d-lifetimeHH:MM:SSMONTH(1-31)(1993-2035)HH:MM:SS(1-31)MONTH(1993-2035)","Setsend
lifetimeofthekey\n""Timetostart\n""Monthoftheyeartostart\n""Dayofthmonthtostart\
n""Yeartostart\n""Timetoexpire\n""Dayofthmonthtoexpire\n""Monthoftheyeartoexpire
\n""Yeartoexpire\n"){intidx_hhmmss=1;intidx_month=2;intidx_number=3;intidx_numbe
r_2=4;intidx_hhmmss_2=5;intidx_number_3=6;intidx_month_2=7;intidx_number_4=8;VTY
_DECLVAR_CONTEXT_SUB(key,key);returnkey_lifetime_set(vty,&key->send,argv[idx_hhm
mss]->arg,argv[idx_number]->arg,argv[idx_month]->arg,argv[idx_number_2]->arg,arg
v[idx_hhmmss_2]->arg,argv[idx_number_3]->arg,argv[idx_month_2]->arg,argv[idx_num
ber_4]->arg);}DEFUN(send_lifetime_month_day_month_day,send_lifetime_month_day_mo
nth_day_cmd,"send-lifetimeHH:MM:SSMONTH(1-31)(1993-2035)HH:MM:SSMONTH(1-31)(1993
-2035)","Setsendlifetimeofthekey\n""Timetostart\n""Monthoftheyeartostart\n""Dayo
fthmonthtostart\n""Yeartostart\n""Timetoexpire\n""Monthoftheyeartoexpire\n""Dayo
fthmonthtoexpire\n""Yeartoexpire\n"){intidx_hhmmss=1;intidx_month=2;intidx_numbe
r=3;intidx_number_2=4;intidx_hhmmss_2=5;intidx_month_2=6;intidx_number_3=7;intid
x_number_4=8;VTY_DECLVAR_CONTEXT_SUB(key,key);returnkey_lifetime_set(vty,&key->s
end,argv[idx_hhmmss]->arg,argv[idx_number]->arg,argv[idx_month]->arg,argv[idx_nu
mber_2]->arg,argv[idx_hhmmss_2]->arg,argv[idx_number_3]->arg,argv[idx_month_2]->
arg,argv[idx_number_4]->arg);}DEFUN(send_lifetime_infinite_day_month,send_lifeti
me_infinite_day_month_cmd,"send-lifetimeHH:MM:SS(1-31)MONTH(1993-2035)infinite",
"Setsendlifetimeofthekey\n""Timetostart\n""Dayofthmonthtostart\n""Monthoftheyear
tostart\n""Yeartostart\n""Neverexpires\n"){intidx_hhmmss=1;intidx_number=2;intid
x_month=3;intidx_number_2=4;VTY_DECLVAR_CONTEXT_SUB(key,key);returnkey_lifetime_
infinite_set(vty,&key->send,argv[idx_hhmmss]->arg,argv[idx_number]->arg,argv[idx
_month]->arg,argv[idx_number_2]->arg);}DEFUN(send_lifetime_infinite_month_day,se
nd_lifetime_infinite_month_day_cmd,"send-lifetimeHH:MM:SSMONTH(1-31)(1993-2035)i
nfinite","Setsendlifetimeofthekey\n""Timetostart\n""Monthoftheyeartostart\n""Day
ofthmonthtostart\n""Yeartostart\n""Neverexpires\n"){intidx_hhmmss=1;intidx_month
=2;intidx_number=3;intidx_number_2=4;VTY_DECLVAR_CONTEXT_SUB(key,key);returnkey_
lifetime_infinite_set(vty,&key->send,argv[idx_hhmmss]->arg,argv[idx_number]->arg
,argv[idx_month]->arg,argv[idx_number_2]->arg);}DEFUN(send_lifetime_duration_day
_month,send_lifetime_duration_day_month_cmd,"send-lifetimeHH:MM:SS(1-31)MONTH(19
93-2035)duration(1-2147483646)","Setsendlifetimeofthekey\n""Timetostart\n""Dayof
thmonthtostart\n""Monthoftheyeartostart\n""Yeartostart\n""Durationofthekey\n""Du
rationseconds\n"){intidx_hhmmss=1;intidx_number=2;intidx_month=3;intidx_number_2
=4;intidx_number_3=6;VTY_DECLVAR_CONTEXT_SUB(key,key);returnkey_lifetime_duratio
n_set(vty,&key->send,argv[idx_hhmmss]->arg,argv[idx_number]->arg,argv[idx_month]
->arg,argv[idx_number_2]->arg,argv[idx_number_3]->arg);}DEFUN(send_lifetime_dura
tion_month_day,send_lifetime_duration_month_day_cmd,"send-lifetimeHH:MM:SSMONTH(
1-31)(1993-2035)duration(1-2147483646)","Setsendlifetimeofthekey\n""Timetostart\
n""Monthoftheyeartostart\n""Dayofthmonthtostart\n""Yeartostart\n""Durationofthek
ey\n""Durationseconds\n"){intidx_hhmmss=1;intidx_month=2;intidx_number=3;intidx_
number_2=4;intidx_number_3=6;VTY_DECLVAR_CONTEXT_SUB(key,key);returnkey_lifetime
_duration_set(vty,&key->send,argv[idx_hhmmss]->arg,argv[idx_number]->arg,argv[id
x_month]->arg,argv[idx_number_2]->arg,argv[idx_number_3]->arg);}DEFUN(no_send_li
fetime,no_send_lifetime_cmd,"nosend-lifetime",NO_STR"Unsetsend-lifetime\n"){VTY_
DECLVAR_CONTEXT_SUB(key,key);if(key->send.start)key->send.start=0;if(key->send.e
nd)key->send.end=0;if(key->send.duration)key->send.duration=0;returnCMD_SUCCESS;
}staticstructcmd_nodekeychain_node={KEYCHAIN_NODE,"%s(config-keychain)#",1};stat
icstructcmd_nodekeychain_key_node={KEYCHAIN_KEY_NODE,"%s(config-keychain-key)#",
1};staticintkeychain_strftime(char*buf,intbufsiz,time_t*time){structtm*tm;size_t
len;tm=localtime(time);len=strftime(buf,bufsiz,"%T%b%d%Y",tm);returnlen;}statici
ntkeychain_config_write(structvty*vty){structkeychain*keychain;structkey*key;str
uctlistnode*node;structlistnode*knode;charbuf[BUFSIZ];for(ALL_LIST_ELEMENTS_RO(k
eychain_list,node,keychain)){vty_out(vty,"keychain%s\n",keychain->name);for(ALL_
LIST_ELEMENTS_RO(keychain->key,knode,key)){vty_out(vty,"key%d\n",key->index);if(
key->string)vty_out(vty,"key-string%s\n",key->string);if(key->accept.start){keyc
hain_strftime(buf,BUFSIZ,&key->accept.start);vty_out(vty,"accept-lifetime%s",buf
);if(key->accept.end==-1)vty_out(vty,"infinite");elseif(key->accept.duration)vty
_out(vty,"duration%ld",(long)(key->accept.end-key->accept.start));else{keychain_
strftime(buf,BUFSIZ,&key->accept.end);vty_out(vty,"%s",buf);}vty_out(vty,"\n");}
if(key->send.start){keychain_strftime(buf,BUFSIZ,&key->send.start);vty_out(vty,"
send-lifetime%s",buf);if(key->send.end==-1)vty_out(vty,"infinite");elseif(key->s
end.duration)vty_out(vty,"duration%ld",(long)(key->send.end-key->send.start));el
se{keychain_strftime(buf,BUFSIZ,&key->send.end);vty_out(vty,"%s",buf);}vty_out(v
ty,"\n");}}vty_out(vty,"!\n");}return0;}voidkeychain_init(){keychain_list=list_n
ew();install_node(&keychain_node,keychain_config_write);install_node(&keychain_k
ey_node,NULL);install_default(KEYCHAIN_NODE);install_default(KEYCHAIN_KEY_NODE);
install_element(CONFIG_NODE,&key_chain_cmd);install_element(CONFIG_NODE,&no_key_
chain_cmd);install_element(KEYCHAIN_NODE,&key_cmd);install_element(KEYCHAIN_NODE
,&no_key_cmd);install_element(KEYCHAIN_NODE,&key_chain_cmd);install_element(KEYC
HAIN_NODE,&no_key_chain_cmd);install_element(KEYCHAIN_KEY_NODE,&key_string_cmd);
install_element(KEYCHAIN_KEY_NODE,&no_key_string_cmd);install_element(KEYCHAIN_K
EY_NODE,&key_chain_cmd);install_element(KEYCHAIN_KEY_NODE,&no_key_chain_cmd);ins
tall_element(KEYCHAIN_KEY_NODE,&key_cmd);install_element(KEYCHAIN_KEY_NODE,&no_k
ey_cmd);install_element(KEYCHAIN_KEY_NODE,&accept_lifetime_day_month_day_month_c
md);install_element(KEYCHAIN_KEY_NODE,&accept_lifetime_day_month_month_day_cmd);
install_element(KEYCHAIN_KEY_NODE,&accept_lifetime_month_day_day_month_cmd);inst
all_element(KEYCHAIN_KEY_NODE,&accept_lifetime_month_day_month_day_cmd);install_
element(KEYCHAIN_KEY_NODE,&accept_lifetime_infinite_day_month_cmd);install_eleme
nt(KEYCHAIN_KEY_NODE,&accept_lifetime_infinite_month_day_cmd);install_element(KE
YCHAIN_KEY_NODE,&accept_lifetime_duration_day_month_cmd);install_element(KEYCHAI
N_KEY_NODE,&accept_lifetime_duration_month_day_cmd);install_element(KEYCHAIN_KEY
_NODE,&no_accept_lifetime_cmd);install_element(KEYCHAIN_KEY_NODE,&send_lifetime_
day_month_day_month_cmd);install_element(KEYCHAIN_KEY_NODE,&send_lifetime_day_mo
nth_month_day_cmd);install_element(KEYCHAIN_KEY_NODE,&send_lifetime_month_day_da
y_month_cmd);install_element(KEYCHAIN_KEY_NODE,&send_lifetime_month_day_month_da
y_cmd);install_element(KEYCHAIN_KEY_NODE,&send_lifetime_infinite_day_month_cmd);
install_element(KEYCHAIN_KEY_NODE,&send_lifetime_infinite_month_day_cmd);install
_element(KEYCHAIN_KEY_NODE,&send_lifetime_duration_day_month_cmd);install_elemen
t(KEYCHAIN_KEY_NODE,&send_lifetime_duration_month_day_cmd);install_element(KEYCH
AIN_KEY_NODE,&no_send_lifetime_cmd);}