/**PIMforQuagga*Copyright(C)2008EvertondaSilvaMarques**Thisprogramisfreesoftware
;youcanredistributeitand/ormodify*itunderthetermsoftheGNUGeneralPublicLicenseasp
ublishedby*theFreeSoftwareFoundation;eitherversion2oftheLicense,or*(atyouroption
)anylaterversion.**Thisprogramisdistributedinthehopethatitwillbeuseful,but*WITHO
UTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTIC
ULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceived
acopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,w
ritetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-130
1USA*/#include<zebra.h>#include<string.h>#include<sys/time.h>#include<time.h>#in
clude"log.h"#include"thread.h"#include"pim_time.h"staticintgettime_monotonic(str
ucttimeval*tv){intresult;result=gettimeofday(tv,0);if(result){zlog_err("%s:getti
meofday()failure:errno=%d:%s",__PRETTY_FUNCTION__,errno,safe_strerror(errno));}r
eturnresult;}/*pim_time_monotonic_sec():numberofsecondssincesomeunspecifiedstart
ingpoint*/int64_tpim_time_monotonic_sec(){structtimevalnow_tv;if(gettime_monoton
ic(&now_tv)){zlog_err("%s:gettime_monotonic()failure:errno=%d:%s",__PRETTY_FUNCT
ION__,errno,safe_strerror(errno));return-1;}returnnow_tv.tv_sec;}/*pim_time_mono
tonic_dsec():numberofdecisecondssincesomeunspecifiedstartingpoint*/int64_tpim_ti
me_monotonic_dsec(){structtimevalnow_tv;int64_tnow_dsec;if(gettime_monotonic(&no
w_tv)){zlog_err("%s:gettime_monotonic()failure:errno=%d:%s",__PRETTY_FUNCTION__,
errno,safe_strerror(errno));return-1;}now_dsec=((int64_t)now_tv.tv_sec)*10+((int
64_t)now_tv.tv_usec)/100000;returnnow_dsec;}int64_tpim_time_monotonic_usec(void)
{structtimevalnow_tv;int64_tnow_dsec;if(gettime_monotonic(&now_tv)){zlog_err("%s
:gettime_monotonic()failure:errno=%d:%s",__PRETTY_FUNCTION__,errno,safe_strerror
(errno));return-1;}now_dsec=((int64_t)now_tv.tv_sec)*1000000+((int64_t)now_tv.tv
_usec);returnnow_dsec;}intpim_time_mmss(char*buf,intbuf_size,longsec){longmm;int
wr;zassert(buf_size>=5);mm=sec/60;sec%=60;wr=snprintf(buf,buf_size,"%02ld:%02ld"
,mm,sec);returnwr!=8;}staticintpim_time_hhmmss(char*buf,intbuf_size,longsec){lon
ghh;longmm;intwr;zassert(buf_size>=8);hh=sec/3600;sec%=3600;mm=sec/60;sec%=60;wr
=snprintf(buf,buf_size,"%02ld:%02ld:%02ld",hh,mm,sec);returnwr!=8;}voidpim_time_
timer_to_mmss(char*buf,intbuf_size,structthread*t_timer){if(t_timer){pim_time_mm
ss(buf,buf_size,thread_timer_remain_second(t_timer));}else{snprintf(buf,buf_size
,"--:--");}}voidpim_time_timer_to_hhmmss(char*buf,intbuf_size,structthread*t_tim
er){if(t_timer){pim_time_hhmmss(buf,buf_size,thread_timer_remain_second(t_timer)
);}else{snprintf(buf,buf_size,"--:--:--");}}voidpim_time_uptime(char*buf,intbuf_
size,int64_tuptime_sec){zassert(buf_size>=8);pim_time_hhmmss(buf,buf_size,uptime
_sec);}voidpim_time_uptime_begin(char*buf,intbuf_size,int64_tnow,int64_tbegin){i
f(begin>0)pim_time_uptime(buf,buf_size,now-begin);elsesnprintf(buf,buf_size,"--:
--:--");}longpim_time_timer_remain_msec(structthread*t_timer){/*FIXME:Actuallyfe
tchmsecresolutionfromthread*//*notimerthreadrunningmeanstimerhasexpired:return0*
/returnt_timer?1000*thread_timer_remain_second(t_timer):0;}