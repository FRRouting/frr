/*getopt_longandgetopt_long_onlyentrypointsforGNUgetopt.*Copyright(C)1987,88,89,
90,91,92,93,94,96,97,98*FreeSoftwareFoundation,Inc.**NOTE:Thecanonicalsourceofth
isfileismaintainedwiththeGNUCLibrary.*Bugscanbereportedtobug-glibc@gnu.org.**Thi
sprogramisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNUG
eneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(aty
ouroption)any*laterversion.**Thisprogramisdistributedinthehopethatitwillbeuseful
,*butWITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESS
FORAPARTICULARPURPOSE.Seethe*GNUGeneralPublicLicenseformoredetails.**Youshouldha
vereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYI
NG;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,M
A02110-1301USA*/#include<zebra.h>#include"getopt.h"#if!defined__STDC__||!__STDC_
_/*Thisisaseparateconditionalsincesomestdcsystemsreject`defined(const)'.*/#ifnde
fconst#defineconst#endif#endif#include<stdio.h>/*Commentoutallthiscodeifweareusi
ngtheGNUCLibrary,andarenotactuallycompilingthelibraryitself.ThiscodeispartoftheG
NUCLibrary,butalsoincludedinmanyotherGNUdistributions.Compilingandlinkinginthisc
odeisawastewhenusingtheGNUClibrary(especiallyifitisasharedlibrary).Ratherthanhav
ingeveryGNUprogramunderstand`configure--with-gnu-libc'andomittheobjectfiles,itis
simplertojustdothisinthesourceforeachsuchfile.*/#defineGETOPT_INTERFACE_VERSION2
#if!defined_LIBC&&defined__GLIBC__&&__GLIBC__>=2#include<gnu-versions.h>#if_GNU_
GETOPT_INTERFACE_VERSION==GETOPT_INTERFACE_VERSION#defineELIDE_CODE#endif#endif#
ifndefELIDE_CODE/*Thisneedstocomeaftersomelibrary#includetoget__GNU_LIBRARY__def
ined.*/#ifdef__GNU_LIBRARY__#include<stdlib.h>#endif#ifndefNULL#defineNULL0#endi
fintgetopt_long(argc,argv,options,long_options,opt_index)intargc;char*const*argv
;constchar*options;conststructoption*long_options;int*opt_index;{return_getopt_i
nternal(argc,argv,options,long_options,opt_index,0);}/*Likegetopt_long,but'-'asw
ellas'--'canindicatealongoption.Ifanoptionthatstartswith'-'(not'--')doesn'tmatch
alongoption,butdoesmatchashortoption,itisparsedasashortoptioninstead.*/intgetopt
_long_only(argc,argv,options,long_options,opt_index)intargc;char*const*argv;cons
tchar*options;conststructoption*long_options;int*opt_index;{return_getopt_intern
al(argc,argv,options,long_options,opt_index,1);}#endif/*NotELIDE_CODE.*/#ifdefTE
ST#include<stdio.h>intmain(argc,argv)intargc;char**argv;{intc;intdigit_optind=0;
while(1){intthis_option_optind=optind?optind:1;intoption_index=0;staticstructopt
ionlong_options[]={{"add",1,0,0},{"append",0,0,0},{"delete",1,0,0},{"verbose",0,
0,0},{"create",0,0,0},{"file",1,0,0},{0,0,0,0}};c=getopt_long(argc,argv,"abc:d:0
123456789",long_options,&option_index);if(c==-1)break;switch(c){case0:printf("op
tion%s",long_options[option_index].name);if(optarg)printf("witharg%s",optarg);pr
intf("\n");break;case'0':case'1':case'2':case'3':case'4':case'5':case'6':case'7'
:case'8':case'9':if(digit_optind!=0&&digit_optind!=this_option_optind)printf("di
gitsoccurintwodifferentargv-elements.\n");digit_optind=this_option_optind;printf
("option%c\n",c);break;case'a':printf("optiona\n");break;case'b':printf("optionb
\n");break;case'c':printf("optioncwithvalue`%s'\n",optarg);break;case'd':printf(
"optiondwithvalue`%s'\n",optarg);break;case'?':break;default:printf("??getoptret
urnedcharactercode0%o??\n",c);}}if(optind<argc){printf("non-optionARGV-elements:
");while(optind<argc)printf("%s",argv[optind++]);printf("\n");}exit(0);}#endif/*
TEST*/