/*Copyright(c)20156WINDS.A.*Author:NicolasDichtel<nicolas.dichtel@6wind.com>**Th
isprogramisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsandcondi
tionsoftheGNUGeneralPublicLicense,*version2,aspublishedbytheFreeSoftwareFoundati
on.*/#ifndef_LINUX_NET_NAMESPACE_H_#define_LINUX_NET_NAMESPACE_H_/*AttributesofR
TM_NEWNSID/RTM_GETNSIDmessages*/enum{NETNSA_NONE,#defineNETNSA_NSID_NOT_ASSIGNED
-1NETNSA_NSID,NETNSA_PID,NETNSA_FD,__NETNSA_MAX,};#defineNETNSA_MAX(__NETNSA_MAX
-1)#endif/*_LINUX_NET_NAMESPACE_H_*/