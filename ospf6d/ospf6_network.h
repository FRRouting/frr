/**Copyright(C)2003YasuhiroOhara**ThisfileispartofGNUZebra.**GNUZebraisfreesoftw
are;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicense
aspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(atyouroption)any*later
version.**GNUZebraisdistributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANT
Y;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.
SeetheGNU*GeneralPublicLicenseformoredetails.**YoushouldhavereceivedacopyoftheGN
UGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,writetotheFre
eSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#ifnde
fOSPF6_NETWORK_H#defineOSPF6_NETWORK_Hexternintospf6_sock;externstructin6_addral
lspfrouters6;externstructin6_addralldrouters6;externintospf6_serv_sock(void);ext
ernintospf6_sso(ifindex_tifindex,structin6_addr*group,intoption);externintospf6_
sendmsg(structin6_addr*,structin6_addr*,ifindex_t*,structiovec*);externintospf6_
recvmsg(structin6_addr*,structin6_addr*,ifindex_t*,structiovec*);#endif/*OSPF6_N
ETWORK_H*/