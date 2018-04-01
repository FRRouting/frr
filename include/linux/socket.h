#ifndef_LINUX_SOCKET_H#define_LINUX_SOCKET_H/**Desireddesignofmaximumsizeandalig
nment(seeRFC2553)*/#define_K_SS_MAXSIZE128/*Implementationspecificmaxsize*/#defi
ne_K_SS_ALIGNSIZE(__alignof__(structsockaddr*))/*Implementationspecificdesiredal
ignment*/typedefunsignedshort__kernel_sa_family_t;struct__kernel_sockaddr_storag
e{__kernel_sa_family_tss_family;/*addressfamily*//*Followingfield(s)areimplement
ationspecific*/char__data[_K_SS_MAXSIZE-sizeof(unsignedshort)];/*spacetoachieved
esiredsize,*//*_SS_MAXSIZEvalueminussizeofss_family*/}__attribute__((aligned(_K_
SS_ALIGNSIZE)));/*forcedesiredalignment*/#endif/*_LINUX_SOCKET_H*/