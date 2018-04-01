/**mplstunnelapi**Authors:*RoopaPrabhu<roopa@cumulusnetworks.com>**Thisprogramis
freesoftware;youcanredistributeitand/or*modifyitunderthetermsoftheGNUGeneralPubl
icLicense*aspublishedbytheFreeSoftwareFoundation;eitherversion*2oftheLicense,or(
atyouroption)anylaterversion.*/#ifndef_LINUX_MPLS_IPTUNNEL_H#define_LINUX_MPLS_I
PTUNNEL_H/*MPLStunnelattributes*[RTA_ENCAP]={*[MPLS_IPTUNNEL_DST]*[MPLS_IPTUNNEL
_TTL]*}*/enum{MPLS_IPTUNNEL_UNSPEC,MPLS_IPTUNNEL_DST,MPLS_IPTUNNEL_TTL,__MPLS_IP
TUNNEL_MAX,};#defineMPLS_IPTUNNEL_MAX(__MPLS_IPTUNNEL_MAX-1)#endif/*_LINUX_MPLS_
IPTUNNEL_H*/