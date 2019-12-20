#include <if.h>

#include <nhrpd/nhrpd.h>

int os_socket(struct nhrp_vrf *nhrp_vrf);
int os_sendmsg(const uint8_t *buf, size_t len, int ifindex, const uint8_t *addr,
	       size_t addrlen, uint16_t protocol, int fd);
int os_recvmsg(uint8_t *buf, size_t *len, int *ifindex, uint8_t *addr,
	       size_t *addrlen, int fd);
int os_configure_dmvpn(struct interface *ifp, int af,
		       struct nhrp_vrf *nhrp_vrf);
