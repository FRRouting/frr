
int os_socket(void);
int os_sendmsg(const uint8_t *buf, size_t len, int ifindex, const uint8_t *addr,
	       size_t addrlen);
int os_recvmsg(uint8_t *buf, size_t *len, int *ifindex, uint8_t *addr,
	       size_t *addrlen);
int os_configure_dmvpn(unsigned int ifindex, const char *ifname, int af);
