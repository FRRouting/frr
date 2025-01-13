//TCP-AO Configuration Current status: Working
//All we are really doing here is adding a new MKT to the socket
#define _GNU_SOURCE
#include <linux/tcp.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "tcp_ao.h"
#define LISTEN_BACKLOG 50
//Connect, listen, bind, and accept are all set based on the value given (true or false)
int set_tcpA0_sockopt(int sock, int family, const char *alg_name, uint8_t sndid, const char *key, uint8_t rcvid)
{
		
	//Setting up the MKT
	struct sockaddr_in addr = {
		.sin_family = family, 
	};


    int keylen = key ? strlen(key) : 0;

	if (keylen > TCP_AO_MAXKEYLEN){
		printf("Key length is too long\n");
		return -1;
	}


	struct tcp_ao_add tcp_ao = {};
	// struct tcp_ao_add { /* setsockopt(TCP_AO_ADD_KEY) */
	// 	struct __kernel_sockaddr_storage addr;	/* peer's address for the key */
	// 	char	alg_name[64];		/* crypto hash algorithm to use */
	// 	__s32	ifindex;		/* L3 dev index for VRF */
	// 	__u32   set_current	:1,	/* set key as Current_key at once */
	// 		set_rnext	:1,	/* request it from peer with RNext_key */
	// 		reserved	:30;	/* must be 0 */
	// 	__u16	reserved2;		/* padding, must be 0 */
	// 	__u8	prefix;			/* peer's address prefix */
	// 	__u8	sndid;			/* SendID for outgoing segments */
	// 	__u8	rcvid;			/* RecvID to match for incoming seg */
	// 	__u8	maclen;			/* length of authentication code (hash) */
	// 	__u8	keyflags;		/* see TCP_AO_KEYF_ */
	// 	__u8	keylen;			/* length of ::key */
	// 	__u8	key[TCP_AO_MAXKEYLEN];
	// } __attribute__((aligned(8)));

	//Setting the socket 
	
	tcp_ao.sndid = sndid;
	
	tcp_ao.rcvid = rcvid;
	
	tcp_ao.keylen = keylen;

	memcpy(tcp_ao.key, key, sizeof(key));

	strcpy(tcp_ao.alg_name, alg_name);

	memcpy(&tcp_ao.addr, &addr, sizeof(addr));


	printf("Setting the socket option\n");
	int ret = setsockopt(sock, IPPROTO_TCP, TCP_AO_ADD_KEY, &tcp_ao, sizeof(tcp_ao));
	if (ret < 0){
		printf("Error setting the socket option, errno: %d, %s\n", errno, strerror(errno));
		return -1;
	} else {
		printf("Socket option set successfully\n");
	}
	return ret;
}




