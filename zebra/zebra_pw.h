#ifndef ZEBRA_PW_H_
#define ZEBRA_PW_H_

#include <net/if.h>
#include <netinet/in.h>

#define PW_PROCESS_HOLD_TIME 10
#define PW_MAX_RETRIES 3

#define PW_SET 1
#define PW_UNSET 2

#define PW_STATUS_DOWN 0
#define PW_STATUS_UP 1

#define L2VPN_NAME_LEN 32 /* must be synced with the one in ldpd/ldpd.h */

struct zebra_pw_t
{
	int cmd; /* set or unset */
	char ifname[IF_NAMESIZE];
	unsigned short ifindex;
	int	pw_type;
	struct in_addr lsr_id;
	int	af;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} nexthop;
	uint32_t local_label;
	uint32_t remote_label;
	uint8_t	flags;
	uint32_t pwid;
	char vpn_name[L2VPN_NAME_LEN];
	unsigned short ac_port_ifindex;
	/* Work queue flags */
	u_int32_t queue_flags;
#define PW_FLAG_SCHEDULED        (1 << 0)
#define PW_FLAG_INSTALLED        (1 << 1)
#define PW_FLAG_CHANGED          (1 << 2)
};

DECLARE_HOOK(pw_change, (struct zebra_pw_t *pw), (pw))

struct zebra_pw_t *pw_add (void);
void pw_del (struct zebra_pw_t *pw);
void pw_queue_add (struct zebra_pw_t *pw);
void unqueue_pw (struct zebra_pw_t *pw);
void zebra_pw_init (void);

#endif /* ZEBRA_PW_H_ */
