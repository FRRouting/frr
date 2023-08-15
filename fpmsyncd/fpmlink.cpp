#include <string.h>
#include <errno.h>
#include <system_error>
#include "fpmparser.h"
#include "log.h"
#include "netlink/msg.h"
#include "fpmlink.h"
#include "zlog.h"
#include <sys/epoll.h>

using namespace std;

#define MAX_EVENTS 10
extern Fpmparser *global_parser;

void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta,
			  int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max) {
			tb[rta->rta_type] = rta;
		} else {
			/* FRR 7.5 is sending RTA_ENCAP with NLA_F_NESTED bit set*/
			if (rta->rta_type & NLA_F_NESTED) {
				int rta_type = rta->rta_type & ~NLA_F_NESTED;
				if (rta_type <= max) {
					tb[rta_type] = rta;
				}
			}
		}
		rta = RTA_NEXT(rta, len);
	}
}

bool FpmLink::isRawProcessing(struct nlmsghdr *h)
{
	int len;
	short encap_type = 0;
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1] = { 0 };

	rtm = (struct rtmsg *)NLMSG_DATA(h);
	if (h->nlmsg_type != RTM_NEWROUTE && h->nlmsg_type != RTM_DELROUTE) {
		return false;
	}
	len = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)));
	if (len < 0) {
		return false;
	}
	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (!tb[RTA_MULTIPATH]) {
		if (tb[RTA_ENCAP_TYPE]) {
			encap_type = *(short *)RTA_DATA(tb[RTA_ENCAP_TYPE]);
		}
	} else {
		/* This is a multipath route */
		int len;
		struct rtnexthop *rtnh =
			(struct rtnexthop *)RTA_DATA(tb[RTA_MULTIPATH]);
		len = (int)RTA_PAYLOAD(tb[RTA_MULTIPATH]);
		struct rtattr *subtb[RTA_MAX + 1];

		for (;;) {
			if (len < (int)sizeof(*rtnh) || rtnh->rtnh_len > len) {
				break;
			}

			if (rtnh->rtnh_len > sizeof(*rtnh)) {
				memset(subtb, 0, sizeof(subtb));
				netlink_parse_rtattr(subtb, RTA_MAX,
						     RTNH_DATA(rtnh),
						     (int)(rtnh->rtnh_len -
							   sizeof(*rtnh)));
				if (subtb[RTA_ENCAP_TYPE]) {
					encap_type = *(uint16_t *)RTA_DATA(
						subtb[RTA_ENCAP_TYPE]);
					break;
				}
			}

			if (rtnh->rtnh_len == 0) {
				break;
			}

			len -= NLMSG_ALIGN(rtnh->rtnh_len);
			rtnh = RTNH_NEXT(rtnh);
		}
	}

	if (encap_type > 0) {
		return true;
	}
	return false;
}

FpmLink::FpmLink(unsigned short port)
	: MSG_BATCH_SIZE(256)
	, m_bufSize(FPM_MAX_MSG_LEN * MSG_BATCH_SIZE)
	, m_messageBuffer(NULL)
	, m_pos(0)
{
	struct sockaddr_in addr = {};
	int true_val = 1;

	m_server_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_server_socket < 0)
		throw system_error(errno, system_category());

	if (setsockopt(m_server_socket, SOL_SOCKET, SO_REUSEADDR, &true_val,
		       sizeof(true_val)) < 0) {
		close(m_server_socket);
		throw system_error(errno, system_category());
	}

	if (setsockopt(m_server_socket, SOL_SOCKET, SO_KEEPALIVE, &true_val,
		       sizeof(true_val)) < 0) {
		close(m_server_socket);
		throw system_error(errno, system_category());
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(m_server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(m_server_socket);
		throw system_error(errno, system_category());
	}

	if (listen(m_server_socket, 2) != 0) {
		close(m_server_socket);
		throw system_error(errno, system_category());
	}


	m_messageBuffer = new char[m_bufSize];
}


FpmLink::~FpmLink()
{
	delete[] m_messageBuffer;
	close(m_connection_socket);
	close(m_server_socket);
}

void FpmLink::accept()
{
	struct sockaddr_in client_addr;

	socklen_t client_len = sizeof(struct sockaddr_in);

	m_connection_socket = ::accept(m_server_socket,
				       (struct sockaddr *)&client_addr,
				       &client_len);
	if (m_connection_socket < 0)
		throw system_error(errno, system_category());

	zlog_info("New connection accepted from: %s",
		  inet_ntoa(client_addr.sin_addr));
}

void FpmLink::readData()
{
	fpm_msg_hdr_t *hdr;
	size_t msg_len;
	size_t start = 0, left;
	ssize_t read;

	read = ::read(m_connection_socket, m_messageBuffer + m_pos,
		      m_bufSize - m_pos);
	if (read == 0)
		throw FpmConnectionClosedException();
	if (read < 0)
		throw system_error(errno, system_category());
	m_pos += (uint32_t)read;

	/* Check for complete messages */
	while (true) {
		hdr = reinterpret_cast<fpm_msg_hdr_t *>(
			static_cast<void *>(m_messageBuffer + start));
		left = m_pos - start;
		if (left < FPM_MSG_HDR_LEN) {
			break;
		}

		/* fpm_msg_len includes header size */
		msg_len = fpm_msg_len(hdr);
		if (left < msg_len) {
			break;
		}

		if (!fpm_msg_ok(hdr, left)) {
			throw system_error(make_error_code(errc::bad_message),
					   "Malformed FPM message received");
		}

		process_fpm_msg(hdr);

		start += msg_len;
	}

	memmove(m_messageBuffer, m_messageBuffer + start, m_pos - start);
	m_pos = m_pos - (uint32_t)start;
}


void FpmLink::epoll()
{
	struct epoll_event event, events[MAX_EVENTS];
	int epoll_fd;
	epoll_fd = epoll_create1(0);
	event.events = EPOLLIN;
	event.data.fd = m_server_socket;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, m_server_socket, &event) == -1)
		throw system_error(errno, system_category());

	while (true) {
		int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			throw system_error(errno, system_category());
		}

		for (int i = 0; i < n; i++) {
			if (events[i].data.fd == m_server_socket) {
				accept();
				event.events = EPOLLIN;
				event.data.fd = m_connection_socket;
				if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD,
					      m_connection_socket, &event) == -1)
					throw system_error(errno,
							   system_category());
				zlog_info("Connection established");
			} else {
				readData();
			}
		}
	}
}
void FpmLink::parse(struct nl_object *obj, void *arg)
{
	global_parser->process_normal_msg(obj, arg);
}

void FpmLink::process_fpm_msg(fpm_msg_hdr_t *hdr)
{
	size_t msg_len = fpm_msg_len(hdr);

	if (hdr->msg_type != FPM_MSG_TYPE_NETLINK) {
		return;
	}
	nlmsghdr *nl_hdr = (nlmsghdr *)fpm_msg_data(hdr);

	/* Read all netlink messages inside FPM message */
	for (; NLMSG_OK(nl_hdr, msg_len); nl_hdr = NLMSG_NEXT(nl_hdr, msg_len)) {
		/*
         * EVPN Type5 Add Routes need to be process in Raw mode as they contain
         * RMAC, VLAN and L3VNI information.
         * Where as all other route will be using rtnl api to extract information
         * from the netlink msg.
         */
		bool isRaw = isRawProcessing(nl_hdr);

		nl_msg *msg = nlmsg_convert(nl_hdr);
		if (msg == NULL) {
			throw system_error(make_error_code(errc::bad_message),
					   "Unable to convert nlmsg");
		}

		nlmsg_set_proto(msg, NETLINK_ROUTE);

		if (isRaw) {
			/* EVPN Type5 Add route processing */
			global_parser->process_raw_msg(nl_hdr);
		} else {
			/* All other route processing */
			nl_msg_parse(msg, FpmLink::parse, nl_hdr);
		}
		nlmsg_free(msg);
	}
}
