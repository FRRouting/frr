#ifndef __FPMPARSER__
#define __FPMPARSER__

#include <string.h>
#include <netlink/route/route.h>
#include "json.hpp"
#include "zlog.h"
#include "fpmjson.h"
#include <fstream>
#include <thread>


#ifndef RTM_F_OFFLOAD
#define RTM_F_OFFLOAD 0x4000 /* route is offloaded */
#endif

using namespace std;

/* Ring buffer is used to buffer route */
template <typename DataType, int Length = 100000> class RingBuffer {
      private:
	DataType datas[Length];
	int head = 0;
	int tail = 0;
	int count = 0;

      public:
	bool is_full()
	{
		return (tail + 1) % Length == head;
	}
	bool is_empty()
	{
		return tail == head;
	}
	bool push(DataType data)
	{
		if (is_full())
			return false;
		datas[tail] = data;
		tail = (tail + 1) % Length;

		return true;
	}
	bool pop(DataType &data)
	{
		if (is_empty())
			return false;
		data = datas[head];
		head = (head + 1) % Length;
		return true;
	}
	int size()
	{
		if (tail >= head)
			return tail - head;
		else
			return tail + Length - head;
	}
};


//ATTENTION: Do not use zlog in thread flushtimer_t, it will cause core dump
class Fpmparser {
      private:
	/* Json file path*/
	char *m_output_file_path;
	/* Json file stream*/
	std::ofstream m_output_file;
	/* Buffer to store route msg */
	RingBuffer<nlohmann::json> m_task_ringbuffer;
	/* Thread to flush route msg to json file */
	std::thread flushtimer_t;
	/* Thread exit flag */
	std::atomic<bool> thread_exit;
	struct nl_cache *m_link_cache;
	struct nl_sock *m_nl_sock;

      public:
	enum { MAX_ADDR_SIZE = 64 };

	Fpmparser(char *file_path);
	~Fpmparser();
	virtual void process_normal_msg(struct nl_object *obj, void *arg);
	virtual void process_raw_msg(struct nlmsghdr *h);





	/* Add one route json to ring buffer */
	void push_to_ringbuffer(fpmjson::header &header,
				fpmjson::payload &payload);


	void parseEncap(struct rtattr *tb, uint32_t &encap_value, string &rmac);

	void parseRtAttrNested(struct rtattr **tb, int max, struct rtattr *rta);

	char *prefixMac2Str(char *mac, char *buf, int size);


	/* Handle prefix route */
	void onEvpnRouteMsg(struct nlmsghdr *h, int len,
			    fpmjson::payload &payload);


	bool getEvpnNextHopList(struct nlmsghdr *h, struct rtattr *tb[],
			       std::vector<fpmjson::nexthop*> &nexthop_list);


	/* Get next hop list */
	void getNextHopList(struct rtnl_route *route_obj,
			       std::vector<fpmjson::nexthop*> &nexthop_list);

	bool parse_evpn_nexthop(struct rtattr **tb, struct rtattr **subtb,
				   fpmjson::evpn_nexthop *nexthop);


	/* Flush thread function */
	void timer_flush_pipe();

	/* Flush route msg to json file */
	void fflush();
	/* Check if json file is empty */
	bool is_output_file_empty();
	bool getIfName(int if_index, char *if_name, size_t name_len);

	
};



#endif
