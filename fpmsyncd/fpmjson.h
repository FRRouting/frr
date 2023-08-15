#ifndef __FPMJSON__
#define __FPMJSON__


#include <string.h>
#include <vector>
#include "json.hpp"
#include "zlog.h"

using namespace std;

/* Parse the Raw netlink msg */
extern void netlink_parse_rtattr(struct rtattr **tb, int max,
				 struct rtattr *rta, int len);

namespace fpmjson
{
class header {
    public:
		std::string flags;
		int len;
		int pid;
		int seq;
		std::string type;
		header(std::string f, int l, int p, int s, std::string t)
			: flags(f)
			, len(l)
			, pid(p)
			, seq(s)
			, type(t){};
		NLOHMANN_DEFINE_TYPE_INTRUSIVE(header, flags, len, pid, seq, type)
};

class nexthop {
      public:
	virtual ~nexthop(){};
};
class evpn_nexthop : public nexthop {
    public:
		std::string gate;
		std::string interface;
		std::string rmac;
		std::string vni;
		evpn_nexthop(){}; // default constructor
		NLOHMANN_DEFINE_TYPE_INTRUSIVE(evpn_nexthop, gate, interface, rmac, vni);
};

class normal_nexthop : public nexthop {
    public:
		std::string interface;
		std::string dip;
		std::string mpls;
		std::string weight;
		normal_nexthop(char *intf, char *dip, char *mpls, uint8_t weight)
			: dip(string(dip))
			, interface(string(intf))
			, mpls(string(mpls))
			, weight(to_string(weight)){};
		NLOHMANN_DEFINE_TYPE_INTRUSIVE(normal_nexthop, dip, interface, mpls,
						weight);
};
class payload {
    public:
		uint32_t vrf_index;
		std::string protocol;
		int family;
		std::string prefix;
		std::vector<fpmjson::nexthop *> nexthops;
		std::string type;
		nlohmann::json to_json()
		{
			nlohmann::json j = { { "vrf_index", vrf_index },
						{ "protocol", protocol },
						{ "family", family },
						{ "prefix", prefix } };
			nlohmann::json nexthops_json = nlohmann::json::array();
			for (fpmjson::nexthop *nh : nexthops) {
				nlohmann::json nh_json;
				if (type == "evpn") {
					nh_json = *((fpmjson::evpn_nexthop *)(nh));
				} else {
					nh_json = *((fpmjson::normal_nexthop *)(nh));
				}
				nexthops_json.push_back(nh_json);
				delete nh;
			};
			nexthops.clear();
			j["nexthops"] = nexthops_json;
			return j;
		}
};

class msg {
    public:
		fpmjson::header header;
		fpmjson::payload payload;
		std::string timestamp;
		msg(fpmjson::header h, fpmjson::payload p, std::string t)
			: header(h)
			, payload(p)
			, timestamp(t){};
		nlohmann::json to_json()
		{
			return nlohmann::json{ { "header", header },
						{ "payload", payload.to_json() },
						{ "timestamp", timestamp } };
		};
};

}


#endif
