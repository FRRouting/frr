// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * May 16 2021, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2021, LabN Consulting, L.L.C
 */

#include <time.h>
#include <unistd.h>
#include <zebra.h>

#include "debug.h"
#include "filter.h"
#include "frr_pthread.h"
#include "libfrr.h"
#include "routing_nb.h"
#include "northbound_cli.h"
#include "frrevent.h"
#include "vrf.h"
#include "vty.h"

#include "staticd/static_debug.h"
#include "staticd/static_nb.h"
#include "staticd/static_vrf.h"
#include "staticd/static_vty.h"
#include "staticd/static_zebra.h"

// GRPC C++ includes
#include <string>
#include <sstream>
#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include "grpc/frr-northbound.grpc.pb.h"

DEFINE_HOOK(test_grpc_late_init, (struct event_loop * tm), (tm));
DEFINE_KOOH(test_grpc_fini, (), ());

struct vty *vty;

bool mpls_enabled;
struct event_loop *master;
struct zebra_privs_t static_privs = {0};
struct frrmod_runtime *grpc_module;
char binpath[2 * MAXPATHLEN + 1];

extern const char *json_expect1;
extern const char *json_expect2;
extern const char *json_expect3;
extern const char *json_loadconf1;

int test_dbg = 1;

void inline test_debug(const std::string &s)
{
	if (test_dbg)
		std::cout << s << std::endl;
}

// static struct option_chain modules[] = {{ .arg = "grpc:50051" }]
// static struct option_chain **modnext = modules->next;

static const struct frr_yang_module_info *const staticd_yang_modules[] = {
	&frr_interface_info, &frr_filter_info, &frr_routing_info,
	&frr_staticd_info,   &frr_vrf_info,
};

static void grpc_thread_stop(struct event *thread);

static void _err_print(const void *cookie, const char *errstr)
{
	std::cout << "Failed to load grpc module:" << errstr << std::endl;
}

static void static_startup(void)
{
	// struct frrmod_runtime module;
	// static struct option_chain *oc;

	cmd_init(1);
	debug_init();

	zlog_aux_init("NONE: ", LOG_DEBUG);
	zprivs_preinit(&static_privs);
	zprivs_init(&static_privs);

	/* Load the server side module -- check libtool path first */
	std::string modpath = std::string(binpath) + std::string("../../lib/.libs");
	grpc_module = frrmod_load("grpc:50051", modpath.c_str(), 0, 0);
	if (!grpc_module) {
		modpath = std::string(binpath) +  std::string("../../lib");
		grpc_module = frrmod_load("grpc:50051", modpath.c_str(),
					  _err_print, 0);
	}
	if (!grpc_module) {
		modpath = std::string(binpath) +
			  std::string("../../../lib/.libs");
		grpc_module = frrmod_load("grpc:50051", modpath.c_str(),
					  _err_print, 0);
	}
	if (!grpc_module) {
		modpath = std::string(binpath) + std::string("../../../lib");
		grpc_module = frrmod_load("grpc:50051", modpath.c_str(),
					  _err_print, 0);
	}
	if (!grpc_module)
		exit(1);

	static_debug_init();

	master = event_master_create(NULL);
	nb_init(master, staticd_yang_modules, array_size(staticd_yang_modules), false, false);

	static_zebra_init();
	vty_init(master, true);
	static_vrf_init();
	static_vty_init();

	hook_register(routing_conf_event,
		      routing_control_plane_protocols_name_validate);
	hook_register(routing_create,
		      routing_control_plane_protocols_staticd_create);
	hook_register(routing_destroy,
		      routing_control_plane_protocols_staticd_destroy);

	// Add a route
	vty = vty_new();
	vty->type = vty::VTY_TERM;
	vty_config_enter(vty, true, false, false);

	auto ret = cmd_execute(vty, "ip route 11.0.0.0/8 Null0", NULL, 0);
	assert(!ret);

	ret = cmd_execute(vty, "end", NULL, 0);
	assert(!ret);

	nb_cli_pending_commit_check(vty);

	frr_pthread_init();

	// frr_config_fork();
	hook_call(test_grpc_late_init, master);
}

static void static_shutdown(void)
{
	hook_call(test_grpc_fini);
	vty_close(vty);
	vrf_terminate();
	vty_terminate();
	cmd_terminate();
	nb_terminate();
	yang_terminate();
	event_master_free(master);
	master = NULL;
}

using frr::Northbound;
using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;

class NorthboundClient
{
      public:
	NorthboundClient(std::shared_ptr<Channel> channel)
	    : stub_(frr::Northbound::NewStub(channel))
	{
	}

	void Commit(uint32_t candidate_id)
	{
		frr::CommitRequest request;
		frr::CommitResponse reply;
		ClientContext context;
		Status status;

		request.set_candidate_id(candidate_id);

		request.set_phase(frr::CommitRequest::ALL);
		status = stub_->Commit(&context, request, &reply);
		_throw_if_not_ok(status);
#if 0
		request.set_phase(frr::CommitRequest::VALIDATE);
		status = stub_->Commit(&context, request, &reply);
		_throw_if_not_ok(status);

		request.set_phase(frr::CommitRequest::PREPARE);
		status = stub_->Commit(&context, request, &reply);
		_throw_if_not_ok(status);

		request.set_phase(frr::CommitRequest::APPLY);
		status = stub_->Commit(&context, request, &reply);
		_throw_if_not_ok(status);
#endif
	}

	uint32_t CreateCandidate()
	{
		frr::CreateCandidateRequest request;
		frr::CreateCandidateResponse reply;
		ClientContext context;
		Status status;

		status = stub_->CreateCandidate(&context, request, &reply);
		_throw_if_not_ok(status);
		return reply.candidate_id();
	}

	void DeleteCandidate(uint32_t candidate_id)
	{
		frr::DeleteCandidateRequest request;
		frr::DeleteCandidateResponse reply;
		ClientContext context;
		Status status;

		request.set_candidate_id(candidate_id);
		status = stub_->DeleteCandidate(&context, request, &reply);
		_throw_if_not_ok(status);
	}

	void EditCandidate(uint32_t candidate_id, const std::string &path,
			   const std::string &value)
	{
		frr::EditCandidateRequest request;
		frr::EditCandidateResponse reply;
		ClientContext context;

		request.set_candidate_id(candidate_id);
		frr::PathValue *pv = request.add_update();
		pv->set_path(path);
		pv->set_value(value);

		Status status = stub_->EditCandidate(&context, request, &reply);
		_throw_if_not_ok(status);
	}

	std::string Get(const std::string &path,
			frr::GetRequest::DataType dtype, frr::Encoding enc,
			bool with_defaults)
	{
		frr::GetRequest request;
		frr::GetResponse reply;
		ClientContext context;
		std::ostringstream ss;

		request.set_type(dtype);
		request.set_encoding(enc);
		request.set_with_defaults(with_defaults);
		request.add_path(path);

		auto stream = stub_->Get(&context, request);
		while (stream->Read(&reply)) {
			ss << reply.data().data() << std::endl;
		}
		auto status = stream->Finish();
		_throw_if_not_ok(status);
		return ss.str();
	}

	std::string GetCapabilities()
	{
		frr::GetCapabilitiesRequest request;
		frr::GetCapabilitiesResponse reply;
		ClientContext context;

		Status status =
			stub_->GetCapabilities(&context, request, &reply);
		_throw_if_not_ok(status);

		std::ostringstream ss;
		ss << "Capabilities:" << std::endl
		   << "\tVersion: " << reply.frr_version() << std::endl
		   << "\tRollback Support: " << reply.rollback_support()
		   << std::endl
		   << "\tSupported Modules:";

		for (int i = 0; i < reply.supported_modules_size(); i++) {
			auto sm = reply.supported_modules(i);
			ss << std::endl
			   << "\t\tName: \"" << sm.name()
			   << "\" Revision: " << sm.revision() << " Org: \""
			   << sm.organization() << "\"";
		}

		ss << std::endl << "\tSupported Encodings:";

		for (int i = 0; i < reply.supported_encodings_size(); i++) {
			auto se = reply.supported_encodings(i);
			auto desc =
				google::protobuf::GetEnumDescriptor<decltype(
					se)>();
			ss << std::endl
			   << "\t\t" << desc->FindValueByNumber(se)->name();
		}

		ss << std::endl;

		return ss.str();
	}

	void LoadToCandidate(uint32_t candidate_id, bool is_replace,
			     bool is_json, const std::string &data)
	{
		frr::LoadToCandidateRequest request;
		frr::LoadToCandidateResponse reply;
		frr::DataTree *dt = new frr::DataTree;
		ClientContext context;

		request.set_candidate_id(candidate_id);
		request.set_type(is_replace
					 ? frr::LoadToCandidateRequest::REPLACE
					 : frr::LoadToCandidateRequest::MERGE);
		dt->set_encoding(is_json ? frr::JSON : frr::XML);
		dt->set_data(data);
		request.set_allocated_config(dt);

		Status status =
			stub_->LoadToCandidate(&context, request, &reply);
		_throw_if_not_ok(status);
	}

	std::string ListTransactions()
	{
		frr::ListTransactionsRequest request;
		frr::ListTransactionsResponse reply;
		ClientContext context;
		std::ostringstream ss;

		auto stream = stub_->ListTransactions(&context, request);

		while (stream->Read(&reply)) {
			ss << "Tx ID: " << reply.id()
			   << " client: " << reply.client()
			   << " date: " << reply.date()
			   << " comment: " << reply.comment() << std::endl;
		}

		auto status = stream->Finish();
		_throw_if_not_ok(status);
		return ss.str();
	}

      private:
	std::unique_ptr<frr::Northbound::Stub> stub_;

	void _throw_if_not_ok(Status &status)
	{
		if (!status.ok())
			throw std::runtime_error(
				std::to_string(status.error_code()) + ": "
				+ status.error_message());
	}
};


bool stop = false;

int grpc_client_test_stop(struct frr_pthread *fpt, void **result)
{
	test_debug("client: STOP pthread");

	assert(fpt->running);
	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);

	test_debug("client: joining pthread");
	pthread_join(fpt->thread, result);

	test_debug("client: joined pthread");
	return 0;
}

int find_first_diff(const std::string &s1, const std::string &s2)
{
	int s1len = s1.length();
	int s2len = s2.length();
	int mlen = std::min(s1len, s2len);

	for (int i = 0; i < mlen; i++)
		if (s1[i] != s2[i])
			return i;
	return s1len == s2len ? -1 : mlen;
}

void assert_no_diff(const std::string &s1, const std::string &s2)
{
	int pos = find_first_diff(s1, s2);
	if (pos == -1)
		return;
	std::cout << "not ok" << std::endl;
	std::cout << "Same: " << s1.substr(0, pos) << std::endl;
	std::cout << "Diff s1: " << s1.substr(pos) << std::endl;
	std::cout << "Diff s2: " << s2.substr(pos) << std::endl;
	assert(false);
}

void assert_config_same(NorthboundClient &client, const std::string &compare)
{
	std::string confs = client.Get("/frr-routing:routing",
				       frr::GetRequest::ALL, frr::JSON, true);
	assert_no_diff(confs, compare);
	std::cout << "ok" << std::endl;
}

void grpc_client_run_test(void)
{
	NorthboundClient client(grpc::CreateChannel(
		"localhost:50051", grpc::InsecureChannelCredentials()));

	std::string reply = client.GetCapabilities();

	uint32_t cid;
	cid = client.CreateCandidate();
	std::cout << "CreateCandidate -> " << cid << std::endl;
	assert(cid == 1);
	client.DeleteCandidate(cid);
	std::cout << "DeleteCandidate(" << cid << ")" << std::endl;
	cid = client.CreateCandidate();
	assert(cid == 2);
	std::cout << "CreateCandidate -> " << cid << std::endl;

	/*
	 * Get initial configuration
	 */
	std::cout << "Comparing initial config...";
	assert_config_same(client, json_expect1);

	/*
	 * Add config using EditCandidate
	 */

	char xpath_buf[1024];
	strlcpy(xpath_buf,
		"/frr-routing:routing/control-plane-protocols/"
		"control-plane-protocol[type='frr-staticd:staticd']"
		"[name='staticd'][vrf='default']/frr-staticd:staticd/route-list",
		sizeof(xpath_buf));
	int slen = strlen(xpath_buf);
	for (int i = 0; i < 4; i++) {
		snprintf(xpath_buf + slen, sizeof(xpath_buf) - slen,
			 "[prefix='13.0.%d.0/24']"
			 "[afi-safi='frr-routing:ipv4-unicast']/"
			 "path-list[table-id='0'][distance='1']/"
			 "frr-nexthops/nexthop[nh-type='blackhole']"
			 "[vrf='default'][gateway=''][interface='(null)']",
			 i);
		client.EditCandidate(cid, xpath_buf, "");
	}
	client.Commit(cid);
	std::cout << "Comparing EditCandidate config...";
	assert_config_same(client, json_expect2);

	client.DeleteCandidate(cid);
	std::cout << "DeleteCandidate(" << cid << ")" << std::endl;

	/*
	 * Add config using LoadToCandidate
	 */

	cid = client.CreateCandidate();
	std::cout << "CreateCandidate -> " << cid << std::endl;

	client.LoadToCandidate(cid, false, true, json_loadconf1);
	client.Commit(cid);

	std::cout << "Comparing LoadToCandidate config...";
	assert_config_same(client, json_expect3);

	client.DeleteCandidate(cid);
	std::cout << "DeleteCandidate(" << cid << ")" << std::endl;

	std::string ltxreply = client.ListTransactions();
	// std::cout << "client: pthread received: " << ltxreply << std::endl;
}

void *grpc_client_test_start(void *arg)
{
	struct frr_pthread *fpt = (struct frr_pthread *)arg;
	fpt->master->owner = pthread_self();
	frr_pthread_set_name(fpt);
	frr_pthread_notify_running(fpt);

	try {
		grpc_client_run_test();
		std::cout << "TEST PASSED" << std::endl;
	} catch (std::exception &e) {
		std::cout << "Exception in test: " << e.what() << std::endl;
	}

	// Signal FRR event loop to stop
	test_debug("client: pthread: adding event to stop us");
	event_add_event(master, grpc_thread_stop, NULL, 0, NULL);

	test_debug("client: pthread: DONE (returning)");

	return NULL;
}

static void grpc_thread_start(struct event *thread)
{
	struct frr_pthread_attr client = {
		.start = grpc_client_test_start,
		.stop = grpc_client_test_stop,
	};

	auto pth = frr_pthread_new(&client, "GRPC Client thread", "grpc");
	frr_pthread_run(pth, NULL);
	frr_pthread_wait_running(pth);
}

static void grpc_thread_stop(struct event *thread)
{
	std::cout << __func__ << ": frr_pthread_stop_all" << std::endl;
	frr_pthread_stop_all();
	std::cout << __func__ << ": static_shutdown" << std::endl;
	static_shutdown();
	std::cout << __func__ << ": exit cleanly" << std::endl;
	exit(0);
}

/*
 * return abs path to this binary with trailing `/`. Does not parse path
 * environment to find in path, which should not matter for unit testing.
 */
static int get_binpath(const char *argv0, char cwd[2 * MAXPATHLEN + 1])
{
	const char *rch;
	if (argv0[0] == '/') {
		*cwd = 0;
		rch = strrchr(argv0, '/');
		strlcpy(cwd, argv0, MIN(rch - argv0 + 2, 2 * MAXPATHLEN + 1));
		return 0;
	}
	if (!(rch = strrchr(argv0, '/'))) {
		/* Does not handle using PATH, shouldn't matter for test */
		errno = EINVAL;
		return -1;
	}
	if (!getcwd(cwd, MAXPATHLEN))
		return -1;
	int len = strlen(cwd);
	cwd[len++] = '/';
	strlcpy(cwd + len, argv0, MIN(rch - argv0 + 2, 2 * MAXPATHLEN + 1));
	return 0;
}

int main(int argc, char **argv)
{
	assert(argc >= 1);
	if (get_binpath(argv[0], binpath) < 0)
		exit(1);

	static_startup();

	event_add_event(master, grpc_thread_start, NULL, 0, NULL);

	/* Event Loop */
	struct event thread;
	while (event_fetch(master, &thread))
		event_call(&thread);
	return 0;
}

// clang-format off

const char *json_expect1 = R"NONCE({
  "frr-routing:routing": {
    "control-plane-protocols": {
      "control-plane-protocol": [
        {
          "type": "frr-staticd:staticd",
          "name": "staticd",
          "vrf": "default",
          "frr-staticd:staticd": {
            "route-list": [
              {
                "prefix": "11.0.0.0/8",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              }
            ]
          }
        }
      ]
    }
  },
  "frr-vrf:lib": {
    "vrf": [
      {
        "name": "default",
        "state": {
          "active": false
        }
      }
    ]
  }
}

)NONCE";

const char *json_loadconf1 = R"NONCE(
{
  "frr-routing:routing": {
    "control-plane-protocols": {
      "control-plane-protocol": [
        {
          "type": "frr-staticd:staticd",
          "name": "staticd",
          "vrf": "default",
          "frr-staticd:staticd": {
            "route-list": [
              {
                "prefix": "10.0.0.0/13",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)"
                        }
                      ]
                    }
                  }
                ]
              }
            ]
          }
        }
      ]
    }
  },
  "frr-vrf:lib": {
    "vrf": [
      {
        "name": "default"
      }
    ]
  }
})NONCE";

const char *json_expect2 = R"NONCE({
  "frr-routing:routing": {
    "control-plane-protocols": {
      "control-plane-protocol": [
        {
          "type": "frr-staticd:staticd",
          "name": "staticd",
          "vrf": "default",
          "frr-staticd:staticd": {
            "route-list": [
              {
                "prefix": "11.0.0.0/8",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "prefix": "13.0.0.0/24",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "prefix": "13.0.1.0/24",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "prefix": "13.0.2.0/24",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "prefix": "13.0.3.0/24",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              }
            ]
          }
        }
      ]
    }
  },
  "frr-vrf:lib": {
    "vrf": [
      {
        "name": "default",
        "state": {
          "active": false
        }
      }
    ]
  }
}

)NONCE";

const char *json_expect3 = R"NONCE({
  "frr-routing:routing": {
    "control-plane-protocols": {
      "control-plane-protocol": [
        {
          "type": "frr-staticd:staticd",
          "name": "staticd",
          "vrf": "default",
          "frr-staticd:staticd": {
            "route-list": [
              {
                "prefix": "11.0.0.0/8",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "prefix": "13.0.0.0/24",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "prefix": "13.0.1.0/24",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "prefix": "13.0.2.0/24",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "prefix": "13.0.3.0/24",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "prefix": "10.0.0.0/13",
                "afi-safi": "frr-routing:ipv4-unicast",
                "path-list": [
                  {
                    "table-id": 0,
                    "distance": 1,
                    "tag": 0,
                    "frr-nexthops": {
                      "nexthop": [
                        {
                          "nh-type": "blackhole",
                          "vrf": "default",
                          "gateway": "",
                          "interface": "(null)",
                          "bh-type": "null",
                          "onlink": false
                        }
                      ]
                    }
                  }
                ]
              }
            ]
          }
        }
      ]
    }
  },
  "frr-vrf:lib": {
    "vrf": [
      {
        "name": "default",
        "state": {
          "active": false
        }
      }
    ]
  }
}

)NONCE";
