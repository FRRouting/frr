// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (c) 2021-2022, LabN Consulting, L.L.C
// Copyright (C) 2019  NetDEF, Inc.
//                     Renato Westphal
//

#include <zebra.h>
#include <grpcpp/grpcpp.h>
#include "grpc/frr-northbound.grpc.pb.h"

#include "log.h"
#include "libfrr.h"
#include "lib/version.h"
#include "frrevent.h"
#include "command.h"
#include "lib_errors.h"
#include "northbound.h"
#include "northbound_db.h"
#include "frr_pthread.h"

extern "C" {
#include "mgmt_defines.h"
#include "mgmt_fe_client.h"
}

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <memory>
#include <string>

#define GRPC_DEFAULT_PORT 50051


// ------------------------------------------------------
//                 File Local Variables
// ------------------------------------------------------

/*
 * NOTE: we can't use the FRR debugging infrastructure here since it uses
 * atomics and C++ has a different atomics API. Enable gRPC debugging
 * unconditionally until we figure out a way to solve this problem.
 */
static bool nb_dbg_client_grpc = 0;

static struct event_loop *main_master;

static struct frr_pthread *fpt;

static bool grpc_running;

/* mgmtd frontend client: when set, gRPC uses FE API for config/state */
static struct mgmt_fe_client *grpc_fe_client;
static uint64_t grpc_fe_session_id;
static uint64_t grpc_fe_client_id;
static uint64_t grpc_fe_req_id_next;
static bool grpc_fe_connected;
static bool grpc_fe_session_ready;

/* Pending GET: wait for get_tree_notify while pumping event loop */
static pthread_mutex_t grpc_fe_pending_mtx = PTHREAD_MUTEX_INITIALIZER;
static uint64_t grpc_fe_pending_req_id;
static bool grpc_fe_pending_done;
static std::string *grpc_fe_pending_result;
static int grpc_port = GRPC_DEFAULT_PORT;

#define grpc_debug(fmt, ...)                                                                      \
	do {                                                                                      \
		if (nb_dbg_client_grpc)                                                           \
			zlog_debug("GRPCD: %s: " fmt, __func__, ##__VA_ARGS__);                   \
	} while (0)


static int frr_grpc_start_server(uint port);
static void frr_grpc_stop_server(void);

// ------------------------------------------------------
//                      New Types
// ------------------------------------------------------

enum CallState { CREATE, PROCESS, MORE, FINISH, DELETED };
const char *call_states[] = {"CREATE", "PROCESS", "MORE", "FINISH", "DELETED"};

struct candidate {
	uint64_t id;
	struct nb_config *config;
	struct nb_transaction *transaction;
};

class Candidates
{
      public:
	~Candidates(void)
	{
		// Delete candidates.
		for (auto it = _cdb.begin(); it != _cdb.end(); it++)
			delete_candidate(it->first);
	}

	struct candidate *create_candidate(void)
	{
		uint64_t id = ++_next_id;
		assert(id); // TODO: implement an algorithm for unique reusable
			    // IDs.
		struct candidate *c = &_cdb[id];
		c->id = id;
		c->config = nb_config_dup(running_config);
		c->transaction = NULL;

		return c;
	}

	bool contains(uint64_t candidate_id)
	{
		return _cdb.count(candidate_id) > 0;
	}

	void delete_candidate(uint64_t candidate_id)
	{
		struct candidate *c = &_cdb[candidate_id];
		char errmsg[BUFSIZ] = {0};

		nb_config_free(c->config);
		if (c->transaction)
			nb_candidate_commit_abort(c->transaction, errmsg,
						  sizeof(errmsg));
		_cdb.erase(c->id);
	}

	struct candidate *get_candidate(uint64_t id)
	{
		return _cdb.count(id) == 0 ? NULL : &_cdb[id];
	}

      private:
	uint64_t _next_id = 0;
	std::map<uint64_t, struct candidate> _cdb;
};

/*
 * RpcStateBase is the common base class used to track a gRPC RPC.
 */
class RpcStateBase
{
      public:
	virtual void do_request(::frr::Northbound::AsyncService *service,
				::grpc::ServerCompletionQueue *cq,
				bool no_copy) = 0;

	RpcStateBase(const char *name) : name(name){};

	virtual ~RpcStateBase() = default;

	CallState get_state() const
	{
		return state;
	}

	bool is_initial_process() const
	{
		/* Will always be true for Unary */
		return entered_state == CREATE;
	}

	// Returns "more" status, if false caller can delete
	bool run(frr::Northbound::AsyncService *service,
		 grpc::ServerCompletionQueue *cq)
	{
		/*
		 * We enter in either CREATE or MORE state, and transition to
		 * PROCESS state.
		 */
		this->entered_state = this->state;
		this->state = PROCESS;
		grpc_debug("%s RPC: %s -> %s on grpc-io-thread", name,
			   call_states[this->entered_state],
			   call_states[this->state]);
		/*
		 * We schedule the callback on the main pthread, and wait for
		 * the state to transition out of the PROCESS state. The new
		 * state will either be MORE or FINISH. It will always be FINISH
		 * for Unary RPCs.
		 */
		event_add_event(main_master, c_callback, (void *)this, 0, NULL);

		pthread_mutex_lock(&this->cmux);
		while (this->state == PROCESS)
			pthread_cond_wait(&this->cond, &this->cmux);
		pthread_mutex_unlock(&this->cmux);

		grpc_debug("%s RPC in %s on grpc-io-thread", name,
			   call_states[this->state]);

		if (this->state == FINISH) {
			/*
			 * Server is done (FINISH) so prep to receive a new
			 * request of this type. We could do this earlier but
			 * that would mean we could be handling multiple same
			 * type requests in parallel without limit.
			 */
			this->do_request(service, cq, false);
		}
		return true;
	}

      protected:
	virtual CallState run_mainthread(struct event *event) = 0;

	static void c_callback(struct event *event)
	{
		auto _tag = static_cast<RpcStateBase *>(EVENT_ARG(event));
		/*
		 * We hold the lock until the callback finishes and has updated
		 * _tag->state, then we signal done and release.
		 */
		pthread_mutex_lock(&_tag->cmux);

		CallState enter_state = _tag->state;
		grpc_debug("%s RPC: running %s on main event", _tag->name,
			   call_states[enter_state]);

		_tag->state = _tag->run_mainthread(event);

		grpc_debug("%s RPC: %s -> %s [main event]", _tag->name,
			   call_states[enter_state], call_states[_tag->state]);

		pthread_cond_signal(&_tag->cond);
		pthread_mutex_unlock(&_tag->cmux);
		return;
	}

	grpc::ServerContext ctx;
	pthread_mutex_t cmux = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	CallState state = CREATE;
	CallState entered_state = CREATE;

      public:
	const char *name;
};

/*
 * The UnaryRpcState class is used to track the execution of a Unary RPC.
 *
 * Template Args:
 *     Q - the request type for a given unary RPC
 *     S - the response type for a given unary RPC
 */
template <typename Q, typename S> class UnaryRpcState : public RpcStateBase
{
      public:
	typedef void (frr::Northbound::AsyncService::*reqfunc_t)(
		::grpc::ServerContext *, Q *,
		::grpc::ServerAsyncResponseWriter<S> *,
		::grpc::CompletionQueue *, ::grpc::ServerCompletionQueue *,
		void *);

	UnaryRpcState(Candidates *cdb, reqfunc_t rfunc,
		      grpc::Status (*cb)(UnaryRpcState<Q, S> *),
		      const char *name)
	    : RpcStateBase(name), cdb(cdb), requestf(rfunc), callback(cb),
	      responder(&ctx){};

	void do_request(::frr::Northbound::AsyncService *service,
			::grpc::ServerCompletionQueue *cq,
			bool no_copy) override
	{
		grpc_debug("posting a request for: %s", name);
		auto copy = no_copy ? this
				    : new UnaryRpcState(cdb, requestf, callback,
							name);
		(service->*requestf)(&copy->ctx, &copy->request,
				     &copy->responder, cq, cq, copy);
	}

	CallState run_mainthread(struct event *event) override
	{
		// Unary RPC are always finished, see "Unary" :)
		grpc::Status status = this->callback(this);
		responder.Finish(response, status, this);
		return FINISH;
	}

	Candidates *cdb;

	Q request;
	S response;
	grpc::ServerAsyncResponseWriter<S> responder;

	grpc::Status (*callback)(UnaryRpcState<Q, S> *);
	reqfunc_t requestf = NULL;
};

/*
 * The StreamRpcState class is used to track the execution of a Streaming RPC.
 *
 * Template Args:
 *     Q - the request type for a given streaming RPC
 *     S - the response type for a given streaming RPC
 *     X - the type used to track the streaming state
 */
template <typename Q, typename S, typename X>
class StreamRpcState : public RpcStateBase
{
      public:
	typedef void (frr::Northbound::AsyncService::*reqsfunc_t)(
		::grpc::ServerContext *, Q *, ::grpc::ServerAsyncWriter<S> *,
		::grpc::CompletionQueue *, ::grpc::ServerCompletionQueue *,
		void *);

	StreamRpcState(reqsfunc_t rfunc, bool (*cb)(StreamRpcState<Q, S, X> *),
		       const char *name)
	    : RpcStateBase(name), requestsf(rfunc), callback(cb),
	      async_responder(&ctx){};

	void do_request(::frr::Northbound::AsyncService *service,
			::grpc::ServerCompletionQueue *cq,
			bool no_copy) override
	{
		grpc_debug("posting a request for: %s", name);
		auto copy =
			no_copy ? this
				: new StreamRpcState(requestsf, callback, name);
		(service->*requestsf)(&copy->ctx, &copy->request,
				      &copy->async_responder, cq, cq, copy);
	}

	CallState run_mainthread(struct event *event) override
	{
		if (this->callback(this))
			return MORE;
		else
			return FINISH;
	}

	Q request;
	S response;
	grpc::ServerAsyncWriter<S> async_responder;

	bool (*callback)(StreamRpcState<Q, S, X> *);
	reqsfunc_t requestsf = NULL;

	X context;
};

// ------------------------------------------------------
//                    Utility Functions
// ------------------------------------------------------

static LYD_FORMAT encoding2lyd_format(enum frr::Encoding encoding)
{
	switch (encoding) {
	case frr::JSON:
		return LYD_JSON;
	case frr::XML:
		return LYD_XML;
	default:
		flog_err(EC_LIB_DEVELOPMENT,
			 "%s: unknown data encoding format (%u)", __func__,
			 encoding);
		exit(1);
	}
}

static int yang_dnode_edit(struct lyd_node *dnode, const std::string &path,
			   const char *value)
{
	LY_ERR err = lyd_new_path(dnode, ly_native_ctx, path.c_str(), value,
				  LYD_NEW_PATH_UPDATE, &dnode);
	if (err != LY_SUCCESS) {
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_new_path() failed: %s",
			  __func__, ly_errmsg(ly_native_ctx));
		return -1;
	}

	return 0;
}

static int yang_dnode_delete(struct lyd_node *dnode, const std::string &path)
{
	dnode = yang_dnode_get(dnode, path.c_str());
	if (!dnode)
		return -1;

	lyd_free_tree(dnode);

	return 0;
}

static LY_ERR data_tree_from_dnode(frr::DataTree *dt,
				   const struct lyd_node *dnode,
				   LYD_FORMAT lyd_format, bool with_defaults)
{
	char *strp;
	int options = 0;

	SET_FLAG(options, LYD_PRINT_WITHSIBLINGS);
	if (with_defaults)
		SET_FLAG(options, LYD_PRINT_WD_ALL);
	else
		SET_FLAG(options, LYD_PRINT_WD_TRIM);

	LY_ERR err = lyd_print_mem(&strp, dnode, lyd_format, options);
	if (err == LY_SUCCESS) {
		if (strp) {
			dt->set_data(strp);
			free(strp);
		}
	}
	return err;
}

static struct lyd_node *dnode_from_data_tree(const frr::DataTree *dt,
					     bool config_only)
{
	struct lyd_node *dnode;
	int options, opt2;
	LY_ERR err;

	if (config_only) {
		options = LYD_PARSE_NO_STATE;
		opt2 = LYD_VALIDATE_NO_STATE;
	} else {
		options = LYD_PARSE_STRICT;
		opt2 = 0;
	}

	err = lyd_parse_data_mem(ly_native_ctx, dt->data().c_str(),
				 encoding2lyd_format(dt->encoding()), options,
				 opt2, &dnode);
	if (err != LY_SUCCESS) {
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_parse_mem() failed: %s",
			  __func__, ly_errmsg(ly_native_ctx));
	}
	return dnode;
}

/* FE client get_tree_notify: runs on main thread, signals pending GET */
static int grpc_fe_get_tree_notify(struct mgmt_fe_client *client,
				   uintptr_t user_data, uint64_t client_id,
				   uint64_t session_id, uintptr_t session_ctx,
				   uint64_t req_id, enum mgmt_ds_id ds_id,
				   LYD_FORMAT result_type, void *result,
				   size_t len, int partial_error)
{
	(void)client;
	(void)user_data;
	(void)client_id;
	(void)session_id;
	(void)session_ctx;
	(void)ds_id;
	(void)result_type;
	(void)partial_error;

	if (req_id != grpc_fe_pending_req_id)
		return 0;

	pthread_mutex_lock(&grpc_fe_pending_mtx);
	grpc_fe_pending_done = true;
	if (grpc_fe_pending_result && result && len > 0)
		grpc_fe_pending_result->assign((const char *)result, len);
	pthread_mutex_unlock(&grpc_fe_pending_mtx);
	return 0;
}

static void grpc_fe_connect_notify(struct mgmt_fe_client *client,
				   uintptr_t user_data, bool connected)
{
	(void)client;
	(void)user_data;
	grpc_fe_connected = connected;

	/* have connection get session -- this actually short-circuits */
	mgmt_fe_create_client_session(grpc_fe_client, grpc_fe_client_id, 0);
}


static void grpc_fe_session_notify(struct mgmt_fe_client *client,
				   uintptr_t user_data, uint64_t client_id,
				   bool create, bool success,
				   uintptr_t session_id_val,
				   uintptr_t user_session_client)
{
	(void)client;
	(void)user_data;
	(void)user_session_client;

	if (!create || !success) {
		grpc_debug("unexpected session notify: create %d success %d client_id %ld", create,
			   success, (long)client_id);
		if (!create)
			frr_grpc_stop_server();
		return;
	}

	/* We have a session - start handling gRPC requests */
	grpc_debug("got session: %lu", (long)session_id_val);
	grpc_fe_session_id = (uint64_t)session_id_val;
	grpc_fe_session_ready = true;

	if (frr_grpc_start_server(grpc_port) < 0) {
		/* should kill session on failure and retry, better would be to move retry to better spot */
		abort();
	}
}

static grpc::Status grpc_fe_get_path_via_mgmtd(frr::DataTree *dt,
					       const std::string &path,
					       int type, LYD_FORMAT lyd_format,
					       bool with_defaults)
{
	uint8_t flags;
	uint8_t defaults = with_defaults ? GET_DATA_DEFAULTS_ALL
					 : GET_DATA_DEFAULTS_TRIM;
	uint64_t req_id;
	struct event ev;
	struct lyd_node *dnode = NULL;
	struct lyd_node *dnode_config = NULL;
	struct lyd_node *dnode_state = NULL;
	LY_ERR err;
	std::string result_store;

	grpc_fe_pending_result = &result_store;

	auto send_get = [&](uint8_t datastore, uint8_t get_flags) -> grpc::Status {
		req_id = ++grpc_fe_req_id_next;
		pthread_mutex_lock(&grpc_fe_pending_mtx);
		grpc_fe_pending_req_id = req_id;
		grpc_fe_pending_done = false;
		result_store.clear();
		pthread_mutex_unlock(&grpc_fe_pending_mtx);

		if (mgmt_fe_send_get_data_req(
			    grpc_fe_client, grpc_fe_session_id, req_id,
			    datastore, LYD_LYB, get_flags, defaults,
			    path.empty() ? "/" : path.c_str())) {
			return grpc::Status(grpc::StatusCode::UNAVAILABLE,
					    "Failed to send GET_DATA to mgmtd");
		}

		while (true) {
			pthread_mutex_lock(&grpc_fe_pending_mtx);
			if (grpc_fe_pending_done)
				break;
			pthread_mutex_unlock(&grpc_fe_pending_mtx);
			if (event_fetch(main_master, &ev))
				event_call(&ev);
		}
		pthread_mutex_unlock(&grpc_fe_pending_mtx);

		if (result_store.empty())
			return grpc::Status(grpc::StatusCode::INTERNAL,
					    "No data from mgmtd");

		uint32_t parse_opts = LYD_PARSE_ONLY;
#ifdef LYD_PARSE_LYB_SKIP_CTX_CHECK
		parse_opts |= LYD_PARSE_LYB_SKIP_CTX_CHECK;
#endif
		err = lyd_parse_data_mem(ly_native_ctx, result_store.data(),
					LYD_LYB, parse_opts, 0, &dnode);
		if (err != LY_SUCCESS) {
			return grpc::Status(
				grpc::StatusCode::INTERNAL,
				std::string("Failed to parse mgmtd result: ") +
					ly_errmsg(ly_native_ctx));
		}
		return grpc::Status::OK;
	};

	if (type == frr::GetRequest_DataType_CONFIG) {
		flags = GET_DATA_FLAG_CONFIG;
		grpc::Status st = send_get(MGMTD_DS_RUNNING, flags);
		if (!st.ok()) {
			grpc_fe_pending_result = nullptr;
			return st;
		}
		dnode_config = dnode;
		dnode = NULL;
	} else if (type == frr::GetRequest_DataType_STATE) {
		flags = GET_DATA_FLAG_STATE;
		grpc::Status st = send_get(MGMTD_DS_OPERATIONAL, flags);
		if (!st.ok()) {
			grpc_fe_pending_result = nullptr;
			return st;
		}
		dnode_state = dnode;
		dnode = NULL;
	} else {
		/* ALL: get config and state, merge */
		flags = GET_DATA_FLAG_CONFIG;
		grpc::Status st = send_get(MGMTD_DS_RUNNING, flags);
		if (!st.ok()) {
			grpc_fe_pending_result = nullptr;
			return st;
		}
		dnode_config = dnode;
		dnode = NULL;

		flags = GET_DATA_FLAG_STATE;
		st = send_get(MGMTD_DS_OPERATIONAL, flags);
		if (!st.ok()) {
			yang_dnode_free(dnode_config);
			grpc_fe_pending_result = nullptr;
			return st;
		}
		dnode_state = dnode;
		dnode = NULL;

		if (lyd_merge_siblings(&dnode_state, dnode_config,
				       LYD_MERGE_DESTRUCT) != LY_SUCCESS) {
			yang_dnode_free(dnode_state);
			yang_dnode_free(dnode_config);
			grpc_fe_pending_result = nullptr;
			return grpc::Status(grpc::StatusCode::INTERNAL,
					    "Failed to merge config and state");
		}
		dnode = dnode_state;
	}

	struct lyd_node *dnode_final =
		dnode ? dnode : (dnode_config ? dnode_config : dnode_state);
	err = data_tree_from_dnode(dt, dnode_final, lyd_format, with_defaults);
	yang_dnode_free(dnode_final);
	grpc_fe_pending_result = nullptr;
	if (err)
		return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to dump data (1)");
	return grpc::Status::OK;
}

static struct lyd_node *get_dnode_config(const std::string &path)
{
	struct lyd_node *dnode;

	if (!yang_dnode_exists(running_config->dnode,
			       path.empty() ? NULL : path.c_str()))
		return NULL;

	dnode = yang_dnode_get(running_config->dnode,
			       path.empty() ? NULL : path.c_str());
	if (dnode)
		dnode = yang_dnode_dup(dnode);

	return dnode;
}

static struct lyd_node *get_dnode_state(const std::string &path)
{
	struct lyd_node *dnode = NULL;

	(void)nb_oper_iterate_legacy(path.c_str(), NULL, 0, NULL, NULL, &dnode);

	return dnode;
}

static grpc::Status get_path(frr::DataTree *dt, const std::string &path,
			     int type, LYD_FORMAT lyd_format,
			     bool with_defaults)
{
	assert(grpc_fe_client && grpc_fe_connected && grpc_fe_session_ready);
	grpc_debug("calling mgmtd get");
	return grpc_fe_get_path_via_mgmtd(dt, path, type, lyd_format, with_defaults);
}


// ------------------------------------------------------
//       RPC Callback Functions: run on main thread
// ------------------------------------------------------

grpc::Status HandleUnaryGetCapabilities(
	UnaryRpcState<frr::GetCapabilitiesRequest, frr::GetCapabilitiesResponse>
		*tag)
{
	grpc_debug("entered");

	// Response: string frr_version = 1;
	tag->response.set_frr_version(FRR_VERSION);

	// Response: bool rollback_support = 2;
#ifdef HAVE_CONFIG_ROLLBACKS
	tag->response.set_rollback_support(true);
#else
	tag->response.set_rollback_support(false);
#endif
	// Response: repeated ModuleData supported_modules = 3;
	struct yang_module *module;
	RB_FOREACH (module, yang_modules, &yang_modules) {
		auto m = tag->response.add_supported_modules();

		m->set_name(module->name);
		if (module->info->revision)
			m->set_revision(module->info->revision);
		m->set_organization(module->info->org);
	}

	// Response: repeated Encoding supported_encodings = 4;
	tag->response.add_supported_encodings(frr::JSON);
	tag->response.add_supported_encodings(frr::XML);

	grpc_debug("exiting");
	return grpc::Status::OK;
}

// Define the context variable type for this streaming handler
typedef std::list<std::string> GetContextType;

bool HandleStreamingGet(
	StreamRpcState<frr::GetRequest, frr::GetResponse, GetContextType> *tag)
{
	grpc_debug("entered");

	auto mypathps = &tag->context;
	if (tag->is_initial_process()) {
		// Fill our context container first time through
		grpc_debug("initialize streaming state");
		auto paths = tag->request.path();
		for (const std::string &path : paths) {
			grpc_debug("paths: %s", path.c_str());
			mypathps->push_back(std::string(path));
		}
	}

	// Request: DataType type = 1;
	int type = tag->request.type();
	// Request: Encoding encoding = 2;
	frr::Encoding encoding = tag->request.encoding();
	// Request: bool with_defaults = 3;
	bool with_defaults = tag->request.with_defaults();

	if (mypathps->empty()) {
		grpc_debug("empty paths -- finish");
		tag->async_responder.Finish(grpc::Status::OK, tag);
		return false;
	}

	frr::GetResponse response;
	grpc::Status status;

	// Response: int64 timestamp = 1;
	response.set_timestamp(time(NULL));

	// Response: DataTree data = 2;
	auto *data = response.mutable_data();
	data->set_encoding(tag->request.encoding());
	status = get_path(data, mypathps->back().c_str(), type,
			  encoding2lyd_format(encoding), with_defaults);

	if (!status.ok()) {
		grpc_debug("fail get");
		tag->async_responder.WriteAndFinish(
			response, grpc::WriteOptions(), status, tag);
		return false;
	}

	mypathps->pop_back();
	if (mypathps->empty()) {
		tag->async_responder.WriteAndFinish(
			response, grpc::WriteOptions(), grpc::Status::OK, tag);
		return false;
	} else {
		tag->async_responder.Write(response, tag);
		return true;
	}
}

grpc::Status HandleUnaryCreateCandidate(
	UnaryRpcState<frr::CreateCandidateRequest, frr::CreateCandidateResponse>
		*tag)
{
	grpc_debug("entered");

	struct candidate *candidate = tag->cdb->create_candidate();
	if (!candidate)
		return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
				    "Can't create candidate configuration");
	tag->response.set_candidate_id(candidate->id);
	return grpc::Status::OK;
}

grpc::Status HandleUnaryDeleteCandidate(
	UnaryRpcState<frr::DeleteCandidateRequest, frr::DeleteCandidateResponse>
		*tag)
{
	grpc_debug("%s: entered", __func__);

	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	if (!tag->cdb->contains(candidate_id))
		return grpc::Status(grpc::StatusCode::NOT_FOUND,
				    "candidate configuration not found");
	tag->cdb->delete_candidate(candidate_id);
	return grpc::Status::OK;
}

grpc::Status HandleUnaryUpdateCandidate(
	UnaryRpcState<frr::UpdateCandidateRequest, frr::UpdateCandidateResponse>
		*tag)
{
	grpc_debug("%s: entered", __func__);

	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);

	if (!candidate)
		return grpc::Status(grpc::StatusCode::NOT_FOUND,
				    "candidate configuration not found");
	if (candidate->transaction)
		return grpc::Status(
			grpc::StatusCode::FAILED_PRECONDITION,
			"candidate is in the middle of a transaction");
	if (nb_candidate_update(candidate->config) != NB_OK)
		return grpc::Status(grpc::StatusCode::INTERNAL,
				    "failed to update candidate configuration");

	return grpc::Status::OK;
}

grpc::Status HandleUnaryEditCandidate(
	UnaryRpcState<frr::EditCandidateRequest, frr::EditCandidateResponse>
		*tag)
{
	grpc_debug("%s: entered", __func__);

	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);
	if (!candidate)
		return grpc::Status(grpc::StatusCode::NOT_FOUND,
				    "candidate configuration not found");

	struct nb_config *candidate_tmp = nb_config_dup(candidate->config);

	auto pvs = tag->request.update();
	for (const frr::PathValue &pv : pvs) {
		if (yang_dnode_edit(candidate_tmp->dnode, pv.path(),
				    pv.value().c_str()) != 0) {
			nb_config_free(candidate_tmp);

			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Failed to update \"" + pv.path() +
						    "\"");
		}
	}

	pvs = tag->request.delete_();
	for (const frr::PathValue &pv : pvs) {
		if (yang_dnode_delete(candidate_tmp->dnode, pv.path()) != 0) {
			nb_config_free(candidate_tmp);
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Failed to remove \"" + pv.path() +
						    "\"");
		}
	}

	// No errors, accept all changes.
	nb_config_replace(candidate->config, candidate_tmp, false);
	return grpc::Status::OK;
}

grpc::Status HandleUnaryLoadToCandidate(
	UnaryRpcState<frr::LoadToCandidateRequest, frr::LoadToCandidateResponse>
		*tag)
{
	grpc_debug("%s: entered", __func__);

	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	// Request: LoadType type = 2;
	int load_type = tag->request.type();
	// Request: DataTree config = 3;
	auto config = tag->request.config();

	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);
	if (!candidate)
		return grpc::Status(grpc::StatusCode::NOT_FOUND,
				    "candidate configuration not found");

	struct lyd_node *dnode = dnode_from_data_tree(&config, true);
	if (!dnode)
		return grpc::Status(grpc::StatusCode::INTERNAL,
				    "Failed to parse the configuration");

	struct nb_config *loaded_config = nb_config_new(dnode);
	if (load_type == frr::LoadToCandidateRequest::REPLACE)
		nb_config_replace(candidate->config, loaded_config, false);
	else if (nb_config_merge(candidate->config, loaded_config, false) !=
		 NB_OK)
		return grpc::Status(grpc::StatusCode::INTERNAL,
				    "Failed to merge the loaded configuration");

	return grpc::Status::OK;
}

grpc::Status
HandleUnaryCommit(UnaryRpcState<frr::CommitRequest, frr::CommitResponse> *tag)
{
	grpc_debug("%s: entered", __func__);

	// Request: uint32 candidate_id = 1;
	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	// Request: Phase phase = 2;
	int phase = tag->request.phase();
	// Request: string comment = 3;
	const std::string comment = tag->request.comment();

	// Find candidate configuration.
	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);
	if (!candidate)
		return grpc::Status(grpc::StatusCode::NOT_FOUND,
				    "candidate configuration not found");

	int ret = NB_OK;
	uint32_t transaction_id = 0;

	// Check for misuse of the two-phase commit protocol.
	switch (phase) {
	case frr::CommitRequest::PREPARE:
	case frr::CommitRequest::ALL:
		if (candidate->transaction)
			return grpc::Status(
				grpc::StatusCode::FAILED_PRECONDITION,
				"candidate is in the middle of a transaction");
		break;
	case frr::CommitRequest::ABORT:
	case frr::CommitRequest::APPLY:
		if (!candidate->transaction)
			return grpc::Status(
				grpc::StatusCode::FAILED_PRECONDITION,
				"no transaction in progress");
		break;
	default:
		break;
	}


	// Execute the user request.
	struct nb_context context = {};
	context.client = NB_CLIENT_GRPC;
	char errmsg[BUFSIZ] = {0};

	switch (phase) {
	case frr::CommitRequest::VALIDATE:
		grpc_debug("`-> Performing VALIDATE");
		ret = nb_candidate_validate(&context, candidate->config, errmsg,
					    sizeof(errmsg));
		break;
	case frr::CommitRequest::PREPARE:
		grpc_debug("`-> Performing PREPARE");
		ret = nb_candidate_commit_prepare(
			context, candidate->config, comment.c_str(),
			&candidate->transaction, false, false, errmsg,
			sizeof(errmsg));
		break;
	case frr::CommitRequest::ABORT:
		grpc_debug("`-> Performing ABORT");
		nb_candidate_commit_abort(candidate->transaction, errmsg,
					  sizeof(errmsg));
		break;
	case frr::CommitRequest::APPLY:
		grpc_debug("`-> Performing APPLY");
		nb_candidate_commit_apply(candidate->transaction, true,
					  &transaction_id, errmsg,
					  sizeof(errmsg));
		break;
	case frr::CommitRequest::ALL:
		grpc_debug("`-> Performing ALL");
		ret = nb_candidate_commit(context, candidate->config, true,
					  comment.c_str(), &transaction_id,
					  errmsg, sizeof(errmsg));
		break;
	}

	// Map northbound error codes to gRPC status codes.
	grpc::Status status;
	switch (ret) {
	case NB_OK:
		status = grpc::Status::OK;
		break;
	case NB_ERR_NO_CHANGES:
		status = grpc::Status(grpc::StatusCode::ABORTED, errmsg);
		break;
	case NB_ERR_LOCKED:
		status = grpc::Status(grpc::StatusCode::UNAVAILABLE, errmsg);
		break;
	case NB_ERR_VALIDATION:
		status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				      errmsg);
		break;
	case NB_ERR_RESOURCE:
		status = grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
				      errmsg);
		break;
	case NB_ERR:
	default:
		status = grpc::Status(grpc::StatusCode::INTERNAL, errmsg);
		break;
	}

	grpc_debug("`-> Result: %s (message: '%s')",
		   nb_err_name((enum nb_error)ret), errmsg);

	if (ret == NB_OK) {
		// Response: uint32 transaction_id = 1;
		if (transaction_id)
			tag->response.set_transaction_id(transaction_id);
	}
	if (strlen(errmsg) > 0)
		tag->response.set_error_message(errmsg);

	return status;
}

grpc::Status HandleUnaryLockConfig(
	UnaryRpcState<frr::LockConfigRequest, frr::LockConfigResponse> *tag)
{
	grpc_debug("%s: entered", __func__);

	if (nb_running_lock(NB_CLIENT_GRPC, NULL))
		return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
				    "running configuration is locked already");
	return grpc::Status::OK;
}

grpc::Status HandleUnaryUnlockConfig(
	UnaryRpcState<frr::UnlockConfigRequest, frr::UnlockConfigResponse> *tag)
{
	grpc_debug("%s: entered", __func__);

	if (nb_running_unlock(NB_CLIENT_GRPC, NULL))
		return grpc::Status(
			grpc::StatusCode::FAILED_PRECONDITION,
			"failed to unlock the running configuration");
	return grpc::Status::OK;
}

static void list_transactions_cb(void *arg, int transaction_id,
				 const char *client_name, const char *date,
				 const char *comment)
{
	auto list = static_cast<std::list<
		std::tuple<int, std::string, std::string, std::string>> *>(arg);
	list->push_back(
		std::make_tuple(transaction_id, std::string(client_name),
				std::string(date), std::string(comment)));
}

// Define the context variable type for this streaming handler
typedef std::list<std::tuple<int, std::string, std::string, std::string>>
	ListTransactionsContextType;

bool HandleStreamingListTransactions(
	StreamRpcState<frr::ListTransactionsRequest,
		       frr::ListTransactionsResponse,
		       ListTransactionsContextType> *tag)
{
	grpc_debug("%s: entered", __func__);

	auto list = &tag->context;
	if (tag->is_initial_process()) {
		grpc_debug("%s: initialize streaming state", __func__);
		// Fill our context container first time through
		nb_db_transactions_iterate(list_transactions_cb, list);
		list->push_back(std::make_tuple(
			0xFFFF, std::string("fake client"),
			std::string("fake date"), std::string("fake comment")));
		list->push_back(std::make_tuple(0xFFFE,
						std::string("fake client2"),
						std::string("fake date"),
						std::string("fake comment2")));
	}

	if (list->empty()) {
		tag->async_responder.Finish(grpc::Status::OK, tag);
		return false;
	}

	auto item = list->back();

	frr::ListTransactionsResponse response;

	// Response: uint32 id = 1;
	response.set_id(std::get<0>(item));

	// Response: string client = 2;
	response.set_client(std::get<1>(item).c_str());

	// Response: string date = 3;
	response.set_date(std::get<2>(item).c_str());

	// Response: string comment = 4;
	response.set_comment(std::get<3>(item).c_str());

	list->pop_back();
	if (list->empty()) {
		tag->async_responder.WriteAndFinish(
			response, grpc::WriteOptions(), grpc::Status::OK, tag);
		return false;
	} else {
		tag->async_responder.Write(response, tag);
		return true;
	}
}

grpc::Status HandleUnaryGetTransaction(
	UnaryRpcState<frr::GetTransactionRequest, frr::GetTransactionResponse>
		*tag)
{
	grpc_debug("%s: entered", __func__);

	// Request: uint32 transaction_id = 1;
	uint32_t transaction_id = tag->request.transaction_id();
	// Request: Encoding encoding = 2;
	frr::Encoding encoding = tag->request.encoding();
	// Request: bool with_defaults = 3;
	bool with_defaults = tag->request.with_defaults();

	grpc_debug("%s(transaction_id: %u, encoding: %u)", __func__,
		   transaction_id, encoding);

	struct nb_config *nb_config;

	// Load configuration from the transactions database.
	nb_config = nb_db_transaction_load(transaction_id);
	if (!nb_config)
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Transaction not found");

	// Response: DataTree config = 1;
	auto config = tag->response.mutable_config();
	config->set_encoding(encoding);

	// Dump data using the requested format.
	if (data_tree_from_dnode(config, nb_config->dnode,
				 encoding2lyd_format(encoding), with_defaults)
	    != 0) {
		nb_config_free(nb_config);
		return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to dump data (2)");
	}

	nb_config_free(nb_config);

	return grpc::Status::OK;
}

grpc::Status HandleUnaryExecute(
	UnaryRpcState<frr::ExecuteRequest, frr::ExecuteResponse> *tag)
{
	grpc_debug("%s: entered", __func__);

	struct nb_node *nb_node;
	struct lyd_node *input_tree, *output_tree, *child;
	const char *xpath;
	char errmsg[BUFSIZ] = {0};
	char path[XPATH_MAXLEN];
	LY_ERR err;

	// Request: string path = 1;
	xpath = tag->request.path().c_str();

	grpc_debug("%s(path: \"%s\")", __func__, xpath);

	if (tag->request.path().empty())
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Data path is empty");

	nb_node = nb_node_find(xpath);
	if (!nb_node)
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Unknown data path");

	// Create input data tree.
	err = yang_new_path2(NULL, ly_native_ctx, xpath, NULL, 0, (LYD_ANYDATA_VALUETYPE)0, 0,
			     NULL, &input_tree);
	if (err != LY_SUCCESS) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Invalid data path");
	}

	// Read input parameters.
	auto input = tag->request.input();
	for (const frr::PathValue &pv : input) {
		// Request: repeated PathValue input = 2;
		err = lyd_new_path(input_tree, ly_native_ctx, pv.path().c_str(),
				   pv.value().c_str(), 0, NULL);
		if (err != LY_SUCCESS) {
			lyd_free_tree(input_tree);
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Invalid input data");
		}
	}

	// Validate input data.
	err = lyd_validate_op(input_tree, NULL, LYD_TYPE_RPC_YANG, NULL);
	if (err != LY_SUCCESS) {
		lyd_free_tree(input_tree);
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Invalid input data");
	}

	// Create output data tree.
	err = yang_new_path2(NULL, ly_native_ctx, xpath, NULL, 0, (LYD_ANYDATA_VALUETYPE)0, 0,
			     NULL, &output_tree);
	if (err != LY_SUCCESS) {
		lyd_free_tree(input_tree);
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Invalid data path");
	}

	// Execute callback registered for this XPath.
	if (nb_callback_rpc(nb_node, xpath, input_tree, output_tree, errmsg,
			    sizeof(errmsg)) != NB_OK) {
		flog_warn(EC_LIB_NB_CB_RPC, "%s: rpc callback failed: %s",
			  __func__, xpath);
		lyd_free_tree(input_tree);
		lyd_free_tree(output_tree);

		return grpc::Status(grpc::StatusCode::INTERNAL, "RPC failed");
	}

	// Process output parameters.
	LY_LIST_FOR (lyd_child(output_tree), child) {
		// Response: repeated PathValue output = 1;
		frr::PathValue *pv = tag->response.add_output();
		pv->set_path(lyd_path(child, LYD_PATH_STD, path, sizeof(path)));
		pv->set_value(yang_dnode_get_string(child, NULL));
	}

	// Release memory.
	lyd_free_tree(input_tree);
	lyd_free_tree(output_tree);

	return grpc::Status::OK;
}

// ------------------------------------------------------
//        Thread Initialization and Run Functions
// ------------------------------------------------------


#define REQUEST_NEWRPC(NAME, cdb)                                              \
	do {                                                                   \
		auto _rpcState = new UnaryRpcState<frr::NAME##Request,         \
						   frr::NAME##Response>(       \
			(cdb), &frr::Northbound::AsyncService::Request##NAME,  \
			&HandleUnary##NAME, #NAME);                            \
		_rpcState->do_request(&service, cq.get(), true);               \
	} while (0)

#define REQUEST_NEWRPC_STREAMING(NAME)                                         \
	do {                                                                   \
		auto _rpcState = new StreamRpcState<frr::NAME##Request,        \
						    frr::NAME##Response,       \
						    NAME##ContextType>(        \
			&frr::Northbound::AsyncService::Request##NAME,         \
			&HandleStreaming##NAME, #NAME);                        \
		_rpcState->do_request(&service, cq.get(), true);               \
	} while (0)

struct grpc_pthread_attr {
	struct frr_pthread_attr attr;
	unsigned long port;
};

// Capture these objects so we can try to shut down cleanly
static pthread_mutex_t s_server_lock = PTHREAD_MUTEX_INITIALIZER;
static grpc::Server *s_server;

static void *grpc_pthread_start(void *arg)
{
	struct frr_pthread *fpt = static_cast<frr_pthread *>(arg);
	uint port = (uint) reinterpret_cast<intptr_t>(fpt->data);

	Candidates candidates;
	grpc::ServerBuilder builder;
	std::stringstream server_address;
	frr::Northbound::AsyncService service;

	frr_pthread_set_name(fpt);

	server_address << "0.0.0.0:" << port;
	builder.AddListeningPort(server_address.str(),
				 grpc::InsecureServerCredentials());
	builder.RegisterService(&service);
	builder.AddChannelArgument(
		GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS, 5000);
	std::unique_ptr<grpc::ServerCompletionQueue> cq =
		builder.AddCompletionQueue();
	std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
	s_server = server.get();

	pthread_mutex_lock(&s_server_lock); // Make coverity happy
	grpc_running = true;
	pthread_mutex_unlock(&s_server_lock); // Make coverity happy

	/* Schedule unary RPC handlers */
	REQUEST_NEWRPC(GetCapabilities, NULL);
	REQUEST_NEWRPC(CreateCandidate, &candidates);
	REQUEST_NEWRPC(DeleteCandidate, &candidates);
	REQUEST_NEWRPC(UpdateCandidate, &candidates);
	REQUEST_NEWRPC(EditCandidate, &candidates);
	REQUEST_NEWRPC(LoadToCandidate, &candidates);
	REQUEST_NEWRPC(Commit, &candidates);
	REQUEST_NEWRPC(GetTransaction, NULL);
	REQUEST_NEWRPC(LockConfig, NULL);
	REQUEST_NEWRPC(UnlockConfig, NULL);
	REQUEST_NEWRPC(Execute, NULL);

	/* Schedule streaming RPC handlers */
	REQUEST_NEWRPC_STREAMING(Get);
	REQUEST_NEWRPC_STREAMING(ListTransactions);

	zlog_notice("gRPC server listening on %s",
		    server_address.str().c_str());

	/* Process inbound RPCs */
	bool ok;
	void *tag;
	while (true) {
		if (!cq->Next(&tag, &ok)) {
			grpc_debug("%s: CQ empty exiting", __func__);
			break;
		}

		grpc_debug("%s: got next from CQ tag: %p ok: %d", __func__, tag,
			   ok);

		if (!ok) {
			delete static_cast<RpcStateBase *>(tag);
			break;
		}

		RpcStateBase *rpc = static_cast<RpcStateBase *>(tag);
		if (rpc->get_state() != FINISH)
			rpc->run(&service, cq.get());
		else {
			grpc_debug("%s RPC FINISH -> [delete]", rpc->name);
			delete rpc;
		}
	}

	/* This was probably done for us to get here, but let's be safe */
	pthread_mutex_lock(&s_server_lock);
	grpc_running = false;
	if (s_server) {
		grpc_debug("%s: shutdown server and CQ", __func__);
		server->Shutdown();
		s_server = NULL;
	}
	pthread_mutex_unlock(&s_server_lock);

	grpc_debug("%s: shutting down CQ", __func__);
	cq->Shutdown();

	grpc_debug("%s: draining the CQ", __func__);
	while (cq->Next(&tag, &ok)) {
		grpc_debug("%s: drain tag %p", __func__, tag);
		delete static_cast<RpcStateBase *>(tag);
	}

	zlog_info("%s: exiting from grpc pthread", __func__);
	return NULL;
}


static int frr_grpc_start_server(uint port)
{
	struct frr_pthread_attr attr = {
		.start = grpc_pthread_start,
		.stop = NULL,
	};

	assert(fpt == NULL);

	grpc_debug("%s: entered", __func__);

	fpt = frr_pthread_new(&attr, "frr-grpc", "frr-grpc");
	fpt->data = reinterpret_cast<void *>((intptr_t)port);

	/* Create a pthread for gRPC since it runs its own event loop. */
	if (frr_pthread_run(fpt, NULL) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL, "%s: error creating pthread: %s",
			 __func__, safe_strerror(errno));
		return -1;
	}

	return 0;
}

static void frr_grpc_stop_server(void)
{
	grpc_debug("%s: entered", __func__);

	if (!fpt)
		return;

	pthread_mutex_lock(&s_server_lock);
	grpc_running = false;
	if (s_server) {
		grpc_debug("%s: shutdown server", __func__);
		s_server->Shutdown();
		s_server = NULL;
	}
	pthread_mutex_unlock(&s_server_lock);

	grpc_debug("%s: joining and destroy grpc thread", __func__);
	pthread_join(fpt->thread, NULL);
	frr_pthread_destroy(fpt);
	fpt = NULL;
}

static int frr_grpc_finish(void)
{
	grpc_debug("%s: entered", __func__);

	if (!fpt)
		return 0;

	/*
	 * Shut the server down here in main thread. This will cause the wait on
	 * the completion queue (cq.Next()) to exit and cleanup everything else.
	 */

	frr_grpc_stop_server();

	if (grpc_fe_client) {
		mgmt_fe_client_destroy(grpc_fe_client);
		grpc_fe_client = NULL;
		grpc_fe_session_id = 0;
		grpc_fe_connected = false;
		grpc_fe_session_ready = false;
	}

	// Fix protobuf 'memory leaks' during shutdown.
	// https://groups.google.com/g/protobuf/c/4y_EmQiCGgs
	google::protobuf::ShutdownProtobufLibrary();

	return 0;
}

static int frr_grpc_module_late_init(struct event_loop *tm)
{
	const char *progname = frr_get_progname();
	const char *args = THIS_MODULE->load_args;

	/* Get the port to serve gRPC requests from */
	if (args) {
		uint port = std::stoul(args);
		if (port < 1024 || port > UINT16_MAX) {
			flog_err(EC_LIB_GRPC_INIT, "%s: port number must be between 1024 and %d",
				 __func__, UINT16_MAX);
			abort();
			return -1;
		}
		grpc_port = port;
	}

	main_master = tm;

	/*
	 * gRPC northbound runs only on mgmtd and uses the mgmtd frontend client
	 * API for config/state so it can configure and query all daemons.
	 * When loaded in other daemons, do nothing.
	 */
	if (!progname || strcmp(progname, "mgmtd") != 0) {
		zlog_info("gRPC module: only supported when loaded in mgmtd (current: %s), skipping",
			  progname ? progname : "unknown");
		return -1;
	}

	/* Create mgmtd frontend client so gRPC uses mgmtd for config/state */
	static struct mgmt_fe_client_cbs fe_cbs = {
		.client_connect_notify = grpc_fe_connect_notify,
		.client_session_notify = grpc_fe_session_notify,
		.get_tree_notify = grpc_fe_get_tree_notify,
	};
	grpc_fe_client = mgmt_fe_client_create("grpc-nb", &fe_cbs, 0, main_master);
	assert(grpc_fe_client);

	/* client connect will drive rest of the initialization */

	hook_register(frr_fini, frr_grpc_finish);
	return 0;
}

static int frr_grpc_module_init(void)
{
	hook_register(frr_late_init, frr_grpc_module_late_init);

	return 0;
}

FRR_MODULE_SETUP(.name = "frr_grpc", .version = FRR_VERSION,
		 .description = "FRR gRPC northbound module",
		 .init = frr_grpc_module_init, );
