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
#include "json.h"

#include <iostream>
#include <chrono>
#include <sstream>
#include <memory>
#include <string>
#include <deque>
#include <exception>
#include <iterator>
#include <list>
#include <vector>

#define GRPC_DEFAULT_PORT 50051
#define GRPC_SUBSCRIBE_MIN_INTERVAL_MS	   100
#define GRPC_SUBSCRIBE_DEFAULT_MAX_PENDING 128


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
static bool grpc_shutting_down;
static size_t grpc_subscribe_max_pending = GRPC_SUBSCRIBE_DEFAULT_MAX_PENDING;
static pthread_mutex_t s_server_lock = PTHREAD_MUTEX_INITIALIZER;
static grpc::Server *s_server;
static grpc::ServerCompletionQueue *s_cq;

static bool grpc_is_running(void)
{
	bool running;

	pthread_mutex_lock(&s_server_lock);
	running = grpc_running;
	pthread_mutex_unlock(&s_server_lock);

	return running;
}

static bool grpc_is_shutting_down(void)
{
	bool shutting_down;

	pthread_mutex_lock(&s_server_lock);
	shutting_down = grpc_shutting_down;
	pthread_mutex_unlock(&s_server_lock);

	return shutting_down;
}

#define grpc_debug(...)                                                        \
	do {                                                                   \
		if (nb_dbg_client_grpc)                                        \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

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

	virtual bool repost_on_finish(void) const
	{
		return true;
	}

	virtual bool handle_cq_error(void)
	{
		return true;
	}

	virtual bool repost_on_cq_error(void) const
	{
		return state == CREATE;
	}

	bool is_initial_process() const
	{
		/* Will always be true for Unary */
		return entered_state == CREATE;
	}

	bool is_cancelled() const
	{
		return ctx.IsCancelled();
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

		if (this->state == FINISH && this->repost_on_finish()) {
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
		grpc_debug("%s, posting a request for: %s", __func__, name);
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
		grpc_debug("%s, posting a request for: %s", __func__, name);
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

static bool encoding2lyd_format(enum frr::Encoding encoding, LYD_FORMAT *format)
{
	switch (encoding) {
	case frr::JSON:
		*format = LYD_JSON;
		return true;
	case frr::XML:
		*format = LYD_XML;
		return true;
	default:
		flog_warn(EC_LIB_GRPC_INIT, "%s: unknown data encoding format (%u)", __func__,
			  encoding);
		return false;
	}
}

static grpc::Status invalid_encoding_status(enum frr::Encoding encoding)
{
	return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
			    std::string("Unknown data encoding format: ") +
				    std::to_string(encoding));
}

static bool parse_unsigned_arg(const std::string &arg, unsigned long *value)
{
	size_t parsed = 0;

	if (arg.empty() || arg[0] == '-' || arg[0] == '+')
		return false;

	try {
		*value = std::stoul(arg, &parsed);
	} catch (const std::exception &) {
		return false;
	}

	return parsed == arg.size();
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

	LYD_FORMAT lyd_format;

	if (!encoding2lyd_format(dt->encoding(), &lyd_format))
		return NULL;

	err = lyd_parse_data_mem(ly_native_ctx, dt->data().c_str(), lyd_format, options, opt2,
				 &dnode);
	if (err != LY_SUCCESS) {
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_parse_mem() failed: %s",
			  __func__, ly_errmsg(ly_native_ctx));
	}
	return dnode;
}

static bool get_path_is_root(const std::string &path)
{
	return path.empty() || path == "/";
}

static struct lyd_node *dup_single_dnode(const struct lyd_node *dnode)
{
	struct lyd_node *dup = NULL;
	LY_ERR err;

	err = lyd_dup_single(dnode, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &dup);
	if (err) {
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_dup_single() failed: %s", __func__,
			  ly_errmsg(ly_native_ctx));
		return NULL;
	}

	return dup;
}

static struct lyd_node *select_config_get_result(struct lyd_node *dnode,
						 const std::string &path)
{
	struct lyd_node *target;
	struct lyd_node *dup;

	if (get_path_is_root(path))
		return dnode;

	/*
	 * A frontend dispatcher may return a parent-preserving fragment so the
	 * selected node can be found in its datastore context. The gRPC response
	 * already carries the requested path, so serialise the YANG subtree
	 * rooted at that path.
	 */
	target = yang_dnode_get(dnode, path.c_str());
	if (!target || target == dnode)
		return dnode;

	dup = dup_single_dnode(target);
	if (!dup)
		return dnode;

	yang_dnode_free(dnode);

	return dup;
}

static struct lyd_node *get_dnode_config(const std::string &path)
{
	struct lyd_node *dnode;
	char errmsg[BUFSIZ] = {};
	int ret;

	ret = nb_config_get_dispatch(path.empty() ? NULL : path.c_str(), &dnode, errmsg,
				     sizeof(errmsg));
	if (!ret)
		return select_config_get_result(dnode, path);
	if (ret == -ENOENT)
		return NULL;
	if (ret != -EOPNOTSUPP) {
		flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE, "%s: failed to fetch config path %s: %s",
			  __func__, path.c_str(), errmsg);
		return NULL;
	}

	if (!running_config)
		return NULL;

	if (get_path_is_root(path))
		return yang_dnode_dup(running_config->dnode);

	if (!yang_dnode_exists(running_config->dnode, path.c_str()))
		return NULL;

	dnode = yang_dnode_get(running_config->dnode, path.c_str());
	if (dnode)
		dnode = dup_single_dnode(dnode);

	return dnode;
}

static const struct lyd_node *get_execute_dep_tree(void)
{
	const struct lyd_node *dnode = NULL;
	char errmsg[BUFSIZ] = {};
	int ret;

	ret = nb_config_root_borrow_dispatch(&dnode, errmsg, sizeof(errmsg));
	if (!ret)
		return dnode;

	if (ret != -EOPNOTSUPP) {
		flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE, "%s: failed to fetch running config: %s",
			  __func__, errmsg);
		return NULL;
	}

	/*
	 * Daemon-local gRPC can lend libyang the in-process running datastore
	 * while validating RPC input. This assumes the daemon has one running
	 * config root; a frontend with central state, such as mgmtd, supplies a
	 * borrowed root through nb_config_root_borrow_dispatch() above so its
	 * datastore ownership remains inside that frontend.
	 */
	return running_config ? running_config->dnode : NULL;
}

static struct lyd_node *get_dnode_state(const std::string &path)
{
	struct lyd_node *dnode = NULL;

	(void)nb_oper_iterate_legacy(path.c_str(), NULL, 0, NULL, NULL, &dnode);

	return dnode;
}

static grpc::Status get_state_snapshot_path(frr::DataTree *dt, const std::string &path,
					    LYD_FORMAT lyd_format, bool with_defaults)
{
	struct lyd_node *dnode_state;
	LY_ERR err;

	dnode_state = get_dnode_state(path);
	if (!dnode_state)
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Failed to fetch operational data");

	err = data_tree_from_dnode(dt, dnode_state, lyd_format, with_defaults);
	yang_dnode_free(dnode_state);
	if (err)
		return grpc::Status(grpc::StatusCode::INTERNAL, "Failed to dump data");

	return grpc::Status::OK;
}

static grpc::Status get_path(frr::DataTree *dt, const std::string &path,
			     int type, LYD_FORMAT lyd_format,
			     bool with_defaults)
{
	struct lyd_node *dnode_config = NULL;
	struct lyd_node *dnode_state = NULL;
	struct lyd_node *dnode_final;
	bool validate = false;

	// Configuration data.
	if (type == frr::GetRequest_DataType_ALL
	    || type == frr::GetRequest_DataType_CONFIG) {
		dnode_config = get_dnode_config(path);
		if (!dnode_config && type == frr::GetRequest_DataType_CONFIG)
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Data path not found");
	}

	// Operational data.
	if (type == frr::GetRequest_DataType_ALL
	    || type == frr::GetRequest_DataType_STATE) {
		dnode_state = get_dnode_state(path);
		if (!dnode_state) {
			if (type == frr::GetRequest_DataType_ALL && dnode_config)
				goto have_data;
			if (dnode_config)
				yang_dnode_free(dnode_config);
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    type == frr::GetRequest_DataType_ALL
						    ? "Data path not found"
						    : "Failed to fetch operational data");
		}
	}

	if (!dnode_config && !dnode_state)
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Data path not found");

have_data:
	switch (type) {
	case frr::GetRequest_DataType_ALL:
		if (!dnode_config) {
			dnode_final = dnode_state;
			validate = false;
			break;
		}
		if (!dnode_state) {
			dnode_final = dnode_config;
			validate = get_path_is_root(path);
			break;
		}
		//
		// Combine configuration and state data into a single
		// dnode.
		//
		if (lyd_merge_siblings(&dnode_state, dnode_config,
				       LYD_MERGE_DESTRUCT)
		    != LY_SUCCESS) {
			yang_dnode_free(dnode_state);
			yang_dnode_free(dnode_config);
			return grpc::Status(
				grpc::StatusCode::INTERNAL,
				"Failed to merge configuration and state data",
				ly_errmsg(ly_native_ctx));
		}

		dnode_final = dnode_state;
		validate = get_path_is_root(path);
		break;
	case frr::GetRequest_DataType_CONFIG:
		dnode_final = dnode_config;
		validate = get_path_is_root(path);
		break;
	case frr::GetRequest_DataType_STATE:
		dnode_final = dnode_state;
		break;
	}

	/*
	 * Validate complete root reads to create implicit default nodes. A
	 * path-specific subtree was selected from an already-valid datastore,
	 * but is not itself a complete datastore: leafrefs may point outside the
	 * returned fragment.
	 */
	int validate_opts = 0;
	if (type == frr::GetRequest_DataType_CONFIG || !dnode_state)
		validate_opts = LYD_VALIDATE_NO_STATE;
	else
		validate_opts = 0;

	LY_ERR err = LY_SUCCESS;
	if (validate)
		err = lyd_validate_all(&dnode_final, ly_native_ctx, validate_opts, NULL);

	if (err)
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_validate_all() failed: %s",
			  __func__, ly_errmsg(ly_native_ctx));
	// Dump data using the requested format.
	if (!err)
		err = data_tree_from_dnode(dt, dnode_final, lyd_format,
					   with_defaults);
	yang_dnode_free(dnode_final);
	if (err)
		return grpc::Status(grpc::StatusCode::INTERNAL,
				    "Failed to dump data");
	return grpc::Status::OK;
}

// ------------------------------------------------------
//       RPC Callback Functions: run on main thread
// ------------------------------------------------------

grpc::Status HandleUnaryGetCapabilities(
	UnaryRpcState<frr::GetCapabilitiesRequest, frr::GetCapabilitiesResponse>
		*tag)
{
	grpc_debug("%s: entered", __func__);

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

	return grpc::Status::OK;
}

// Define the context variable type for this streaming handler
typedef std::list<std::string> GetContextType;

bool HandleStreamingGet(
	StreamRpcState<frr::GetRequest, frr::GetResponse, GetContextType> *tag)
{
	grpc_debug("%s: entered", __func__);

	auto mypathps = &tag->context;
	if (tag->is_initial_process()) {
		// Fill our context container first time through
		grpc_debug("%s: initialize streaming state", __func__);
		auto paths = tag->request.path();
		for (const std::string &path : paths) {
			mypathps->push_back(std::string(path));
		}
		if (mypathps->empty())
			mypathps->push_back("/");
	}

	// Request: DataType type = 1;
	int type = tag->request.type();
	// Request: Encoding encoding = 2;
	frr::Encoding encoding = tag->request.encoding();
	LYD_FORMAT lyd_format;
	// Request: bool with_defaults = 3;
	bool with_defaults = tag->request.with_defaults();

	if (mypathps->empty()) {
		tag->async_responder.Finish(grpc::Status::OK, tag);
		return false;
	}

	frr::GetResponse response;
	grpc::Status status;

	if (!encoding2lyd_format(encoding, &lyd_format)) {
		tag->async_responder.WriteAndFinish(response, grpc::WriteOptions(),
						    invalid_encoding_status(encoding), tag);
		return false;
	}

	// Response: int64 timestamp = 1;
	response.set_timestamp(time(NULL));

	// Response: DataTree data = 2;
	auto *data = response.mutable_data();
	data->set_encoding(tag->request.encoding());
	data->set_path(mypathps->back());
	if (type == frr::GetRequest_DataType_STATE)
		status = get_state_snapshot_path(data, mypathps->back().c_str(), lyd_format,
						 with_defaults);
	else
		status = get_path(data, mypathps->back().c_str(), type, lyd_format, with_defaults);

	if (!status.ok()) {
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
	grpc_debug("%s: entered", __func__);

	struct candidate *candidate = tag->cdb->create_candidate();
	if (!candidate)
		return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
				    "Can't create candidate configuration");
	tag->response.set_candidate_id(candidate->id);
	return grpc::Status::OK;
}

/*
 * Subscribe streaming RPC.
 *
 * Server-streaming RPC: the client sends one SubscribeRequest, the server
 * keeps the stream open and writes a SubscribeResponse for every YANG
 * notification matching the subscribed paths.  This is the gNMI shape; it
 * works with off-the-shelf tools (gnmic, gNMI Python libraries) that
 * already expect a server-streaming Subscribe.
 *
 * Per-stream state lives in a Subscription owned by SubscribeRpcState.
 * Notification selector matching is delegated to the daemon-specific
 * notification-data subscription provider.  In mgmtd this is the same
 * selector tree used by native frontend clients.
 *
 * Thread invariants:
 *   - run_mainthread(), finish_from_event_thread(), close_subscription(),
 *     deregister_subscription(), and timer callbacks run on the libfrr main
 *     thread.
 *   - handle_cq_error() runs on the gRPC completion-queue pthread.
 *   - enqueue_notification_for() can be entered while gRPC write completions
 *     are also flowing.
 *
 * Locking:
 *   - RpcStateBase::cmux protects the SubscribeRpcState::sub pointer and RPC
 *     state transitions coordinated with the completion-queue pthread.
 *   - Subscription::mtx protects pending, write_in_flight, timer handles,
 *     cancelled and the mgmtd unsubscribe handle.
 *
 *   gRPC's per-stream Write must be serialised by the caller; that is
 *   enforced by write_in_flight: the notification callback only posts a new
 *   Write when write_in_flight is false; the handler only clears
 *   write_in_flight after the previous Write has completed.
 *
 * Modes:
 *   ON_CHANGE  -- implemented here.
 *   STREAM     -- send initial operational-state snapshot, then notifications.
 *   SAMPLE     -- periodically send operational-state snapshots.
 *   POLL       -- requires a client-streaming request shape; unimplemented.
 */

struct Subscription;

class SubscribeRpcState : public RpcStateBase {
      public:
	typedef void (frr::Northbound::AsyncService::*reqsfunc_t)(
		::grpc::ServerContext *, frr::SubscribeRequest *,
		::grpc::ServerAsyncWriter<frr::SubscribeResponse> *, ::grpc::CompletionQueue *,
		::grpc::ServerCompletionQueue *, void *);

	SubscribeRpcState();
	~SubscribeRpcState() override;

	void do_request(::frr::Northbound::AsyncService *service,
			::grpc::ServerCompletionQueue *cq, bool no_copy) override;
	CallState run_mainthread(struct event *event) override;
	bool repost_on_finish(void) const override;
	bool handle_cq_error(void) override;
	void enqueue_notification(frr::SubscribeResponse &&resp);
	void enqueue_notification_for(struct Subscription *expected_sub,
				      frr::SubscribeResponse &&resp);
	static void deregister_all_from_main(void);
	static void cancel_cleanup_events_from_main(void);

	frr::SubscribeRequest request;
	frr::SubscribeResponse response;
	grpc::ServerAsyncWriter<frr::SubscribeResponse> async_responder;

      private:
	enum class CqOp { ACCEPT, WRITE, FINISH };

	void finish_from_event_thread(grpc::Status status);
	void deregister_subscription(void);
	void close_subscription(grpc::Status status);
	bool enqueue_response(frr::SubscribeResponse &&resp, bool resets_heartbeat,
			      grpc::Status *status = NULL);
	grpc::Status enqueue_state_snapshot(bool sync_response);
	bool subscription_finish_deferred(void);
	void schedule_sample_timer(void);
	void schedule_heartbeat_timer(void);
	static void sample_timer_event(struct event *event);
	static void heartbeat_timer_event(struct event *event);

	reqsfunc_t requestsf = &frr::Northbound::AsyncService::RequestSubscribe;
	::frr::Northbound::AsyncService *service = NULL;
	::grpc::ServerCompletionQueue *cq = NULL;
	struct Subscription *sub = NULL;
	struct Subscription *shutdown_sub = NULL;
	CqOp op = CqOp::ACCEPT;
	bool accepted_stream = false;
};

struct Subscription {
	pthread_mutex_t mtx;

	/* Set by handler on initial entry; used by notification callback. */
	SubscribeRpcState *tag;
	std::list<std::string> selectors;
	frr::Encoding encoding;
	LYD_FORMAT lyd_format;

	/* gRPC write-serialisation. */
	std::deque<frr::SubscribeResponse> pending;
	bool write_in_flight;

	bool cancelled;
	bool main_released;
	bool finish_after_write;
	grpc::Status finish_status;
	void *mgmt_notify_handle;
	struct event *sample_timer;
	struct event *heartbeat_timer;
	uint32_t sample_interval_ms;
	uint32_t heartbeat_interval_ms;
};

struct SubscribeCleanup;
static pthread_mutex_t active_subscriptions_mtx = PTHREAD_MUTEX_INITIALIZER;
static std::list<Subscription *> active_subscriptions;
static pthread_mutex_t active_subscribe_cleanups_mtx = PTHREAD_MUTEX_INITIALIZER;
static std::list<SubscribeCleanup *> active_subscribe_cleanups;

struct SubscribeCleanup {
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	struct event *event;
	bool done;
	bool waiter;
	struct Subscription *sub;
};

static void subscribe_cleanup_free(struct SubscribeCleanup *cleanup);

static std::string notification_data_path(const char *xpath, LYD_FORMAT format, const char *data)
{
	struct lyd_node *tree = NULL;
	struct json_object *json = NULL;
	struct json_object_iter iter;
	char path[XPATH_MAXLEN];
	LY_ERR err;
	std::string result;

	if (xpath && xpath[0])
		return xpath;
	if (!data || !data[0])
		return "";

	/*
	 * mgmtd normally derives the notification path before dispatching to
	 * gRPC. Keep this fallback for daemon-local notification dispatch.
	 */
	err = lyd_parse_data_mem(ly_native_ctx, data, format, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0,
				 &tree);
	if (err != LY_SUCCESS || !tree)
		goto json_fallback;

	if (lyd_path(tree, LYD_PATH_STD, path, sizeof(path)) && path[0]) {
		result = path;
	} else if (tree->schema) {
		result = "/";
		result += tree->schema->module->name;
		result += ":";
		result += tree->schema->name;
	}
	lyd_free_all(tree);

	return result;

json_fallback:
	if (tree)
		lyd_free_all(tree);
	if (format != LYD_JSON)
		return "";

	json = json_tokener_parse(data);
	if (!json || json_object_get_type(json) != json_type_object)
		goto done;

	json_object_object_foreachC(json, iter)
	{
		result = "/";
		result += iter.key;
		break;
	}

done:
	if (json)
		json_object_put(json);
	return result;
}

static void subscription_track(struct Subscription *sub)
{
	pthread_mutex_lock(&active_subscriptions_mtx);
	active_subscriptions.push_back(sub);
	pthread_mutex_unlock(&active_subscriptions_mtx);
}

static void subscription_untrack(struct Subscription *sub)
{
	pthread_mutex_lock(&active_subscriptions_mtx);
	active_subscriptions.remove(sub);
	pthread_mutex_unlock(&active_subscriptions_mtx);
}

static void subscribe_cleanup_track(struct SubscribeCleanup *cleanup)
{
	pthread_mutex_lock(&active_subscribe_cleanups_mtx);
	active_subscribe_cleanups.push_back(cleanup);
	pthread_mutex_unlock(&active_subscribe_cleanups_mtx);
}

static void subscribe_cleanup_untrack(struct SubscribeCleanup *cleanup)
{
	pthread_mutex_lock(&active_subscribe_cleanups_mtx);
	active_subscribe_cleanups.remove(cleanup);
	pthread_mutex_unlock(&active_subscribe_cleanups_mtx);
}

static void grpc_notification_data_dispatch(const char *xpath, LYD_FORMAT format, const char *data,
					    void *arg)
{
	auto *sub = static_cast<struct Subscription *>(arg);
	SubscribeRpcState *tag;
	frr::Encoding encoding;
	frr::SubscribeResponse resp;
	auto *update = resp.mutable_update();
	std::string update_path;

	pthread_mutex_lock(&sub->mtx);
	tag = sub->tag;
	encoding = sub->encoding;
	pthread_mutex_unlock(&sub->mtx);

	if (!tag)
		return;

	update_path = notification_data_path(xpath, format, data);
	if (update_path.empty())
		flog_warn(EC_LIB_GRPC_INIT, "%s: unable to infer notification path", __func__);
	update->set_encoding(encoding);
	update->set_path(update_path);
	update->set_data(data ? data : "");
	tag->enqueue_notification_for(sub, std::move(resp));
}

static void subscription_destroy(struct Subscription *sub)
{
	pthread_mutex_destroy(&sub->mtx);
	delete sub;
}

static void subscription_release_main_resources(struct Subscription *sub)
{
	void *mgmt_notify_handle = NULL;

	event_cancel(&sub->sample_timer);
	event_cancel(&sub->heartbeat_timer);
	pthread_mutex_lock(&sub->mtx);
	if (!sub->main_released) {
		sub->main_released = true;
		sub->cancelled = true;
		mgmt_notify_handle = sub->mgmt_notify_handle;
		sub->mgmt_notify_handle = NULL;
		if (sub->write_in_flight) {
			if (sub->pending.size() > 1)
				sub->pending.erase(std::next(sub->pending.begin()),
						   sub->pending.end());
		} else {
			sub->pending.clear();
		}
	}
	pthread_mutex_unlock(&sub->mtx);

	if (mgmt_notify_handle)
		nb_notification_data_unsubscribe(mgmt_notify_handle);
}

static void subscription_deregister(struct Subscription *sub)
{
	subscription_untrack(sub);
	subscription_release_main_resources(sub);
	subscription_destroy(sub);
}

void SubscribeRpcState::deregister_all_from_main(void)
{
	while (true) {
		struct Subscription *sub;
		SubscribeRpcState *tag;

		pthread_mutex_lock(&active_subscriptions_mtx);
		if (active_subscriptions.empty()) {
			pthread_mutex_unlock(&active_subscriptions_mtx);
			return;
		}
		sub = active_subscriptions.front();
		active_subscriptions.pop_front();
		pthread_mutex_unlock(&active_subscriptions_mtx);

		subscription_release_main_resources(sub);

		pthread_mutex_lock(&sub->mtx);
		tag = sub->tag;
		pthread_mutex_unlock(&sub->mtx);
		if (tag) {
			pthread_mutex_lock(&tag->cmux);
			if (tag->sub == sub) {
				tag->sub = NULL;
				tag->shutdown_sub = sub;
			}
			pthread_mutex_unlock(&tag->cmux);
		}
	}
}

void SubscribeRpcState::cancel_cleanup_events_from_main(void)
{
	while (true) {
		struct SubscribeCleanup *cleanup;
		struct Subscription *cleanup_sub;
		bool free_now;

		pthread_mutex_lock(&active_subscribe_cleanups_mtx);
		if (active_subscribe_cleanups.empty()) {
			pthread_mutex_unlock(&active_subscribe_cleanups_mtx);
			return;
		}
		cleanup = active_subscribe_cleanups.front();
		active_subscribe_cleanups.pop_front();
		pthread_mutex_unlock(&active_subscribe_cleanups_mtx);

		event_cancel(&cleanup->event);
		pthread_mutex_lock(&cleanup->mtx);
		cleanup_sub = cleanup->sub;
		cleanup->sub = NULL;
		cleanup->done = true;
		free_now = !cleanup->waiter;
		if (cleanup->waiter)
			pthread_cond_signal(&cleanup->cond);
		pthread_mutex_unlock(&cleanup->mtx);

		if (cleanup_sub) {
			subscription_untrack(cleanup_sub);
			subscription_release_main_resources(cleanup_sub);
			subscription_destroy(cleanup_sub);
		}
		if (free_now)
			subscribe_cleanup_free(cleanup);
	}
}

SubscribeRpcState::SubscribeRpcState()
	: RpcStateBase("Subscribe")
	, async_responder(&ctx)
{
}

SubscribeRpcState::~SubscribeRpcState()
{
	pthread_mutex_lock(&cmux);
	deregister_subscription();
	pthread_mutex_unlock(&cmux);
}

void SubscribeRpcState::do_request(::frr::Northbound::AsyncService *svc,
				   ::grpc::ServerCompletionQueue *queue, bool no_copy)
{
	grpc_debug("%s, posting a request for: %s", __func__, name);
	auto copy = no_copy ? this : new SubscribeRpcState();

	copy->service = svc;
	copy->cq = queue;
	copy->op = CqOp::ACCEPT;
	(svc->*requestsf)(&copy->ctx, &copy->request, &copy->async_responder, queue, queue, copy);
}

bool SubscribeRpcState::repost_on_finish(void) const
{
	return !accepted_stream;
}

void SubscribeRpcState::finish_from_event_thread(grpc::Status status)
{
	/*
	 * The CQ FINISH completion observes state == FINISH and deletes this
	 * RPC tag directly, without another run_mainthread() pass.  Release the
	 * mgmtd subscription before issuing Finish(), including slow-consumer
	 * paths that close immediately after a Write completion.
	 */
	deregister_subscription();
	state = FINISH;
	op = CqOp::FINISH;
	async_responder.Finish(status, this);
}

void SubscribeRpcState::deregister_subscription(void)
{
	/* Caller must hold cmux; sub pointers may be cleared. */
	if (shutdown_sub) {
		subscription_destroy(shutdown_sub);
		shutdown_sub = NULL;
	}

	if (sub) {
		subscription_deregister(sub);
		sub = NULL;
	}
}

static void subscribe_cleanup_free(struct SubscribeCleanup *cleanup)
{
	if (!cleanup)
		return;

	pthread_cond_destroy(&cleanup->cond);
	pthread_mutex_destroy(&cleanup->mtx);
	delete cleanup;
}

static void subscribe_cq_error_event(struct event *event)
{
	auto *cleanup = static_cast<SubscribeCleanup *>(EVENT_ARG(event));
	bool free_now;

	subscribe_cleanup_untrack(cleanup);
	cleanup->event = NULL;
	if (!cleanup->sub)
		goto done;

	subscription_deregister(cleanup->sub);

done:
	pthread_mutex_lock(&cleanup->mtx);
	cleanup->done = true;
	free_now = !cleanup->waiter;
	if (cleanup->waiter)
		pthread_cond_signal(&cleanup->cond);
	pthread_mutex_unlock(&cleanup->mtx);

	if (free_now)
		subscribe_cleanup_free(cleanup);
}

void SubscribeRpcState::close_subscription(grpc::Status status)
{
	void *mgmt_notify_handle = NULL;
	bool finish_now = false;

	/* Caller must hold cmux; sub is dereferenced and may be cleared. */
	if (!sub)
		return;

	event_cancel(&sub->sample_timer);
	event_cancel(&sub->heartbeat_timer);

	pthread_mutex_lock(&sub->mtx);
	if (!sub->cancelled) {
		sub->cancelled = true;
		mgmt_notify_handle = sub->mgmt_notify_handle;
		sub->mgmt_notify_handle = NULL;
	}

	sub->finish_status = status;
	if (sub->write_in_flight) {
		sub->finish_after_write = true;
		if (sub->pending.size() > 1)
			sub->pending.erase(std::next(sub->pending.begin()), sub->pending.end());
	} else {
		sub->pending.clear();
		finish_now = true;
	}
	pthread_mutex_unlock(&sub->mtx);

	if (mgmt_notify_handle)
		nb_notification_data_unsubscribe(mgmt_notify_handle);

	if (finish_now)
		finish_from_event_thread(status);
}

bool SubscribeRpcState::enqueue_response(frr::SubscribeResponse &&resp, bool resets_heartbeat,
					 grpc::Status *status)
{
	bool start_write = false;
	bool close_slow_consumer = false;
	grpc::Status close_status;

	/* Caller must hold cmux; sub is dereferenced below. */
	if (!sub)
		return false;

	pthread_mutex_lock(&sub->mtx);
	if (!sub->cancelled) {
		if (sub->pending.size() >= grpc_subscribe_max_pending) {
			close_slow_consumer = true;
		} else {
			sub->pending.push_back(std::move(resp));
			if (!sub->write_in_flight) {
				sub->write_in_flight = true;
				start_write = true;
			}
		}
	}
	if (sub->cancelled)
		close_status = grpc::Status(grpc::StatusCode::CANCELLED,
					    "Subscribe stream is closed");
	pthread_mutex_unlock(&sub->mtx);

	if (close_slow_consumer) {
		close_status = grpc::Status(grpc::StatusCode::OUT_OF_RANGE,
					    "Subscribe stream pending queue limit exceeded");
		close_subscription(close_status);
		if (status)
			*status = close_status;
		return false;
	}

	if (!close_status.ok()) {
		if (status)
			*status = close_status;
		return false;
	}

	if (resets_heartbeat)
		schedule_heartbeat_timer();

	if (start_write) {
		op = CqOp::WRITE;
		async_responder.Write(sub->pending.front(), this);
	}

	return true;
}

grpc::Status SubscribeRpcState::enqueue_state_snapshot(bool sync_response)
{
	std::vector<frr::SubscribeResponse> responses;

	/* Caller must hold cmux; sub is dereferenced below. */
	for (const auto &path : sub->selectors) {
		frr::SubscribeResponse resp;
		auto *update = resp.mutable_update();

		update->set_encoding(sub->encoding);
		update->set_path(path);
		grpc::Status status = get_state_snapshot_path(update, path, sub->lyd_format, false);
		if (!status.ok())
			return status;

		responses.push_back(std::move(resp));
	}

	for (auto &resp : responses) {
		grpc::Status status;

		if (!enqueue_response(std::move(resp), true, &status))
			return status;
	}

	if (sync_response) {
		frr::SubscribeResponse sync;

		sync.mutable_sync_response();
		grpc::Status status;

		if (!enqueue_response(std::move(sync), false, &status))
			return status;
	}

	return grpc::Status::OK;
}

bool SubscribeRpcState::subscription_finish_deferred(void)
{
	bool deferred;

	/* Caller must hold cmux; sub is dereferenced below. */
	if (!sub)
		return false;

	pthread_mutex_lock(&sub->mtx);
	deferred = sub->cancelled && sub->finish_after_write;
	pthread_mutex_unlock(&sub->mtx);

	return deferred;
}

void SubscribeRpcState::schedule_sample_timer(void)
{
	/* Caller must hold cmux; sub is dereferenced below. */
	if (!sub || !sub->sample_interval_ms)
		return;

	event_add_timer_msec(main_master, sample_timer_event, this, sub->sample_interval_ms,
			     &sub->sample_timer);
}

void SubscribeRpcState::schedule_heartbeat_timer(void)
{
	bool cancelled;

	/* Caller must hold cmux; sub is dereferenced below. */
	if (!sub || !sub->heartbeat_interval_ms)
		return;

	pthread_mutex_lock(&sub->mtx);
	cancelled = sub->cancelled;
	pthread_mutex_unlock(&sub->mtx);
	if (cancelled)
		return;

	event_cancel(&sub->heartbeat_timer);
	event_add_timer_msec(main_master, heartbeat_timer_event, this, sub->heartbeat_interval_ms,
			     &sub->heartbeat_timer);
}

void SubscribeRpcState::sample_timer_event(struct event *event)
{
	auto *tag = static_cast<SubscribeRpcState *>(EVENT_ARG(event));
	bool cancelled;

	pthread_mutex_lock(&tag->cmux);
	if (!tag->sub) {
		pthread_mutex_unlock(&tag->cmux);
		return;
	}

	tag->sub->sample_timer = NULL;
	pthread_mutex_lock(&tag->sub->mtx);
	cancelled = tag->sub->cancelled;
	pthread_mutex_unlock(&tag->sub->mtx);
	if (!cancelled) {
		grpc::Status status = tag->enqueue_state_snapshot(false);
		if (!status.ok()) {
			if (tag->subscription_finish_deferred()) {
				pthread_mutex_unlock(&tag->cmux);
				return;
			}
			if (!tag->sub) {
				pthread_mutex_unlock(&tag->cmux);
				return;
			}
			tag->finish_from_event_thread(status);
			pthread_mutex_unlock(&tag->cmux);
			return;
		}
	}

	tag->schedule_sample_timer();
	pthread_mutex_unlock(&tag->cmux);
}

void SubscribeRpcState::heartbeat_timer_event(struct event *event)
{
	auto *tag = static_cast<SubscribeRpcState *>(EVENT_ARG(event));
	frr::SubscribeResponse resp;
	bool cancelled;

	pthread_mutex_lock(&tag->cmux);
	if (!tag->sub) {
		pthread_mutex_unlock(&tag->cmux);
		return;
	}

	tag->sub->heartbeat_timer = NULL;
	pthread_mutex_lock(&tag->sub->mtx);
	cancelled = tag->sub->cancelled;
	pthread_mutex_unlock(&tag->sub->mtx);
	if (!cancelled) {
		resp.mutable_heartbeat();
		tag->enqueue_response(std::move(resp), false);
	}

	tag->schedule_heartbeat_timer();
	pthread_mutex_unlock(&tag->cmux);
}

void SubscribeRpcState::enqueue_notification(frr::SubscribeResponse &&resp)
{
	enqueue_response(std::move(resp), true);
}

void SubscribeRpcState::enqueue_notification_for(struct Subscription *expected_sub,
						 frr::SubscribeResponse &&resp)
{
	pthread_mutex_lock(&cmux);
	if (sub == expected_sub)
		enqueue_notification(std::move(resp));
	pthread_mutex_unlock(&cmux);
}

CallState SubscribeRpcState::run_mainthread(struct event *event)
{
	grpc_debug("%s: entered", __func__);

	if (op == CqOp::FINISH) {
		deregister_subscription();
		return FINISH;
	}

	if (is_initial_process()) {
		auto mode = request.mode();

		if (mode != frr::SubscribeRequest::ON_CHANGE &&
		    mode != frr::SubscribeRequest::STREAM &&
		    mode != frr::SubscribeRequest::SAMPLE) {
			finish_from_event_thread(
				grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
					     "POLL requires a client-streaming Subscribe RPC shape"));
			return FINISH;
		}
		if (grpc_is_shutting_down()) {
			finish_from_event_thread(grpc::Status(grpc::StatusCode::UNAVAILABLE,
							      "gRPC server is shutting down"));
			return FINISH;
		}

		if (request.path_size() == 0) {
			finish_from_event_thread(
				grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					     "At least one subscription path is required"));
			return FINISH;
		}

		if (mode == frr::SubscribeRequest::SAMPLE &&
		    request.sample_interval_ms() < GRPC_SUBSCRIBE_MIN_INTERVAL_MS) {
			finish_from_event_thread(
				grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					     "SAMPLE subscriptions require sample_interval_ms >= 100"));
			return FINISH;
		}

		if (request.heartbeat_interval_ms() &&
		    request.heartbeat_interval_ms() < GRPC_SUBSCRIBE_MIN_INTERVAL_MS) {
			finish_from_event_thread(
				grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					     "heartbeat_interval_ms must be zero or >= 100"));
			return FINISH;
		}

		sub = new Subscription();
		pthread_mutex_init(&sub->mtx, NULL);
		sub->tag = this;
		sub->encoding = request.response_encoding();
		if (!encoding2lyd_format(sub->encoding, &sub->lyd_format)) {
			pthread_mutex_destroy(&sub->mtx);
			delete sub;
			sub = NULL;
			finish_from_event_thread(
				invalid_encoding_status(request.response_encoding()));
			return FINISH;
		}
		sub->write_in_flight = false;
		sub->cancelled = false;
		sub->main_released = false;
		sub->finish_after_write = false;
		sub->mgmt_notify_handle = NULL;
		sub->sample_timer = NULL;
		sub->heartbeat_timer = NULL;
		sub->sample_interval_ms = request.sample_interval_ms();
		sub->heartbeat_interval_ms = request.heartbeat_interval_ms();
		for (const auto &p : request.path())
			sub->selectors.push_back(p);

		if (mode == frr::SubscribeRequest::SAMPLE) {
			grpc::Status status = enqueue_state_snapshot(false);
			if (!status.ok()) {
				if (subscription_finish_deferred()) {
					accepted_stream = true;
					do_request(service, cq, false);
					return MORE;
				}
				if (!sub)
					return FINISH;
				deregister_subscription();
				finish_from_event_thread(status);
				return FINISH;
			}
			schedule_sample_timer();
		} else {
			std::vector<const char *> selectors;
			selectors.reserve(sub->selectors.size());
			for (const auto &p : sub->selectors)
				selectors.push_back(p.c_str());

			char errmsg[256] = {};
			int ret = nb_notification_data_subscribe(selectors.data(),
								 selectors.size(), sub->lyd_format,
								 grpc_notification_data_dispatch,
								 sub, &sub->mgmt_notify_handle,
								 errmsg, sizeof(errmsg));
			if (ret) {
				pthread_mutex_destroy(&sub->mtx);
				delete sub;
				sub = NULL;
				grpc::StatusCode code = grpc::StatusCode::INTERNAL;
				if (ret == -EOPNOTSUPP)
					code = grpc::StatusCode::UNIMPLEMENTED;
				else if (ret == -EINVAL)
					code = grpc::StatusCode::INVALID_ARGUMENT;
				finish_from_event_thread(grpc::Status(
					code,
					errmsg[0]
						? errmsg
						: "Could not register notification subscription"));
				return FINISH;
			}

			if (mode == frr::SubscribeRequest::STREAM) {
				grpc::Status status = enqueue_state_snapshot(true);
				if (!status.ok()) {
					if (subscription_finish_deferred()) {
						accepted_stream = true;
						do_request(service, cq, false);
						return MORE;
					}
					if (!sub)
						return FINISH;
					deregister_subscription();
					finish_from_event_thread(status);
					return FINISH;
				}
			}
		}

		subscription_track(sub);
		schedule_heartbeat_timer();
		accepted_stream = true;
		do_request(service, cq, false);
		return MORE;
	}

	/* A Write just completed.  Pop the message that was just sent and
	 * issue the next one, if any.
	 */
	if (!sub) {
		/* Shutdown detached the subscription before this CQ event ran. */
		deregister_subscription();
		return FINISH;
	}

	pthread_mutex_lock(&sub->mtx);
	if (!sub->pending.empty())
		sub->pending.pop_front();

	if (!sub->pending.empty()) {
		pthread_mutex_unlock(&sub->mtx);
		op = CqOp::WRITE;
		async_responder.Write(sub->pending.front(), this);
		return MORE;
	} else {
		sub->write_in_flight = false;
	}

	if (sub->finish_after_write) {
		grpc::Status status = sub->finish_status;

		pthread_mutex_unlock(&sub->mtx);
		finish_from_event_thread(status);
		return FINISH;
	}
	pthread_mutex_unlock(&sub->mtx);

	return MORE;
}

bool SubscribeRpcState::handle_cq_error(void)
{
	struct SubscribeCleanup *cleanup;
	pthread_condattr_t condattr;
	struct timespec wait_until;

	/*
	 * Normal stream cancellation must unregister the mgmtd selector on the
	 * main thread.  During module shutdown the main thread is already in
	 * frr_grpc_finish() waiting for this pthread, so queueing a synchronous
	 * main-thread cleanup would deadlock.  The queued cleanup context owns
	 * the Subscription, so the RPC object can still be deleted if shutdown
	 * interrupts the wait.
	 */
	if (!grpc_is_running()) {
		struct Subscription *cleanup_sub;

		pthread_mutex_lock(&cmux);
		cleanup_sub = shutdown_sub ? shutdown_sub : sub;
		shutdown_sub = NULL;
		sub = NULL;
		pthread_mutex_unlock(&cmux);
		if (cleanup_sub)
			subscription_destroy(cleanup_sub);
		return true;
	}

	cleanup = new SubscribeCleanup();
	pthread_mutex_init(&cleanup->mtx, NULL);
	pthread_condattr_init(&condattr);
	pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC);
	pthread_cond_init(&cleanup->cond, &condattr);
	pthread_condattr_destroy(&condattr);
	cleanup->event = NULL;
	cleanup->done = false;
	cleanup->waiter = true;

	pthread_mutex_lock(&cmux);
	cleanup->sub = sub;
	if (!cleanup->sub) {
		pthread_mutex_unlock(&cmux);
		subscribe_cleanup_free(cleanup);
		return true;
	}
	pthread_mutex_lock(&cleanup->sub->mtx);
	cleanup->sub->tag = NULL;
	pthread_mutex_unlock(&cleanup->sub->mtx);
	sub = NULL;
	subscribe_cleanup_track(cleanup);
	event_add_event(main_master, subscribe_cq_error_event, cleanup, 0, &cleanup->event);
	pthread_mutex_unlock(&cmux);

	pthread_mutex_lock(&cleanup->mtx);
	while (!cleanup->done) {
		clock_gettime(CLOCK_MONOTONIC, &wait_until);
		wait_until.tv_nsec += 100 * 1000 * 1000;
		if (wait_until.tv_nsec >= 1000 * 1000 * 1000) {
			wait_until.tv_sec++;
			wait_until.tv_nsec -= 1000 * 1000 * 1000;
		}
		pthread_cond_timedwait(&cleanup->cond, &cleanup->mtx, &wait_until);
		if (!grpc_is_running())
			break;
	}
	if (cleanup->done) {
		cleanup->waiter = false;
		pthread_mutex_unlock(&cleanup->mtx);
		subscribe_cleanup_free(cleanup);
	} else {
		cleanup->waiter = false;
		pthread_mutex_unlock(&cleanup->mtx);
	}

	return true;
}

grpc::Status HandleUnaryDeleteCandidate(
	UnaryRpcState<frr::DeleteCandidateRequest, frr::DeleteCandidateResponse> *tag)
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
	UnaryRpcState<frr::UpdateCandidateRequest, frr::UpdateCandidateResponse> *tag)
{
	grpc_debug("%s: entered", __func__);

	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);

	if (!candidate)
		return grpc::Status(grpc::StatusCode::NOT_FOUND,
				    "candidate configuration not found");
	if (candidate->transaction)
		return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
				    "candidate is in the middle of a transaction");
	if (nb_candidate_update(candidate->config) != NB_OK)
		return grpc::Status(grpc::StatusCode::INTERNAL,
				    "failed to update candidate configuration");

	return grpc::Status::OK;
}

grpc::Status
HandleUnaryEditCandidate(UnaryRpcState<frr::EditCandidateRequest, frr::EditCandidateResponse> *tag)
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
		if (yang_dnode_edit(candidate_tmp->dnode, pv.path(), pv.value().c_str()) != 0) {
			nb_config_free(candidate_tmp);

			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Failed to update \"" + pv.path() + "\"");
		}
	}

	pvs = tag->request.delete_();
	for (const frr::PathValue &pv : pvs) {
		if (yang_dnode_delete(candidate_tmp->dnode, pv.path()) != 0) {
			nb_config_free(candidate_tmp);
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Failed to remove \"" + pv.path() + "\"");
		}
	}

	// No errors, accept all changes.
	nb_config_replace(candidate->config, candidate_tmp, false);
	return grpc::Status::OK;
}

grpc::Status HandleUnaryLoadToCandidate(
	UnaryRpcState<frr::LoadToCandidateRequest, frr::LoadToCandidateResponse> *tag)
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
	else if (nb_config_merge(candidate->config, loaded_config, false) != NB_OK)
		return grpc::Status(grpc::StatusCode::INTERNAL,
				    "Failed to merge the loaded configuration");

	return grpc::Status::OK;
}

static grpc::Status status_from_nb_error(enum nb_error error, const char *errmsg)
{
	const char *message = errmsg && errmsg[0] ? errmsg : nb_err_name(error);

	switch (error) {
	case NB_OK:
		return grpc::Status::OK;
	case NB_ERR_NO_CHANGES:
		return grpc::Status(grpc::StatusCode::ABORTED, message);
	case NB_ERR_NOT_FOUND:
		return grpc::Status(grpc::StatusCode::NOT_FOUND, message);
	case NB_ERR_EXISTS:
		return grpc::Status(grpc::StatusCode::ALREADY_EXISTS, message);
	case NB_ERR_LOCKED:
		return grpc::Status(grpc::StatusCode::UNAVAILABLE, message);
	case NB_ERR_VALIDATION:
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, message);
	case NB_ERR_RESOURCE:
		return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, message);
	case NB_ERR_INCONSISTENCY:
	case NB_ERR:
	case NB_YIELD:
	default:
		return grpc::Status(grpc::StatusCode::INTERNAL, message);
	}
}

grpc::Status HandleUnaryCommit(UnaryRpcState<frr::CommitRequest, frr::CommitResponse> *tag)
{
	grpc_debug("%s: entered", __func__);

	// Request: uint32 candidate_id = 1;
	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	// Request: commit phase = 2;
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

	grpc::Status status = status_from_nb_error((enum nb_error)ret, errmsg);

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

static grpc::Status status_from_errno(int error, const char *errmsg)
{
	grpc::StatusCode code;
	int errnum;

	if (!error)
		return grpc::Status::OK;

	errnum = error < 0 ? -error : error;

	switch (errnum) {
	case EINVAL:
		code = grpc::StatusCode::INVALID_ARGUMENT;
		break;
	case EOPNOTSUPP:
		code = grpc::StatusCode::UNIMPLEMENTED;
		break;
	case ENOENT:
		code = grpc::StatusCode::NOT_FOUND;
		break;
	case ETIMEDOUT:
		code = grpc::StatusCode::DEADLINE_EXCEEDED;
		break;
	case ENOMEM:
		code = grpc::StatusCode::RESOURCE_EXHAUSTED;
		break;
	case EBUSY:
	case EINPROGRESS:
		code = grpc::StatusCode::UNAVAILABLE;
		break;
	case ECANCELED:
		code = grpc::StatusCode::CANCELLED;
		break;
	default:
		code = grpc::StatusCode::INTERNAL;
		break;
	}

	return grpc::Status(code, errmsg && errmsg[0] ? errmsg : safe_strerror(errnum));
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
	LYD_FORMAT lyd_format;
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
	if (!encoding2lyd_format(encoding, &lyd_format)) {
		nb_config_free(nb_config);
		return invalid_encoding_status(encoding);
	}

	// Response: DataTree config = 1;
	auto config = tag->response.mutable_config();
	config->set_encoding(encoding);

	// Dump data using the requested format.
	if (data_tree_from_dnode(config, nb_config->dnode, lyd_format, with_defaults) != 0) {
		nb_config_free(nb_config);
		return grpc::Status(grpc::StatusCode::INTERNAL,
				    "Failed to dump data");
	}

	nb_config_free(nb_config);

	return grpc::Status::OK;
}

static grpc::Status execute_add_output(frr::ExecuteResponse *response, struct lyd_node *output_tree)
{
	struct lyd_node *child;
	char path[XPATH_MAXLEN];

	if (!output_tree)
		return grpc::Status::OK;

	LY_LIST_FOR (lyd_child(output_tree), child) {
		if (child->schema->nodetype != LYS_LEAF && child->schema->nodetype != LYS_LEAFLIST) {
			grpc::Status status = execute_add_output(response, child);

			if (!status.ok())
				return status;
			continue;
		}

		if (!lyd_path(child, LYD_PATH_STD, path, sizeof(path)))
			return grpc::Status(grpc::StatusCode::INTERNAL,
					    "RPC output path is too long");

		const char *value = yang_dnode_get_string(child, NULL);
		if (!value)
			return grpc::Status(grpc::StatusCode::INTERNAL,
					    "RPC output value is not scalar");

		frr::PathValue *pv = response->add_output();
		pv->set_path(path);
		pv->set_value(value);
	}

	return grpc::Status::OK;
}

static grpc::Status execute_prepare_input(const frr::ExecuteRequest &request,
					  struct nb_node **nb_node, struct lyd_node **input_tree)
{
	const struct lyd_node *dep_tree = NULL;
	char errmsg[BUFSIZ];
	const char *xpath;
	LY_ERR err;

	xpath = request.path().c_str();

	grpc_debug("%s(path: \"%s\")", __func__, xpath);

	if (request.path().empty())
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Data path is empty");

	*nb_node = nb_node_find(xpath);
	if (!*nb_node)
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Unknown data path");

	// Create input data tree.
	err = yang_new_path2(NULL, ly_native_ctx, xpath, NULL, 0, (LYD_ANYDATA_VALUETYPE)0, 0,
			     NULL, input_tree);
	if (err != LY_SUCCESS) {
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				    "Invalid data path");
	}

	// Read input parameters.
	auto input = request.input();
	for (const frr::PathValue &pv : input) {
		// Request: repeated PathValue input = 2;
		err = lyd_new_path(*input_tree, ly_native_ctx, pv.path().c_str(),
				   pv.value().c_str(), 0, NULL);
		if (err != LY_SUCCESS) {
			lyd_free_tree(*input_tree);
			*input_tree = NULL;
			snprintf(errmsg, sizeof(errmsg), "Invalid input data: %s",
				 ly_errmsg(ly_native_ctx));
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, errmsg);
		}
	}

	dep_tree = get_execute_dep_tree();
	err = lyd_validate_op(*input_tree, dep_tree, LYD_TYPE_RPC_YANG, NULL);
	if (err != LY_SUCCESS) {
		lyd_free_tree(*input_tree);
		*input_tree = NULL;
		snprintf(errmsg, sizeof(errmsg), "Invalid input data: %s",
			 ly_errmsg(ly_native_ctx));
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, errmsg);
	}

	return grpc::Status::OK;
}

static grpc::Status execute_local_rpc(const frr::ExecuteRequest &request, struct nb_node *nb_node,
				      struct lyd_node *input_tree, frr::ExecuteResponse *response)
{
	struct lyd_node *output_tree;
	const char *xpath = request.path().c_str();
	char errmsg[BUFSIZ] = { 0 };
	enum nb_error ret;
	LY_ERR err;

	if (!nb_node->cbs.rpc)
		return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
				    "No RPC callback for data path");

	// Create output data tree.
	err = yang_new_path2(NULL, ly_native_ctx, xpath, NULL, 0, (LYD_ANYDATA_VALUETYPE)0, 0,
			     NULL, &output_tree);
	if (err != LY_SUCCESS)
		return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid data path");

	// Execute callback registered for this XPath.
	ret = (enum nb_error)nb_callback_rpc(nb_node, xpath, input_tree, output_tree, errmsg,
					     sizeof(errmsg));
	if (ret != NB_OK) {
		flog_warn(EC_LIB_NB_CB_RPC, "%s: rpc callback failed: %s", __func__, xpath);
		lyd_free_tree(output_tree);
		return status_from_nb_error(ret, errmsg);
	}

	grpc::Status status = execute_add_output(response, output_tree);
	lyd_free_tree(output_tree);
	return status;
}

class ExecuteRpcState : public RpcStateBase {
      public:
	ExecuteRpcState()
		: RpcStateBase("Execute")
		, responder(&ctx){};

	void do_request(::frr::Northbound::AsyncService *service,
			::grpc::ServerCompletionQueue *cq, bool no_copy) override
	{
		grpc_debug("%s, posting a request for: %s", __func__, name);
		auto copy = no_copy ? this : new ExecuteRpcState();

		copy->service = service;
		copy->cq = cq;
		service->RequestExecute(&copy->ctx, &copy->request, &copy->responder, cq, cq, copy);
	}

	CallState run_mainthread(struct event *event) override
	{
		struct nb_node *nb_node;
		struct lyd_node *input_tree = NULL;
		char errmsg[BUFSIZ] = { 0 };
		grpc::Status status;
		int ret;

		grpc_debug("%s: entered", __func__);

		status = execute_prepare_input(request, &nb_node, &input_tree);
		if (!status.ok()) {
			responder.Finish(response, status, this);
			return FINISH;
		}

		ret = nb_rpc_dispatch_async(request.path().c_str(), input_tree, async_done, this,
					    errmsg, sizeof(errmsg));
		if (!ret) {
			async_pending = true;
			lyd_free_tree(input_tree);
			return MORE;
		}

		if (ret != -EOPNOTSUPP)
			status = status_from_errno(ret, errmsg);
		else
			status = execute_local_rpc(request, nb_node, input_tree, &response);

		lyd_free_tree(input_tree);
		responder.Finish(response, status, this);
		return FINISH;
	}

	void finish_async(grpc::Status status)
	{
		bool delete_now = false;
		bool repost = false;
		bool running = grpc_is_running();

		/*
		 * If the client cancelled while a backend RPC was outstanding,
		 * handle_cq_error() left this tag alive for async_done().  In
		 * that case async_done() is the final owner and deletes here.
		 * If shutdown has already stopped gRPC, there is no live CQ for
		 * another Finish operation, so async_done() also deletes here.
		 */
		pthread_mutex_lock(&cmux);
		async_pending = false;
		if (cancelled || !running) {
			delete_now = true;
			repost = !reposted && running;
		} else {
			state = FINISH;
			repost = !reposted && running;
		}
		if (repost)
			reposted = true;
		pthread_mutex_unlock(&cmux);

		if (repost)
			do_request(service, cq, false);

		if (delete_now) {
			delete this;
			return;
		}

		responder.Finish(response, status, this);
	}

	bool handle_cq_error(void) override
	{
		bool keep_until_async_done = false;
		bool repost = false;

		pthread_mutex_lock(&cmux);
		cancelled = true;
		if (async_pending) {
			keep_until_async_done = true;
			repost = !reposted && grpc_is_running();
			if (repost)
				reposted = true;
		}
		pthread_mutex_unlock(&cmux);

		if (repost)
			do_request(service, cq, false);

		return !keep_until_async_done;
	}

	frr::ExecuteRequest request;
	frr::ExecuteResponse response;
	grpc::ServerAsyncResponseWriter<frr::ExecuteResponse> responder;

      private:
	static void async_done(int error, const char *errmsg, struct lyd_node *output, void *arg)
	{
		auto tag = static_cast<ExecuteRpcState *>(arg);
		grpc::Status status = status_from_errno(error, errmsg);

		if (status.ok())
			status = execute_add_output(&tag->response, output);
		lyd_free_all(output);
		tag->finish_async(status);
	}

	::frr::Northbound::AsyncService *service = NULL;
	::grpc::ServerCompletionQueue *cq = NULL;
	bool async_pending = false;
	bool cancelled = false;
	bool reposted = false;
};

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

	pthread_mutex_lock(&s_server_lock);
	s_server = server.get();
	s_cq = cq.get();
	grpc_shutting_down = false;
	grpc_running = true;
	pthread_mutex_unlock(&s_server_lock);

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
	{
		auto _rpcState = new ExecuteRpcState();
		_rpcState->do_request(&service, cq.get(), true);
	}

	/* Schedule streaming RPC handlers */
	REQUEST_NEWRPC_STREAMING(Get);
	REQUEST_NEWRPC_STREAMING(ListTransactions);
	{
		auto _rpcState = new SubscribeRpcState();
		_rpcState->do_request(&service, cq.get(), true);
	}

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

		RpcStateBase *rpc = static_cast<RpcStateBase *>(tag);

		/*
		 * `ok=false` means the individual operation associated with
		 * this tag completed unsuccessfully -- typically the stream
		 * was cancelled, the connection dropped, or a Write failed
		 * because the client has gone away.  It does NOT mean the
		 * server is shutting down: server shutdown is signalled by
		 * cq->Next() returning false (handled just above).
		 *
		 * The previous behaviour was to delete the tag and break out
		 * of the loop, which killed mgmtd's whole gRPC service the
		 * moment any single stream had a Write fail.  Let the RPC type
		 * clean up any state owned outside the CQ tag, then delete the
		 * failed tag and continue serving other RPCs.
		 */
		if (!ok) {
			bool shutting_down = !grpc_is_running();

			bool delete_tag = rpc->handle_cq_error();
			if (shutting_down || !grpc_is_running()) {
				grpc_debug("%s RPC tag cancelled during shutdown", rpc->name);
				if (delete_tag)
					delete rpc;
				continue;
			}
			if (delete_tag) {
				if (rpc->repost_on_cq_error())
					rpc->do_request(&service, cq.get(), false);
				grpc_debug("%s RPC tag cancelled -> [delete]", rpc->name);
				delete rpc;
			}
			continue;
		}

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
	if (s_cq) {
		grpc_debug("%s: shutdown CQ", __func__);
		cq->Shutdown();
		s_cq = NULL;
	}
	pthread_mutex_unlock(&s_server_lock);

	grpc_debug("%s: draining the CQ", __func__);
	while (cq->Next(&tag, &ok)) {
		RpcStateBase *rpc = static_cast<RpcStateBase *>(tag);
		bool delete_tag;

		grpc_debug("%s: drain tag %p", __func__, tag);
		/*
		 * mgmtd terminates queued and dispatched backend RPC requests
		 * before firing the gRPC terminate hook, so Execute tags should
		 * not still be waiting on async backend completion here.
		 */
		delete_tag = rpc->handle_cq_error();
		if (delete_tag)
			delete rpc;
	}

	zlog_info("%s: exiting from grpc pthread", __func__);
	return NULL;
}


static int frr_grpc_init(uint port)
{
	struct frr_pthread_attr attr = {
		.start = grpc_pthread_start,
		.stop = NULL,
	};

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

static int frr_grpc_finish(void)
{
	grpc_debug("%s: entered", __func__);

	if (!fpt)
		return 0;

	pthread_mutex_lock(&s_server_lock);
	grpc_shutting_down = true;
	pthread_mutex_unlock(&s_server_lock);

	/*
	 * Release Subscribe timers and mgmtd notification selectors on the
	 * main thread before shutting down the completion queue.  CQ shutdown
	 * errors are handled by the gRPC pthread, which must not call FRR's
	 * main-thread event and mgmtd frontend cleanup APIs.
	 */
	SubscribeRpcState::deregister_all_from_main();

	pthread_mutex_lock(&s_server_lock);
	grpc_running = false;
	pthread_mutex_unlock(&s_server_lock);
	SubscribeRpcState::cancel_cleanup_events_from_main();

	/*
	 * Shut the server down here in main thread. This will cause the wait on
	 * the completion queue (cq.Next()) to exit and cleanup everything else.
	 */
	pthread_mutex_lock(&s_server_lock);
	if (s_server) {
		grpc_debug("%s: shutdown server", __func__);
		s_server->Shutdown(std::chrono::system_clock::now());
		s_server = NULL;
	}
	if (s_cq) {
		grpc_debug("%s: shutdown CQ", __func__);
		s_cq->Shutdown();
		s_cq = NULL;
	}
	pthread_mutex_unlock(&s_server_lock);

	grpc_debug("%s: joining and destroy grpc thread", __func__);
	pthread_join(fpt->thread, NULL);
	frr_pthread_destroy(fpt);
	fpt = NULL;

	// Fix protobuf 'memory leaks' during shutdown.
	// https://groups.google.com/g/protobuf/c/4y_EmQiCGgs
	google::protobuf::ShutdownProtobufLibrary();

	return 0;
}

/*
 * This is done this way because module_init and module_late_init are both
 * called during daemon pre-fork initialization. Because the GRPC library
 * spawns threads internally, we need to delay initializing it until after
 * fork. This is done by scheduling this init function as an event task, since
 * the event loop doesn't run until after fork.
 */
static void frr_grpc_module_very_late_init(struct event *event)
{
	const char *args = THIS_MODULE->load_args;
	uint port = GRPC_DEFAULT_PORT;

	if (args) {
		std::string spec(args);
		size_t comma = spec.find(',');
		std::string port_arg = spec.substr(0, comma);
		unsigned long parsed_port;

		if (!parse_unsigned_arg(port_arg, &parsed_port)) {
			flog_err(EC_LIB_GRPC_INIT, "%s: invalid gRPC port value: %s", __func__,
				 port_arg.c_str());
			goto error;
		}
		if (parsed_port < 1024 || parsed_port > UINT16_MAX) {
			flog_err(EC_LIB_GRPC_INIT,
				 "%s: port number must be between 1025 and %d",
				 __func__, UINT16_MAX);
			goto error;
		}
		port = parsed_port;

		if (comma != std::string::npos) {
			std::string max_pending_arg = spec.substr(comma + 1);
			unsigned long max_pending;

			if (!parse_unsigned_arg(max_pending_arg, &max_pending)) {
				flog_err(EC_LIB_GRPC_INIT,
					 "%s: invalid subscribe pending limit: %s", __func__,
					 max_pending_arg.c_str());
				goto error;
			}

			if (max_pending == 0) {
				flog_err(EC_LIB_GRPC_INIT,
					 "%s: subscribe pending limit must be non-zero", __func__);
				goto error;
			}
			grpc_subscribe_max_pending = max_pending;
		}
	}

	if (frr_grpc_init(port) < 0)
		goto error;

	return;

error:
	flog_err(EC_LIB_GRPC_INIT, "failed to initialize the gRPC module");
}

static int frr_grpc_module_late_init(struct event_loop *tm)
{
	main_master = tm;
	hook_register(nb_grpc_terminate, frr_grpc_finish);
	hook_register(frr_fini, frr_grpc_finish);
	event_add_event(tm, frr_grpc_module_very_late_init, NULL, 0, NULL);
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
