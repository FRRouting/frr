//
// Copyright (C) 2019  NetDEF, Inc.
//                     Renato Westphal
// Copyright (c) 2021, LabN Consulting, L.L.C
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation; either version 2 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; see the file COPYING; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
//

#include <zebra.h>
#include <grpcpp/grpcpp.h>
#include "grpc/frr-northbound.grpc.pb.h"

#include "log.h"
#include "libfrr.h"
#include "lib/version.h"
#include "lib/thread.h"
#include "command.h"
#include "lib_errors.h"
#include "northbound.h"
#include "northbound_db.h"
#include "frr_pthread.h"

#include <iostream>
#include <sstream>
#include <memory>
#include <string>

#define GRPC_DEFAULT_PORT 50051

/*
 * NOTE: we can't use the FRR debugging infrastructure here since it uses
 * atomics and C++ has a different atomics API. Enable gRPC debugging
 * unconditionally until we figure out a way to solve this problem.
 */
static bool nb_dbg_client_grpc = 0;

static struct thread_master *main_master;

static struct frr_pthread *fpt;

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
			delete_candidate(&it->second);
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

	void delete_candidate(struct candidate *c)
	{
		char errmsg[BUFSIZ] = {0};

		_cdb.erase(c->id);
		nb_config_free(c->config);
		if (c->transaction)
			nb_candidate_commit_abort(c->transaction, errmsg,
						  sizeof(errmsg));
	}

	struct candidate *get_candidate(uint32_t id)
	{
		return _cdb.count(id) == 0 ? NULL : &_cdb[id];
	}

      private:
	uint64_t _next_id = 0;
	std::map<uint32_t, struct candidate> _cdb;
};

class RpcStateBase
{
      public:
	virtual CallState doCallback() = 0;
	virtual void do_request(::frr::Northbound::AsyncService *service,
				::grpc::ServerCompletionQueue *cq) = 0;
};

/*
 * The RPC state class is used to track the execution of an RPC.
 */
template <typename Q, typename S> class NewRpcState : RpcStateBase
{
	typedef void (frr::Northbound::AsyncService::*reqfunc_t)(
		::grpc::ServerContext *, Q *,
		::grpc::ServerAsyncResponseWriter<S> *,
		::grpc::CompletionQueue *, ::grpc::ServerCompletionQueue *,
		void *);
	typedef void (frr::Northbound::AsyncService::*reqsfunc_t)(
		::grpc::ServerContext *, Q *, ::grpc::ServerAsyncWriter<S> *,
		::grpc::CompletionQueue *, ::grpc::ServerCompletionQueue *,
		void *);

      public:
	NewRpcState(Candidates *cdb, reqfunc_t rfunc,
		    void (*cb)(NewRpcState<Q, S> *), const char *name)
	    : requestf(rfunc), callback(cb), responder(&ctx),
	      async_responder(&ctx), name(name), cdb(cdb){};
	NewRpcState(Candidates *cdb, reqsfunc_t rfunc,
		    void (*cb)(NewRpcState<Q, S> *), const char *name)
	    : requestsf(rfunc), callback(cb), responder(&ctx),
	      async_responder(&ctx), name(name), cdb(cdb){};

	CallState doCallback() override
	{
		CallState enter_state = this->state;
		CallState new_state;
		if (enter_state == FINISH) {
			grpc_debug("%s RPC FINISH -> DELETED", name);
			new_state = FINISH;
		} else {
			grpc_debug("%s RPC: %s -> PROCESS", name,
				   call_states[this->state]);
			new_state = PROCESS;
		}
		/*
		 * We are either in state CREATE, MORE or FINISH. If CREATE or
		 * MORE move back to PROCESS, otherwise we are cleaning up
		 * (FINISH) so leave it in that state. Run the callback on the
		 * main threadmaster/pthread; and wait for expected transition
		 * from main thread. If transition is to FINISH->DELETED.
		 * delete us.
		 *
		 * We update the state prior to scheduling the callback which
		 * may then update the state in the master pthread. Then we
		 * obtain the lock in the condvar-check-loop as the callback
		 * will be modifying updating the state value.
		 */
		this->state = new_state;
		thread_add_event(main_master, c_callback, (void *)this, 0,
				 NULL);
		pthread_mutex_lock(&this->cmux);
		while (this->state == new_state)
			pthread_cond_wait(&this->cond, &this->cmux);
		pthread_mutex_unlock(&this->cmux);

		if (this->state == DELETED) {
			grpc_debug("%s RPC: -> [DELETED]", name);
			delete this;
			return DELETED;
		}
		return this->state;
	}

	void do_request(::frr::Northbound::AsyncService *service,
			::grpc::ServerCompletionQueue *cq) override
	{
		grpc_debug("%s, posting a request for: %s", __func__, name);
		if (requestf) {
			NewRpcState<Q, S> *copy =
				new NewRpcState(cdb, requestf, callback, name);
			(service->*requestf)(&copy->ctx, &copy->request,
					     &copy->responder, cq, cq, copy);
		} else {
			NewRpcState<Q, S> *copy =
				new NewRpcState(cdb, requestsf, callback, name);
			(service->*requestsf)(&copy->ctx, &copy->request,
					      &copy->async_responder, cq, cq,
					      copy);
		}
	}


	static int c_callback(struct thread *thread)
	{
		auto _tag = static_cast<NewRpcState<Q, S> *>(thread->arg);
		/*
		 * We hold the lock until the callback finishes and has updated
		 * _tag->state, then we signal done and release.
		 */
		pthread_mutex_lock(&_tag->cmux);

		CallState enter_state = _tag->state;
		grpc_debug("%s RPC running on main thread", _tag->name);

		_tag->callback(_tag);

		grpc_debug("%s RPC: %s -> %s", _tag->name,
			   call_states[enter_state], call_states[_tag->state]);

		pthread_cond_signal(&_tag->cond);
		pthread_mutex_unlock(&_tag->cmux);
		return 0;
	}
	NewRpcState<Q, S> *orig;

	const char *name;
	grpc::ServerContext ctx;
	Q request;
	S response;
	grpc::ServerAsyncResponseWriter<S> responder;
	grpc::ServerAsyncWriter<S> async_responder;

	Candidates *cdb;
	void (*callback)(NewRpcState<Q, S> *);
	reqfunc_t requestf;
	reqsfunc_t requestsf;

	pthread_mutex_t cmux = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	void *context;

	CallState state = CREATE;
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
			   const std::string &value)
{
	LY_ERR err = lyd_new_path(dnode, ly_native_ctx, path.c_str(),
				  value.c_str(), LYD_NEW_PATH_UPDATE, &dnode);
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

static int get_oper_data_cb(const struct lysc_node *snode,
			    struct yang_translator *translator,
			    struct yang_data *data, void *arg)
{
	struct lyd_node *dnode = static_cast<struct lyd_node *>(arg);
	int ret = yang_dnode_edit(dnode, data->xpath, data->value);
	yang_data_free(data);

	return (ret == 0) ? NB_OK : NB_ERR;
}

static struct lyd_node *get_dnode_state(const std::string &path)
{
	struct lyd_node *dnode = yang_dnode_new(ly_native_ctx, false);
	if (nb_oper_data_iterate(path.c_str(), NULL, 0, get_oper_data_cb, dnode)
	    != NB_OK) {
		yang_dnode_free(dnode);
		return NULL;
	}

	return dnode;
}

static grpc::Status get_path(frr::DataTree *dt, const std::string &path,
			     int type, LYD_FORMAT lyd_format,
			     bool with_defaults)
{
	struct lyd_node *dnode_config = NULL;
	struct lyd_node *dnode_state = NULL;
	struct lyd_node *dnode_final;

	// Configuration data.
	if (type == frr::GetRequest_DataType_ALL
	    || type == frr::GetRequest_DataType_CONFIG) {
		dnode_config = get_dnode_config(path);
		if (!dnode_config)
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Data path not found");
	}

	// Operational data.
	if (type == frr::GetRequest_DataType_ALL
	    || type == frr::GetRequest_DataType_STATE) {
		dnode_state = get_dnode_state(path);
		if (!dnode_state) {
			if (dnode_config)
				yang_dnode_free(dnode_config);
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Failed to fetch operational data");
		}
	}

	switch (type) {
	case frr::GetRequest_DataType_ALL:
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
		break;
	case frr::GetRequest_DataType_CONFIG:
		dnode_final = dnode_config;
		break;
	case frr::GetRequest_DataType_STATE:
		dnode_final = dnode_state;
		break;
	}

	// Validate data to create implicit default nodes if necessary.
	int validate_opts = 0;
	if (type == frr::GetRequest_DataType_CONFIG)
		validate_opts = LYD_VALIDATE_NO_STATE;
	else
		validate_opts = 0;

	LY_ERR err = lyd_validate_all(&dnode_final, ly_native_ctx,
				      validate_opts, NULL);

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

void HandleUnaryGetCapabilities(NewRpcState<frr::GetCapabilitiesRequest,
					    frr::GetCapabilitiesResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

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

	/* Should we do this in the async process call? */
	tag->responder.Finish(tag->response, grpc::Status::OK, tag);

	/* Indicate we are done. */
	tag->state = FINISH;
}

void HandleStreamingGet(NewRpcState<frr::GetRequest, frr::GetResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		delete static_cast<std::list<std::string> *>(tag->context);
		tag->state = DELETED;
		return;
	}

	if (!tag->context) {
		/* Creating, first time called for this RPC */
		auto mypaths = new std::list<std::string>();
		tag->context = mypaths;
		auto paths = tag->request.path();
		for (const std::string &path : paths) {
			mypaths->push_back(std::string(path));
		}
	}

	// Request: DataType type = 1;
	int type = tag->request.type();
	// Request: Encoding encoding = 2;
	frr::Encoding encoding = tag->request.encoding();
	// Request: bool with_defaults = 3;
	bool with_defaults = tag->request.with_defaults();

	auto mypathps = static_cast<std::list<std::string> *>(tag->context);
	if (mypathps->empty()) {
		tag->async_responder.Finish(grpc::Status::OK, tag);
		tag->state = FINISH;
		return;
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
		tag->async_responder.WriteAndFinish(
			response, grpc::WriteOptions(), status, tag);
		tag->state = FINISH;
		return;
	}

	mypathps->pop_back();
	if (mypathps->empty()) {
		tag->async_responder.WriteAndFinish(
			response, grpc::WriteOptions(), grpc::Status::OK, tag);
		tag->state = FINISH;
	} else {
		tag->async_responder.Write(response, tag);
		tag->state = MORE;
	}
}

void HandleUnaryCreateCandidate(NewRpcState<frr::CreateCandidateRequest,
					    frr::CreateCandidateResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

	struct candidate *candidate = tag->cdb->create_candidate();
	if (!candidate) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
				     "Can't create candidate configuration"),
			tag);
	} else {
		tag->response.set_candidate_id(candidate->id);
		tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	}

	tag->state = FINISH;
}

void HandleUnaryDeleteCandidate(NewRpcState<frr::DeleteCandidateRequest,
					    frr::DeleteCandidateResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

	// Request: uint32 candidate_id = 1;
	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);
	if (!candidate) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::NOT_FOUND,
				     "candidate configuration not found"),
			tag);
	} else {
		tag->cdb->delete_candidate(candidate);
		tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	}
	tag->state = FINISH;
}

void HandleUnaryUpdateCandidate(NewRpcState<frr::UpdateCandidateRequest,
					    frr::UpdateCandidateResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

	// Request: uint32 candidate_id = 1;
	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);

	if (!candidate)
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::NOT_FOUND,
				     "candidate configuration not found"),
			tag);
	else if (candidate->transaction)
		tag->responder.Finish(
			tag->response,
			grpc::Status(
				grpc::StatusCode::FAILED_PRECONDITION,
				"candidate is in the middle of a transaction"),
			tag);
	else if (nb_candidate_update(candidate->config) != NB_OK)
		tag->responder.Finish(
			tag->response,
			grpc::Status(
				grpc::StatusCode::INTERNAL,
				"failed to update candidate configuration"),
			tag);

	else
		tag->responder.Finish(tag->response, grpc::Status::OK, tag);

	tag->state = FINISH;
}

void HandleUnaryEditCandidate(
	NewRpcState<frr::EditCandidateRequest, frr::EditCandidateResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

	// Request: uint32 candidate_id = 1;
	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);

	if (!candidate) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::NOT_FOUND,
				     "candidate configuration not found"),
			tag);
		tag->state = FINISH;
		return;
	}

	struct nb_config *candidate_tmp = nb_config_dup(candidate->config);

	auto pvs = tag->request.update();
	for (const frr::PathValue &pv : pvs) {
		if (yang_dnode_edit(candidate_tmp->dnode, pv.path(), pv.value())
		    != 0) {
			nb_config_free(candidate_tmp);

			tag->responder.Finish(
				tag->response,
				grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					     "Failed to update \"" + pv.path()
						     + "\""),
				tag);

			tag->state = FINISH;
			return;
		}
	}

	pvs = tag->request.delete_();
	for (const frr::PathValue &pv : pvs) {
		if (yang_dnode_delete(candidate_tmp->dnode, pv.path()) != 0) {
			nb_config_free(candidate_tmp);
			tag->responder.Finish(
				tag->response,
				grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					     "Failed to remove \"" + pv.path()
						     + "\""),
				tag);
			tag->state = FINISH;
			return;
		}
	}

	// No errors, accept all changes.
	nb_config_replace(candidate->config, candidate_tmp, false);

	tag->responder.Finish(tag->response, grpc::Status::OK, tag);

	tag->state = FINISH;
}

void HandleUnaryLoadToCandidate(NewRpcState<frr::LoadToCandidateRequest,
					    frr::LoadToCandidateResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

	// Request: uint32 candidate_id = 1;
	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	// Request: LoadType type = 2;
	int load_type = tag->request.type();
	// Request: DataTree config = 3;
	auto config = tag->request.config();


	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);

	if (!candidate) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::NOT_FOUND,
				     "candidate configuration not found"),
			tag);
		tag->state = FINISH;
		return;
	}

	struct lyd_node *dnode = dnode_from_data_tree(&config, true);
	if (!dnode) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::INTERNAL,
				     "Failed to parse the configuration"),
			tag);
		tag->state = FINISH;
		return;
	}

	struct nb_config *loaded_config = nb_config_new(dnode);

	if (load_type == frr::LoadToCandidateRequest::REPLACE)
		nb_config_replace(candidate->config, loaded_config, false);
	else if (nb_config_merge(candidate->config, loaded_config, false)
		 != NB_OK) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(
				grpc::StatusCode::INTERNAL,
				"Failed to merge the loaded configuration"),
			tag);
		tag->state = FINISH;
		return;
	}

	tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	tag->state = FINISH;
}

void HandleUnaryCommit(
	NewRpcState<frr::CommitRequest, frr::CommitResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

	// Request: uint32 candidate_id = 1;
	uint32_t candidate_id = tag->request.candidate_id();

	grpc_debug("%s(candidate_id: %u)", __func__, candidate_id);

	// Request: Phase phase = 2;
	int phase = tag->request.phase();
	// Request: string comment = 3;
	const std::string comment = tag->request.comment();

	// Find candidate configuration.
	struct candidate *candidate = tag->cdb->get_candidate(candidate_id);
	if (!candidate) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::NOT_FOUND,
				     "candidate configuration not found"),
			tag);
		tag->state = FINISH;
		return;
	}

	int ret = NB_OK;
	uint32_t transaction_id = 0;

	// Check for misuse of the two-phase commit protocol.
	switch (phase) {
	case frr::CommitRequest::PREPARE:
	case frr::CommitRequest::ALL:
		if (candidate->transaction) {
			tag->responder.Finish(
				tag->response,
				grpc::Status(
					grpc::StatusCode::FAILED_PRECONDITION,
					"candidate is in the middle of a transaction"),
				tag);
			tag->state = FINISH;
			return;
		}
		break;
	case frr::CommitRequest::ABORT:
	case frr::CommitRequest::APPLY:
		if (!candidate->transaction) {
			tag->responder.Finish(
				tag->response,
				grpc::Status(
					grpc::StatusCode::FAILED_PRECONDITION,
					"no transaction in progress"),
				tag);
			tag->state = FINISH;
			return;
		}
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
			&context, candidate->config, comment.c_str(),
			&candidate->transaction, errmsg, sizeof(errmsg));
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
		ret = nb_candidate_commit(&context, candidate->config, true,
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

	tag->responder.Finish(tag->response, status, tag);
	tag->state = FINISH;
}

void HandleUnaryLockConfig(
	NewRpcState<frr::LockConfigRequest, frr::LockConfigResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

	if (nb_running_lock(NB_CLIENT_GRPC, NULL)) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
				     "running configuration is locked already"),
			tag);
	} else {
		tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	}
	tag->state = FINISH;
}

void HandleUnaryUnlockConfig(
	NewRpcState<frr::UnlockConfigRequest, frr::UnlockConfigResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

	if (nb_running_unlock(NB_CLIENT_GRPC, NULL)) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(
				grpc::StatusCode::FAILED_PRECONDITION,
				"failed to unlock the running configuration"),
			tag);
	} else {
		tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	}
	tag->state = FINISH;
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

void HandleStreamingListTransactions(
	NewRpcState<frr::ListTransactionsRequest, frr::ListTransactionsResponse>
		*tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		delete static_cast<std::list<std::tuple<
			int, std::string, std::string, std::string>> *>(
			tag->context);
		tag->state = DELETED;
		return;
	}

	if (!tag->context) {
		/* Creating, first time called for this RPC */
		auto new_list =
			new std::list<std::tuple<int, std::string, std::string,
						 std::string>>();
		tag->context = new_list;
		nb_db_transactions_iterate(list_transactions_cb, tag->context);

		new_list->push_back(std::make_tuple(
			0xFFFF, std::string("fake client"),
			std::string("fake date"), std::string("fake comment")));
		new_list->push_back(
			std::make_tuple(0xFFFE, std::string("fake client2"),
					std::string("fake date"),
					std::string("fake comment2")));
	}

	auto list = static_cast<std::list<
		std::tuple<int, std::string, std::string, std::string>> *>(
		tag->context);

	if (list->empty()) {
		tag->async_responder.Finish(grpc::Status::OK, tag);
		tag->state = FINISH;
		return;
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
		tag->state = FINISH;
	} else {
		tag->async_responder.Write(response, tag);
		tag->state = MORE;
	}
}

void HandleUnaryGetTransaction(NewRpcState<frr::GetTransactionRequest,
					   frr::GetTransactionResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

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
	if (!nb_config) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				     "Transaction not found"),
			tag);
		tag->state = FINISH;
		return;
	}

	// Response: DataTree config = 1;
	auto config = tag->response.mutable_config();
	config->set_encoding(encoding);

	// Dump data using the requested format.
	if (data_tree_from_dnode(config, nb_config->dnode,
				 encoding2lyd_format(encoding), with_defaults)
	    != 0) {
		nb_config_free(nb_config);
		tag->responder.Finish(tag->response,
				      grpc::Status(grpc::StatusCode::INTERNAL,
						   "Failed to dump data"),
				      tag);
		tag->state = FINISH;
		return;
	}

	nb_config_free(nb_config);

	tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	tag->state = FINISH;
}

void HandleUnaryExecute(
	NewRpcState<frr::ExecuteRequest, frr::ExecuteResponse> *tag)
{
	grpc_debug("%s: state: %s", __func__, call_states[tag->state]);

	if (tag->state == FINISH) {
		tag->state = DELETED;
		return;
	}

	struct nb_node *nb_node;
	struct list *input_list;
	struct list *output_list;
	struct listnode *node;
	struct yang_data *data;
	const char *xpath;
	char errmsg[BUFSIZ] = {0};

	// Request: string path = 1;
	xpath = tag->request.path().c_str();

	grpc_debug("%s(path: \"%s\")", __func__, xpath);

	if (tag->request.path().empty()) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				     "Data path is empty"),
			tag);
		tag->state = FINISH;
		return;
	}

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				     "Unknown data path"),
			tag);
		tag->state = FINISH;
		return;
	}

	input_list = yang_data_list_new();
	output_list = yang_data_list_new();

	// Read input parameters.
	auto input = tag->request.input();
	for (const frr::PathValue &pv : input) {
		// Request: repeated PathValue input = 2;
		data = yang_data_new(pv.path().c_str(), pv.value().c_str());
		listnode_add(input_list, data);
	}

	// Execute callback registered for this XPath.
	if (nb_callback_rpc(nb_node, xpath, input_list, output_list, errmsg,
			    sizeof(errmsg))
	    != NB_OK) {
		flog_warn(EC_LIB_NB_CB_RPC, "%s: rpc callback failed: %s",
			  __func__, xpath);
		list_delete(&input_list);
		list_delete(&output_list);

		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::INTERNAL, "RPC failed"),
			tag);
		tag->state = FINISH;
		return;
	}

	// Process output parameters.
	for (ALL_LIST_ELEMENTS_RO(output_list, node, data)) {
		// Response: repeated PathValue output = 1;
		frr::PathValue *pv = tag->response.add_output();
		pv->set_path(data->xpath);
		pv->set_value(data->value);
	}

	// Release memory.
	list_delete(&input_list);
	list_delete(&output_list);

	tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	tag->state = FINISH;
}

// ------------------------------------------------------
//        Thread Initialization and Run Functions
// ------------------------------------------------------


#define REQUEST_NEWRPC(NAME, cdb)                                              \
	do {                                                                   \
		auto _rpcState = new NewRpcState<frr::NAME##Request,           \
						 frr::NAME##Response>(         \
			(cdb), &frr::Northbound::AsyncService::Request##NAME,  \
			&HandleUnary##NAME, #NAME);                            \
		_rpcState->do_request(service, s_cq);                          \
	} while (0)

#define REQUEST_NEWRPC_STREAMING(NAME, cdb)                                    \
	do {                                                                   \
		auto _rpcState = new NewRpcState<frr::NAME##Request,           \
						 frr::NAME##Response>(         \
			(cdb), &frr::Northbound::AsyncService::Request##NAME,  \
			&HandleStreaming##NAME, #NAME);                        \
		_rpcState->do_request(service, s_cq);                          \
	} while (0)

struct grpc_pthread_attr {
	struct frr_pthread_attr attr;
	unsigned long port;
};

// Capture these objects so we can try to shut down cleanly
static std::unique_ptr<grpc::Server> s_server;
static grpc::ServerCompletionQueue *s_cq;

static void *grpc_pthread_start(void *arg)
{
	struct frr_pthread *fpt = static_cast<frr_pthread *>(arg);
	uint port = (uint) reinterpret_cast<intptr_t>(fpt->data);

	Candidates candidates;
	grpc::ServerBuilder builder;
	std::stringstream server_address;
	frr::Northbound::AsyncService *service =
		new frr::Northbound::AsyncService();

	frr_pthread_set_name(fpt);

	server_address << "0.0.0.0:" << port;
	builder.AddListeningPort(server_address.str(),
				 grpc::InsecureServerCredentials());
	builder.RegisterService(service);
	auto cq = builder.AddCompletionQueue();
	s_cq = cq.get();
	s_server = builder.BuildAndStart();

	/* Schedule all RPC handlers */
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
	REQUEST_NEWRPC_STREAMING(Get, NULL);
	REQUEST_NEWRPC_STREAMING(ListTransactions, NULL);

	zlog_notice("gRPC server listening on %s",
		    server_address.str().c_str());

	/* Process inbound RPCs */
	while (true) {
		void *tag;
		bool ok;

		s_cq->Next(&tag, &ok);
		if (!ok)
			break;

		grpc_debug("%s: Got next from CompletionQueue, %p %d", __func__,
			   tag, ok);

		RpcStateBase *rpc = static_cast<RpcStateBase *>(tag);
		CallState state = rpc->doCallback();
		grpc_debug("%s: Callback returned RPC State: %s", __func__,
			   call_states[state]);

		/*
		 * Our side is done (FINISH) receive new requests of this type
		 * We could do this earlier but that would mean we could be
		 * handling multiple same type requests in parallel. We expect
		 * to be called back once more in the FINISH state (from the
		 * user indicating Finish() for cleanup.
		 */
		if (state == FINISH)
			rpc->do_request(service, s_cq);
	}

	return NULL;
}


static int frr_grpc_init(uint port)
{
	struct frr_pthread_attr attr = {
		.start = grpc_pthread_start,
		.stop = NULL,
	};

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
	// Shutdown the grpc server
	if (s_server) {
		s_server->Shutdown();
		s_cq->Shutdown();

		// And drain the queue
		void *ignore;
		bool ok;

		while (s_cq->Next(&ignore, &ok))
			;
	}

	if (fpt) {
		pthread_join(fpt->thread, NULL);
		frr_pthread_destroy(fpt);
	}

	return 0;
}

/*
 * This is done this way because module_init and module_late_init are both
 * called during daemon pre-fork initialization. Because the GRPC library
 * spawns threads internally, we need to delay initializing it until after
 * fork. This is done by scheduling this init function as an event task, since
 * the event loop doesn't run until after fork.
 */
static int frr_grpc_module_very_late_init(struct thread *thread)
{
	const char *args = THIS_MODULE->load_args;
	uint port = GRPC_DEFAULT_PORT;

	if (args) {
		port = std::stoul(args);
		if (port < 1024 || port > UINT16_MAX) {
			flog_err(EC_LIB_GRPC_INIT,
				 "%s: port number must be between 1025 and %d",
				 __func__, UINT16_MAX);
			goto error;
		}
	}

	if (frr_grpc_init(port) < 0)
		goto error;

	return 0;

error:
	flog_err(EC_LIB_GRPC_INIT, "failed to initialize the gRPC module");
	return -1;
}

static int frr_grpc_module_late_init(struct thread_master *tm)
{
	main_master = tm;
	hook_register(frr_fini, frr_grpc_finish);
	thread_add_event(tm, frr_grpc_module_very_late_init, NULL, 0, NULL);
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
