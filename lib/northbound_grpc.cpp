//
// Copyright (C) 2019  NetDEF, Inc.
//                     Renato Westphal
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
#include "version.h"
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

static void *grpc_pthread_start(void *arg);

/*
 * NOTE: we can't use the FRR debugging infrastructure here since it uses
 * atomics and C++ has a different atomics API. Enable gRPC debugging
 * unconditionally until we figure out a way to solve this problem.
 */
static bool nb_dbg_client_grpc = 1;

static struct frr_pthread *fpt;

/* Default frr_pthread attributes */
static const struct frr_pthread_attr attr = {
	.start = grpc_pthread_start,
	.stop = NULL,
};

enum CallStatus { CREATE, PROCESS, FINISH };

/* Thanks gooble */
class RpcStateBase
{
      public:
	virtual void doCallback() = 0;
};

class NorthboundImpl;

template <typename Q, typename S> class RpcState : RpcStateBase
{
      public:
	RpcState(NorthboundImpl *svc,
		 void (NorthboundImpl::*cb)(RpcState<Q, S> *))
	    : callback(cb), responder(&ctx), async_responder(&ctx),
	      service(svc){};

	void doCallback() override
	{
		(service->*callback)(this);
	}

	grpc::ServerContext ctx;
	Q request;
	S response;
	grpc::ServerAsyncResponseWriter<S> responder;
	grpc::ServerAsyncWriter<S> async_responder;

	NorthboundImpl *service;
	void (NorthboundImpl::*callback)(RpcState<Q, S> *);

	void *context;
	CallStatus state = CREATE;
};

#define REQUEST_RPC(NAME)                                                      \
	do {                                                                   \
		auto _rpcState =                                               \
			new RpcState<frr::NAME##Request, frr::NAME##Response>( \
				this, &NorthboundImpl::Handle##NAME);          \
		_service->Request##NAME(&_rpcState->ctx, &_rpcState->request,  \
					&_rpcState->responder, _cq, _cq,       \
					_rpcState);                            \
	} while (0)

#define REQUEST_RPC_STREAMING(NAME)                                            \
	do {                                                                   \
		auto _rpcState =                                               \
			new RpcState<frr::NAME##Request, frr::NAME##Response>( \
				this, &NorthboundImpl::Handle##NAME);          \
		_service->Request##NAME(&_rpcState->ctx, &_rpcState->request,  \
					&_rpcState->async_responder, _cq, _cq, \
					_rpcState);                            \
	} while (0)

class NorthboundImpl
{
      public:
	NorthboundImpl(void)
	{
		_nextCandidateId = 0;
		_service = new frr::Northbound::AsyncService();
	}

	~NorthboundImpl(void)
	{
		// Delete candidates.
		for (auto it = _candidates.begin(); it != _candidates.end();
		     it++)
			delete_candidate(&it->second);
	}

	void Run(unsigned long port)
	{
		grpc::ServerBuilder builder;
		std::stringstream server_address;

		server_address << "0.0.0.0:" << port;

		builder.AddListeningPort(server_address.str(),
					 grpc::InsecureServerCredentials());
		builder.RegisterService(_service);

		auto cq = builder.AddCompletionQueue();
		_cq = cq.get();
		auto _server = builder.BuildAndStart();

		/* Schedule all RPC handlers */
		REQUEST_RPC(GetCapabilities);
		REQUEST_RPC(CreateCandidate);
		REQUEST_RPC(DeleteCandidate);
		REQUEST_RPC(UpdateCandidate);
		REQUEST_RPC(EditCandidate);
		REQUEST_RPC(LoadToCandidate);
		REQUEST_RPC(Commit);
		REQUEST_RPC(GetTransaction);
		REQUEST_RPC(LockConfig);
		REQUEST_RPC(UnlockConfig);
		REQUEST_RPC(Execute);
		REQUEST_RPC_STREAMING(Get);
		REQUEST_RPC_STREAMING(ListTransactions);

		zlog_notice("gRPC server listening on %s",
			    server_address.str().c_str());

		/* Process inbound RPCs */
		void *tag;
		bool ok;
		while (true) {
			_cq->Next(&tag, &ok);
			GPR_ASSERT(ok);
			static_cast<RpcStateBase *>(tag)->doCallback();
			tag = nullptr;
		}
	}

	void HandleGetCapabilities(RpcState<frr::GetCapabilitiesRequest,
					    frr::GetCapabilitiesResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(GetCapabilities);
			tag->state = PROCESS;
		case PROCESS: {
			if (nb_dbg_client_grpc)
				zlog_debug("received RPC GetCapabilities()");

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
				if (module->info->rev_size)
					m->set_revision(
						module->info->rev[0].date);
				m->set_organization(module->info->org);
			}

			// Response: repeated Encoding supported_encodings = 4;
			tag->response.add_supported_encodings(frr::JSON);
			tag->response.add_supported_encodings(frr::XML);

			tag->responder.Finish(tag->response, grpc::Status::OK,
					      tag);
			tag->state = FINISH;
			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void HandleGet(RpcState<frr::GetRequest, frr::GetResponse> *tag)
	{
		switch (tag->state) {
		case CREATE: {
			auto mypaths = new std::list<std::string>();
			tag->context = mypaths;
			auto paths = tag->request.path();
			for (const std::string &path : paths) {
				mypaths->push_back(std::string(path));
			}
			REQUEST_RPC_STREAMING(Get);
			tag->state = PROCESS;
		}
		case PROCESS: {
			// Request: DataType type = 1;
			int type = tag->request.type();
			// Request: Encoding encoding = 2;
			frr::Encoding encoding = tag->request.encoding();
			// Request: bool with_defaults = 3;
			bool with_defaults = tag->request.with_defaults();

			if (nb_dbg_client_grpc)
				zlog_debug(
					"received RPC Get(type: %u, encoding: %u, with_defaults: %u)",
					type, encoding, with_defaults);

			auto mypaths = static_cast<std::list<std::string> *>(
				tag->context);

			if (mypaths->empty()) {
				tag->async_responder.Finish(grpc::Status::OK,
							    tag);
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
			status = get_path(data, mypaths->back().c_str(), type,
					  encoding2lyd_format(encoding),
					  with_defaults);

			// Something went wrong...
			if (!status.ok()) {
				tag->async_responder.WriteAndFinish(
					response, grpc::WriteOptions(), status,
					tag);
				tag->state = FINISH;
				return;
			}

			mypaths->pop_back();

			tag->async_responder.Write(response, tag);

			break;
		}
		case FINISH:
			if (nb_dbg_client_grpc)
				zlog_debug("received RPC Get() end");

			delete static_cast<std::list<std::string> *>(
				tag->context);
			delete tag;
		}
	}

	void HandleCreateCandidate(RpcState<frr::CreateCandidateRequest,
					    frr::CreateCandidateResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(CreateCandidate);
			tag->state = PROCESS;
		case PROCESS: {
			if (nb_dbg_client_grpc)
				zlog_debug("received RPC CreateCandidate()");

			struct candidate *candidate = create_candidate();
			if (!candidate) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::
							RESOURCE_EXHAUSTED,
						"Can't create candidate configuration"),
					tag);
			} else {
				tag->response.set_candidate_id(candidate->id);
				tag->responder.Finish(tag->response,
						      grpc::Status::OK, tag);
			}

			tag->state = FINISH;

			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void HandleDeleteCandidate(RpcState<frr::DeleteCandidateRequest,
					    frr::DeleteCandidateResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(DeleteCandidate);
			tag->state = PROCESS;
		case PROCESS: {

			// Request: uint32 candidate_id = 1;
			uint32_t candidate_id = tag->request.candidate_id();

			if (nb_dbg_client_grpc)
				zlog_debug(
					"received RPC DeleteCandidate(candidate_id: %u)",
					candidate_id);

			struct candidate *candidate =
				get_candidate(candidate_id);
			if (!candidate) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::NOT_FOUND,
						"candidate configuration not found"),
					tag);
				tag->state = FINISH;
				return;
			} else {
				delete_candidate(candidate);
				tag->responder.Finish(tag->response,
						      grpc::Status::OK, tag);
				tag->state = FINISH;
				return;
			}
			tag->state = FINISH;
			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void HandleUpdateCandidate(RpcState<frr::UpdateCandidateRequest,
					    frr::UpdateCandidateResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(UpdateCandidate);
			tag->state = PROCESS;
		case PROCESS: {

			// Request: uint32 candidate_id = 1;
			uint32_t candidate_id = tag->request.candidate_id();

			if (nb_dbg_client_grpc)
				zlog_debug(
					"received RPC UpdateCandidate(candidate_id: %u)",
					candidate_id);

			struct candidate *candidate =
				get_candidate(candidate_id);

			if (!candidate)
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::NOT_FOUND,
						"candidate configuration not found"),
					tag);
			else if (candidate->transaction)
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::
							FAILED_PRECONDITION,
						"candidate is in the middle of a transaction"),
					tag);
			else if (nb_candidate_update(candidate->config)
				 != NB_OK)
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::INTERNAL,
						"failed to update candidate configuration"),
					tag);

			else
				tag->responder.Finish(tag->response,
						      grpc::Status::OK, tag);

			tag->state = FINISH;

			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void HandleEditCandidate(RpcState<frr::EditCandidateRequest,
					  frr::EditCandidateResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(EditCandidate);
			tag->state = PROCESS;
		case PROCESS: {

			// Request: uint32 candidate_id = 1;
			uint32_t candidate_id = tag->request.candidate_id();

			if (nb_dbg_client_grpc)
				zlog_debug(
					"received RPC EditCandidate(candidate_id: %u)",
					candidate_id);

			struct candidate *candidate =
				get_candidate(candidate_id);

			if (!candidate) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::NOT_FOUND,
						"candidate configuration not found"),
					tag);
				tag->state = FINISH;
				break;
			}

			struct nb_config *candidate_tmp =
				nb_config_dup(candidate->config);

			auto pvs = tag->request.update();
			for (const frr::PathValue &pv : pvs) {
				if (yang_dnode_edit(candidate_tmp->dnode,
						    pv.path(), pv.value())
				    != 0) {
					nb_config_free(candidate_tmp);

					tag->responder.Finish(
						tag->response,
						grpc::Status(
							grpc::StatusCode::
								INVALID_ARGUMENT,
							"Failed to update \""
								+ pv.path()
								+ "\""),
						tag);

					tag->state = FINISH;
					return;
				}
			}

			pvs = tag->request.delete_();
			for (const frr::PathValue &pv : pvs) {
				if (yang_dnode_delete(candidate_tmp->dnode,
						      pv.path())
				    != 0) {
					nb_config_free(candidate_tmp);
					tag->responder.Finish(
						tag->response,
						grpc::Status(
							grpc::StatusCode::
								INVALID_ARGUMENT,
							"Failed to remove \""
								+ pv.path()
								+ "\""),
						tag);
					tag->state = FINISH;
					return;
				}
			}

			// No errors, accept all changes.
			nb_config_replace(candidate->config, candidate_tmp,
					  false);

			tag->responder.Finish(tag->response, grpc::Status::OK,
					      tag);

			tag->state = FINISH;

			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void HandleLoadToCandidate(RpcState<frr::LoadToCandidateRequest,
					    frr::LoadToCandidateResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(LoadToCandidate);
			tag->state = PROCESS;
		case PROCESS: {
			// Request: uint32 candidate_id = 1;
			uint32_t candidate_id = tag->request.candidate_id();

			if (nb_dbg_client_grpc)
				zlog_debug(
					"received RPC LoadToCandidate(candidate_id: %u)",
					candidate_id);

			// Request: LoadType type = 2;
			int load_type = tag->request.type();
			// Request: DataTree config = 3;
			auto config = tag->request.config();


			struct candidate *candidate =
				get_candidate(candidate_id);

			if (!candidate) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::NOT_FOUND,
						"candidate configuration not found"),
					tag);
				tag->state = FINISH;
				return;
			}

			struct lyd_node *dnode =
				dnode_from_data_tree(&config, true);
			if (!dnode) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::INTERNAL,
						"Failed to parse the configuration"),
					tag);
				tag->state = FINISH;
				return;
			}

			struct nb_config *loaded_config = nb_config_new(dnode);

			if (load_type == frr::LoadToCandidateRequest::REPLACE)
				nb_config_replace(candidate->config,
						  loaded_config, false);
			else if (nb_config_merge(candidate->config,
						 loaded_config, false)
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

			tag->responder.Finish(tag->response, grpc::Status::OK,
					      tag);
			tag->state = FINISH;
			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void
	HandleCommit(RpcState<frr::CommitRequest, frr::CommitResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(Commit);
			tag->state = PROCESS;
		case PROCESS: {
			// Request: uint32 candidate_id = 1;
			uint32_t candidate_id = tag->request.candidate_id();
			if (nb_dbg_client_grpc)
				zlog_debug(
					"received RPC Commit(candidate_id: %u)",
					candidate_id);

			// Request: Phase phase = 2;
			int phase = tag->request.phase();
			// Request: string comment = 3;
			const std::string comment = tag->request.comment();

			// Find candidate configuration.
			struct candidate *candidate =
				get_candidate(candidate_id);
			if (!candidate) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::NOT_FOUND,
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
							grpc::StatusCode::
								FAILED_PRECONDITION,
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
							grpc::StatusCode::
								FAILED_PRECONDITION,
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
				ret = nb_candidate_validate(
					&context, candidate->config, errmsg,
					sizeof(errmsg));
				break;
			case frr::CommitRequest::PREPARE:
				ret = nb_candidate_commit_prepare(
					&context, candidate->config,
					comment.c_str(),
					&candidate->transaction, errmsg,
					sizeof(errmsg));
				break;
			case frr::CommitRequest::ABORT:
				nb_candidate_commit_abort(
					candidate->transaction, errmsg,
					sizeof(errmsg));
				break;
			case frr::CommitRequest::APPLY:
				nb_candidate_commit_apply(
					candidate->transaction, true,
					&transaction_id, errmsg,
					sizeof(errmsg));
				break;
			case frr::CommitRequest::ALL:
				ret = nb_candidate_commit(
					&context, candidate->config, true,
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
				status = grpc::Status(grpc::StatusCode::ABORTED,
						      errmsg);
				break;
			case NB_ERR_LOCKED:
				status = grpc::Status(
					grpc::StatusCode::UNAVAILABLE, errmsg);
				break;
			case NB_ERR_VALIDATION:
				status = grpc::Status(
					grpc::StatusCode::INVALID_ARGUMENT,
					errmsg);
				break;
			case NB_ERR_RESOURCE:
				status = grpc::Status(
					grpc::StatusCode::RESOURCE_EXHAUSTED,
					errmsg);
				break;
			case NB_ERR:
			default:
				status = grpc::Status(
					grpc::StatusCode::INTERNAL, errmsg);
				break;
			}
			if (ret == NB_OK) {
				// Response: uint32 transaction_id = 1;
				if (transaction_id)
					tag->response.set_transaction_id(
						transaction_id);
			}
			if (strlen(errmsg) > 0)
				tag->response.set_error_message(errmsg);

			tag->responder.Finish(tag->response, status, tag);
			tag->state = FINISH;
			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void
	HandleListTransactions(RpcState<frr::ListTransactionsRequest,
					frr::ListTransactionsResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC_STREAMING(ListTransactions);
			tag->context = new std::list<std::tuple<
				int, std::string, std::string, std::string>>();
			nb_db_transactions_iterate(list_transactions_cb,
						   tag->context);
			tag->state = PROCESS;
		case PROCESS: {
			if (nb_dbg_client_grpc)
				zlog_debug("received RPC ListTransactions()");

			auto list = static_cast<std::list<std::tuple<
				int, std::string, std::string, std::string>> *>(
				tag->context);
			if (list->empty()) {
				tag->async_responder.Finish(grpc::Status::OK,
							    tag);
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

			tag->async_responder.Write(response, tag);
			break;
		}
		case FINISH:
			delete static_cast<std::list<std::tuple<
				int, std::string, std::string, std::string>> *>(
				tag->context);
			delete tag;
		}
	}

	void HandleGetTransaction(RpcState<frr::GetTransactionRequest,
					   frr::GetTransactionResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(GetTransaction);
			tag->state = PROCESS;
		case PROCESS: {
			// Request: uint32 transaction_id = 1;
			uint32_t transaction_id = tag->request.transaction_id();
			// Request: Encoding encoding = 2;
			frr::Encoding encoding = tag->request.encoding();
			// Request: bool with_defaults = 3;
			bool with_defaults = tag->request.with_defaults();

			if (nb_dbg_client_grpc)
				zlog_debug(
					"received RPC GetTransaction(transaction_id: %u, encoding: %u)",
					transaction_id, encoding);

			struct nb_config *nb_config;

			// Load configuration from the transactions database.
			nb_config = nb_db_transaction_load(transaction_id);
			if (!nb_config) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(grpc::StatusCode::
							     INVALID_ARGUMENT,
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
						 encoding2lyd_format(encoding),
						 with_defaults)
			    != 0) {
				nb_config_free(nb_config);
				tag->responder.Finish(
					tag->response,
					grpc::Status(grpc::StatusCode::INTERNAL,
						     "Failed to dump data"),
					tag);
				tag->state = FINISH;
				return;
			}

			nb_config_free(nb_config);

			tag->responder.Finish(tag->response, grpc::Status::OK,
					      tag);
			tag->state = FINISH;
			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void HandleLockConfig(
		RpcState<frr::LockConfigRequest, frr::LockConfigResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(LockConfig);
			tag->state = PROCESS;
		case PROCESS: {
			if (nb_dbg_client_grpc)
				zlog_debug("received RPC LockConfig()");

			if (nb_running_lock(NB_CLIENT_GRPC, NULL)) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::
							FAILED_PRECONDITION,
						"running configuration is locked already"),
					tag);
				tag->state = FINISH;
				return;
			}

			tag->responder.Finish(tag->response, grpc::Status::OK,
					      tag);
			tag->state = FINISH;
			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void HandleUnlockConfig(RpcState<frr::UnlockConfigRequest,
					 frr::UnlockConfigResponse> *tag)
	{
		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(UnlockConfig);
			tag->state = PROCESS;
		case PROCESS: {
			if (nb_dbg_client_grpc)
				zlog_debug("received RPC UnlockConfig()");

			if (nb_running_unlock(NB_CLIENT_GRPC, NULL)) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(
						grpc::StatusCode::
							FAILED_PRECONDITION,
						"failed to unlock the running configuration"),
					tag);
				tag->state = FINISH;
				return;
			}

			tag->responder.Finish(tag->response, grpc::Status::OK,
					      tag);
			tag->state = FINISH;
			break;
		}
		case FINISH:
			delete tag;
		}
	}

	void
	HandleExecute(RpcState<frr::ExecuteRequest, frr::ExecuteResponse> *tag)
	{
		struct nb_node *nb_node;
		struct list *input_list;
		struct list *output_list;
		struct listnode *node;
		struct yang_data *data;
		const char *xpath;

		switch (tag->state) {
		case CREATE:
			REQUEST_RPC(Execute);
			tag->state = PROCESS;
		case PROCESS: {
			// Request: string path = 1;
			xpath = tag->request.path().c_str();

			if (nb_dbg_client_grpc)
				zlog_debug("received RPC Execute(path: \"%s\")",
					   xpath);

			if (tag->request.path().empty()) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(grpc::StatusCode::
							     INVALID_ARGUMENT,
						     "Data path is empty"),
					tag);
				tag->state = FINISH;
				return;
			}

			nb_node = nb_node_find(xpath);
			if (!nb_node) {
				tag->responder.Finish(
					tag->response,
					grpc::Status(grpc::StatusCode::
							     INVALID_ARGUMENT,
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
				data = yang_data_new(pv.path().c_str(),
						     pv.value().c_str());
				listnode_add(input_list, data);
			}

			// Execute callback registered for this XPath.
			if (nb_callback_rpc(nb_node, xpath, input_list,
					    output_list)
			    != NB_OK) {
				flog_warn(EC_LIB_NB_CB_RPC,
					  "%s: rpc callback failed: %s",
					  __func__, xpath);
				list_delete(&input_list);
				list_delete(&output_list);

				tag->responder.Finish(
					tag->response,
					grpc::Status(grpc::StatusCode::INTERNAL,
						     "RPC failed"),
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

			tag->responder.Finish(tag->response, grpc::Status::OK,
					      tag);
			tag->state = FINISH;
			break;
		}
		case FINISH:
			delete tag;
		}
	}

      private:
	frr::Northbound::AsyncService *_service;
	grpc::ServerCompletionQueue *_cq;

	struct candidate {
		uint32_t id;
		struct nb_config *config;
		struct nb_transaction *transaction;
	};
	std::map<uint32_t, struct candidate> _candidates;
	uint32_t _nextCandidateId;

	static int yang_dnode_edit(struct lyd_node *dnode,
				   const std::string &path,
				   const std::string &value)
	{
		ly_errno = LY_SUCCESS;
		dnode = lyd_new_path(dnode, ly_native_ctx, path.c_str(),
				     (void *)value.c_str(),
				     (LYD_ANYDATA_VALUETYPE)0,
				     LYD_PATH_OPT_UPDATE);
		if (!dnode && ly_errno != LY_SUCCESS) {
			flog_warn(EC_LIB_LIBYANG, "%s: lyd_new_path() failed",
				  __func__);
			return -1;
		}

		return 0;
	}

	static int yang_dnode_delete(struct lyd_node *dnode,
				     const std::string &path)
	{
		dnode = yang_dnode_get(dnode, path.c_str());
		if (!dnode)
			return -1;

		lyd_free(dnode);

		return 0;
	}

	static LYD_FORMAT encoding2lyd_format(enum frr::Encoding encoding)
	{
		switch (encoding) {
		case frr::JSON:
			return LYD_JSON;
		case frr::XML:
			return LYD_XML;
		default:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown data encoding format (%u)",
				 __func__, encoding);
			exit(1);
		}
	}

	static int get_oper_data_cb(const struct lys_node *snode,
				    struct yang_translator *translator,
				    struct yang_data *data, void *arg)
	{
		struct lyd_node *dnode = static_cast<struct lyd_node *>(arg);
		int ret = yang_dnode_edit(dnode, data->xpath, data->value);
		yang_data_free(data);

		return (ret == 0) ? NB_OK : NB_ERR;
	}

	static void list_transactions_cb(void *arg, int transaction_id,
					 const char *client_name,
					 const char *date, const char *comment)
	{

		auto list = static_cast<std::list<std::tuple<
			int, std::string, std::string, std::string>> *>(arg);
		list->push_back(std::make_tuple(
			transaction_id, std::string(client_name),
			std::string(date), std::string(comment)));
	}

	static int data_tree_from_dnode(frr::DataTree *dt,
					const struct lyd_node *dnode,
					LYD_FORMAT lyd_format,
					bool with_defaults)
	{
		char *strp;
		int options = 0;

		SET_FLAG(options, LYP_FORMAT | LYP_WITHSIBLINGS);
		if (with_defaults)
			SET_FLAG(options, LYP_WD_ALL);
		else
			SET_FLAG(options, LYP_WD_TRIM);

		if (lyd_print_mem(&strp, dnode, lyd_format, options) == 0) {
			if (strp) {
				dt->set_data(strp);
				free(strp);
			}
			return 0;
		}

		return -1;
	}

	static struct lyd_node *dnode_from_data_tree(const frr::DataTree *dt,
						     bool config_only)
	{
		struct lyd_node *dnode;
		int options;

		if (config_only)
			options = LYD_OPT_CONFIG;
		else
			options = LYD_OPT_DATA | LYD_OPT_DATA_NO_YANGLIB;

		dnode = lyd_parse_mem(ly_native_ctx, dt->data().c_str(),
				      encoding2lyd_format(dt->encoding()),
				      options);

		return dnode;
	}

	static struct lyd_node *get_dnode_config(const std::string &path)
	{
		struct lyd_node *dnode;

		dnode = yang_dnode_get(running_config->dnode,
				       path.empty() ? NULL : path.c_str());
		if (dnode)
			dnode = yang_dnode_dup(dnode);

		return dnode;
	}

	static struct lyd_node *get_dnode_state(const std::string &path)
	{
		struct lyd_node *dnode;

		dnode = yang_dnode_new(ly_native_ctx, false);
		if (nb_oper_data_iterate(path.c_str(), NULL, 0,
					 get_oper_data_cb, dnode)
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
				return grpc::Status(
					grpc::StatusCode::INVALID_ARGUMENT,
					"Data path not found");
		}

		// Operational data.
		if (type == frr::GetRequest_DataType_ALL
		    || type == frr::GetRequest_DataType_STATE) {
			dnode_state = get_dnode_state(path);
			if (!dnode_state) {
				if (dnode_config)
					yang_dnode_free(dnode_config);
				return grpc::Status(
					grpc::StatusCode::INVALID_ARGUMENT,
					"Failed to fetch operational data");
			}
		}

		switch (type) {
		case frr::GetRequest_DataType_ALL:
			//
			// Combine configuration and state data into a single
			// dnode.
			//
			if (lyd_merge(dnode_state, dnode_config,
				      LYD_OPT_EXPLICIT)
			    != 0) {
				yang_dnode_free(dnode_state);
				yang_dnode_free(dnode_config);
				return grpc::Status(
					grpc::StatusCode::INTERNAL,
					"Failed to merge configuration and state data");
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
			validate_opts = LYD_OPT_CONFIG;
		else
			validate_opts = LYD_OPT_DATA | LYD_OPT_DATA_NO_YANGLIB;
		lyd_validate(&dnode_final, validate_opts, ly_native_ctx);

		// Dump data using the requested format.
		int ret = data_tree_from_dnode(dt, dnode_final, lyd_format,
					       with_defaults);
		yang_dnode_free(dnode_final);
		if (ret != 0)
			return grpc::Status(grpc::StatusCode::INTERNAL,
					    "Failed to dump data");

		return grpc::Status::OK;
	}

	struct candidate *create_candidate(void)
	{
		uint32_t candidate_id = ++_nextCandidateId;

		// Check for overflow.
		// TODO: implement an algorithm for unique reusable IDs.
		if (candidate_id == 0)
			return NULL;

		struct candidate *candidate = &_candidates[candidate_id];
		candidate->id = candidate_id;
		candidate->config = nb_config_dup(running_config);
		candidate->transaction = NULL;

		return candidate;
	}

	void delete_candidate(struct candidate *candidate)
	{
		char errmsg[BUFSIZ] = {0};

		_candidates.erase(candidate->id);
		nb_config_free(candidate->config);
		if (candidate->transaction)
			nb_candidate_commit_abort(candidate->transaction,
						  errmsg, sizeof(errmsg));
	}

	struct candidate *get_candidate(uint32_t candidate_id)
	{
		struct candidate *candidate;

		if (_candidates.count(candidate_id) == 0)
			return NULL;

		return &_candidates[candidate_id];
	}
};

static void *grpc_pthread_start(void *arg)
{
	struct frr_pthread *fpt = static_cast<frr_pthread *>(arg);
	unsigned long *port = static_cast<unsigned long *>(fpt->data);

	frr_pthread_set_name(fpt);

	NorthboundImpl nb;
	nb.Run(*port);

	return NULL;
}

static int frr_grpc_init(unsigned long *port)
{
	fpt = frr_pthread_new(&attr, "frr-grpc", "frr-grpc");
	fpt->data = static_cast<void *>(port);

	/* Create a pthread for gRPC since it runs its own event loop. */
	if (frr_pthread_run(fpt, NULL) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL, "%s: error creating pthread: %s",
			 __func__, safe_strerror(errno));
		return -1;
	}
	pthread_detach(fpt->thread);

	return 0;
}

static int frr_grpc_finish(void)
{
	if (fpt)
		frr_pthread_destroy(fpt);
	// TODO: cancel the gRPC pthreads gracefully.

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
	static unsigned long port = GRPC_DEFAULT_PORT;
	const char *args = THIS_MODULE->load_args;

	// Parse port number.
	if (args) {
		try {
			port = std::stoul(args);
			if (port < 1024)
				throw std::invalid_argument(
					"can't use privileged port");
			if (port > UINT16_MAX)
				throw std::invalid_argument(
					"port number is too big");
		} catch (std::exception &e) {
			flog_err(EC_LIB_GRPC_INIT,
				 "%s: failed to parse port number: %s",
				 __func__, e.what());
			goto error;
		}
	}

	if (frr_grpc_init(&port) < 0)
		goto error;

	return 0;

error:
	flog_err(EC_LIB_GRPC_INIT, "failed to initialize the gRPC module");
	return -1;
}

static int frr_grpc_module_late_init(struct thread_master *tm)
{
	thread_add_event(tm, frr_grpc_module_very_late_init, NULL, 0, NULL);
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
		 .init = frr_grpc_module_init, )
