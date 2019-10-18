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
static bool nb_dbg_client_grpc = 1;

static pthread_t grpc_pthread;

class NorthboundImpl final : public frr::Northbound::Service
{
      public:
	NorthboundImpl(void)
	{
		_nextCandidateId = 0;
	}

	~NorthboundImpl(void)
	{
		// Delete candidates.
		for (auto it = _candidates.begin(); it != _candidates.end();
		     it++)
			delete_candidate(&it->second);
	}

	grpc::Status
	GetCapabilities(grpc::ServerContext *context,
			frr::GetCapabilitiesRequest const *request,
			frr::GetCapabilitiesResponse *response) override
	{
		if (nb_dbg_client_grpc)
			zlog_debug("received RPC GetCapabilities()");

		// Response: string frr_version = 1;
		response->set_frr_version(FRR_VERSION);

		// Response: bool rollback_support = 2;
#ifdef HAVE_CONFIG_ROLLBACKS
		response->set_rollback_support(true);
#else
		response->set_rollback_support(false);
#endif

		// Response: repeated ModuleData supported_modules = 3;
		struct yang_module *module;
		RB_FOREACH (module, yang_modules, &yang_modules) {
			auto m = response->add_supported_modules();

			m->set_name(module->name);
			if (module->info->rev_size)
				m->set_revision(module->info->rev[0].date);
			m->set_organization(module->info->org);
		}

		// Response: repeated Encoding supported_encodings = 4;
		response->add_supported_encodings(frr::JSON);
		response->add_supported_encodings(frr::XML);

		return grpc::Status::OK;
	}

	grpc::Status Get(grpc::ServerContext *context,
			 frr::GetRequest const *request,
			 grpc::ServerWriter<frr::GetResponse> *writer) override
	{
		// Request: DataType type = 1;
		int type = request->type();
		// Request: Encoding encoding = 2;
		frr::Encoding encoding = request->encoding();
		// Request: bool with_defaults = 3;
		bool with_defaults = request->with_defaults();

		if (nb_dbg_client_grpc)
			zlog_debug(
				"received RPC Get(type: %u, encoding: %u, with_defaults: %u)",
				type, encoding, with_defaults);

		// Request: repeated string path = 4;
		auto paths = request->path();
		for (const std::string &path : paths) {
			frr::GetResponse response;
			grpc::Status status;

			// Response: int64 timestamp = 1;
			response.set_timestamp(time(NULL));

			// Response: DataTree data = 2;
			auto *data = response.mutable_data();
			data->set_encoding(request->encoding());
			status = get_path(data, path, type,
					  encoding2lyd_format(encoding),
					  with_defaults);

			// Something went wrong...
			if (!status.ok())
				return status;

			writer->Write(response);
		}

		if (nb_dbg_client_grpc)
			zlog_debug("received RPC Get() end");

		return grpc::Status::OK;
	}

	grpc::Status
	CreateCandidate(grpc::ServerContext *context,
			frr::CreateCandidateRequest const *request,
			frr::CreateCandidateResponse *response) override
	{
		if (nb_dbg_client_grpc)
			zlog_debug("received RPC CreateCandidate()");

		struct candidate *candidate = create_candidate();
		if (!candidate)
			return grpc::Status(
				grpc::StatusCode::RESOURCE_EXHAUSTED,
				"Can't create candidate configuration");

		// Response: uint32 candidate_id = 1;
		response->set_candidate_id(candidate->id);

		return grpc::Status::OK;
	}

	grpc::Status
	DeleteCandidate(grpc::ServerContext *context,
			frr::DeleteCandidateRequest const *request,
			frr::DeleteCandidateResponse *response) override
	{
		// Request: uint32 candidate_id = 1;
		uint32_t candidate_id = request->candidate_id();

		if (nb_dbg_client_grpc)
			zlog_debug(
				"received RPC DeleteCandidate(candidate_id: %u)",
				candidate_id);

		struct candidate *candidate = get_candidate(candidate_id);
		if (!candidate)
			return grpc::Status(
				grpc::StatusCode::NOT_FOUND,
				"candidate configuration not found");

		delete_candidate(candidate);

		return grpc::Status::OK;
	}

	grpc::Status
	UpdateCandidate(grpc::ServerContext *context,
			frr::UpdateCandidateRequest const *request,
			frr::UpdateCandidateResponse *response) override
	{
		// Request: uint32 candidate_id = 1;
		uint32_t candidate_id = request->candidate_id();

		if (nb_dbg_client_grpc)
			zlog_debug(
				"received RPC UpdateCandidate(candidate_id: %u)",
				candidate_id);

		struct candidate *candidate = get_candidate(candidate_id);
		if (!candidate)
			return grpc::Status(
				grpc::StatusCode::NOT_FOUND,
				"candidate configuration not found");

		if (candidate->transaction)
			return grpc::Status(
				grpc::StatusCode::FAILED_PRECONDITION,
				"candidate is in the middle of a transaction");

		if (nb_candidate_update(candidate->config) != NB_OK)
			return grpc::Status(
				grpc::StatusCode::INTERNAL,
				"failed to update candidate configuration");

		return grpc::Status::OK;
	}

	grpc::Status
	EditCandidate(grpc::ServerContext *context,
		      frr::EditCandidateRequest const *request,
		      frr::EditCandidateResponse *response) override
	{
		// Request: uint32 candidate_id = 1;
		uint32_t candidate_id = request->candidate_id();

		if (nb_dbg_client_grpc)
			zlog_debug(
				"received RPC EditCandidate(candidate_id: %u)",
				candidate_id);

		struct candidate *candidate = get_candidate(candidate_id);
		if (!candidate)
			return grpc::Status(
				grpc::StatusCode::NOT_FOUND,
				"candidate configuration not found");

		// Create a copy of the candidate. For consistency, we need to
		// ensure that either all changes are accepted or none are (in
		// the event of an error).
		struct nb_config *candidate_tmp =
			nb_config_dup(candidate->config);

		auto pvs = request->update();
		for (const frr::PathValue &pv : pvs) {
			if (yang_dnode_edit(candidate_tmp->dnode, pv.path(),
					    pv.value())
			    != 0) {
				nb_config_free(candidate_tmp);
				return grpc::Status(
					grpc::StatusCode::INVALID_ARGUMENT,
					"Failed to update \"" + pv.path()
						+ "\"");
			}
		}

		pvs = request->delete_();
		for (const frr::PathValue &pv : pvs) {
			if (yang_dnode_delete(candidate_tmp->dnode, pv.path())
			    != 0) {
				nb_config_free(candidate_tmp);
				return grpc::Status(
					grpc::StatusCode::INVALID_ARGUMENT,
					"Failed to remove \"" + pv.path()
						+ "\"");
			}
		}

		// No errors, accept all changes.
		nb_config_replace(candidate->config, candidate_tmp, false);

		return grpc::Status::OK;
	}

	grpc::Status
	LoadToCandidate(grpc::ServerContext *context,
			frr::LoadToCandidateRequest const *request,
			frr::LoadToCandidateResponse *response) override
	{
		// Request: uint32 candidate_id = 1;
		uint32_t candidate_id = request->candidate_id();
		// Request: LoadType type = 2;
		int load_type = request->type();
		// Request: DataTree config = 3;
		auto config = request->config();

		if (nb_dbg_client_grpc)
			zlog_debug(
				"received RPC LoadToCandidate(candidate_id: %u)",
				candidate_id);

		struct candidate *candidate = get_candidate(candidate_id);
		if (!candidate)
			return grpc::Status(
				grpc::StatusCode::NOT_FOUND,
				"candidate configuration not found");

		struct lyd_node *dnode = dnode_from_data_tree(&config, true);
		if (!dnode)
			return grpc::Status(
				grpc::StatusCode::INTERNAL,
				"Failed to parse the configuration");

		struct nb_config *loaded_config = nb_config_new(dnode);

		if (load_type == frr::LoadToCandidateRequest::REPLACE)
			nb_config_replace(candidate->config, loaded_config,
					  false);
		else if (nb_config_merge(candidate->config, loaded_config,
					 false)
			 != NB_OK)
			return grpc::Status(
				grpc::StatusCode::INTERNAL,
				"Failed to merge the loaded configuration");

		return grpc::Status::OK;
	}

	grpc::Status Commit(grpc::ServerContext *context,
			    frr::CommitRequest const *request,
			    frr::CommitResponse *response) override
	{
		// Request: uint32 candidate_id = 1;
		uint32_t candidate_id = request->candidate_id();
		// Request: Phase phase = 2;
		int phase = request->phase();
		// Request: string comment = 3;
		const std::string comment = request->comment();

		if (nb_dbg_client_grpc)
			zlog_debug("received RPC Commit(candidate_id: %u)",
				   candidate_id);

		// Find candidate configuration.
		struct candidate *candidate = get_candidate(candidate_id);
		if (!candidate)
			return grpc::Status(
				grpc::StatusCode::NOT_FOUND,
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
					"pending transaction in progress");
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
		switch (phase) {
		case frr::CommitRequest::VALIDATE:
			ret = nb_candidate_validate(candidate->config);
			break;
		case frr::CommitRequest::PREPARE:
			ret = nb_candidate_commit_prepare(
				candidate->config, NB_CLIENT_GRPC, NULL,
				comment.c_str(), &candidate->transaction);
			break;
		case frr::CommitRequest::ABORT:
			nb_candidate_commit_abort(candidate->transaction);
			break;
		case frr::CommitRequest::APPLY:
			nb_candidate_commit_apply(candidate->transaction, true,
						  &transaction_id);
			break;
		case frr::CommitRequest::ALL:
			ret = nb_candidate_commit(
				candidate->config, NB_CLIENT_GRPC, NULL, true,
				comment.c_str(), &transaction_id);
			break;
		}

		// Map northbound error codes to gRPC error codes.
		switch (ret) {
		case NB_ERR_NO_CHANGES:
			return grpc::Status(
				grpc::StatusCode::ABORTED,
				"No configuration changes detected");
		case NB_ERR_LOCKED:
			return grpc::Status(
				grpc::StatusCode::UNAVAILABLE,
				"There's already a transaction in progress");
		case NB_ERR_VALIDATION:
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Validation error");
		case NB_ERR_RESOURCE:
			return grpc::Status(
				grpc::StatusCode::RESOURCE_EXHAUSTED,
				"Failed do allocate resources");
		case NB_ERR:
			return grpc::Status(grpc::StatusCode::INTERNAL,
					    "Internal error");
		default:
			break;
		}

		// Response: uint32 transaction_id = 1;
		if (transaction_id)
			response->set_transaction_id(transaction_id);

		return grpc::Status::OK;
	}

	grpc::Status
	ListTransactions(grpc::ServerContext *context,
			 frr::ListTransactionsRequest const *request,
			 grpc::ServerWriter<frr::ListTransactionsResponse>
				 *writer) override
	{
		if (nb_dbg_client_grpc)
			zlog_debug("received RPC ListTransactions()");

		nb_db_transactions_iterate(list_transactions_cb, writer);

		return grpc::Status::OK;
	}

	grpc::Status
	GetTransaction(grpc::ServerContext *context,
		       frr::GetTransactionRequest const *request,
		       frr::GetTransactionResponse *response) override
	{
		struct nb_config *nb_config;

		// Request: uint32 transaction_id = 1;
		uint32_t transaction_id = request->transaction_id();
		// Request: Encoding encoding = 2;
		frr::Encoding encoding = request->encoding();
		// Request: bool with_defaults = 3;
		bool with_defaults = request->with_defaults();

		if (nb_dbg_client_grpc)
			zlog_debug(
				"received RPC GetTransaction(transaction_id: %u, encoding: %u)",
				transaction_id, encoding);

		// Load configuration from the transactions database.
		nb_config = nb_db_transaction_load(transaction_id);
		if (!nb_config)
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Transaction not found");

		// Response: DataTree config = 1;
		auto config = response->mutable_config();
		config->set_encoding(encoding);

		// Dump data using the requested format.
		if (data_tree_from_dnode(config, nb_config->dnode,
					 encoding2lyd_format(encoding),
					 with_defaults)
		    != 0) {
			nb_config_free(nb_config);
			return grpc::Status(grpc::StatusCode::INTERNAL,
					    "Failed to dump data");
		}

		nb_config_free(nb_config);

		return grpc::Status::OK;
	}

	grpc::Status LockConfig(grpc::ServerContext *context,
				frr::LockConfigRequest const *request,
				frr::LockConfigResponse *response) override
	{
		if (nb_dbg_client_grpc)
			zlog_debug("received RPC LockConfig()");

		if (nb_running_lock(NB_CLIENT_GRPC, NULL))
			return grpc::Status(
				grpc::StatusCode::FAILED_PRECONDITION,
				"running configuration is locked already");

		return grpc::Status::OK;
	}

	grpc::Status UnlockConfig(grpc::ServerContext *context,
				  frr::UnlockConfigRequest const *request,
				  frr::UnlockConfigResponse *response) override
	{
		if (nb_dbg_client_grpc)
			zlog_debug("received RPC UnlockConfig()");

		if (nb_running_unlock(NB_CLIENT_GRPC, NULL))
			return grpc::Status(
				grpc::StatusCode::FAILED_PRECONDITION,
				"failed to unlock the running configuration");

		return grpc::Status::OK;
	}

	grpc::Status Execute(grpc::ServerContext *context,
			     frr::ExecuteRequest const *request,
			     frr::ExecuteResponse *response) override
	{
		struct nb_node *nb_node;
		struct list *input_list;
		struct list *output_list;
		struct listnode *node;
		struct yang_data *data;
		const char *xpath;

		// Request: string path = 1;
		xpath = request->path().c_str();

		if (nb_dbg_client_grpc)
			zlog_debug("received RPC Execute(path: \"%s\")", xpath);

		if (request->path().empty())
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Data path is empty");

		nb_node = nb_node_find(xpath);
		if (!nb_node)
			return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
					    "Unknown data path");

		input_list = yang_data_list_new();
		output_list = yang_data_list_new();

		// Read input parameters.
		auto input = request->input();
		for (const frr::PathValue &pv : input) {
			// Request: repeated PathValue input = 2;
			data = yang_data_new(pv.path().c_str(),
					     pv.value().c_str());
			listnode_add(input_list, data);
		}

		// Execute callback registered for this XPath.
		if (nb_node->cbs.rpc(xpath, input_list, output_list) != NB_OK) {
			flog_warn(EC_LIB_NB_CB_RPC,
				  "%s: rpc callback failed: %s", __func__,
				  xpath);
			list_delete(&input_list);
			list_delete(&output_list);
			return grpc::Status(grpc::StatusCode::INTERNAL,
					    "RPC failed");
		}

		// Process output parameters.
		for (ALL_LIST_ELEMENTS_RO(output_list, node, data)) {
			// Response: repeated PathValue output = 1;
			frr::PathValue *pv = response->add_output();
			pv->set_path(data->xpath);
			pv->set_value(data->value);
		}

		// Release memory.
		list_delete(&input_list);
		list_delete(&output_list);

		return grpc::Status::OK;
	}

      private:
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
		grpc::ServerWriter<frr::ListTransactionsResponse> *writer =
			static_cast<grpc::ServerWriter<
				frr::ListTransactionsResponse> *>(arg);
		frr::ListTransactionsResponse response;

		// Response: uint32 id = 1;
		response.set_id(transaction_id);

		// Response: string client = 2;
		response.set_client(client_name);

		// Response: string date = 3;
		response.set_date(date);

		// Response: string comment = 4;
		response.set_comment(comment);

		writer->Write(response);
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
		_candidates.erase(candidate->id);
		nb_config_free(candidate->config);
		if (candidate->transaction)
			nb_candidate_commit_abort(candidate->transaction);
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
	unsigned long *port = static_cast<unsigned long *>(arg);
	NorthboundImpl service;
	std::stringstream server_address;

	server_address << "0.0.0.0:" << *port;

	grpc::ServerBuilder builder;
	builder.AddListeningPort(server_address.str(),
				 grpc::InsecureServerCredentials());
	builder.RegisterService(&service);

	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

	zlog_notice("gRPC server listening on %s",
		    server_address.str().c_str());

	server->Wait();

	return NULL;
}

static int frr_grpc_init(unsigned long *port)
{
	/* Create a pthread for gRPC since it runs its own event loop. */
	if (pthread_create(&grpc_pthread, NULL, grpc_pthread_start, port)) {
		flog_err(EC_LIB_SYSTEM_CALL, "%s: error creating pthread: %s",
			 __func__, safe_strerror(errno));
		return -1;
	}
	pthread_detach(grpc_pthread);

	return 0;
}

static int frr_grpc_finish(void)
{
	// TODO: cancel the gRPC pthreads gracefully.

	return 0;
}

static int frr_grpc_module_late_init(struct thread_master *tm)
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

	hook_register(frr_fini, frr_grpc_finish);

	return 0;

error:
	flog_err(EC_LIB_GRPC_INIT, "failed to initialize the gRPC module");
	return -1;
}

static int frr_grpc_module_init(void)
{
	hook_register(frr_late_init, frr_grpc_module_late_init);

	return 0;
}

FRR_MODULE_SETUP(.name = "frr_grpc", .version = FRR_VERSION,
		 .description = "FRR gRPC northbound module",
		 .init = frr_grpc_module_init, )
