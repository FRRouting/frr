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
#include "lib/northbound_grpc_call.h"
#include "lib/northbound_grpc_candidates.h"

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

void HandleUnaryGetCapabilities(
	NorthboundCall<frr::GetCapabilitiesRequest,
		       frr::GetCapabilitiesResponse> *tag)
{
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
	tag->finish();
}

void HandleStreamingGet(
	NorthboundCallAsync<frr::GetRequest, frr::GetResponse> *tag)
{
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
		delete static_cast<std::list<std::string> *>(tag->context);
		tag->finish();
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
		delete static_cast<std::list<std::string> *>(tag->context);
		tag->finish();
		return;
	}

	mypathps->pop_back();
	if (mypathps->empty()) {
		tag->async_responder.WriteAndFinish(
			response, grpc::WriteOptions(), grpc::Status::OK, tag);
		delete static_cast<std::list<std::string> *>(tag->context);
		tag->finish();
	} else {
		tag->async_responder.Write(response, tag);
	}
}

void HandleUnaryCreateCandidate(
	NorthboundCall<frr::CreateCandidateRequest,
		       frr::CreateCandidateResponse> *tag)
{
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

	tag->finish();
}

void HandleUnaryDeleteCandidate(
	NorthboundCall<frr::DeleteCandidateRequest,
		       frr::DeleteCandidateResponse> *tag)
{
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
	tag->finish();
}

void HandleUnaryUpdateCandidate(
	NorthboundCall<frr::UpdateCandidateRequest,
		       frr::UpdateCandidateResponse> *tag)
{
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

	tag->finish();
}

void HandleUnaryEditCandidate(NorthboundCall<frr::EditCandidateRequest,
					     frr::EditCandidateResponse> *tag)
{
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
		tag->finish();
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

			tag->finish();
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
			tag->finish();
			return;
		}
	}

	// No errors, accept all changes.
	nb_config_replace(candidate->config, candidate_tmp, false);

	tag->responder.Finish(tag->response, grpc::Status::OK, tag);

	tag->finish();
}

void HandleUnaryLoadToCandidate(
	NorthboundCall<frr::LoadToCandidateRequest,
		       frr::LoadToCandidateResponse> *tag)
{
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
		tag->finish();
		return;
	}

	struct lyd_node *dnode = dnode_from_data_tree(&config, true);
	if (!dnode) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::INTERNAL,
				     "Failed to parse the configuration"),
			tag);
		tag->finish();
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
		tag->finish();
		return;
	}

	tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	tag->finish();
}

void HandleUnaryCommit(
	NorthboundCall<frr::CommitRequest, frr::CommitResponse> *tag)
{
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
		tag->finish();
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
			tag->finish();
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
			tag->finish();
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
	tag->finish();
}

void HandleUnaryLockConfig(
	NorthboundCall<frr::LockConfigRequest, frr::LockConfigResponse> *tag)
{
	if (nb_running_lock(NB_CLIENT_GRPC, NULL)) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
				     "running configuration is locked already"),
			tag);
	} else {
		tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	}
	tag->finish();
}

void HandleUnaryUnlockConfig(NorthboundCall<frr::UnlockConfigRequest,
					    frr::UnlockConfigResponse> *tag)
{
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
	tag->finish();
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
	NorthboundCallAsync<frr::ListTransactionsRequest,
			    frr::ListTransactionsResponse> *tag)
{
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
		delete static_cast<std::list<std::tuple<
			int, std::string, std::string, std::string>> *>(
			tag->context);
		tag->finish();
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
		delete static_cast<std::list<std::tuple<
			int, std::string, std::string, std::string>> *>(
			tag->context);
		tag->finish();
	} else {
		tag->async_responder.Write(response, tag);
	}
}

void HandleUnaryGetTransaction(NorthboundCall<frr::GetTransactionRequest,
					      frr::GetTransactionResponse> *tag)
{
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
		tag->finish();
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
		tag->finish();
		return;
	}

	nb_config_free(nb_config);

	tag->responder.Finish(tag->response, grpc::Status::OK, tag);
	tag->finish();
}

void HandleUnaryExecute(
	NorthboundCall<frr::ExecuteRequest, frr::ExecuteResponse> *tag)
{
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
		tag->finish();
		return;
	}

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		tag->responder.Finish(
			tag->response,
			grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
				     "Unknown data path"),
			tag);
		tag->finish();
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
		tag->finish();
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
	tag->finish();
}

class NorthboundServer
{
      public:
	NorthboundServer() : m_running(false)
	{
	}

	void initialize(std::string uri, struct thread_master *main)
	{
		m_uri = uri;
		m_main = main;
	}

	void shutdown()
	{
		void *tag;
		bool ok;

		// Server was never run, so just quit.
		if (!m_running)
			return;

		m_running = false;
		m_server->Shutdown();
		m_queue->Shutdown();

		// Empty queue.
		while (m_queue->Next(&tag, &ok)) {
			// NOTHING
		}
	}

/*
 * Macros to make it easy on the eyes the handler declarations.
 *
 * Parameters:
 * - frr::Northbound::AsyncService *
 * - grpc::ServerCompletionQueue *
 * - struct thread_master *
 * - Candidates *
 * - bool *
 * - (text/code) Service name
 */
#define NORTHBOUND_ASYNC_RESPONDER(service, queue, main, candidate, running,   \
				   name)                                       \
	new NorthboundCallAsync<frr::name##Request, frr::name##Response>(      \
		(service), (queue), (main), (candidate), (running),            \
		&frr::Northbound::AsyncService::Request##name,                 \
		&HandleStreaming##name)

#define NORTHBOUND_RESPONDER(service, queue, main, candidate, running, name)   \
	new NorthboundCall<frr::name##Request, frr::name##Response>(           \
		(service), (queue), (main), (candidate), (running),            \
		&frr::Northbound::AsyncService::Request##name,                 \
		&HandleUnary##name)

	/** Server main loop. Don't forget to call `initialize` first. */
	void run()
	{
		void *tag;
		bool ok;
		grpc::ServerBuilder server_builder;

		server_builder.AddListeningPort(
			m_uri, grpc::InsecureServerCredentials());
		server_builder.RegisterService(&m_service);
		server_builder.AddChannelArgument(
			GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS,
			5000);
		m_queue = server_builder.AddCompletionQueue();
		m_server = server_builder.BuildAndStart();
		m_running = true;

		zlog_notice("gRPC server listening on %s", m_uri.c_str());

		NORTHBOUND_ASYNC_RESPONDER(&m_service, m_queue.get(), m_main,
					   NULL, &m_running, Get);
		NORTHBOUND_ASYNC_RESPONDER(&m_service, m_queue.get(), m_main,
					   NULL, &m_running, ListTransactions);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main, NULL,
				     &m_running, Execute);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main, NULL,
				     &m_running, GetCapabilities);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main,
				     &m_candidates, &m_running,
				     CreateCandidate);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main,
				     &m_candidates, &m_running,
				     DeleteCandidate);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main,
				     &m_candidates, &m_running,
				     UpdateCandidate);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main,
				     &m_candidates, &m_running, EditCandidate);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main,
				     &m_candidates, &m_running,
				     LoadToCandidate);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main,
				     &m_candidates, &m_running, Commit);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main, NULL,
				     &m_running, GetTransaction);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main, NULL,
				     &m_running, LockConfig);
		NORTHBOUND_RESPONDER(&m_service, m_queue.get(), m_main, NULL,
				     &m_running, UnlockConfig);

		while (m_running) {
			if (!m_queue->Next(&tag, &ok)) {
				// We are shutting down.
				break;
			}

			// Skip bad call states.
			if (!ok) {
				break;
			}

			// We are not running anymore, let the main thread
			// handle the queue depletion in the main thread.
			if (!m_running) {
				break;
			}

			static_cast<NorthboundCallInterface *>(tag)->run();
		}
	}

      private:
	frr::Northbound::AsyncService m_service;

	std::unique_ptr<grpc::ServerCompletionQueue> m_queue;
	std::unique_ptr<grpc::Server> m_server;
	grpc::ServerContext m_server_context;

	struct thread_master *m_main;
	Candidates m_candidates;
	std::string m_uri;
	bool m_running;
};

// ------------------------------------------------------
//        Thread Initialization and Run Functions
// ------------------------------------------------------

struct grpc_pthread_attr {
	struct frr_pthread_attr attr;
	unsigned long port;
};

NorthboundServer northbound_server;

static void *grpc_pthread_start(void *arg)
{
	struct frr_pthread *fpt = static_cast<frr_pthread *>(arg);
	uint port = (uint) reinterpret_cast<intptr_t>(fpt->data);
	std::stringstream server_address;
	sigset_t allsigs;

	/* make sure all signal handling happens on main FRR thread */
	sigfillset(&allsigs);
	sigprocmask(SIG_BLOCK, &allsigs, NULL);
	frr_pthread_set_name(fpt);

	server_address << "0.0.0.0:" << port;

	// Server main loop: only ends on shutdown.
	northbound_server.initialize(server_address.str(), main_master);
	northbound_server.run();

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
	northbound_server.shutdown();

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
	hook_register(frr_early_fini, frr_grpc_finish);
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
