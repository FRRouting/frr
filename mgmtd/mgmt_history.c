// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include "md5.h"
#include "frrevent.h"
#include "xref.h"

#include "mgmt_fe_client.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_history.h"

struct mgmt_cmt_info_t {
	struct mgmt_cmt_infos_item cmts;

	char cmtid_str[MGMT_SHORT_TIME_MAX_LEN];
	char time_str[MGMT_LONG_TIME_MAX_LEN];
	char cmt_json_file[PATH_MAX];
};


DECLARE_DLIST(mgmt_cmt_infos, struct mgmt_cmt_info_t, cmts);

#define FOREACH_CMT_REC(mm, cmt_info)                                          \
	frr_each_safe (mgmt_cmt_infos, &mm->cmts, cmt_info)

/*
 * The only instance of VTY session that has triggered an ongoing
 * config rollback operation.
 */
static struct vty *rollback_vty;

static bool file_exists(const char *path)
{
	return !access(path, F_OK);
}

static void remove_file(const char *path)
{
	if (!file_exists(path))
		return;
	if (unlink(path))
		zlog_err("Failed to remove commit history file %s: %s", path,
			 safe_strerror(errno));
}

static struct mgmt_cmt_info_t *mgmt_history_new_cmt_info(void)
{
	struct mgmt_cmt_info_t *new;
	struct timespec tv;
	struct tm tm;

	new = XCALLOC(MTYPE_MGMTD_CMT_INFO, sizeof(struct mgmt_cmt_info_t));

	clock_gettime(CLOCK_REALTIME, &tv);
	localtime_r(&tv.tv_sec, &tm);

	mgmt_time_to_string(&tv, true, new->time_str, sizeof(new->time_str));
	mgmt_time_to_string(&tv, false, new->cmtid_str, sizeof(new->cmtid_str));
	snprintf(new->cmt_json_file, sizeof(new->cmt_json_file),
		 MGMTD_COMMIT_FILE_PATH(new->cmtid_str));

	return new;
}

static struct mgmt_cmt_info_t *mgmt_history_create_cmt_rec(void)
{
	struct mgmt_cmt_info_t *new = mgmt_history_new_cmt_info();
	struct mgmt_cmt_info_t *cmt_info;
	struct mgmt_cmt_info_t *last_cmt_info = NULL;

	if (mgmt_cmt_infos_count(&mm->cmts) == MGMTD_MAX_COMMIT_LIST) {
		FOREACH_CMT_REC (mm, cmt_info)
			last_cmt_info = cmt_info;

		if (last_cmt_info) {
			remove_file(last_cmt_info->cmt_json_file);
			mgmt_cmt_infos_del(&mm->cmts, last_cmt_info);
			XFREE(MTYPE_MGMTD_CMT_INFO, last_cmt_info);
		}
	}

	mgmt_cmt_infos_add_head(&mm->cmts, new);
	return new;
}

static struct mgmt_cmt_info_t *
mgmt_history_find_cmt_record(const char *cmtid_str)
{
	struct mgmt_cmt_info_t *cmt_info;

	FOREACH_CMT_REC (mm, cmt_info) {
		if (strcmp(cmt_info->cmtid_str, cmtid_str) == 0)
			return cmt_info;
	}

	return NULL;
}

static bool mgmt_history_read_cmt_record_index(void)
{
	char index_path[MAXPATHLEN];
	FILE *fp;
	struct mgmt_cmt_info_t cmt_info;
	struct mgmt_cmt_info_t *new;
	int cnt = 0;

	snprintf(index_path, sizeof(index_path), MGMTD_COMMIT_INDEX_FILE_PATH);

	fp = fopen(index_path, "rb");
	if (!fp) {
		if (errno == ENOENT || errno == ENOTDIR)
			return false;

		zlog_err("Failed to open commit history %pSQq for reading: %m",
			 index_path);
		return false;
	}

	while ((fread(&cmt_info, sizeof(cmt_info), 1, fp)) > 0) {
		if (cnt < MGMTD_MAX_COMMIT_LIST) {
			if (!file_exists(cmt_info.cmt_json_file)) {
				zlog_err("Commit in index, but file %s missing",
					 cmt_info.cmt_json_file);
				continue;
			}

			new = XCALLOC(MTYPE_MGMTD_CMT_INFO,
				      sizeof(struct mgmt_cmt_info_t));
			memcpy(new, &cmt_info, sizeof(struct mgmt_cmt_info_t));
			mgmt_cmt_infos_add_tail(&mm->cmts, new);
		} else {
			zlog_warn("More records found in commit history file %pSQq than expected",
				  index_path);
			fclose(fp);
			return false;
		}

		cnt++;
	}

	fclose(fp);
	return true;
}

static bool mgmt_history_dump_cmt_record_index(void)
{
	char index_path[MAXPATHLEN];
	FILE *fp;
	int ret = 0;
	struct mgmt_cmt_info_t *cmt_info;
	struct mgmt_cmt_info_t cmt_info_set[10];
	int cnt = 0;

	snprintf(index_path, sizeof(index_path), MGMTD_COMMIT_INDEX_FILE_PATH);

	fp = fopen(index_path, "wb");
	if (!fp) {
		zlog_err("Failed to open commit history %pSQq for writing: %m",
			 index_path);
		return false;
	}

	FOREACH_CMT_REC (mm, cmt_info) {
		memcpy(&cmt_info_set[cnt], cmt_info,
		       sizeof(struct mgmt_cmt_info_t));
		cnt++;
	}

	if (!cnt) {
		fclose(fp);
		return false;
	}

	ret = fwrite(&cmt_info_set, sizeof(struct mgmt_cmt_info_t), cnt, fp);
	fclose(fp);
	if (ret != cnt) {
		zlog_err("Failed to write full commit history, removing file");
		remove_file(index_path);
		return false;
	}
	return true;
}

static int mgmt_history_rollback_to_cmt(struct vty *vty,
				   struct mgmt_cmt_info_t *cmt_info,
				   bool skip_file_load)
{
	struct mgmt_ds_ctx *src_ds_ctx;
	struct mgmt_ds_ctx *dst_ds_ctx;
	int ret = 0;

	if (rollback_vty) {
		vty_out(vty, "ERROR: Rollback already in progress!\n");
		return -1;
	}

	src_ds_ctx = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_CANDIDATE);
	dst_ds_ctx = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_RUNNING);
	assert(src_ds_ctx);
	assert(dst_ds_ctx);

	ret = mgmt_ds_lock(src_ds_ctx, vty->mgmt_session_id);
	if (ret != 0) {
		vty_out(vty,
			"Failed to lock the DS %u for rollback Reason: %s!\n",
			MGMTD_DS_RUNNING, strerror(ret));
		return -1;
	}

	ret = mgmt_ds_lock(dst_ds_ctx, vty->mgmt_session_id);
	if (ret != 0) {
		mgmt_ds_unlock(src_ds_ctx);
		vty_out(vty,
			"Failed to lock the DS %u for rollback Reason: %s!\n",
			MGMTD_DS_RUNNING, strerror(ret));
		return -1;
	}

	if (!skip_file_load) {
		ret = mgmt_ds_load_config_from_file(
			src_ds_ctx, cmt_info->cmt_json_file, false);
		if (ret != 0) {
			vty_out(vty,
				"Error with parsing the file with error code %d\n",
				ret);
			goto failed_unlock;
		}
	}

	/* Internally trigger a commit-request. */
	ret = mgmt_txn_rollback_trigger_cfg_apply(src_ds_ctx, dst_ds_ctx);
	if (ret != 0) {
		vty_out(vty,
			"Error with creating commit apply txn with error code %d\n",
			ret);
		goto failed_unlock;
	}

	mgmt_history_dump_cmt_record_index();

	/*
	 * TODO: Cleanup: the generic TXN code currently checks for rollback
	 * and does the unlock when it completes.
	 */

	/*
	 * Block the rollback command from returning till the rollback
	 * is completed. On rollback completion mgmt_history_rollback_complete()
	 * shall be called to resume the rollback command return to VTYSH.
	 */
	vty->mgmt_req_pending_cmd = "ROLLBACK";
	rollback_vty = vty;
	return 0;

failed_unlock:
	mgmt_ds_unlock(src_ds_ctx);
	mgmt_ds_unlock(dst_ds_ctx);
	return ret;
}

void mgmt_history_rollback_complete(bool success)
{
	vty_mgmt_resume_response(rollback_vty,
				 success ? CMD_SUCCESS
					 : CMD_WARNING_CONFIG_FAILED);
	rollback_vty = NULL;
}

int mgmt_history_rollback_by_id(struct vty *vty, const char *cmtid_str)
{
	int ret = 0;
	struct mgmt_cmt_info_t *cmt_info;

	if (!mgmt_cmt_infos_count(&mm->cmts) ||
	    !mgmt_history_find_cmt_record(cmtid_str)) {
		vty_out(vty, "Invalid commit Id\n");
		return -1;
	}

	FOREACH_CMT_REC (mm, cmt_info) {
		if (strcmp(cmt_info->cmtid_str, cmtid_str) == 0) {
			ret = mgmt_history_rollback_to_cmt(vty, cmt_info,
							   false);
			return ret;
		}

		remove_file(cmt_info->cmt_json_file);
		mgmt_cmt_infos_del(&mm->cmts, cmt_info);
		XFREE(MTYPE_MGMTD_CMT_INFO, cmt_info);
	}

	return 0;
}

int mgmt_history_rollback_n(struct vty *vty, int num_cmts)
{
	int ret = 0;
	int cnt = 0;
	struct mgmt_cmt_info_t *cmt_info;
	size_t cmts;

	if (!num_cmts)
		num_cmts = 1;

	cmts = mgmt_cmt_infos_count(&mm->cmts);
	if ((int)cmts < num_cmts) {
		vty_out(vty,
			"Number of commits found (%d) less than required to rollback\n",
			(int)cmts);
		return -1;
	}

	if ((int)cmts == 1 || (int)cmts == num_cmts) {
		vty_out(vty,
			"Number of commits found (%d), Rollback of last commit is not supported\n",
			(int)cmts);
		return -1;
	}

	FOREACH_CMT_REC (mm, cmt_info) {
		if (cnt == num_cmts) {
			ret = mgmt_history_rollback_to_cmt(vty, cmt_info,
							   false);
			return ret;
		}

		cnt++;
		remove_file(cmt_info->cmt_json_file);
		mgmt_cmt_infos_del(&mm->cmts, cmt_info);
		XFREE(MTYPE_MGMTD_CMT_INFO, cmt_info);
	}

	if (!mgmt_cmt_infos_count(&mm->cmts)) {
		mgmt_ds_reset_candidate();
		ret = mgmt_history_rollback_to_cmt(vty, cmt_info, true);
	}

	return ret;
}

void show_mgmt_cmt_history(struct vty *vty)
{
	struct mgmt_cmt_info_t *cmt_info;
	int slno = 0;

	vty_out(vty, "Last 10 commit history:\n");
	vty_out(vty, "Slot Commit-ID               Commit-Record-Time\n");
	FOREACH_CMT_REC (mm, cmt_info) {
		vty_out(vty, "%4d %23s %s\n", slno, cmt_info->cmtid_str,
			cmt_info->time_str);
		slno++;
	}
}

void mgmt_history_new_record(struct mgmt_ds_ctx *ds_ctx)
{
	struct mgmt_cmt_info_t *cmt_info = mgmt_history_create_cmt_rec();

	mgmt_ds_dump_ds_to_file(cmt_info->cmt_json_file, ds_ctx);
	mgmt_history_dump_cmt_record_index();
}

void mgmt_history_init(void)
{
	/* Create commit record for previously stored commit-apply */
	mgmt_cmt_infos_init(&mm->cmts);
	mgmt_history_read_cmt_record_index();
}

void mgmt_history_destroy(void)
{
	struct mgmt_cmt_info_t *cmt_info;

	FOREACH_CMT_REC(mm, cmt_info) {
		mgmt_cmt_infos_del(&mm->cmts, cmt_info);
		XFREE(MTYPE_MGMTD_CMT_INFO, cmt_info);
	}

	mgmt_cmt_infos_fini(&mm->cmts);
}
