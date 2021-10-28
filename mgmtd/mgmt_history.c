// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include "md5.h"
#include "thread.h"
#include "xref.h"

#include "mgmt_fe_client.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_history.h"

struct mgmt_cmt_info_t {
	struct mgmt_cmt_infos_item cmts;

	char cmtid_str[MGMTD_MD5_HASH_STR_HEX_LEN];
	char time_str[MGMTD_COMMIT_TIME_STR_LEN];
	char cmt_json_file[PATH_MAX];
};


DECLARE_DLIST(mgmt_cmt_infos, struct mgmt_cmt_info_t, cmts);

#define FOREACH_CMT_REC(mm, cmt_info)                                          \
	frr_each_safe (mgmt_cmt_infos, &mm->cmts, cmt_info)



static bool mgmt_history_record_exists(char *file_path)
{
	int exist;

	exist = access(file_path, F_OK);
	if (exist == 0)
		return true;
	else
		return false;
}

static void mgmt_history_remove_file(char *name)
{
	if (remove(name) == 0)
		zlog_debug("Old commit info deletion succeeded");
	else
		zlog_err("Old commit info deletion failed");
}

static void mgmt_history_hash(const char *input_str, char *hash)
{
	int i;
	unsigned char digest[MGMTD_MD5_HASH_LEN];
	MD5_CTX ctx;

	memset(&ctx, 0, sizeof(ctx));
	MD5Init(&ctx);
	MD5Update(&ctx, input_str, strlen(input_str));
	MD5Final(digest, &ctx);

	for (i = 0; i < MGMTD_MD5_HASH_LEN; i++)
		snprintf(&hash[i * 2], MGMTD_MD5_HASH_STR_HEX_LEN, "%02x",
			 (unsigned int)digest[i]);
}

static struct mgmt_cmt_info_t *mgmt_history_create_cmt_rec(void)
{
	struct mgmt_cmt_info_t *new;
	struct mgmt_cmt_info_t *cmt_info;
	struct mgmt_cmt_info_t *last_cmt_info = NULL;
	struct timeval cmt_recd_tv;

	new = XCALLOC(MTYPE_MGMTD_CMT_INFO, sizeof(struct mgmt_cmt_info_t));
	gettimeofday(&cmt_recd_tv, NULL);
	mgmt_realtime_to_string(&cmt_recd_tv, new->time_str,
				sizeof(new->time_str));
	mgmt_history_hash(new->time_str, new->cmtid_str);
	snprintf(new->cmt_json_file, sizeof(new->cmt_json_file),
		 MGMTD_COMMIT_FILE_PATH, new->cmtid_str);

	if (mgmt_cmt_infos_count(&mm->cmts) == MGMTD_MAX_COMMIT_LIST) {
		FOREACH_CMT_REC (mm, cmt_info)
			last_cmt_info = cmt_info;

		if (last_cmt_info) {
			mgmt_history_remove_file(last_cmt_info->cmt_json_file);
			mgmt_cmt_infos_del(&mm->cmts, last_cmt_info);
			XFREE(MTYPE_MGMTD_CMT_INFO, last_cmt_info);
		}
	}

	mgmt_cmt_infos_add_head(&mm->cmts, new);
	return new;
}

static struct mgmt_cmt_info_t *mgmt_history_find_cmt_record(const char *cmtid_str)
{
	struct mgmt_cmt_info_t *cmt_info;

	FOREACH_CMT_REC (mm, cmt_info) {
		if (strncmp(cmt_info->cmtid_str, cmtid_str,
			    MGMTD_MD5_HASH_STR_HEX_LEN) == 0)
			return cmt_info;
	}

	return NULL;
}

static bool mgmt_history_read_cmt_record_index(void)
{
	FILE *fp;
	struct mgmt_cmt_info_t cmt_info;
	struct mgmt_cmt_info_t *new;
	int cnt = 0;

	fp = fopen(MGMTD_COMMIT_INDEX_FILE_NAME, "rb");
	if (!fp) {
		zlog_err("Failed to open file %s rb mode",
			 MGMTD_COMMIT_INDEX_FILE_NAME);
		return false;
	}

	while ((fread(&cmt_info, sizeof(cmt_info), 1, fp)) > 0) {
		if (cnt < MGMTD_MAX_COMMIT_LIST) {
			if (!mgmt_history_record_exists(cmt_info.cmt_json_file)) {
				zlog_err(
					"Commit record present in index_file, but commit file %s missing",
					cmt_info.cmt_json_file);
				continue;
			}

			new = XCALLOC(MTYPE_MGMTD_CMT_INFO,
				      sizeof(struct mgmt_cmt_info_t));
			memcpy(new, &cmt_info, sizeof(struct mgmt_cmt_info_t));
			mgmt_cmt_infos_add_tail(&mm->cmts, new);
		} else {
			zlog_err("More records found in index file %s",
				 MGMTD_COMMIT_INDEX_FILE_NAME);
			return false;
		}

		cnt++;
	}

	fclose(fp);
	return true;
}

static bool mgmt_history_dump_cmt_record_index(void)
{
	FILE *fp;
	int ret = 0;
	struct mgmt_cmt_info_t *cmt_info;
	struct mgmt_cmt_info_t cmt_info_set[10];
	int cnt = 0;

	mgmt_history_remove_file((char *)MGMTD_COMMIT_INDEX_FILE_NAME);
	fp = fopen(MGMTD_COMMIT_INDEX_FILE_NAME, "ab");
	if (!fp) {
		zlog_err("Failed to open file %s ab mode",
			 MGMTD_COMMIT_INDEX_FILE_NAME);
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
		zlog_err("Write record failed");
		return false;
	} else {
		return true;
	}
}

static int mgmt_history_rollback_to_cmt(struct vty *vty,
				   struct mgmt_cmt_info_t *cmt_info,
				   bool skip_file_load)
{
	struct mgmt_ds_ctx *src_ds_ctx;
	struct mgmt_ds_ctx *dst_ds_ctx;
	int ret = 0;

	src_ds_ctx = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_CANDIDATE);
	if (!src_ds_ctx) {
		vty_out(vty, "ERROR: Couldnot access Candidate datastore!\n");
		return -1;
	}

	/*
	 * Note: Write lock on src_ds is not required. This is already
	 * taken in 'conf te'.
	 */
	dst_ds_ctx = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_RUNNING);
	if (!dst_ds_ctx) {
		vty_out(vty, "ERROR: Couldnot access Running datastore!\n");
		return -1;
	}

	ret = mgmt_ds_write_lock(dst_ds_ctx);
	if (ret != 0) {
		vty_out(vty,
			"Failed to lock the DS %u for rollback Reason: %s!\n",
			MGMTD_DS_RUNNING, strerror(ret));
		return -1;
	}

	if (!skip_file_load) {
		ret = mgmt_ds_load_config_from_file(
			src_ds_ctx, cmt_info->cmt_json_file, false);
		if (ret != 0) {
			mgmt_ds_unlock(dst_ds_ctx);
			vty_out(vty,
				"Error with parsing the file with error code %d\n",
				ret);
			return ret;
		}
	}

	/* Internally trigger a commit-request. */
	ret = mgmt_txn_rollback_trigger_cfg_apply(src_ds_ctx, dst_ds_ctx);
	if (ret != 0) {
		mgmt_ds_unlock(dst_ds_ctx);
		vty_out(vty,
			"Error with creating commit apply txn with error code %d\n",
			ret);
		return ret;
	}

	mgmt_history_dump_cmt_record_index();
	return 0;
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
		if (strncmp(cmt_info->cmtid_str, cmtid_str,
			    MGMTD_MD5_HASH_STR_HEX_LEN) == 0) {
			ret = mgmt_history_rollback_to_cmt(vty, cmt_info, false);
			return ret;
		}

		mgmt_history_remove_file(cmt_info->cmt_json_file);
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
			ret = mgmt_history_rollback_to_cmt(vty, cmt_info, false);
			return ret;
		}

		cnt++;
		mgmt_history_remove_file(cmt_info->cmt_json_file);
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
	vty_out(vty, "  Sl.No\tCommit-ID(HEX)\t\t\t  Commit-Record-Time\n");
	FOREACH_CMT_REC (mm, cmt_info) {
		vty_out(vty, "  %d\t%s  %s\n", slno, cmt_info->cmtid_str,
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
