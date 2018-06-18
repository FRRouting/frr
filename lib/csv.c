/* CSV
 * Copyright (C) 2013 Cumulus Networks, Inc.
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <unistd.h>
#include "csv.h"

#define DEBUG_E 1
#define DEBUG_V 1

#define log_error(fmt, ...)                                                    \
	do {                                                                   \
		if (DEBUG_E)                                                   \
			fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__,          \
				__LINE__, __func__, ##__VA_ARGS__);            \
	} while (0)

#define log_verbose(fmt, ...)                                                  \
	do {                                                                   \
		if (DEBUG_V)                                                   \
			fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__,          \
				__LINE__, __func__, __VA_ARGS__);              \
	} while (0)

struct _csv_field_t_ {
	TAILQ_ENTRY(_csv_field_t_) next_field;
	char *field;
	int field_len;
};

struct _csv_record_t_ {
	TAILQ_HEAD(, _csv_field_t_) fields;
	TAILQ_ENTRY(_csv_record_t_) next_record;
	char *record;
	int rec_len;
};

struct _csv_t_ {
	TAILQ_HEAD(, _csv_record_t_) records;
	char *buf;
	int buflen;
	int csv_len;
	int pointer;
	int num_recs;
};


int csvlen(csv_t *csv)
{
	return (csv->csv_len);
}

csv_t *csv_init(csv_t *csv, char *buf, int buflen)
{
	if (csv == NULL) {
		csv = malloc(sizeof(csv_t));
		if (csv == NULL) {
			log_error("CSV Malloc failed\n");
			return (NULL);
		}
	}
	memset(csv, 0, sizeof(csv_t));

	csv->buf = buf;
	csv->buflen = buflen;
	TAILQ_INIT(&(csv->records));
	return (csv);
}

void csv_clean(csv_t *csv)
{
	csv_record_t *rec;
	csv_record_t *rec_n;

	rec = TAILQ_FIRST(&(csv->records));
	while (rec != NULL) {
		rec_n = TAILQ_NEXT(rec, next_record);
		csv_remove_record(csv, rec);
		rec = rec_n;
	}
}

void csv_free(csv_t *csv)
{
	if (csv != NULL) {
		free(csv);
	}
}

static void csv_init_record(csv_record_t *record)
{
	TAILQ_INIT(&(record->fields));
	record->rec_len = 0;
}

csv_record_t *csv_record_iter(csv_t *csv)
{
	return (TAILQ_FIRST(&(csv->records)));
}

csv_record_t *csv_record_iter_next(csv_record_t *rec)
{
	if (!rec)
		return NULL;
	return (TAILQ_NEXT(rec, next_record));
}

char *csv_field_iter(csv_record_t *rec, csv_field_t **fld)
{
	if (!rec)
		return NULL;
	*fld = TAILQ_FIRST(&(rec->fields));
	return ((*fld)->field);
}

char *csv_field_iter_next(csv_field_t **fld)
{
	*fld = TAILQ_NEXT(*fld, next_field);
	if ((*fld) == NULL) {
		return (NULL);
	}
	return ((*fld)->field);
}

int csv_field_len(csv_field_t *fld)
{
	if (fld) {
		return fld->field_len;
	}
	return 0;
}

static void csv_decode_record(csv_record_t *rec)
{
	char *curr = rec->record;
	char *field;
	csv_field_t *fld;

	field = strpbrk(curr, ",");
	while (field != NULL) {
		fld = malloc(sizeof(csv_field_t));
		if (fld) {
			TAILQ_INSERT_TAIL(&(rec->fields), fld, next_field);
			fld->field = curr;
			fld->field_len = field - curr;
		}
		curr = field + 1;
		field = strpbrk(curr, ",");
	}
	field = strstr(curr, "\n");
	if (!field)
		return;

	fld = malloc(sizeof(csv_field_t));
	if (fld) {
		fld->field = curr;
		fld->field_len = field - curr;
		TAILQ_INSERT_TAIL(&(rec->fields), fld, next_field);
	}
}

static csv_field_t *csv_add_field_to_record(csv_t *csv, csv_record_t *rec,
					    char *col)
{
	csv_field_t *fld;
	char *str = rec->record;
	int rlen = rec->rec_len;
	int blen = csv->buflen;

	fld = malloc(sizeof(csv_field_t));
	if (!fld) {
		log_error("field malloc failed\n");
		/* more cleanup needed */
		return (NULL);
	}
	TAILQ_INSERT_TAIL(&(rec->fields), fld, next_field);
	fld->field = str + rlen;
	fld->field_len = snprintf((str + rlen), (blen - rlen), "%s", col);
	rlen += fld->field_len;
	rec->rec_len = rlen;
	return fld;
}

csv_record_t *csv_encode(csv_t *csv, int count, ...)
{
	int tempc;
	va_list list;
	char *buf = csv->buf;
	int len = csv->buflen;
	int pointer = csv->pointer;
	char *str = NULL;
	char *col;
	csv_record_t *rec;
	csv_field_t *fld;

	if (buf) {
		str = buf + pointer;
	} else {
		/* allocate sufficient buffer */
		str = (char *)malloc(csv->buflen);
		if (!str) {
			log_error("field str malloc failed\n");
			return (NULL);
		}
	}

	va_start(list, count);
	rec = malloc(sizeof(csv_record_t));
	if (!rec) {
		log_error("record malloc failed\n");
		if (!buf)
			free(str);
		va_end(list);
		return (NULL);
	}
	csv_init_record(rec);
	rec->record = str;
	TAILQ_INSERT_TAIL(&(csv->records), rec, next_record);
	csv->num_recs++;

	/**
	 * Iterate through the fields passed as a variable list and add them
	 */
	for (tempc = 0; tempc < count; tempc++) {
		col = va_arg(list, char *);
		fld = csv_add_field_to_record(csv, rec, col);
		if (!fld) {
			log_error("fld malloc failed\n");
			csv_remove_record(csv, rec);
			va_end(list);
			return (NULL);
		}
		if (tempc < (count - 1)) {
			rec->rec_len += snprintf((str + rec->rec_len),
						 (len - rec->rec_len), ",");
		}
	}
	rec->rec_len +=
		snprintf((str + rec->rec_len), (len - rec->rec_len), "\n");
	va_end(list);
	csv->csv_len += rec->rec_len;
	csv->pointer += rec->rec_len;
	return (rec);
}

int csv_num_records(csv_t *csv)
{
	if (csv) {
		return csv->num_recs;
	}
	return 0;
}

csv_record_t *csv_encode_record(csv_t *csv, csv_record_t *rec, int count, ...)
{
	int tempc;
	va_list list;
	char *str;
	char *col;
	csv_field_t *fld = NULL;
	int i;

	va_start(list, count);
	str = csv_field_iter(rec, &fld);
	if (!fld) {
		va_end(list);
		return NULL;
	}

	for (tempc = 0; tempc < count; tempc++) {
		col = va_arg(list, char *);
		for (i = 0; i < fld->field_len; i++) {
			str[i] = col[i];
		}
		str = csv_field_iter_next(&fld);
	}
	va_end(list);
	return (rec);
}

csv_record_t *csv_append_record(csv_t *csv, csv_record_t *rec, int count, ...)
{
	int tempc;
	va_list list;
	int len = csv->buflen, tlen;
	char *str;
	csv_field_t *fld;
	char *col;

	if (csv->buf) {
		/* not only works with discrete bufs */
		return NULL;
	}

	if (!rec) {
		/* create a new rec */
		rec = calloc(1, sizeof(csv_record_t));
		if (!rec) {
			log_error("record malloc failed\n");
			return NULL;
		}
		csv_init_record(rec);
		rec->record = calloc(1, csv->buflen);
		if (!rec->record) {
			log_error("field str malloc failed\n");
			free(rec);
			return NULL;
		}
		csv_insert_record(csv, rec);
	}

	str = rec->record;

	va_start(list, count);

	if (rec->rec_len && (str[rec->rec_len - 1] == '\n'))
		str[rec->rec_len - 1] = ',';

	/**
	 * Iterate through the fields passed as a variable list and add them
	 */
	tlen = rec->rec_len;
	for (tempc = 0; tempc < count; tempc++) {
		col = va_arg(list, char *);
		fld = csv_add_field_to_record(csv, rec, col);
		if (!fld) {
			log_error("fld malloc failed\n");
			break;
		}
		if (tempc < (count - 1)) {
			rec->rec_len += snprintf((str + rec->rec_len),
						 (len - rec->rec_len), ",");
		}
	}
	rec->rec_len +=
		snprintf((str + rec->rec_len), (len - rec->rec_len), "\n");
	va_end(list);
	csv->csv_len += (rec->rec_len - tlen);
	csv->pointer += (rec->rec_len - tlen);
	return (rec);
}

int csv_serialize(csv_t *csv, char *msgbuf, int msglen)
{
	csv_record_t *rec;
	int offset = 0;

	if (!csv || !msgbuf)
		return -1;

	rec = csv_record_iter(csv);
	while (rec != NULL) {
		if ((offset + rec->rec_len) >= msglen)
			return -1;
		offset += sprintf(&msgbuf[offset], "%s", rec->record);
		rec = csv_record_iter_next(rec);
	}

	return 0;
}

void csv_clone_record(csv_t *csv, csv_record_t *in_rec, csv_record_t **out_rec)
{
	char *curr;
	csv_record_t *rec;

	/* first check if rec belongs to this csv */
	if (!csv_is_record_valid(csv, in_rec)) {
		log_error("rec not in this csv\n");
		return;
	}

	/* only works with csv with discrete bufs */
	if (csv->buf) {
		log_error(
			"un-supported for this csv type - single buf detected\n");
		return;
	}

	/* create a new rec */
	rec = calloc(1, sizeof(csv_record_t));
	if (!rec) {
		log_error("record malloc failed\n");
		return;
	}
	csv_init_record(rec);
	curr = calloc(1, csv->buflen);
	if (!curr) {
		log_error("field str malloc failed\n");
		free(rec);
		return;
	}
	rec->record = curr;
	rec->rec_len = in_rec->rec_len;
	strcpy(rec->record, in_rec->record);

	/* decode record into fields */
	csv_decode_record(rec);

	*out_rec = rec;
}

void csv_remove_record(csv_t *csv, csv_record_t *rec)
{
	csv_field_t *fld = NULL, *p_fld;

	/* first check if rec belongs to this csv */
	if (!csv_is_record_valid(csv, rec)) {
		log_error("rec not in this csv\n");
		return;
	}

	/* remove fields */
	csv_field_iter(rec, &fld);
	while (fld) {
		p_fld = fld;
		csv_field_iter_next(&fld);
		TAILQ_REMOVE(&(rec->fields), p_fld, next_field);
		free(p_fld);
	}

	TAILQ_REMOVE(&(csv->records), rec, next_record);

	csv->num_recs--;
	csv->csv_len -= rec->rec_len;
	csv->pointer -= rec->rec_len;
	if (!csv->buf)
		free(rec->record);
	free(rec);
}

void csv_insert_record(csv_t *csv, csv_record_t *rec)
{
	/* first check if rec already in csv */
	if (csv_is_record_valid(csv, rec)) {
		log_error("rec already in this csv\n");
		return;
	}

	/* we can only insert records if no buf was supplied during csv init */
	if (csv->buf) {
		log_error(
			"un-supported for this csv type - single buf detected\n");
		return;
	}

	/* do we go beyond the max buf set for this csv ?*/
	if ((csv->csv_len + rec->rec_len) > csv->buflen) {
		log_error("cannot insert - exceeded buf size\n");
		return;
	}

	TAILQ_INSERT_TAIL(&(csv->records), rec, next_record);
	csv->num_recs++;
	csv->csv_len += rec->rec_len;
	csv->pointer += rec->rec_len;
}

csv_record_t *csv_concat_record(csv_t *csv, csv_record_t *rec1,
				csv_record_t *rec2)
{
	char *curr;
	char *ret;
	csv_record_t *rec;

	/* first check if rec1 and rec2 belong to this csv */
	if (!csv_is_record_valid(csv, rec1)
	    || !csv_is_record_valid(csv, rec2)) {
		log_error("rec1 and/or rec2 invalid\n");
		return (NULL);
	}

	/* we can only concat records if no buf was supplied during csv init */
	if (csv->buf) {
		log_error(
			"un-supported for this csv type - single buf detected\n");
		return (NULL);
	}

	/* create a new rec */
	rec = calloc(1, sizeof(csv_record_t));
	if (!rec) {
		log_error("record malloc failed\n");
		return (NULL);
	}
	csv_init_record(rec);

	curr = (char *)calloc(1, csv->buflen);
	if (!curr) {
		log_error("field str malloc failed\n");
		goto out_rec;
	}
	rec->record = curr;

	/* concat the record string */
	ret = strstr(rec1->record, "\n");
	if (!ret) {
		log_error("rec1 str not properly formatted\n");
		goto out_curr;
	}

	snprintf(curr, (int)(ret - rec1->record + 1), "%s", rec1->record);
	strcat(curr, ",");

	ret = strstr(rec2->record, "\n");
	if (!ret) {
		log_error("rec2 str not properly formatted\n");
		goto out_curr;
	}

	snprintf((curr + strlen(curr)), (int)(ret - rec2->record + 1), "%s",
		 rec2->record);
	strcat(curr, "\n");
	rec->rec_len = strlen(curr);

	/* paranoia */
	assert(csv->buflen
	       > (csv->csv_len - rec1->rec_len - rec2->rec_len + rec->rec_len));

	/* decode record into fields */
	csv_decode_record(rec);

	/* now remove rec1 and rec2 and insert rec into this csv */
	csv_remove_record(csv, rec1);
	csv_remove_record(csv, rec2);
	csv_insert_record(csv, rec);

	return rec;

out_curr:
	free(curr);
out_rec:
	free(rec);
	return NULL;
}

void csv_decode(csv_t *csv, char *inbuf)
{
	char *buf;
	char *pos;
	csv_record_t *rec;

	buf = (inbuf) ? inbuf : csv->buf;
	pos = strpbrk(buf, "\n");
	while (pos != NULL) {
		rec = calloc(1, sizeof(csv_record_t));
		if (!rec)
			return;
		csv_init_record(rec);
		TAILQ_INSERT_TAIL(&(csv->records), rec, next_record);
		csv->num_recs++;
		if (csv->buf)
			rec->record = buf;
		else {
			rec->record = calloc(1, csv->buflen);
			if (!rec->record) {
				log_error("field str malloc failed\n");
				return;
			}
			strncpy(rec->record, buf, pos - buf + 1);
		}
		rec->rec_len = pos - buf + 1;
		/* decode record into fields */
		csv_decode_record(rec);
		buf = pos + 1;
		pos = strpbrk(buf, "\n");
	}
}

int csv_is_record_valid(csv_t *csv, csv_record_t *in_rec)
{
	csv_record_t *rec;
	int valid = 0;

	rec = csv_record_iter(csv);
	while (rec) {
		if (rec == in_rec) {
			valid = 1;
			break;
		}
		rec = csv_record_iter_next(rec);
	}

	return valid;
}

void csv_dump(csv_t *csv)
{
	csv_record_t *rec;
	csv_field_t *fld;
	char *str;

	rec = csv_record_iter(csv);
	while (rec != NULL) {
		str = csv_field_iter(rec, &fld);
		while (str != NULL) {
			fprintf(stderr, "%s\n", str);
			str = csv_field_iter_next(&fld);
		}
		rec = csv_record_iter_next(rec);
	}
}

#ifdef TEST_CSV

static int get_memory_usage(pid_t pid)
{
	int fd, data, stack;
	char buf[4096], status_child[BUFSIZ];
	char *vm;

	sprintf(status_child, "/proc/%d/status", pid);
	if ((fd = open(status_child, O_RDONLY)) < 0)
		return -1;

	read(fd, buf, 4095);
	buf[4095] = '\0';
	close(fd);

	data = stack = 0;

	vm = strstr(buf, "VmData:");
	if (vm) {
		sscanf(vm, "%*s %d", &data);
	}
	vm = strstr(buf, "VmStk:");
	if (vm) {
		sscanf(vm, "%*s %d", &stack);
	}

	return data + stack;
}

int main()
{
	char buf[10000];
	csv_t csv;
	int i;
	csv_record_t *rec;
	char hdr1[32], hdr2[32];

	log_verbose("Mem: %d\n", get_memory_usage(getpid()));
	csv_init(&csv, buf, 256);
	sprintf(hdr1, "%4d", 0);
	sprintf(hdr2, "%4d", 1);
	log_verbose("(%zu/%zu/%d/%d)\n", strlen(hdr1), strlen(hdr2), atoi(hdr1),
		    atoi(hdr2));
	rec = csv_encode(&csv, 2, hdr1, hdr2);
	csv_encode(&csv, 4, "name", "age", "sex", "hei");
	csv_encode(&csv, 3, NULL, "0", NULL);
	csv_encode(&csv, 2, "p", "35");
	for (i = 0; i < 50; i++) {
		csv_encode(&csv, 2, "p", "10");
	}
	csv_encode(&csv, 2, "pdfadfadfadsadsaddfdfdsfdsd", "35444554545454545");
	log_verbose("%s\n", buf);
	sprintf(hdr1, "%4d", csv.csv_len);
	sprintf(hdr2, "%4d", 1);
	log_verbose("(%zu/%zu/%d/%d)\n", strlen(hdr1), strlen(hdr2), atoi(hdr1),
		    atoi(hdr2));
	rec = csv_encode_record(&csv, rec, 2, hdr1, hdr2);
	log_verbose("(%d/%d)\n%s\n", rec->rec_len, csv.csv_len, buf);

	log_verbose("Mem: %d\n", get_memory_usage(getpid()));
	csv_clean(&csv);
	log_verbose("Mem: %d\n", get_memory_usage(getpid()));
	csv_init(&csv, buf, 256);
	csv_decode(&csv, NULL);
	log_verbose("%s", "AFTER DECODE\n");
	csv_dump(&csv);
	csv_clean(&csv);
	log_verbose("Mem: %d\n", get_memory_usage(getpid()));
}
#endif
