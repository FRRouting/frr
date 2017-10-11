#include "test_fuzz_isis_tlv_tests.h"

#include <zebra.h>

#include "memory.h"
#include "sbuf.h"
#include "stream.h"
#include "thread.h"

#include "isisd/isis_circuit.h"
#include "isisd/isis_tlvs.h"

#define TEST_STREAM_SIZE 1500

struct thread_master *master;
int isis_sock_init(struct isis_circuit *circuit);
int isis_sock_init(struct isis_circuit *circuit)
{
	return 0;
}

struct zebra_privs_t isisd_privs;

static bool atexit_registered;

static void show_meminfo_at_exit(void)
{
	log_memstats(stderr, "isis fuzztest");
}

static int comp_line(const void *p1, const void *p2)
{
	return strcmp(*(char * const *)p1, *(char * const *)p2);
}

static char *sortlines(char *in)
{
	size_t line_count = 1;
	size_t rv_len = strlen(in) + 1;
	size_t rv_pos = 0;
	char *rv = XMALLOC(MTYPE_TMP, rv_len);

	for (char *c = in; *c; c++) {
		if (*c == '\n')
			line_count++;
	}

	if (line_count == 1) {
		strncpy(rv, in, rv_len);
		return rv;
	}

	char **lines = XCALLOC(MTYPE_TMP, sizeof(char *)*line_count);
	char *saveptr = NULL;
	size_t i = 0;

	for (char *line = strtok_r(in, "\n", &saveptr); line;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		lines[i++] = line;
		assert(i <= line_count);
	}

	line_count = i;

	qsort(lines, line_count, sizeof(char *), comp_line);

	for (i = 0; i < line_count; i++) {
		int printf_rv = snprintf(rv + rv_pos, rv_len - rv_pos, "%s\n", lines[i]);
		assert(printf_rv >= 0);
		rv_pos += printf_rv;
	}

	XFREE(MTYPE_TMP, lines);
	return rv;
}

static int test(FILE *input, FILE *output)
{
	struct stream *s = stream_new(TEST_STREAM_SIZE);
	char buf[TEST_STREAM_SIZE];
	size_t bytes_read = 0;

	if (!atexit_registered) {
		atexit(show_meminfo_at_exit);
		atexit_registered = true;
	}

	while (STREAM_WRITEABLE(s) && !feof(input)) {
		bytes_read = fread(buf, 1, STREAM_WRITEABLE(s), input);
		if (bytes_read == 0)
			break;
		stream_put(s, buf, bytes_read);
	}

	if (bytes_read && !feof(input)) {
		fprintf(output, "Too much input data.\n");
		stream_free(s);
		return 1;
	}

	stream_set_getp(s, 0);
	struct isis_tlvs *tlvs;
	const char *log;
	int rv = isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log);

	if (rv) {
		fprintf(output, "Could not unpack TLVs:\n%s\n", log);
		isis_free_tlvs(tlvs);
		stream_free(s);
		return 2;
	}

	fprintf(output, "Unpack log:\n%s", log);
	const char *s_tlvs = isis_format_tlvs(tlvs);
	fprintf(output, "Unpacked TLVs:\n%s", s_tlvs);

	struct isis_tlvs *tlv_copy = isis_copy_tlvs(tlvs);
	isis_free_tlvs(tlvs);

	struct stream *s2 = stream_new(TEST_STREAM_SIZE);

	if (isis_pack_tlvs(tlv_copy, s2, (size_t)-1, false, false)) {
		fprintf(output, "Could not pack TLVs.\n");
		assert(0);
	}

	stream_set_getp(s2, 0);
	rv = isis_unpack_tlvs(STREAM_READABLE(s2), s2, &tlvs, &log);
	if (rv) {
		fprintf(output, "Could not unpack own TLVs:\n%s\n", log);
		assert(0);
	}

	char *orig_tlvs = XSTRDUP(MTYPE_TMP, s_tlvs);
	s_tlvs = isis_format_tlvs(tlvs);

	if (strcmp(orig_tlvs, s_tlvs)) {
		fprintf(output,
			"Deserialized and Serialized LSP seem to differ.\n");
		fprintf(output, "Re-Unpacked TLVs:\n%s", s_tlvs);
		assert(0);
	}

	isis_free_tlvs(tlv_copy);
	stream_free(s);
	stream_free(s2);

	struct list *fragments = isis_fragment_tlvs(tlvs, 550);
	isis_free_tlvs(tlvs);
	if (!fragments) {
		XFREE(MTYPE_TMP, orig_tlvs);
		return 0;
	}

	s = stream_new(550);

	struct sbuf fragment_format;
	sbuf_init(&fragment_format, NULL, 0);

	struct listnode *node;
	for (ALL_LIST_ELEMENTS_RO(fragments, node, tlvs)) {
		stream_reset(s);
		int rv = isis_pack_tlvs(tlvs, s, (size_t)-1, false, false);
		if (rv) {
			fprintf(output, "Could not pack fragment, too large.\n");
			assert(0);
		}
		sbuf_push(&fragment_format, 0, "%s", isis_format_tlvs(tlvs));
		isis_free_tlvs(tlvs);
	}
	list_delete_and_null(&fragments);
	stream_free(s);

	char *fragment_content = sortlines((char *)sbuf_buf(&fragment_format));
	sbuf_free(&fragment_format);
	char *orig_tlv_content = sortlines(orig_tlvs);
	XFREE(MTYPE_TMP, orig_tlvs);

	if (strcmp(fragment_content, orig_tlv_content)) {
		fprintf(output, "Fragmented and unfragmented LSP seem to differ.\n");
		fprintf(output, "Original:\n%s\nFragmented:\n%s\n",
			orig_tlv_content, fragment_content);
		assert(0);
	}

	XFREE(MTYPE_TMP, fragment_content);
	XFREE(MTYPE_TMP, orig_tlv_content);

	return 0;
}
