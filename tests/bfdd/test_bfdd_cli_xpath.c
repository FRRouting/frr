// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bfdd "peer" CLI commands with over-long names.
 *
 * The bfdd peer commands build the session xpath in a XPATH_MAXLEN stack
 * buffer from the interface, VRF and session names. Names longer than
 * bfdd keeps (IFNAMSIZ - 1, VRF_NAMSIZ, BFD_NAME_SIZE) must be refused;
 * a longer name must neither write past the buffer nor be enqueued.
 *
 * Each row runs one command in BFD_NODE through the real command parser
 * and bfdd_cli.c, which is built into this test with
 * nb_cli_enqueue_change() and nb_cli_apply_changes() renamed and
 * replaced to record the changes. Expected:
 *  - the exact command return value and output (the error message, or
 *    nothing);
 *  - accepted: the command's number of changes, the first being the
 *    session xpath with its operation, every path shorter than
 *    XPATH_MAXLEN, and one apply. A create is followed by
 *    "authentication algorithm meticulous" in the new peer node, whose
 *    path must be the session xpath plus its leaf;
 *  - refused: no changes and no apply.
 *
 * Each case runs in a child process so that a sanitizer abort or a crash
 * fails only that case.
 */

#include <zebra.h>

#include <sys/wait.h>

#include "buffer.h"
#include "command.h"
#include "frrevent.h"
#include "northbound_cli.h"
#include "vty.h"
#include "yang.h"

#include "bfdd/bfd.h"

/* subdir.am renames the two northbound calls for this file and bfdd_cli.c */
#ifndef nb_cli_enqueue_change
#error "nb_cli_enqueue_change must be renamed"
#endif

enum kind { POSITIVE, NEGATIVE, BOUNDARY, CORNER };
static const char *const kind2str[] = { "positive", "negative", "boundary", "corner" };

/* Child exit codes, distinct from the sanitizers' error exit code (1). */
#define EXIT_MATCH    10
#define EXIT_MISMATCH 11

#define FAIL CMD_WARNING_CONFIG_FAILED

/* Which name a command is expected to refuse. */
enum refused { NONE, IF_NAME, VRF_NAME, BFD_NAME };

/* A command: the name goes in the first "%s", the VRF name in the second. */
struct form {
	const char *cmd;
	/* session xpath */
	const char *xpath;
	/* the session's operation, and the number of changes when accepted */
	enum nb_operation op;
	int nchanges;
};

#define SH     "/frr-bfdd:bfdd/bfd/sessions/single-hop[dest-addr='10.0.0.1']"
#define ECHO_X "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo[source-addr='2001:db8::1'][bfd-name='%s']"
#define INIT_X                                                                                    \
	"/frr-bfdd:bfdd/bfd/sessions/sbfd-init[source-addr='10.0.0.1'][dest-addr='10.0.0.2'][bfd-name='%s']"
#define INIT6_X                                                                                   \
	"/frr-bfdd:bfdd/bfd/sessions/sbfd-init[source-addr='2001:db8::1'][dest-addr='2001:db8::2'][bfd-name='%s']"
#define LA6_VRF	   "local-address 2001:db8::1 vrf %s "
#define ECHO_ARGS  "srv6-source-ipv6 2001:db8::2 srv6-encap-data 2001:db8::3"
#define INIT6_ARGS "remote-discr 1 srv6-source-ipv6 2001:db8::3 srv6-encap-data 2001:db8::4"

/* longest IPv6 addresses */
#define A1 "2001:0db8:ffff:ffff:ffff:ffff:ffff:1111"
#define A2 "2001:0db8:ffff:ffff:ffff:ffff:ffff:2222"

static const struct form peer = {
	"peer 10.0.0.1 interface %s vrf %s",
	SH "[interface='%s'][vrf='%s']",
	NB_OP_CREATE,
	1,
};
static const struct form no_peer = {
	"no peer 10.0.0.1 interface %s vrf %s",
	SH "[interface='%s'][vrf='%s']",
	NB_OP_DESTROY,
	1,
};
static const struct form echo = {
	"peer 2001:db8::1 bfd-mode sbfd-echo bfd-name %s " LA6_VRF ECHO_ARGS,
	ECHO_X "[vrf='%s']",
	NB_OP_CREATE,
	4,
};
static const struct form no_echo = {
	"no peer 2001:db8::1 bfd-mode sbfd-echo bfd-name %s " LA6_VRF ECHO_ARGS,
	ECHO_X "[vrf='%s']",
	NB_OP_DESTROY,
	1,
};
static const struct form init6 = {
	"peer 2001:db8::2 bfd-mode sbfd-init bfd-name %s " LA6_VRF INIT6_ARGS,
	INIT6_X "[vrf='%s']",
	NB_OP_CREATE,
	4,
};
static const struct form no_init6 = {
	"no peer 2001:db8::2 bfd-mode sbfd-init bfd-name %s " LA6_VRF INIT6_ARGS,
	INIT6_X "[vrf='%s']",
	NB_OP_DESTROY,
	1,
};
static const struct form init = {
	"peer 10.0.0.2 bfd-mode sbfd-init bfd-name %s local-address 10.0.0.1 vrf %s remote-discr 1",
	INIT_X "[vrf='%s']",
	NB_OP_CREATE,
	2,
};
static const struct form no_init = {
	"no peer 10.0.0.2 bfd-mode sbfd-init bfd-name %s local-address 10.0.0.1 vrf %s remote-discr 1",
	INIT_X "[vrf='%s']",
	NB_OP_DESTROY,
	1,
};
static const struct form init6_long = {
	"peer " A2 " bfd-mode sbfd-init bfd-name %s local-address " A1
	" vrf %s remote-discr 1 srv6-source-ipv6 " A1 " srv6-encap-data " A2,
	"/frr-bfdd:bfdd/bfd/sessions/sbfd-init[source-addr='" A1 "'][dest-addr='" A2
	"'][bfd-name='%s'][vrf='%s']",
	NB_OP_CREATE,
	4,
};

struct tcase {
	const char *description;
	enum kind kind;
	const struct form *form;
	/* lengths of the interface or session name, and of the VRF name */
	int name_len;
	int vrf_len;
	/* expected: the return value, and the name the error message is about */
	int ret;
	enum refused refused;
};

#define IFMAX  (IFNAMSIZ - 1)
#define VRFMAX VRF_NAMSIZ
#define BFDMAX BFD_NAME_SIZE

static const struct tcase tcases[] = {
	{ "peer", POSITIVE, &peer, 4, 4, CMD_SUCCESS, NONE },
	{ "no peer", POSITIVE, &no_peer, 4, 4, CMD_SUCCESS, NONE },
	{ "sbfd-echo peer", POSITIVE, &echo, 4, 4, CMD_SUCCESS, NONE },
	{ "no sbfd-echo peer", POSITIVE, &no_echo, 4, 4, CMD_SUCCESS, NONE },
	{ "sbfd-init peer with srv6", POSITIVE, &init6, 4, 4, CMD_SUCCESS, NONE },
	{ "no sbfd-init peer with srv6", POSITIVE, &no_init6, 4, 4, CMD_SUCCESS, NONE },
	{ "sbfd-init peer", POSITIVE, &init, 4, 4, CMD_SUCCESS, NONE },
	{ "no sbfd-init peer", POSITIVE, &no_init, 4, 4, CMD_SUCCESS, NONE },

	{ "peer, interface name of 1100 bytes", NEGATIVE, &peer, 1100, 4, FAIL, IF_NAME },
	{ "peer, vrf name of 1100 bytes", NEGATIVE, &peer, 4, 1100, FAIL, VRF_NAME },
	{ "no peer, interface name of 1100 bytes", NEGATIVE, &no_peer, 1100, 4, FAIL, IF_NAME },
	{ "sbfd-echo, bfd name of 1100 bytes", NEGATIVE, &echo, 1100, 4, FAIL, BFD_NAME },
	{ "no sbfd-echo, bfd name of 1100 bytes", NEGATIVE, &no_echo, 1100, 4, FAIL, BFD_NAME },
	{ "sbfd-init srv6, bfd name of 1100 bytes", NEGATIVE, &init6, 1100, 4, FAIL, BFD_NAME },
	{ "no sbfd-init srv6, bfd name of 1100 bytes", NEGATIVE, &no_init6, 1100, 4, FAIL,
	  BFD_NAME },
	{ "sbfd-init, bfd name of 1100 bytes", NEGATIVE, &init, 1100, 4, FAIL, BFD_NAME },
	{ "no sbfd-init, bfd name of 1100 bytes", NEGATIVE, &no_init, 1100, 4, FAIL, BFD_NAME },

	{ "peer, interface name of IFNAMSIZ - 1", BOUNDARY, &peer, IFMAX, 4, CMD_SUCCESS, NONE },
	{ "peer, interface name of IFNAMSIZ", BOUNDARY, &peer, IFMAX + 1, 4, FAIL, IF_NAME },
	{ "peer, vrf name of VRF_NAMSIZ", BOUNDARY, &peer, 4, VRFMAX, CMD_SUCCESS, NONE },
	{ "peer, vrf name of VRF_NAMSIZ + 1", BOUNDARY, &peer, 4, VRFMAX + 1, FAIL, VRF_NAME },
	{ "no peer, interface name of IFNAMSIZ - 1", BOUNDARY, &no_peer, IFMAX, 4, CMD_SUCCESS,
	  NONE },
	{ "no peer, interface name of IFNAMSIZ", BOUNDARY, &no_peer, IFMAX + 1, 4, FAIL, IF_NAME },
	{ "no peer, vrf name of VRF_NAMSIZ", BOUNDARY, &no_peer, 4, VRFMAX, CMD_SUCCESS, NONE },
	{ "no peer, vrf name of VRF_NAMSIZ + 1", BOUNDARY, &no_peer, 4, VRFMAX + 1, FAIL,
	  VRF_NAME },
	{ "sbfd-echo, bfd name of BFD_NAME_SIZE", BOUNDARY, &echo, BFDMAX, 4, CMD_SUCCESS, NONE },
	{ "sbfd-echo, bfd name of BFD_NAME_SIZE + 1", BOUNDARY, &echo, BFDMAX + 1, 4, FAIL,
	  BFD_NAME },
	{ "no sbfd-echo, bfd name of BFD_NAME_SIZE", BOUNDARY, &no_echo, BFDMAX, 4, CMD_SUCCESS,
	  NONE },
	{ "no sbfd-echo, bfd name of BFD_NAME_SIZE + 1", BOUNDARY, &no_echo, BFDMAX + 1, 4, FAIL,
	  BFD_NAME },
	{ "sbfd-init srv6, bfd name of BFD_NAME_SIZE", BOUNDARY, &init6, BFDMAX, 4, CMD_SUCCESS,
	  NONE },
	{ "sbfd-init srv6, bfd name of BFD_NAME_SIZE + 1", BOUNDARY, &init6, BFDMAX + 1, 4, FAIL,
	  BFD_NAME },
	{ "no sbfd-init srv6, bfd name of BFD_NAME_SIZE", BOUNDARY, &no_init6, BFDMAX, 4,
	  CMD_SUCCESS, NONE },
	{ "no sbfd-init srv6, bfd name of BFD_NAME_SIZE + 1", BOUNDARY, &no_init6, BFDMAX + 1, 4,
	  FAIL, BFD_NAME },
	{ "sbfd-init, bfd name of BFD_NAME_SIZE", BOUNDARY, &init, BFDMAX, 4, CMD_SUCCESS, NONE },
	{ "sbfd-init, bfd name of BFD_NAME_SIZE + 1", BOUNDARY, &init, BFDMAX + 1, 4, FAIL,
	  BFD_NAME },
	{ "sbfd-init, vrf name of VRF_NAMSIZ", BOUNDARY, &init, 4, VRFMAX, CMD_SUCCESS, NONE },
	{ "sbfd-init, vrf name of VRF_NAMSIZ + 1", BOUNDARY, &init, 4, VRFMAX + 1, FAIL, VRF_NAME },
	{ "no sbfd-init, bfd name of BFD_NAME_SIZE", BOUNDARY, &no_init, BFDMAX, 4, CMD_SUCCESS,
	  NONE },
	{ "no sbfd-init, bfd name of BFD_NAME_SIZE + 1", BOUNDARY, &no_init, BFDMAX + 1, 4, FAIL,
	  BFD_NAME },

	{ "peer, longest interface and vrf names", CORNER, &peer, IFMAX, VRFMAX, CMD_SUCCESS,
	  NONE },
	{ "sbfd-init srv6, longest addresses, bfd and vrf names", CORNER, &init6_long, BFDMAX,
	  VRFMAX, CMD_SUCCESS, NONE },
};

/* bfdd.c globals, needed to link bfdd/libbfd.a */
DEFINE_MGROUP(BFDD, "Bidirectional Forwarding Detection Daemon");
DEFINE_MTYPE(BFDD, BFDD_CLIENT, "BFD client data");
DEFINE_MTYPE(BFDD, BFDD_CLIENT_NOTIFICATION, "BFD client notification data");
struct event_loop *master;
struct bfd_global bglobal;
const struct bfd_diag_str_list diag_list[] = { { .str = NULL } };
const struct bfd_state_str_list state_list[] = { { .str = NULL } };

void socket_close(int *s)
{
}

/* Record what the command would change, instead of the northbound. */
#define FOLLOW_UP      "authentication algorithm meticulous"
#define FOLLOW_UP_LEAF "/authentication-algorithm-meticulous"

struct recorded {
	char *xpath; /* relative paths joined to the vty's, as the northbound does */
	enum nb_operation op;
};

static struct recorded rec[VTY_MAXCFGCHANGES];
static int nchanges;
static int napplies;

void nb_cli_enqueue_change(struct vty *vty, const char *xpath, enum nb_operation operation,
			   const char *value)
{
	struct recorded *r;

	if (nchanges == VTY_MAXCFGCHANGES) {
		nchanges++;
		return;
	}
	r = &rec[nchanges++];
	if (xpath[0] == '.' && vty->xpath_index > 0)
		r->xpath = asprintfrr(MTYPE_TMP, "%s%s", VTY_CURR_XPATH, xpath + 1);
	else
		r->xpath = XSTRDUP(MTYPE_TMP, xpath);
	r->op = operation;
}

int nb_cli_apply_changes(struct vty *vty, const char *xpath_base_fmt, ...)
{
	napplies++;
	return CMD_SUCCESS;
}

static struct cmd_node bfd_node = {
	.name = "bfd",
	.node = BFD_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-bfd)# ",
};

static struct cmd_node bfd_peer_node = {
	.name = "bfd peer",
	.node = BFD_PEER_NODE,
	.parent_node = BFD_NODE,
	.prompt = "%s(config-bfd-peer)# ",
};

/* fmt with its two "%s" replaced by name and vrf */
static char *subst(const char *fmt, const char *name, const char *vrf)
{
	const char *p1 = strstr(fmt, "%s");
	const char *p2;

	assert(p1);
	p2 = strstr(p1 + 2, "%s");
	assert(p2);
	return asprintfrr(MTYPE_TMP, "%.*s%s%.*s%s%s", (int)(p1 - fmt), fmt, name,
			  (int)(p2 - p1 - 2), p1 + 2, vrf, p2 + 2);
}

static char *repeat(char c, int len)
{
	char *s = XMALLOC(MTYPE_TMP, len + 1);

	memset(s, c, len);
	s[len] = '\0';
	return s;
}

static bool check_path(const char *what, const char *got, const char *want)
{
	if (strlen(got) >= XPATH_MAXLEN) {
		printf("    %s: %zu byte xpath does not fit in XPATH_MAXLEN\n", what, strlen(got));
		return false;
	}
	if (want && !strmatch(got, want)) {
		printf("    %s: %zu byte xpath, expected %zu bytes\n", what, strlen(got),
		       strlen(want));
		return false;
	}
	return true;
}

/* the message bfdd_cli.c is expected to print: nothing when accepted */
static char *expected_output(enum refused refused)
{
	switch (refused) {
	case IF_NAME:
		return asprintfrr(MTYPE_TMP, "%% ERROR: interface name longer than %d bytes\r\n",
				  IFMAX);
	case VRF_NAME:
		return asprintfrr(MTYPE_TMP, "%% ERROR: VRF name longer than %d bytes\r\n", VRFMAX);
	case BFD_NAME:
		return asprintfrr(MTYPE_TMP, "%% ERROR: bfd name longer than %d bytes\r\n", BFDMAX);
	case NONE:
		break;
	}
	return XSTRDUP(MTYPE_TMP, "");
}

static int run_case(const struct tcase *tc)
{
	const struct form *f = tc->form;
	bool accepted = tc->ret == CMD_SUCCESS;
	char *name = repeat('a', tc->name_len);
	char *vrf = repeat('v', tc->vrf_len);
	char *cmd = subst(f->cmd, name, vrf);
	char *xpath = subst(f->xpath, name, vrf);
	char *want_out = expected_output(tc->refused);
	char *out;
	struct vty *vty;
	int ret;
	int rc = EXIT_MATCH;

	vty = vty_new();
	vty->type = VTY_TERM;
	vty->node = BFD_NODE;
	ret = cmd_execute(vty, cmd, NULL, 0);

	printf("    return %d, %d changes, %d applies\n", ret, nchanges, napplies);
	if (ret != tc->ret || nchanges != (accepted ? f->nchanges : 0) || napplies != accepted) {
		printf("    expected return %d, %d changes, %d applies\n", tc->ret,
		       accepted ? f->nchanges : 0, accepted);
		rc = EXIT_MISMATCH;
	}
	out = buffer_getstr(vty->obuf);
	if (!strmatch(out, want_out)) {
		printf("    output \"%.80s\", expected \"%s\"\n", out, want_out);
		rc = EXIT_MISMATCH;
	}
	XFREE(MTYPE_TMP, out);
	for (int i = 0; i < MIN(nchanges, VTY_MAXCFGCHANGES); i++) {
		char what[32];

		snprintfrr(what, sizeof(what), "change %d", i);
		if (!check_path(what, rec[i].xpath, i == 0 ? xpath : NULL))
			rc = EXIT_MISMATCH;
	}
	if (nchanges > 0 && rec[0].op != f->op) {
		printf("    change 0: operation %d, expected %d\n", rec[0].op, f->op);
		rc = EXIT_MISMATCH;
	}

	/* a leaf in the new peer node: its path is the session xpath + leaf */
	if (rc == EXIT_MATCH && accepted && f->op == NB_OP_CREATE) {
		char *want = asprintfrr(MTYPE_TMP, "%s%s", xpath, FOLLOW_UP_LEAF);

		nchanges = 0;
		ret = cmd_execute(vty, FOLLOW_UP, NULL, 0);
		if (ret != CMD_SUCCESS || nchanges != 1) {
			printf("    \"%s\": return %d, %d changes\n", FOLLOW_UP, ret, nchanges);
			rc = EXIT_MISMATCH;
		} else if (!check_path(FOLLOW_UP, rec[0].xpath, want))
			rc = EXIT_MISMATCH;
		XFREE(MTYPE_TMP, want);
	}

	XFREE(MTYPE_TMP, want_out);
	XFREE(MTYPE_TMP, xpath);
	XFREE(MTYPE_TMP, cmd);
	XFREE(MTYPE_TMP, vrf);
	XFREE(MTYPE_TMP, name);
	return rc;
}

static int run_table(const struct tcase *table, size_t n)
{
	int failures = 0;

	for (size_t i = 0; i < n; i++) {
		const struct tcase *tc = &table[i];
		char why[96] = "";
		int status = 0;
		pid_t pid, waited;

		fflush(stdout);
		pid = fork();
		if (pid == 0) {
			int rc = run_case(tc);

			fflush(stdout);
			_exit(rc);
		}

		if (pid < 0) {
			snprintfrr(why, sizeof(why), " (fork: %s)", safe_strerror(errno));
		} else {
			do {
				waited = waitpid(pid, &status, 0);
			} while (waited < 0 && errno == EINTR);

			if (waited != pid)
				snprintfrr(why, sizeof(why), " (waitpid: %s)",
					   safe_strerror(errno));
			else if (WIFSIGNALED(status))
				snprintfrr(why, sizeof(why), " (crashed: signal %d)",
					   WTERMSIG(status));
			else if (WEXITSTATUS(status) == EXIT_MISMATCH)
				snprintfrr(why, sizeof(why), " (expected %s)",
					   tc->ret == CMD_SUCCESS ? "accepted" : "refused");
			else if (WEXITSTATUS(status) != EXIT_MATCH)
				snprintfrr(why, sizeof(why), " (abnormal exit %d)",
					   WEXITSTATUS(status));
		}

		printf("[%-8s] %s ... %s%s\n", kind2str[tc->kind], tc->description,
		       why[0] ? "failed" : "OK", why);
		if (why[0])
			failures++;
	}
	return failures;
}

int main(int argc, char **argv)
{
	int failures;

	master = event_master_create(NULL);
	cmd_init(1);
	cmd_hostname_set("test");
	vty_init(master, false);
	zlog_aux_init("NONE: ", ZLOG_DISABLED);
	install_node(&bfd_node);
	install_node(&bfd_peer_node);
	bfdd_cli_init();

	printf("bfdd CLI xpath tests\n\n");
	failures = run_table(tcases, array_size(tcases));
	printf("\n%d of %zu cases failed\n", failures, array_size(tcases));
	return failures ? 1 : 0;
}
