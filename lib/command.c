// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CLI backend interface.
 *
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 * Copyright (C) 2013 by Open Source Routing.
 * Copyright (C) 2013 by Internet Systems Consortium, Inc. ("ISC")
 */

#include <zebra.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <lib/version.h>

#include "command.h"
#include "debug.h"
#include "frrstr.h"
#include "memory.h"
#include "log.h"
#include "log_vty.h"
#include "frrevent.h"
#include "vector.h"
#include "linklist.h"
#include "vty.h"
#include "workqueue.h"
#include "vrf.h"
#include "command_match.h"
#include "command_graph.h"
#include "qobj.h"
#include "defaults.h"
#include "libfrr.h"
#include "jhash.h"
#include "hook.h"
#include "lib_errors.h"
#include "mgmt_be_client.h"
#include "mgmt_fe_client.h"
#include "northbound_cli.h"
#include "network.h"
#include "routemap.h"

#include "frrscript.h"

#include "lib/config_paths.h"

DEFINE_MTYPE_STATIC(LIB, HOST, "Host config");
DEFINE_MTYPE(LIB, COMPLETION, "Completion item");

#define item(x)                                                                \
	{                                                                      \
		x, #x                                                          \
	}

/* clang-format off */
const struct message tokennames[] = {
	item(WORD_TKN),
	item(VARIABLE_TKN),
	item(RANGE_TKN),
	item(IPV4_TKN),
	item(IPV4_PREFIX_TKN),
	item(IPV6_TKN),
	item(IPV6_PREFIX_TKN),
	item(MAC_TKN),
	item(MAC_PREFIX_TKN),
	item(ASNUM_TKN),
	item(FORK_TKN),
	item(JOIN_TKN),
	item(START_TKN),
	item(END_TKN),
	item(NEG_ONLY_TKN),
	{0},
};
/* clang-format on */

/* Command vector which includes some level of command lists. Normally
   each daemon maintains each own cmdvec. */
vector cmdvec = NULL;

/* Host information structure. */
struct host host;

/* for vtysh, put together CLI trees only when switching into node */
static bool defer_cli_tree;

/*
 * Returns host.name if any, otherwise
 * it returns the system hostname.
 */
const char *cmd_hostname_get(void)
{
	return host.name;
}

/*
 * Returns unix domainname
 */
const char *cmd_domainname_get(void)
{
	return host.domainname;
}

const char *cmd_system_get(void)
{
	return host.system;
}

const char *cmd_release_get(void)
{
	return host.release;
}

const char *cmd_version_get(void)
{
	return host.version;
}

bool cmd_allow_reserved_ranges_get(void)
{
	return host.allow_reserved_ranges;
}

const char *cmd_software_version_get(void)
{
	return FRR_FULL_NAME "/" FRR_VERSION;
}

static int root_on_exit(struct vty *vty);

/* Standard command node structures. */
static struct cmd_node auth_node = {
	.name = "auth",
	.node = AUTH_NODE,
	.prompt = "Password: ",
};

static struct cmd_node view_node = {
	.name = "view",
	.node = VIEW_NODE,
	.prompt = "%s> ",
	.node_exit = root_on_exit,
};

static struct cmd_node auth_enable_node = {
	.name = "auth enable",
	.node = AUTH_ENABLE_NODE,
	.prompt = "Password: ",
};

static struct cmd_node enable_node = {
	.name = "enable",
	.node = ENABLE_NODE,
	.prompt = "%s# ",
	.node_exit = root_on_exit,
};

static int config_write_host(struct vty *vty);
static struct cmd_node config_node = {
	.name = "config",
	.node = CONFIG_NODE,
	.parent_node = ENABLE_NODE,
	.prompt = "%s(config)# ",
	.config_write = config_write_host,
	.node_exit = vty_config_node_exit,
};

/* This is called from main when a daemon is invoked with -v or --version. */
void print_version(const char *progname)
{
	printf("%s version %s\n", progname, FRR_VERSION);
	printf("%s\n", FRR_COPYRIGHT);
#ifdef ENABLE_VERSION_BUILD_CONFIG
	printf("configured with:\n\t%s\n", FRR_CONFIG_ARGS);
#endif
}

char *argv_concat(struct cmd_token **argv, int argc, int shift)
{
	int cnt = MAX(argc - shift, 0);
	const char *argstr[cnt + 1];

	if (!cnt)
		return NULL;

	for (int i = 0; i < cnt; i++)
		argstr[i] = argv[i + shift]->arg;

	return frrstr_join(argstr, cnt, " ");
}

vector cmd_make_strvec(const char *string)
{
	if (!string)
		return NULL;

	const char *copy = string;

	/* skip leading whitespace */
	while (isspace((unsigned char)*copy) && *copy != '\0')
		copy++;

	/* if the entire string was whitespace or a comment, return */
	if (*copy == '\0' || *copy == '!' || *copy == '#')
		return NULL;

	vector result = frrstr_split_vec(copy, "\n\r\t ");

	for (unsigned int i = 0; i < vector_active(result); i++) {
		if (strlen(vector_slot(result, i)) == 0) {
			XFREE(MTYPE_TMP, vector_slot(result, i));
			vector_unset(result, i);
		}
	}

	vector_compact(result);

	return result;
}

void cmd_free_strvec(vector v)
{
	frrstr_strvec_free(v);
}

/**
 * Convenience function for accessing argv data.
 *
 * @param argc
 * @param argv
 * @param text definition snippet of the desired token
 * @param index the starting index, and where to store the
 *        index of the found token if it exists
 * @return 1 if found, 0 otherwise
 */
int argv_find(struct cmd_token **argv, int argc, const char *text, int *index)
{
	int found = 0;
	for (int i = *index; i < argc && found == 0; i++)
		if ((found = strmatch(text, argv[i]->text)))
			*index = i;
	return found;
}

static unsigned int cmd_hash_key(const void *p)
{
	int size = sizeof(p);

	return jhash(p, size, 0);
}

static bool cmd_hash_cmp(const void *a, const void *b)
{
	return a == b;
}

/* Install top node of command vector. */
void install_node(struct cmd_node *node)
{
#define CMD_HASH_STR_SIZE 256
	char hash_name[CMD_HASH_STR_SIZE];

	vector_set_index(cmdvec, node->node, node);
	node->cmdgraph = graph_new();
	node->cmd_vector = vector_init(VECTOR_MIN_SIZE);
	// add start node
	struct cmd_token *token = cmd_token_new(START_TKN, 0, NULL, NULL);
	graph_new_node(node->cmdgraph, token,
		       (void (*)(void *)) & cmd_token_del);

	snprintf(hash_name, sizeof(hash_name), "Command Hash: %s", node->name);
	node->cmd_hash =
		hash_create_size(16, cmd_hash_key, cmd_hash_cmp, hash_name);
}

/* Return prompt character of specified node. */
const char *cmd_prompt(enum node_type node)
{
	struct cmd_node *cnode;

	cnode = vector_slot(cmdvec, node);
	return cnode->prompt;
}

void cmd_defer_tree(bool val)
{
	defer_cli_tree = val;
}

/* Install a command into a node. */
void _install_element(enum node_type ntype, const struct cmd_element *cmd)
{
	struct cmd_node *cnode;

	/* cmd_init hasn't been called */
	if (!cmdvec) {
		fprintf(stderr, "%s called before cmd_init, breakage likely\n",
			__func__);
		return;
	}

	cnode = vector_lookup(cmdvec, ntype);

	if (cnode == NULL) {
		fprintf(stderr,
			"%s[%s]:\n"
			"\tnode %d does not exist.\n"
			"\tplease call install_node() before install_element()\n",
			cmd->name, cmd->string, ntype);
		exit(EXIT_FAILURE);
	}

	if (hash_lookup(cnode->cmd_hash, (void *)cmd) != NULL) {
		fprintf(stderr,
			"%s[%s]:\n"
			"\tnode %d (%s) already has this command installed.\n"
			"\tduplicate install_element call?\n",
			cmd->name, cmd->string, ntype, cnode->name);
		return;
	}

	(void)hash_get(cnode->cmd_hash, (void *)cmd, hash_alloc_intern);

	if (cnode->graph_built || !defer_cli_tree) {
		struct graph *graph = graph_new();
		struct cmd_token *token =
			cmd_token_new(START_TKN, 0, NULL, NULL);
		graph_new_node(graph, token,
			       (void (*)(void *)) & cmd_token_del);

		cmd_graph_parse(graph, cmd);
		cmd_graph_names(graph);
		cmd_graph_merge(cnode->cmdgraph, graph, +1);
		graph_delete_graph(graph);

		cnode->graph_built = true;
	}

	vector_set(cnode->cmd_vector, (void *)cmd);

	if (ntype == VIEW_NODE)
		_install_element(ENABLE_NODE, cmd);
}

static void cmd_finalize_iter(struct hash_bucket *hb, void *arg)
{
	struct cmd_node *cnode = arg;
	const struct cmd_element *cmd = hb->data;
	struct graph *graph = graph_new();
	struct cmd_token *token = cmd_token_new(START_TKN, 0, NULL, NULL);

	graph_new_node(graph, token, (void (*)(void *)) & cmd_token_del);

	cmd_graph_parse(graph, cmd);
	cmd_graph_names(graph);
	cmd_graph_merge(cnode->cmdgraph, graph, +1);
	graph_delete_graph(graph);
}

void cmd_finalize_node(struct cmd_node *cnode)
{
	if (cnode->graph_built)
		return;

	hash_iterate(cnode->cmd_hash, cmd_finalize_iter, cnode);
	cnode->graph_built = true;
}

void uninstall_element(enum node_type ntype, const struct cmd_element *cmd)
{
	struct cmd_node *cnode;

	/* cmd_init hasn't been called */
	if (!cmdvec) {
		fprintf(stderr, "%s called before cmd_init, breakage likely\n",
			__func__);
		return;
	}

	cnode = vector_lookup(cmdvec, ntype);

	if (cnode == NULL) {
		fprintf(stderr,
			"%s[%s]:\n"
			"\tnode %d does not exist.\n"
			"\tplease call install_node() before uninstall_element()\n",
			cmd->name, cmd->string, ntype);
		exit(EXIT_FAILURE);
	}

	if (hash_release(cnode->cmd_hash, (void *)cmd) == NULL) {
		fprintf(stderr,
			"%s[%s]:\n"
			"\tnode %d (%s) does not have this command installed.\n"
			"\tduplicate uninstall_element call?\n",
			cmd->name, cmd->string, ntype, cnode->name);
		return;
	}

	vector_unset_value(cnode->cmd_vector, (void *)cmd);

	if (cnode->graph_built) {
		struct graph *graph = graph_new();
		struct cmd_token *token =
			cmd_token_new(START_TKN, 0, NULL, NULL);
		graph_new_node(graph, token,
			       (void (*)(void *)) & cmd_token_del);

		cmd_graph_parse(graph, cmd);
		cmd_graph_names(graph);
		cmd_graph_merge(cnode->cmdgraph, graph, -1);
		graph_delete_graph(graph);
	}

	if (ntype == VIEW_NODE)
		uninstall_element(ENABLE_NODE, cmd);
}


static const unsigned char itoa64[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(char *s, long v, int n)
{
	while (--n >= 0) {
		*s++ = itoa64[v & 0x3f];
		v >>= 6;
	}
}

static char *zencrypt(const char *passwd)
{
	char salt[6];
	struct timeval tv;

	gettimeofday(&tv, 0);

	to64(&salt[0], frr_weak_random(), 3);
	to64(&salt[3], tv.tv_usec, 3);
	salt[5] = '\0';

	return crypt(passwd, salt);
}

static bool full_cli;

/* This function write configuration of this host. */
static int config_write_host(struct vty *vty)
{
	const char *name;

	name = cmd_hostname_get();
	if (name && name[0] != '\0')
		vty_out(vty, "hostname %s\n", name);

	name = cmd_domainname_get();
	if (name && name[0] != '\0')
		vty_out(vty, "domainname %s\n", name);

	if (cmd_allow_reserved_ranges_get())
		vty_out(vty, "allow-reserved-ranges\n");

	/* The following are all configuration commands that are not sent to
	 * watchfrr.  For instance watchfrr is hardcoded to log to syslog so
	 * we would always display 'log syslog informational' in the config
	 * which would cause other daemons to then switch to syslog when they
	 * parse frr.conf.
	 */
	if (full_cli) {
		if (host.encrypt) {
			if (host.password_encrypt)
				vty_out(vty, "password 8 %s\n",
					host.password_encrypt);
			if (host.enable_encrypt)
				vty_out(vty, "enable password 8 %s\n",
					host.enable_encrypt);
		} else {
			if (host.password)
				vty_out(vty, "password %s\n", host.password);
			if (host.enable)
				vty_out(vty, "enable password %s\n",
					host.enable);
		}
		log_config_write(vty);

		if (!cputime_enabled)
			vty_out(vty, "no service cputime-stats\n");

		if (!cputime_threshold)
			vty_out(vty, "no service cputime-warning\n");
		else if (cputime_threshold != CONSUMED_TIME_CHECK)
			vty_out(vty, "service cputime-warning %lu\n",
				cputime_threshold / 1000);

		if (!walltime_threshold)
			vty_out(vty, "no service walltime-warning\n");
		else if (walltime_threshold != CONSUMED_TIME_CHECK)
			vty_out(vty, "service walltime-warning %lu\n",
				walltime_threshold / 1000);

		if (host.advanced)
			vty_out(vty, "service advanced-vty\n");

		if (host.encrypt)
			vty_out(vty, "service password-encryption\n");

		if (host.lines >= 0)
			vty_out(vty, "service terminal-length %d\n",
				host.lines);

		if (host.motdfile)
			vty_out(vty, "banner motd file %s\n", host.motdfile);
		else if (host.motd
			 && strncmp(host.motd, FRR_DEFAULT_MOTD,
				    strlen(host.motd)))
			vty_out(vty, "banner motd line %s\n", host.motd);
		else if (!host.motd)
			vty_out(vty, "no banner motd\n");
	}

	if (debug_memstats_at_exit)
		vty_out(vty, "!\ndebug memstats-at-exit\n");

	return 1;
}

/* Utility function for getting command graph. */
static struct graph *cmd_node_graph(vector v, enum node_type ntype)
{
	struct cmd_node *cnode = vector_slot(v, ntype);

	cmd_finalize_node(cnode);
	return cnode->cmdgraph;
}

static int cmd_try_do_shortcut(enum node_type node, char *first_word)
{
	if (first_word != NULL && node != AUTH_NODE && node != VIEW_NODE
	    && node != AUTH_ENABLE_NODE && 0 == strcmp("do", first_word))
		return 1;
	return 0;
}

/**
 * Compare function for cmd_token.
 * Used with qsort to sort command completions.
 */
static int compare_completions(const void *fst, const void *snd)
{
	const struct cmd_token *first = *(const struct cmd_token * const *)fst,
			       *secnd = *(const struct cmd_token * const *)snd;
	return strcmp(first->text, secnd->text);
}

/**
 * Takes a list of completions returned by command_complete,
 * dedeuplicates them based on both text and description,
 * sorts them, and returns them as a vector.
 *
 * @param completions linked list of cmd_token
 * @return deduplicated and sorted vector with
 */
vector completions_to_vec(struct list *completions)
{
	vector comps = vector_init(VECTOR_MIN_SIZE);

	struct listnode *ln;
	struct cmd_token *token, *cr = NULL;
	unsigned int i, exists;
	for (ALL_LIST_ELEMENTS_RO(completions, ln, token)) {
		if (token->type == END_TKN && (cr = token))
			continue;

		// linear search for token in completions vector
		exists = 0;
		for (i = 0; i < vector_active(comps) && !exists; i++) {
			struct cmd_token *curr = vector_slot(comps, i);
#ifdef VTYSH_DEBUG
			exists = !strcmp(curr->text, token->text)
				 && !strcmp(curr->desc, token->desc);
#else
			exists = !strcmp(curr->text, token->text);
#endif /* VTYSH_DEBUG */
		}

		if (!exists)
			vector_set(comps, token);
	}

	// sort completions
	qsort(comps->index, vector_active(comps), sizeof(void *),
	      &compare_completions);

	// make <cr> the first element, if it is present
	if (cr) {
		vector_set_index(comps, vector_active(comps), NULL);
		memmove(comps->index + 1, comps->index,
			(comps->alloced - 1) * sizeof(void *));
		vector_set_index(comps, 0, cr);
	}

	return comps;
}
/**
 * Generates a vector of cmd_token representing possible completions
 * on the current input.
 *
 * @param vline the vectorized input line
 * @param vty the vty with the node to match on
 * @param status pointer to matcher status code
 * @return vector of struct cmd_token * with possible completions
 */
static vector cmd_complete_command_real(vector vline, struct vty *vty,
					int *status)
{
	struct list *completions;
	struct graph *cmdgraph = cmd_node_graph(cmdvec, vty->node);

	enum matcher_rv rv = command_complete(cmdgraph, vline, &completions);

	if (MATCHER_ERROR(rv)) {
		*status = CMD_ERR_NO_MATCH;
		return NULL;
	}

	vector comps = completions_to_vec(completions);
	list_delete(&completions);

	// set status code appropriately
	switch (vector_active(comps)) {
	case 0:
		*status = CMD_ERR_NO_MATCH;
		break;
	case 1:
		*status = CMD_COMPLETE_FULL_MATCH;
		break;
	default:
		*status = CMD_COMPLETE_LIST_MATCH;
	}

	return comps;
}

vector cmd_describe_command(vector vline, struct vty *vty, int *status)
{
	vector ret;

	if (cmd_try_do_shortcut(vty->node, vector_slot(vline, 0))) {
		enum node_type onode;
		int orig_xpath_index;
		vector shifted_vline;
		unsigned int index;

		onode = vty->node;
		orig_xpath_index = vty->xpath_index;
		vty->node = ENABLE_NODE;
		vty->xpath_index = 0;
		/* We can try it on enable node, cos' the vty is authenticated
		 */

		shifted_vline = vector_init(vector_count(vline));
		/* use memcpy? */
		for (index = 1; index < vector_active(vline); index++) {
			vector_set_index(shifted_vline, index - 1,
					 vector_lookup(vline, index));
		}

		ret = cmd_complete_command_real(shifted_vline, vty, status);

		vector_free(shifted_vline);
		vty->node = onode;
		vty->xpath_index = orig_xpath_index;
		return ret;
	}

	return cmd_complete_command_real(vline, vty, status);
}

static struct list *varhandlers = NULL;

static int __add_key_comp(const struct lyd_node *dnode, void *arg)
{
	const char *key_value = yang_dnode_get_string(dnode, NULL);

	vector_set((vector)arg, XSTRDUP(MTYPE_COMPLETION, key_value));

	return YANG_ITER_CONTINUE;
}

static void __get_list_keys(vector comps, const char *xpath)
{
	yang_dnode_iterate(__add_key_comp, comps,
			   vty_shared_candidate_config->dnode, "%s", xpath);
}

void cmd_variable_complete(struct cmd_token *token, const char *arg,
			   vector comps)
{
	struct listnode *ln;
	const struct cmd_variable_handler *cvh;
	size_t i, argsz;
	vector tmpcomps;

	tmpcomps = arg ? vector_init(VECTOR_MIN_SIZE) : comps;

	for (ALL_LIST_ELEMENTS_RO(varhandlers, ln, cvh)) {
		if (cvh->tokenname && strcmp(cvh->tokenname, token->text))
			continue;
		if (cvh->varname && (!token->varname
				     || strcmp(cvh->varname, token->varname)))
			continue;
		if (cvh->xpath)
			__get_list_keys(tmpcomps, cvh->xpath);
		if (cvh->completions)
			cvh->completions(tmpcomps, token);
		break;
	}

	if (!arg)
		return;

	argsz = strlen(arg);
	for (i = vector_active(tmpcomps); i; i--) {
		char *item = vector_slot(tmpcomps, i - 1);
		if (strlen(item) >= argsz && !strncmp(item, arg, argsz))
			vector_set(comps, item);
		else
			XFREE(MTYPE_COMPLETION, item);
	}
	vector_free(tmpcomps);
}

#define AUTOCOMP_INDENT 5

char *cmd_variable_comp2str(vector comps, unsigned short cols)
{
	size_t bsz = 16;
	char *buf = XCALLOC(MTYPE_TMP, bsz);
	int lc = AUTOCOMP_INDENT;
	size_t cs = AUTOCOMP_INDENT;
	size_t itemlen;
	snprintf(buf, bsz, "%*s", AUTOCOMP_INDENT, "");
	for (size_t j = 0; j < vector_active(comps); j++) {
		char *item = vector_slot(comps, j);
		itemlen = strlen(item);

		size_t next_sz = cs + itemlen + AUTOCOMP_INDENT + 3;

		if (next_sz > bsz) {
			/* Make sure the buf size is large enough */
			bsz = next_sz;
			buf = XREALLOC(MTYPE_TMP, buf, bsz);
		}
		if (lc + itemlen + 1 >= cols) {
			cs += snprintf(&buf[cs], bsz - cs, "\n%*s",
				       AUTOCOMP_INDENT, "");
			lc = AUTOCOMP_INDENT;
		}

		size_t written = snprintf(&buf[cs], bsz - cs, "%s ", item);
		lc += written;
		cs += written;
		XFREE(MTYPE_COMPLETION, item);
		vector_set_index(comps, j, NULL);
	}
	return buf;
}

void cmd_variable_handler_register(const struct cmd_variable_handler *cvh)
{
	if (!varhandlers)
		return;

	for (; cvh->completions || cvh->xpath; cvh++)
		listnode_add(varhandlers, (void *)cvh);
}

DEFUN_HIDDEN (autocomplete,
              autocomplete_cmd,
              "autocomplete TYPE TEXT VARNAME",
              "Autocompletion handler (internal, for vtysh)\n"
              "cmd_token->type\n"
              "cmd_token->text\n"
              "cmd_token->varname\n")
{
	struct cmd_token tok;
	vector comps = vector_init(32);
	size_t i;

	memset(&tok, 0, sizeof(tok));
	tok.type = atoi(argv[1]->arg);
	tok.text = argv[2]->arg;
	tok.varname = argv[3]->arg;
	if (!strcmp(tok.varname, "-"))
		tok.varname = NULL;

	cmd_variable_complete(&tok, NULL, comps);

	for (i = 0; i < vector_active(comps); i++) {
		char *text = vector_slot(comps, i);
		vty_out(vty, "%s\n", text);
		XFREE(MTYPE_COMPLETION, text);
	}

	vector_free(comps);
	return CMD_SUCCESS;
}

/**
 * Generate possible tab-completions for the given input. This function only
 * returns results that would result in a valid command if used as Readline
 * completions (as is the case in vtysh). For instance, if the passed vline ends
 * with '4.3.2', the strings 'A.B.C.D' and 'A.B.C.D/M' will _not_ be returned.
 *
 * @param vline vectorized input line
 * @param vty the vty
 * @param status location to store matcher status code in
 * @return set of valid strings for use with Readline as tab-completions.
 */

char **cmd_complete_command(vector vline, struct vty *vty, int *status)
{
	char **ret = NULL;
	int original_node = vty->node;
	vector input_line = vector_init(vector_count(vline));

	// if the first token is 'do' we'll want to execute the command in the
	// enable node
	int do_shortcut = cmd_try_do_shortcut(vty->node, vector_slot(vline, 0));
	vty->node = do_shortcut ? ENABLE_NODE : original_node;

	// construct the input line we'll be matching on
	unsigned int offset = (do_shortcut) ? 1 : 0;
	for (unsigned index = 0; index + offset < vector_active(vline); index++)
		vector_set_index(input_line, index,
				 vector_lookup(vline, index + offset));

	// get token completions -- this is a copying operation
	vector comps = NULL, initial_comps;
	initial_comps = cmd_complete_command_real(input_line, vty, status);

	if (!MATCHER_ERROR(*status)) {
		assert(initial_comps);
		// filter out everything that is not suitable for a
		// tab-completion
		comps = vector_init(VECTOR_MIN_SIZE);
		for (unsigned int i = 0; i < vector_active(initial_comps);
		     i++) {
			struct cmd_token *token = vector_slot(initial_comps, i);
			if (token->type == WORD_TKN)
				vector_set(comps, XSTRDUP(MTYPE_COMPLETION,
							  token->text));
			else if (IS_VARYING_TOKEN(token->type)) {
				const char *ref = vector_lookup(
					vline, vector_active(vline) - 1);
				cmd_variable_complete(token, ref, comps);
			}
		}
		vector_free(initial_comps);

		// since we filtered results, we need to re-set status code
		switch (vector_active(comps)) {
		case 0:
			*status = CMD_ERR_NO_MATCH;
			break;
		case 1:
			*status = CMD_COMPLETE_FULL_MATCH;
			break;
		default:
			*status = CMD_COMPLETE_LIST_MATCH;
		}

		// copy completions text into an array of char*
		ret = XMALLOC(MTYPE_TMP,
			      (vector_active(comps) + 1) * sizeof(char *));
		unsigned int i;
		for (i = 0; i < vector_active(comps); i++) {
			ret[i] = vector_slot(comps, i);
		}
		// set the last element to NULL, because this array is used in
		// a Readline completion_generator function which expects NULL
		// as a sentinel value
		ret[i] = NULL;
		vector_free(comps);
		comps = NULL;
	} else if (initial_comps)
		vector_free(initial_comps);

	// comps should always be null here
	assert(!comps);

	// free the adjusted input line
	vector_free(input_line);

	// reset vty->node to its original value
	vty->node = original_node;

	return ret;
}

/* return parent node */
/* MUST eventually converge on CONFIG_NODE */
enum node_type node_parent(enum node_type node)
{
	struct cmd_node *cnode;

	assert(node > CONFIG_NODE);

	cnode = vector_lookup(cmdvec, node);

	return cnode->parent_node;
}

/* Execute command by argument vline vector. */
static int cmd_execute_command_real(vector vline, struct vty *vty,
				    const struct cmd_element **cmd,
				    unsigned int up_level)
{
	struct list *argv_list;
	enum matcher_rv status;
	const struct cmd_element *matched_element = NULL;
	unsigned int i;
	int xpath_index = vty->xpath_index;
	int node = vty->node;

	/* only happens for legacy split config file load;  need to check for
	 * a match before calling node_exit handlers below
	 */
	for (i = 0; i < up_level; i++) {
		struct cmd_node *cnode;

		if (node <= CONFIG_NODE)
			return CMD_NO_LEVEL_UP;

		cnode = vector_slot(cmdvec, node);
		node = node_parent(node);

		if (xpath_index > 0 && !cnode->no_xpath)
			xpath_index--;
	}

	struct graph *cmdgraph = cmd_node_graph(cmdvec, node);
	status = command_match(cmdgraph, vline, &argv_list, &matched_element);

	if (cmd)
		*cmd = matched_element;

	// if matcher error, return corresponding CMD_ERR
	if (MATCHER_ERROR(status)) {
		if (argv_list)
			list_delete(&argv_list);
		switch (status) {
		case MATCHER_INCOMPLETE:
			return CMD_ERR_INCOMPLETE;
		case MATCHER_AMBIGUOUS:
			return CMD_ERR_AMBIGUOUS;
		case MATCHER_NO_MATCH:
		case MATCHER_OK:
			return CMD_ERR_NO_MATCH;
		}
	}

	for (i = 0; i < up_level; i++)
		cmd_exit(vty);

	// build argv array from argv list
	struct cmd_token **argv = XMALLOC(
		MTYPE_TMP, argv_list->count * sizeof(struct cmd_token *));
	struct listnode *ln;
	struct cmd_token *token;

	i = 0;
	for (ALL_LIST_ELEMENTS_RO(argv_list, ln, token))
		argv[i++] = token;

	int argc = argv_list->count;

	int ret;
	if (matched_element->daemon)
		ret = CMD_SUCCESS_DAEMON;
	else {
		if (vty->config) {
			/* Clear array of enqueued configuration changes. */
			vty->num_cfg_changes = 0;
			memset(&vty->cfg_changes, 0, sizeof(vty->cfg_changes));

			/* Regenerate candidate configuration if necessary. */
			if (frr_get_cli_mode() == FRR_CLI_CLASSIC
			    && running_config->version
				       > vty->candidate_config->version)
				nb_config_replace(vty->candidate_config,
						  running_config, true);

			/*
			 * Perform pending commit (if any) before executing
			 * non-YANG command.
			 */
			if (!(matched_element->attr & CMD_ATTR_YANG))
				(void)nb_cli_pending_commit_check(vty);
		}

		ret = matched_element->func(matched_element, vty, argc, argv);
	}

	// delete list and cmd_token's in it
	list_delete(&argv_list);
	XFREE(MTYPE_TMP, argv);

	return ret;
}

/**
 * Execute a given command, handling things like "do ..." and checking
 * whether the given command might apply at a parent node if doesn't
 * apply for the current node.
 *
 * @param vline Command line input, vector of char* where each element is
 *              one input token.
 * @param vty The vty context in which the command should be executed.
 * @param cmd Pointer where the struct cmd_element of the matched command
 *            will be stored, if any. May be set to NULL if this info is
 *            not needed.
 * @param vtysh If set != 0, don't lookup the command at parent nodes.
 * @return The status of the command that has been executed or an error code
 *         as to why no command could be executed.
 */
int cmd_execute_command(vector vline, struct vty *vty,
			const struct cmd_element **cmd, int vtysh)
{
	int ret, saved_ret = 0;
	enum node_type onode, try_node;
	int orig_xpath_index;

	onode = try_node = vty->node;
	orig_xpath_index = vty->xpath_index;

	if (cmd_try_do_shortcut(vty->node, vector_slot(vline, 0))) {
		vector shifted_vline;
		unsigned int index;

		vty->node = ENABLE_NODE;
		vty->xpath_index = 0;
		/* We can try it on enable node, cos' the vty is authenticated
		 */

		shifted_vline = vector_init(vector_count(vline));
		/* use memcpy? */
		for (index = 1; index < vector_active(vline); index++)
			vector_set_index(shifted_vline, index - 1,
					 vector_lookup(vline, index));

		ret = cmd_execute_command_real(shifted_vline, vty, cmd, 0);

		vector_free(shifted_vline);
		vty->node = onode;
		vty->xpath_index = orig_xpath_index;
		return ret;
	}

	saved_ret = ret =
		cmd_execute_command_real(vline, vty, cmd, 0);

	if (vtysh)
		return saved_ret;

	if (ret != CMD_SUCCESS && ret != CMD_WARNING
	    && ret != CMD_ERR_AMBIGUOUS && ret != CMD_ERR_INCOMPLETE
	    && ret != CMD_NOT_MY_INSTANCE && ret != CMD_WARNING_CONFIG_FAILED) {
		/* This assumes all nodes above CONFIG_NODE are childs of
		 * CONFIG_NODE */
		while (vty->node > CONFIG_NODE) {
			struct cmd_node *cnode = vector_slot(cmdvec, try_node);

			try_node = node_parent(try_node);
			vty->node = try_node;
			if (vty->xpath_index > 0 && !cnode->no_xpath)
				vty->xpath_index--;

			ret = cmd_execute_command_real(vline, vty, cmd, 0);
			if (ret == CMD_SUCCESS || ret == CMD_WARNING
			    || ret == CMD_ERR_AMBIGUOUS || ret == CMD_ERR_INCOMPLETE
			    || ret == CMD_NOT_MY_INSTANCE
			    || ret == CMD_WARNING_CONFIG_FAILED)
				return ret;
		}
		/* no command succeeded, reset the vty to the original node */
		vty->node = onode;
		vty->xpath_index = orig_xpath_index;
	}

	/* return command status for original node */
	return saved_ret;
}

/**
 * Execute a given command, matching it strictly against the current node.
 * This mode is used when reading config files.
 *
 * @param vline Command line input, vector of char* where each element is
 *              one input token.
 * @param vty The vty context in which the command should be executed.
 * @param cmd Pointer where the struct cmd_element* of the matched command
 *            will be stored, if any. May be set to NULL if this info is
 *            not needed.
 * @return The status of the command that has been executed or an error code
 *         as to why no command could be executed.
 */
int cmd_execute_command_strict(vector vline, struct vty *vty,
			       const struct cmd_element **cmd)
{
	return cmd_execute_command_real(vline, vty, cmd, 0);
}

/*
 * Hook for preprocessing command string before executing.
 *
 * All subscribers are called with the raw command string that is to be
 * executed. If any changes are to be made, a new string should be allocated
 * with MTYPE_TMP and *cmd_out updated to point to this new string. The caller
 * is then responsible for freeing this string.
 *
 * All processing functions must be mutually exclusive in their action, i.e. if
 * one subscriber decides to modify the command, all others must not modify it
 * when called. Feeding the output of one processing command into a subsequent
 * one is not supported.
 *
 * This hook is intentionally internal to the command processing system.
 *
 * cmd_in
 *    The raw command string.
 *
 * cmd_out
 *    The result of any processing.
 */
DECLARE_HOOK(cmd_execute,
	     (struct vty *vty, const char *cmd_in, char **cmd_out),
	     (vty, cmd_in, cmd_out));
DEFINE_HOOK(cmd_execute, (struct vty *vty, const char *cmd_in, char **cmd_out),
	    (vty, cmd_in, cmd_out));

/* Hook executed after a CLI command. */
DECLARE_KOOH(cmd_execute_done, (struct vty *vty, const char *cmd_exec),
	     (vty, cmd_exec));
DEFINE_KOOH(cmd_execute_done, (struct vty *vty, const char *cmd_exec),
	    (vty, cmd_exec));

/*
 * cmd_execute hook subscriber to handle `|` actions.
 */
static int handle_pipe_action(struct vty *vty, const char *cmd_in,
			      char **cmd_out)
{
	/* look for `|` */
	char *orig, *working, *token, *u;
	char *pipe = strstr(cmd_in, "| ");
	int ret = 0;

	if (!pipe)
		return 0;

	/* duplicate string for processing purposes, not including pipe */
	orig = working = XSTRDUP(MTYPE_TMP, pipe + 2);

	/* retrieve action */
	token = strsep(&working, " ");
	assert(token);

	/* match result to known actions */
	if (strmatch(token, "include")) {
		/* the remaining text should be a regexp */
		char *regexp = working;

		if (!regexp) {
			vty_out(vty, "%% Need a regexp to filter with\n");
			ret = 1;
			goto fail;
		}

		bool succ = vty_set_include(vty, regexp);

		if (!succ) {
			vty_out(vty, "%% Bad regexp '%s'\n", regexp);
			ret = 1;
			goto fail;
		}
		*cmd_out = XSTRDUP(MTYPE_TMP, cmd_in);
		u = *cmd_out;
		strsep(&u, "|");
	} else {
		vty_out(vty, "%% Unknown action '%s'\n", token);
		ret = 1;
		goto fail;
	}

fail:
	XFREE(MTYPE_TMP, orig);
	return ret;
}

static int handle_pipe_action_done(struct vty *vty, const char *cmd_exec)
{
	if (vty->filter)
		vty_set_include(vty, NULL);

	return 0;
}

int cmd_execute(struct vty *vty, const char *cmd,
		const struct cmd_element **matched, int vtysh)
{
	int ret;
	char *cmd_out = NULL;
	const char *cmd_exec = NULL;
	vector vline;

	ret = hook_call(cmd_execute, vty, cmd, &cmd_out);
	if (ret) {
		ret = CMD_WARNING;
		goto free;
	}

	cmd_exec = cmd_out ? (const char *)cmd_out : cmd;

	vline = cmd_make_strvec(cmd_exec);

	if (vline) {
		ret = cmd_execute_command(vline, vty, matched, vtysh);
		cmd_free_strvec(vline);
	} else {
		ret = CMD_SUCCESS;
	}

free:
	hook_call(cmd_execute_done, vty, cmd_exec);

	XFREE(MTYPE_TMP, cmd_out);

	return ret;
}


/**
 * Parse one line of config, walking up the parse tree attempting to find a
 * match
 *
 * @param vty The vty context in which the command should be executed.
 * @param cmd Pointer where the struct cmd_element* of the match command
 *            will be stored, if any.  May be set to NULL if this info is
 *            not needed.
 * @param use_daemon Boolean to control whether or not we match on
 * CMD_SUCCESS_DAEMON
 *                   or not.
 * @return The status of the command that has been executed or an error code
 *         as to why no command could be executed.
 */
int command_config_read_one_line(struct vty *vty,
				 const struct cmd_element **cmd,
				 uint32_t line_num, int use_daemon)
{
	vector vline;
	int ret;
	unsigned up_level = 0;

	vline = cmd_make_strvec(vty->buf);

	/* In case of comment line */
	if (vline == NULL)
		return CMD_SUCCESS;

	/* Execute configuration command : this is strict match */
	ret = cmd_execute_command_strict(vline, vty, cmd);

	/* The logic for trying parent nodes is in cmd_execute_command_real()
	 * since calling ->node_exit() correctly is a bit involved.  This is
	 * also the only reason CMD_NO_LEVEL_UP exists.
	 */
	while (!(use_daemon && ret == CMD_SUCCESS_DAEMON)
	       && !(!use_daemon && ret == CMD_ERR_NOTHING_TODO)
	       && ret != CMD_SUCCESS && ret != CMD_WARNING
	       && ret != CMD_ERR_AMBIGUOUS && ret != CMD_ERR_INCOMPLETE
	       && ret != CMD_NOT_MY_INSTANCE && ret != CMD_WARNING_CONFIG_FAILED
	       && ret != CMD_NO_LEVEL_UP)
		ret = cmd_execute_command_real(vline, vty, cmd, ++up_level);

	if (ret == CMD_NO_LEVEL_UP)
		ret = CMD_ERR_NO_MATCH;

	if (ret != CMD_SUCCESS &&
	    ret != CMD_WARNING &&
	    ret != CMD_SUCCESS_DAEMON) {
		struct vty_error *ve = XCALLOC(MTYPE_TMP, sizeof(*ve));

		memcpy(ve->error_buf, vty->buf, VTY_BUFSIZ);
		ve->line_num = line_num;
		ve->cmd_ret = ret;
		if (!vty->error)
			vty->error = list_new();

		listnode_add(vty->error, ve);
	}

	cmd_free_strvec(vline);

	return ret;
}

/* Configuration make from file. */
int config_from_file(struct vty *vty, FILE *fp, unsigned int *line_num)
{
	int ret, error_ret = 0;
	*line_num = 0;

	while (fgets(vty->buf, VTY_BUFSIZ, fp)) {
		++(*line_num);

		if (vty_log_commands) {
			int len = strlen(vty->buf);

			/* now log the command */
			zlog_notice("config-from-file# %.*s", len ? len - 1 : 0,
				    vty->buf);
		}

		ret = command_config_read_one_line(vty, NULL, *line_num, 0);

		if (ret != CMD_SUCCESS && ret != CMD_WARNING
		    && ret != CMD_ERR_NOTHING_TODO)
			error_ret = ret;
	}

	if (error_ret) {
		return error_ret;
	}

	return CMD_SUCCESS;
}

/* Configuration from terminal */
DEFUN (config_terminal,
       config_terminal_cmd,
       "configure [terminal [file-lock]]",
       "Configuration from vty interface\n"
       "Configuration terminal\n"
       "Configuration with locked datastores\n")
{
	return vty_config_enter(vty, false, false, argc == 3);
}

/* Enable command */
DEFUN (enable,
       config_enable_cmd,
       "enable",
       "Turn on privileged mode command\n")
{
	/* If enable password is NULL, change to ENABLE_NODE */
	if ((host.enable == NULL && host.enable_encrypt == NULL)
	    || vty->type == VTY_SHELL_SERV)
		vty->node = ENABLE_NODE;
	else
		vty->node = AUTH_ENABLE_NODE;

	return CMD_SUCCESS;
}

/* Disable command */
DEFUN (disable,
       config_disable_cmd,
       "disable",
       "Turn off privileged mode command\n")
{
	if (vty->node == ENABLE_NODE)
		vty->node = VIEW_NODE;
	return CMD_SUCCESS;
}

/* Down vty node level. */
DEFUN_YANG (config_exit,
       config_exit_cmd,
       "exit",
       "Exit current mode and down to previous mode\n")
{
	cmd_exit(vty);
	return CMD_SUCCESS;
}

static int root_on_exit(struct vty *vty)
{
	if (vty_shell(vty))
		exit(0);
	else
		vty->status = VTY_CLOSE;
	return 0;
}

void cmd_exit(struct vty *vty)
{
	struct cmd_node *cnode = vector_lookup(cmdvec, vty->node);

	if (cnode->node_exit) {
		if (!cnode->node_exit(vty))
			return;
	}
	if (cnode->parent_node)
		vty->node = cnode->parent_node;
	if (vty->xpath_index > 0 && !cnode->no_xpath)
		vty->xpath_index--;
}

/* ALIAS_FIXME */
DEFUN (config_quit,
       config_quit_cmd,
       "quit",
       "Exit current mode and down to previous mode\n")
{
	return config_exit(self, vty, argc, argv);
}


/* End of configuration. */
DEFUN (config_end,
       config_end_cmd,
       "end",
       "End current mode and change to enable mode.\n")
{
	if (vty->config) {
		vty_config_exit(vty);
		vty->node = ENABLE_NODE;
	}
	return CMD_SUCCESS;
}

/* Show version. */
DEFUN (show_version,
       show_version_cmd,
       "show version",
       SHOW_STR
       "Displays zebra version\n")
{
	vty_out(vty, "%s %s (%s) on %s(%s).\n", FRR_FULL_NAME, FRR_VERSION,
		cmd_hostname_get() ? cmd_hostname_get() : "", cmd_system_get(),
		cmd_release_get());
	vty_out(vty, "%s%s\n", FRR_COPYRIGHT, GIT_INFO);
#ifdef ENABLE_VERSION_BUILD_CONFIG
	vty_out(vty, "configured with:\n    %s\n", FRR_CONFIG_ARGS);
#endif
	return CMD_SUCCESS;
}

/* Help display function for all node. */
DEFUN (config_help,
       config_help_cmd,
       "help",
       "Description of the interactive help system\n")
{
	vty_out(vty,
		"FRR VTY provides advanced help feature.  When you need help,\n\
anytime at the command line please press '?'.\n\
\n\
If nothing matches, the help list will be empty and you must backup\n\
 until entering a '?' shows the available options.\n\
Two styles of help are provided:\n\
1. Full help is available when you are ready to enter a\n\
command argument (e.g. 'show ?') and describes each possible\n\
argument.\n\
2. Partial help is provided when an abbreviated argument is entered\n\
   and you want to know what arguments match the input\n\
   (e.g. 'show me?'.)\n\n");
	return CMD_SUCCESS;
}

static void permute(struct graph_node *start, struct vty *vty)
{
	static struct list *position = NULL;
	if (!position)
		position = list_new();

	struct cmd_token *stok = start->data;
	struct graph_node *gnn;
	struct listnode *ln;

	// recursive dfs
	listnode_add(position, start);
	for (unsigned int i = 0; i < vector_active(start->to); i++) {
		struct graph_node *gn = vector_slot(start->to, i);
		struct cmd_token *tok = gn->data;
		if (tok->attr & CMD_ATTR_HIDDEN)
			continue;
		else if (tok->type == END_TKN || gn == start) {
			vty_out(vty, " ");
			for (ALL_LIST_ELEMENTS_RO(position, ln, gnn)) {
				struct cmd_token *tt = gnn->data;
				if (tt->type < SPECIAL_TKN)
					vty_out(vty, " %s", tt->text);
			}
			if (gn == start)
				vty_out(vty, "...");
			vty_out(vty, "\n");
		} else {
			bool skip = false;
			if (stok->type == FORK_TKN && tok->type != FORK_TKN)
				for (ALL_LIST_ELEMENTS_RO(position, ln, gnn))
					if (gnn == gn) {
						skip = true;
						break;
					}
			if (!skip)
				permute(gn, vty);
		}
	}
	list_delete_node(position, listtail(position));
}

static void print_cmd(struct vty *vty, const char *cmd)
{
	int i, j, len = strlen(cmd);
	char buf[len + 1];
	bool skip = false;

	j = 0;
	for (i = 0; i < len; i++) {
		/* skip varname */
		if (cmd[i] == '$')
			skip = true;
		else if (strchr(" ()<>[]{}|", cmd[i]))
			skip = false;

		if (skip)
			continue;

		if (isspace(cmd[i])) {
			/* skip leading whitespace */
			if (i == 0)
				continue;
			/* skip trailing whitespace */
			if (i == len - 1)
				continue;
			/* skip all whitespace after opening brackets or pipe */
			if (strchr("(<[{|", cmd[i - 1])) {
				while (isspace(cmd[i + 1]))
					i++;
				continue;
			}
			/* skip repeated whitespace */
			if (isspace(cmd[i + 1]))
				continue;
			/* skip whitespace before closing brackets or pipe */
			if (strchr(")>]}|", cmd[i + 1]))
				continue;
			/* convert tabs to spaces */
			if (cmd[i] == '\t') {
				buf[j++] = ' ';
				continue;
			}
		}

		buf[j++] = cmd[i];
	}
	buf[j] = 0;

	vty_out(vty, "%s\n", buf);
}

int cmd_list_cmds(struct vty *vty, int do_permute)
{
	struct cmd_node *node = vector_slot(cmdvec, vty->node);

	if (do_permute) {
		cmd_finalize_node(node);
		permute(vector_slot(node->cmdgraph->nodes, 0), vty);
	} else {
		/* loop over all commands at this node */
		const struct cmd_element *element = NULL;
		for (unsigned int i = 0; i < vector_active(node->cmd_vector);
		     i++)
			if ((element = vector_slot(node->cmd_vector, i)) &&
			    !(element->attr & CMD_ATTR_HIDDEN)) {
				vty_out(vty, "    ");
				print_cmd(vty, element->string);
			}
	}
	return CMD_SUCCESS;
}

/* Help display function for all node. */
DEFUN (config_list,
       config_list_cmd,
       "list [permutations]",
       "Print command list\n"
       "Print all possible command permutations\n")
{
	return cmd_list_cmds(vty, argc == 2);
}

DEFUN (show_commandtree,
       show_commandtree_cmd,
       "show commandtree [permutations]",
       SHOW_STR
       "Show command tree\n"
       "Permutations that we are interested in\n")
{
	return cmd_list_cmds(vty, argc == 3);
}

DEFUN_HIDDEN(show_cli_graph,
             show_cli_graph_cmd,
             "show cli graph",
             SHOW_STR
             "CLI reflection\n"
             "Dump current command space as DOT graph\n")
{
	struct cmd_node *cn = vector_slot(cmdvec, vty->node);
	char *dot;

	cmd_finalize_node(cn);
	dot = cmd_graph_dump_dot(cn->cmdgraph);

	vty_out(vty, "%s\n", dot);
	XFREE(MTYPE_TMP, dot);
	return CMD_SUCCESS;
}

static int vty_write_config(struct vty *vty)
{
	size_t i;
	struct cmd_node *node;

	if (host.noconfig)
		return CMD_SUCCESS;

	nb_cli_show_config_prepare(running_config, false);

	if (vty->type == VTY_TERM) {
		vty_out(vty, "\nCurrent configuration:\n");
		vty_out(vty, "!\n");
	}

	if (strcmp(frr_defaults_version(), FRR_VER_SHORT))
		vty_out(vty, "! loaded from %s\n", frr_defaults_version());
	vty_out(vty, "frr version %s\n", FRR_VER_SHORT);
	vty_out(vty, "frr defaults %s\n", frr_defaults_profile());
	vty_out(vty, "!\n");

	for (i = 0; i < vector_active(cmdvec); i++)
		if ((node = vector_slot(cmdvec, i)) && node->config_write) {
			if ((*node->config_write)(vty))
				vty_out(vty, "!\n");
		}

	if (vty->type == VTY_TERM) {
		vty_out(vty, "end\n");
	}

	return CMD_SUCCESS;
}

/* cross-reference frr_daemon_state_save in libfrr.c
 * the code there is similar but not identical (state files always use the same
 * name for the new write, and don't keep a backup of previous state.)
 */
static int file_write_config(struct vty *vty)
{
	int fd, dirfd;
	char *config_file, *slash;
	char *config_file_tmp = NULL;
	char *config_file_sav = NULL;
	int ret = CMD_WARNING;
	struct vty *file_vty;
	struct stat conf_stat;

	if (host.noconfig)
		return CMD_SUCCESS;

	/* Check and see if we are operating under vtysh configuration */
	if (host.config == NULL) {
		vty_out(vty,
			"Can't save to configuration file, using vtysh.\n");
		return CMD_WARNING;
	}

	/* Get filename. */
	config_file = host.config;

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
	slash = strrchr(config_file, '/');
	if (slash) {
		char *config_dir = XSTRDUP(MTYPE_TMP, config_file);
		config_dir[slash - config_file] = '\0';
		dirfd = open(config_dir, O_DIRECTORY | O_RDONLY);
		XFREE(MTYPE_TMP, config_dir);
	} else
		dirfd = open(".", O_DIRECTORY | O_RDONLY);
	/* if dirfd is invalid, directory sync fails, but we're still OK */

	size_t config_file_sav_sz = strlen(config_file) + strlen(CONF_BACKUP_EXT) + 1;
	config_file_sav = XMALLOC(MTYPE_TMP, config_file_sav_sz);
	strlcpy(config_file_sav, config_file, config_file_sav_sz);
	strlcat(config_file_sav, CONF_BACKUP_EXT, config_file_sav_sz);


	config_file_tmp = XMALLOC(MTYPE_TMP, strlen(config_file) + 8);
	snprintf(config_file_tmp, strlen(config_file) + 8, "%s.XXXXXX",
		 config_file);

	/* Open file to configuration write. */
	fd = mkstemp(config_file_tmp);
	if (fd < 0) {
		vty_out(vty, "Can't open configuration file %s.\n",
			config_file_tmp);
		goto finished;
	}
	if (fchmod(fd, CONFIGFILE_MASK) != 0) {
		vty_out(vty, "Can't chmod configuration file %s: %s (%d).\n",
			config_file_tmp, safe_strerror(errno), errno);
		goto finished;
	}

	/* Make vty for configuration file. */
	file_vty = vty_new();
	file_vty->wfd = fd;
	file_vty->type = VTY_FILE;

	/* Config file header print. */
	vty_out(file_vty, "!\n! Zebra configuration saved from vty\n!   ");
	vty_time_print(file_vty, 1);
	vty_out(file_vty, "!\n");
	vty_write_config(file_vty);
	vty_close(file_vty);

	if (stat(config_file, &conf_stat) >= 0) {
		if (unlink(config_file_sav) != 0)
			if (errno != ENOENT) {
				vty_out(vty,
					"Can't unlink backup configuration file %s.\n",
					config_file_sav);
				goto finished;
			}
		if (link(config_file, config_file_sav) != 0) {
			vty_out(vty,
				"Can't backup old configuration file %s.\n",
				config_file_sav);
			goto finished;
		}
		if (dirfd >= 0)
			fsync(dirfd);
	}
	if (rename(config_file_tmp, config_file) != 0) {
		vty_out(vty, "Can't save configuration file %s.\n",
			config_file);
		goto finished;
	}
	if (dirfd >= 0)
		fsync(dirfd);

	vty_out(vty, "Configuration saved to %s\n", config_file);
	ret = CMD_SUCCESS;

finished:
	if (ret != CMD_SUCCESS)
		unlink(config_file_tmp);
	if (dirfd >= 0)
		close(dirfd);
	XFREE(MTYPE_TMP, config_file_tmp);
	XFREE(MTYPE_TMP, config_file_sav);
	return ret;
}

/* Write current configuration into file. */

DEFUN (config_write,
       config_write_cmd,
       "write [<file|memory|terminal>]",
       "Write running configuration to memory, network, or terminal\n"
       "Write to configuration file\n"
       "Write configuration currently in memory\n"
       "Write configuration to terminal\n")
{
	const int idx_type = 1;

	// if command was 'write terminal' or 'write memory'
	if (argc == 2 && (!strcmp(argv[idx_type]->text, "terminal"))) {
		return vty_write_config(vty);
	}

	return file_write_config(vty);
}

/* ALIAS_FIXME for 'write <terminal|memory>' */
DEFUN (show_running_config,
       show_running_config_cmd,
       "show running-config",
       SHOW_STR
       "running configuration (same as write terminal)\n")
{
	return vty_write_config(vty);
}

/* ALIAS_FIXME for 'write file' */
DEFUN (copy_runningconf_startupconf,
       copy_runningconf_startupconf_cmd,
       "copy running-config startup-config",
       "Copy configuration\n"
       "Copy running config to... \n"
       "Copy running config to startup config (same as write file/memory)\n")
{
	return file_write_config(vty);
}
/** -- **/

/* Write startup configuration into the terminal. */
DEFUN (show_startup_config,
       show_startup_config_cmd,
       "show startup-config",
       SHOW_STR
       "Contents of startup configuration\n")
{
	char buf[BUFSIZ];
	FILE *confp;

	if (host.noconfig)
		return CMD_SUCCESS;
	if (host.config == NULL)
		return CMD_WARNING;

	confp = fopen(host.config, "r");
	if (confp == NULL) {
		vty_out(vty, "Can't open configuration file [%s] due to '%s'\n",
			host.config, safe_strerror(errno));
		return CMD_WARNING;
	}

	while (fgets(buf, BUFSIZ, confp)) {
		char *cp = buf;

		while (*cp != '\r' && *cp != '\n' && *cp != '\0')
			cp++;
		*cp = '\0';

		vty_out(vty, "%s\n", buf);
	}

	fclose(confp);

	return CMD_SUCCESS;
}

int cmd_domainname_set(const char *domainname)
{
	XFREE(MTYPE_HOST, host.domainname);
	host.domainname = domainname ? XSTRDUP(MTYPE_HOST, domainname) : NULL;
	return CMD_SUCCESS;
}

/* Hostname configuration */
DEFUN(config_domainname,
      domainname_cmd,
      "domainname WORD",
      "Set system's domain name\n"
      "This system's domain name\n")
{
	struct cmd_token *word = argv[1];

	if (!isalpha((unsigned char)word->arg[0])) {
		vty_out(vty, "Please specify string starting with alphabet\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return cmd_domainname_set(word->arg);
}

DEFUN(config_no_domainname,
      no_domainname_cmd,
      "no domainname [DOMAINNAME]",
      NO_STR
      "Reset system's domain name\n"
      "domain name of this router\n")
{
	return cmd_domainname_set(NULL);
}

int cmd_hostname_set(const char *hostname)
{
	XFREE(MTYPE_HOST, host.name);
	host.name = hostname ? XSTRDUP(MTYPE_HOST, hostname) : NULL;
	return CMD_SUCCESS;
}

/* Hostname configuration */
DEFUN (config_hostname,
       hostname_cmd,
       "hostname WORD",
       "Set system's network name\n"
       "This system's network name\n")
{
	struct cmd_token *word = argv[1];

	if (!isalnum((unsigned char)word->arg[0])) {
		vty_out(vty,
		    "Please specify string starting with alphabet or number\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* With reference to RFC 1123 Section 2.1 */
	if (strlen(word->arg) > HOSTNAME_LEN) {
		vty_out(vty, "Hostname length should be less than %d chars\n",
			HOSTNAME_LEN);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return cmd_hostname_set(word->arg);
}

DEFUN (config_no_hostname,
       no_hostname_cmd,
       "no hostname [HOSTNAME]",
       NO_STR
       "Reset system's network name\n"
       "Host name of this router\n")
{
	return cmd_hostname_set(NULL);
}

/* VTY interface password set. */
DEFUN (config_password,
       password_cmd,
       "password [(8-8)] WORD",
       "Modify the terminal connection password\n"
       "Specifies a HIDDEN password will follow\n"
       "The password string\n")
{
	int idx_8 = 1;
	int idx_word = 2;
	if (argc == 3) // '8' was specified
	{
		if (host.password)
			XFREE(MTYPE_HOST, host.password);
		host.password = NULL;
		if (host.password_encrypt)
			XFREE(MTYPE_HOST, host.password_encrypt);
		host.password_encrypt =
			XSTRDUP(MTYPE_HOST, argv[idx_word]->arg);
		return CMD_SUCCESS;
	}

	if (!isalnum((unsigned char)argv[idx_8]->arg[0])) {
		vty_out(vty,
			"Please specify string starting with alphanumeric\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (host.password)
		XFREE(MTYPE_HOST, host.password);
	host.password = NULL;

	if (host.encrypt) {
		if (host.password_encrypt)
			XFREE(MTYPE_HOST, host.password_encrypt);
		host.password_encrypt =
			XSTRDUP(MTYPE_HOST, zencrypt(argv[idx_8]->arg));
	} else
		host.password = XSTRDUP(MTYPE_HOST, argv[idx_8]->arg);

	return CMD_SUCCESS;
}

/* VTY interface password delete. */
DEFUN (no_config_password,
       no_password_cmd,
       "no password",
       NO_STR
       "Modify the terminal connection password\n")
{
	bool warned = false;

	if (host.password) {
		if (!vty_shell_serv(vty)) {
			vty_out(vty, NO_PASSWD_CMD_WARNING);
			warned = true;
		}
		XFREE(MTYPE_HOST, host.password);
	}
	host.password = NULL;

	if (host.password_encrypt) {
		if (!warned && !vty_shell_serv(vty))
			vty_out(vty, NO_PASSWD_CMD_WARNING);
		XFREE(MTYPE_HOST, host.password_encrypt);
	}
	host.password_encrypt = NULL;

	return CMD_SUCCESS;
}

/* VTY enable password set. */
DEFUN (config_enable_password,
       enable_password_cmd,
       "enable password [(8-8)] WORD",
       "Modify enable password parameters\n"
       "Assign the privileged level password\n"
       "Specifies a HIDDEN password will follow\n"
       "The HIDDEN 'enable' password string\n")
{
	int idx_8 = 2;
	int idx_word = 3;

	/* Crypt type is specified. */
	if (argc == 4) {
		if (argv[idx_8]->arg[0] == '8') {
			if (host.enable)
				XFREE(MTYPE_HOST, host.enable);
			host.enable = NULL;

			if (host.enable_encrypt)
				XFREE(MTYPE_HOST, host.enable_encrypt);
			host.enable_encrypt =
				XSTRDUP(MTYPE_HOST, argv[idx_word]->arg);

			return CMD_SUCCESS;
		} else {
			vty_out(vty, "Unknown encryption type.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (!isalnum((unsigned char)argv[idx_8]->arg[0])) {
		vty_out(vty,
			"Please specify string starting with alphanumeric\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (host.enable)
		XFREE(MTYPE_HOST, host.enable);
	host.enable = NULL;

	/* Plain password input. */
	if (host.encrypt) {
		if (host.enable_encrypt)
			XFREE(MTYPE_HOST, host.enable_encrypt);
		host.enable_encrypt =
			XSTRDUP(MTYPE_HOST, zencrypt(argv[idx_8]->arg));
	} else
		host.enable = XSTRDUP(MTYPE_HOST, argv[idx_8]->arg);

	return CMD_SUCCESS;
}

/* VTY enable password delete. */
DEFUN (no_config_enable_password,
       no_enable_password_cmd,
       "no enable password",
       NO_STR
       "Modify enable password parameters\n"
       "Assign the privileged level password\n")
{
	bool warned = false;

	if (host.enable) {
		if (!vty_shell_serv(vty)) {
			vty_out(vty, NO_PASSWD_CMD_WARNING);
			warned = true;
		}
		XFREE(MTYPE_HOST, host.enable);
	}
	host.enable = NULL;

	if (host.enable_encrypt) {
		if (!warned && !vty_shell_serv(vty))
			vty_out(vty, NO_PASSWD_CMD_WARNING);
		XFREE(MTYPE_HOST, host.enable_encrypt);
	}
	host.enable_encrypt = NULL;

	return CMD_SUCCESS;
}

DEFUN (service_password_encrypt,
       service_password_encrypt_cmd,
       "service password-encryption",
       "Set up miscellaneous service\n"
       "Enable encrypted passwords\n")
{
	if (host.encrypt)
		return CMD_SUCCESS;

	host.encrypt = 1;

	if (host.password) {
		if (host.password_encrypt)
			XFREE(MTYPE_HOST, host.password_encrypt);
		host.password_encrypt =
			XSTRDUP(MTYPE_HOST, zencrypt(host.password));
	}
	if (host.enable) {
		if (host.enable_encrypt)
			XFREE(MTYPE_HOST, host.enable_encrypt);
		host.enable_encrypt =
			XSTRDUP(MTYPE_HOST, zencrypt(host.enable));
	}

	return CMD_SUCCESS;
}

DEFUN (no_service_password_encrypt,
       no_service_password_encrypt_cmd,
       "no service password-encryption",
       NO_STR
       "Set up miscellaneous service\n"
       "Enable encrypted passwords\n")
{
	if (!host.encrypt)
		return CMD_SUCCESS;

	host.encrypt = 0;

	if (host.password_encrypt)
		XFREE(MTYPE_HOST, host.password_encrypt);
	host.password_encrypt = NULL;

	if (host.enable_encrypt)
		XFREE(MTYPE_HOST, host.enable_encrypt);
	host.enable_encrypt = NULL;

	return CMD_SUCCESS;
}

DEFUN (config_terminal_length,
       config_terminal_length_cmd,
       "terminal length (0-512)",
       "Set terminal line parameters\n"
       "Set number of lines on a screen\n"
       "Number of lines on screen (0 for no pausing)\n")
{
	int idx_number = 2;

	vty->lines = atoi(argv[idx_number]->arg);

	return CMD_SUCCESS;
}

DEFUN (config_terminal_no_length,
       config_terminal_no_length_cmd,
       "terminal no length",
       "Set terminal line parameters\n"
       NO_STR
       "Set number of lines on a screen\n")
{
	vty->lines = -1;
	return CMD_SUCCESS;
}

DEFUN (service_terminal_length,
       service_terminal_length_cmd,
       "service terminal-length (0-512)",
       "Set up miscellaneous service\n"
       "System wide terminal length configuration\n"
       "Number of lines of VTY (0 means no line control)\n")
{
	int idx_number = 2;

	host.lines = atoi(argv[idx_number]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_service_terminal_length,
       no_service_terminal_length_cmd,
       "no service terminal-length [(0-512)]",
       NO_STR
       "Set up miscellaneous service\n"
       "System wide terminal length configuration\n"
       "Number of lines of VTY (0 means no line control)\n")
{
	host.lines = -1;
	return CMD_SUCCESS;
}

DEFUN_HIDDEN (do_echo,
              echo_cmd,
              "echo MESSAGE...",
              "Echo a message back to the vty\n"
              "The message to echo\n")
{
	char *message;

	vty_out(vty, "%s\n",
		((message = argv_concat(argv, argc, 1)) ? message : ""));
	if (message)
		XFREE(MTYPE_TMP, message);
	return CMD_SUCCESS;
}

DEFUN (config_logmsg,
       config_logmsg_cmd,
       "logmsg <emergencies|alerts|critical|errors|warnings|notifications|informational|debugging> MESSAGE...",
       "Send a message to enabled logging destinations\n"
       LOG_LEVEL_DESC
       "The message to send\n")
{
	int idx_log_level = 1;
	int idx_message = 2;
	int level;
	char *message;

	level = log_level_match(argv[idx_log_level]->arg);
	if (level == ZLOG_DISABLED)
		return CMD_ERR_NO_MATCH;

	zlog(level, "%s",
	     ((message = argv_concat(argv, argc, idx_message)) ? message : ""));
	if (message)
		XFREE(MTYPE_TMP, message);

	return CMD_SUCCESS;
}

DEFUN (debug_memstats,
       debug_memstats_cmd,
       "[no] debug memstats-at-exit",
       NO_STR
       DEBUG_STR
       "Print memory type statistics at exit\n")
{
	debug_memstats_at_exit = !!strcmp(argv[0]->text, "no");
	return CMD_SUCCESS;
}

int cmd_banner_motd_file(const char *file)
{
	int success = CMD_SUCCESS;
	char p[PATH_MAX];
	char *rpath;
	char *in;

	rpath = realpath(file, p);
	if (!rpath)
		return CMD_ERR_NO_FILE;
	in = strstr(rpath, SYSCONFDIR);
	if (in == rpath) {
		XFREE(MTYPE_HOST, host.motdfile);
		host.motdfile = XSTRDUP(MTYPE_HOST, file);
	} else
		success = CMD_WARNING_CONFIG_FAILED;

	return success;
}

void cmd_banner_motd_line(const char *line)
{
	XFREE(MTYPE_HOST, host.motd);
	host.motd = XSTRDUP(MTYPE_HOST, line);
}

DEFUN (banner_motd_file,
       banner_motd_file_cmd,
       "banner motd file FILE",
       "Set banner\n"
       "Banner for motd\n"
       "Banner from a file\n"
       "Filename\n")
{
	int idx_file = 3;
	const char *filename = argv[idx_file]->arg;
	int cmd = cmd_banner_motd_file(filename);

	if (cmd == CMD_ERR_NO_FILE)
		vty_out(vty, "%s does not exist\n", filename);
	else if (cmd == CMD_WARNING_CONFIG_FAILED)
		vty_out(vty, "%s must be in %s\n", filename, SYSCONFDIR);

	return cmd;
}

DEFUN (banner_motd_line,
       banner_motd_line_cmd,
       "banner motd line LINE...",
       "Set banner\n"
       "Banner for motd\n"
       "Banner from an input\n"
       "Text\n")
{
	int idx = 0;
	char *motd;

	argv_find(argv, argc, "LINE", &idx);
	motd = argv_concat(argv, argc, idx);

	cmd_banner_motd_line(motd);
	XFREE(MTYPE_TMP, motd);

	return CMD_SUCCESS;
}

DEFUN (banner_motd_default,
       banner_motd_default_cmd,
       "banner motd default",
       "Set banner string\n"
       "Strings for motd\n"
       "Default string\n")
{
	cmd_banner_motd_line(FRR_DEFAULT_MOTD);
	return CMD_SUCCESS;
}

DEFUN (no_banner_motd,
       no_banner_motd_cmd,
       "no banner motd",
       NO_STR
       "Set banner string\n"
       "Strings for motd\n")
{
	host.motd = NULL;
	if (host.motdfile)
		XFREE(MTYPE_HOST, host.motdfile);
	host.motdfile = NULL;
	return CMD_SUCCESS;
}

DEFUN(allow_reserved_ranges, allow_reserved_ranges_cmd, "allow-reserved-ranges",
      "Allow using IPv4 (Class E) reserved IP space\n")
{
	host.allow_reserved_ranges = true;
	return CMD_SUCCESS;
}

DEFUN(no_allow_reserved_ranges, no_allow_reserved_ranges_cmd,
      "no allow-reserved-ranges",
      NO_STR "Allow using IPv4 (Class E) reserved IP space\n")
{
	host.allow_reserved_ranges = false;
	return CMD_SUCCESS;
}

int cmd_find_cmds(struct vty *vty, struct cmd_token **argv, int argc)
{
	const struct cmd_node *node;
	const struct cmd_element *cli;
	vector clis;

	regex_t exp = {};

	char *pattern = argv_concat(argv, argc, 1);
	int cr = regcomp(&exp, pattern, REG_NOSUB | REG_EXTENDED);
	XFREE(MTYPE_TMP, pattern);

	if (cr != 0) {
		switch (cr) {
		case REG_BADBR:
			vty_out(vty, "%% Invalid {...} expression\n");
			break;
		case REG_BADRPT:
			vty_out(vty, "%% Bad repetition operator\n");
			break;
		case REG_BADPAT:
			vty_out(vty, "%% Regex syntax error\n");
			break;
		case REG_ECOLLATE:
			vty_out(vty, "%% Invalid collating element\n");
			break;
		case REG_ECTYPE:
			vty_out(vty, "%% Invalid character class name\n");
			break;
		case REG_EESCAPE:
			vty_out(vty,
				"%% Regex ended with escape character (\\)\n");
			break;
		case REG_ESUBREG:
			vty_out(vty,
				"%% Invalid number in \\digit construction\n");
			break;
		case REG_EBRACK:
			vty_out(vty, "%% Unbalanced square brackets\n");
			break;
		case REG_EPAREN:
			vty_out(vty, "%% Unbalanced parentheses\n");
			break;
		case REG_EBRACE:
			vty_out(vty, "%% Unbalanced braces\n");
			break;
		case REG_ERANGE:
			vty_out(vty,
				"%% Invalid endpoint in range expression\n");
			break;
		case REG_ESPACE:
			vty_out(vty, "%% Failed to compile (out of memory)\n");
			break;
		}

		goto done;
	}


	for (unsigned int i = 0; i < vector_active(cmdvec); i++) {
		node = vector_slot(cmdvec, i);
		if (!node)
			continue;
		clis = node->cmd_vector;
		for (unsigned int j = 0; j < vector_active(clis); j++) {
			cli = vector_slot(clis, j);

			if (regexec(&exp, cli->string, 0, NULL, 0) == 0) {
				vty_out(vty, "  (%s)  ", node->name);
				print_cmd(vty, cli->string);
			}
		}
	}

done:
	regfree(&exp);
	return CMD_SUCCESS;
}

DEFUN(find,
      find_cmd,
      "find REGEX...",
      "Find CLI command matching a regular expression\n"
      "Search pattern (POSIX regex)\n")
{
	return cmd_find_cmds(vty, argv, argc);
}

#if defined(DEV_BUILD) && defined(HAVE_SCRIPTING)
DEFUN(script, script_cmd, "script SCRIPT FUNCTION",
      "Test command - execute a function in a script\n"
      "Script name (same as filename in /etc/frr/scripts/)\n"
      "Function name (in the script)\n")
{
	struct prefix p;

	(void)str2prefix("1.2.3.4/24", &p);
	struct frrscript *fs = frrscript_new(argv[1]->arg);

	if (frrscript_load(fs, argv[2]->arg, NULL)) {
		vty_out(vty,
			"/etc/frr/scripts/%s.lua or function '%s' not found\n",
			argv[1]->arg, argv[2]->arg);
	}

	int ret = frrscript_call(fs, argv[2]->arg, ("p", &p));
	char buf[40];
	prefix2str(&p, buf, sizeof(buf));
	vty_out(vty, "p: %s\n", buf);
	vty_out(vty, "Script result: %d\n", ret);

	frrscript_delete(fs);

	return CMD_SUCCESS;
}
#endif

/* Set config filename.  Called from vty.c */
void host_config_set(const char *filename)
{
	XFREE(MTYPE_HOST, host.config);
	host.config = XSTRDUP(MTYPE_HOST, filename);
}

const char *host_config_get(void)
{
	return host.config;
}

void cmd_show_lib_debugs(struct vty *vty)
{
	route_map_show_debug(vty);
	debug_status_write(vty);
}

void install_default(enum node_type node)
{
	_install_element(node, &config_exit_cmd);
	_install_element(node, &config_quit_cmd);
	_install_element(node, &config_end_cmd);
	_install_element(node, &config_help_cmd);
	_install_element(node, &config_list_cmd);
	_install_element(node, &show_cli_graph_cmd);
	_install_element(node, &find_cmd);

	_install_element(node, &config_write_cmd);
	_install_element(node, &show_running_config_cmd);

	_install_element(node, &autocomplete_cmd);

	nb_cli_install_default(node);
}

/* Initialize command interface. Install basic nodes and commands.
 *
 * terminal = 0 -- vtysh / no logging, no config control
 * terminal = 1 -- normal daemon
 * terminal = -1 -- watchfrr / no logging, but minimal config control */
void cmd_init(int terminal)
{
	struct utsname names;

	uname(&names);
	qobj_init();

	/* register command preprocessors */
	hook_register(cmd_execute, handle_pipe_action);
	hook_register(cmd_execute_done, handle_pipe_action_done);

	varhandlers = list_new();

	/* Allocate initial top vector of commands. */
	cmdvec = vector_init(VECTOR_MIN_SIZE);

	/* Default host value settings. */
	host.name = XSTRDUP(MTYPE_HOST, names.nodename);
	host.system = XSTRDUP(MTYPE_HOST, names.sysname);
	host.release = XSTRDUP(MTYPE_HOST, names.release);
	host.version = XSTRDUP(MTYPE_HOST, names.version);

#ifdef HAVE_STRUCT_UTSNAME_DOMAINNAME
	if ((strcmp(names.domainname, "(none)") == 0))
		host.domainname = NULL;
	else
		host.domainname = XSTRDUP(MTYPE_HOST, names.domainname);
#else
	host.domainname = NULL;
#endif
	host.password = NULL;
	host.enable = NULL;
	host.config = NULL;
	host.noconfig = (terminal < 0);
	host.lines = -1;
	cmd_banner_motd_line(FRR_DEFAULT_MOTD);
	host.motdfile = NULL;
	host.allow_reserved_ranges = false;

	/* Install top nodes. */
	install_node(&view_node);
	install_node(&enable_node);
	install_node(&auth_node);
	install_node(&auth_enable_node);
	install_node(&config_node);

	/* Each node's basic commands. */
	install_element(VIEW_NODE, &show_version_cmd);
	install_element(ENABLE_NODE, &show_startup_config_cmd);

	if (terminal) {
		install_element(ENABLE_NODE, &debug_memstats_cmd);

		install_element(VIEW_NODE, &config_list_cmd);
		install_element(VIEW_NODE, &config_exit_cmd);
		install_element(VIEW_NODE, &config_quit_cmd);
		install_element(VIEW_NODE, &config_help_cmd);
		install_element(VIEW_NODE, &config_enable_cmd);
		install_element(VIEW_NODE, &config_terminal_length_cmd);
		install_element(VIEW_NODE, &config_terminal_no_length_cmd);
		install_element(VIEW_NODE, &show_commandtree_cmd);
		install_element(VIEW_NODE, &echo_cmd);
		install_element(VIEW_NODE, &autocomplete_cmd);
		install_element(VIEW_NODE, &find_cmd);
#if defined(DEV_BUILD) && defined(HAVE_SCRIPTING)
		install_element(VIEW_NODE, &script_cmd);
#endif


		install_element(ENABLE_NODE, &config_end_cmd);
		install_element(ENABLE_NODE, &config_disable_cmd);
		install_element(ENABLE_NODE, &config_terminal_cmd);
		install_element(ENABLE_NODE, &copy_runningconf_startupconf_cmd);
		install_element(ENABLE_NODE, &config_write_cmd);
		install_element(ENABLE_NODE, &show_running_config_cmd);
		install_element(ENABLE_NODE, &config_logmsg_cmd);

		install_default(CONFIG_NODE);

		event_cmd_init();
		workqueue_cmd_init();
		hash_cmd_init();
	}

	install_element(CONFIG_NODE, &hostname_cmd);
	install_element(CONFIG_NODE, &no_hostname_cmd);
	install_element(CONFIG_NODE, &domainname_cmd);
	install_element(CONFIG_NODE, &no_domainname_cmd);

	if (terminal > 0) {
		full_cli = true;

		install_element(CONFIG_NODE, &debug_memstats_cmd);

		install_element(CONFIG_NODE, &password_cmd);
		install_element(CONFIG_NODE, &no_password_cmd);
		install_element(CONFIG_NODE, &enable_password_cmd);
		install_element(CONFIG_NODE, &no_enable_password_cmd);

		install_element(CONFIG_NODE, &service_password_encrypt_cmd);
		install_element(CONFIG_NODE, &no_service_password_encrypt_cmd);
		install_element(CONFIG_NODE, &banner_motd_default_cmd);
		install_element(CONFIG_NODE, &banner_motd_file_cmd);
		install_element(CONFIG_NODE, &banner_motd_line_cmd);
		install_element(CONFIG_NODE, &no_banner_motd_cmd);
		install_element(CONFIG_NODE, &service_terminal_length_cmd);
		install_element(CONFIG_NODE, &no_service_terminal_length_cmd);
		install_element(CONFIG_NODE, &allow_reserved_ranges_cmd);
		install_element(CONFIG_NODE, &no_allow_reserved_ranges_cmd);

		log_cmd_init();
		vrf_install_commands();
	}

#ifdef DEV_BUILD
	grammar_sandbox_init();
#endif
}

void cmd_terminate(void)
{
	struct cmd_node *cmd_node;

	hook_unregister(cmd_execute, handle_pipe_action);
	hook_unregister(cmd_execute_done, handle_pipe_action_done);

	if (cmdvec) {
		for (unsigned int i = 0; i < vector_active(cmdvec); i++)
			if ((cmd_node = vector_slot(cmdvec, i)) != NULL) {
				// deleting the graph delets the cmd_element as
				// well
				graph_delete_graph(cmd_node->cmdgraph);
				vector_free(cmd_node->cmd_vector);
				hash_clean_and_free(&cmd_node->cmd_hash, NULL);
			}

		vector_free(cmdvec);
		cmdvec = NULL;
	}

	XFREE(MTYPE_HOST, host.name);
	XFREE(MTYPE_HOST, host.system);
	XFREE(MTYPE_HOST, host.release);
	XFREE(MTYPE_HOST, host.version);
	XFREE(MTYPE_HOST, host.domainname);
	XFREE(MTYPE_HOST, host.password);
	XFREE(MTYPE_HOST, host.password_encrypt);
	XFREE(MTYPE_HOST, host.enable);
	XFREE(MTYPE_HOST, host.enable_encrypt);
	XFREE(MTYPE_HOST, host.motdfile);
	XFREE(MTYPE_HOST, host.config);
	XFREE(MTYPE_HOST, host.motd);

	list_delete(&varhandlers);
	qobj_finish();
}
