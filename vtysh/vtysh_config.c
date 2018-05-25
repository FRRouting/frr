/* Configuration generator.
 * Copyright (C) 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "linklist.h"
#include "memory.h"

#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"

DEFINE_MGROUP(MVTYSH, "vtysh")
DEFINE_MTYPE_STATIC(MVTYSH, VTYSH_CONFIG, "Vtysh configuration")
DEFINE_MTYPE_STATIC(MVTYSH, VTYSH_CONFIG_LINE, "Vtysh configuration line")

vector configvec;

struct config {
	/* Configuration node name. */
	char *name;

	/* Configuration string line. */
	struct list *line;

	/* Configuration can be nest. */
	struct config *config;

	/* Index of this config. */
	uint32_t index;
};

struct list *config_top;

static int line_cmp(char *c1, char *c2)
{
	return strcmp(c1, c2);
}

static void line_del(char *line)
{
	XFREE(MTYPE_VTYSH_CONFIG_LINE, line);
}

static struct config *config_new(void)
{
	struct config *config;
	config = XCALLOC(MTYPE_VTYSH_CONFIG, sizeof(struct config));
	return config;
}

static int config_cmp(struct config *c1, struct config *c2)
{
	return strcmp(c1->name, c2->name);
}

static void config_del(struct config *config)
{
	list_delete_and_null(&config->line);
	if (config->name)
		XFREE(MTYPE_VTYSH_CONFIG_LINE, config->name);
	XFREE(MTYPE_VTYSH_CONFIG, config);
}

static struct config *config_get(int index, const char *line)
{
	struct config *config;
	struct config *config_loop;
	struct list *master;
	struct listnode *node, *nnode;

	config = config_loop = NULL;

	master = vector_lookup_ensure(configvec, index);

	if (!master) {
		master = list_new();
		master->del = (void (*)(void *))config_del;
		master->cmp = (int (*)(void *, void *))config_cmp;
		vector_set_index(configvec, index, master);
	}

	for (ALL_LIST_ELEMENTS(master, node, nnode, config_loop)) {
		if (strcmp(config_loop->name, line) == 0)
			config = config_loop;
	}

	if (!config) {
		config = config_new();
		config->line = list_new();
		config->line->del = (void (*)(void *))line_del;
		config->line->cmp = (int (*)(void *, void *))line_cmp;
		config->name = XSTRDUP(MTYPE_VTYSH_CONFIG_LINE, line);
		config->index = index;
		listnode_add(master, config);
	}
	return config;
}

void config_add_line(struct list *config, const char *line)
{
	listnode_add(config, XSTRDUP(MTYPE_VTYSH_CONFIG_LINE, line));
}

static void config_add_line_uniq(struct list *config, const char *line)
{
	struct listnode *node, *nnode;
	char *pnt;

	for (ALL_LIST_ELEMENTS(config, node, nnode, pnt)) {
		if (strcmp(pnt, line) == 0)
			return;
	}
	listnode_add_sort(config, XSTRDUP(MTYPE_VTYSH_CONFIG_LINE, line));
}

/*
 * I want to explicitly move this command to the end of the line
 */
static void config_add_line_end(struct list *config, const char *line)
{
	struct listnode *node;
	void *item = XSTRDUP(MTYPE_VTYSH_CONFIG_LINE, line);

	listnode_add(config, item);
	node = listnode_lookup(config, item);
	if (node)
		listnode_move_to_tail(config, node);
}

void vtysh_config_parse_line(void *arg, const char *line)
{
	char c;
	static struct config *config = NULL;

	if (!line)
		return;

	c = line[0];

	if (c == '\0')
		return;

	/* printf ("[%s]\n", line); */

	switch (c) {
	/* Suppress exclamation points ! and commented lines. The !s are
	 * generated
	 * dynamically in vtysh_config_dump() */
	case '!':
	case '#':
		break;
	case ' ':
		/* Store line to current configuration. */
		if (config) {
			if (strncmp(line, " link-params",
				    strlen(" link-params"))
			    == 0) {
				config_add_line(config->line, line);
				config->index = LINK_PARAMS_NODE;
			} else if (strncmp(line, " ip multicast boundary",
					   strlen(" ip multicast boundary"))
				   == 0) {
				config_add_line_end(config->line, line);
			} else if (config->index == LINK_PARAMS_NODE
				   && strncmp(line, "  exit-link-params",
					      strlen("  exit"))
					      == 0) {
				config_add_line(config->line, line);
				config->index = INTERFACE_NODE;
			} else if (config->index == VRF_NODE
				   && strncmp(line, " exit-vrf",
					      strlen(" exit-vrf"))
					      == 0) {
				config_add_line(config->line, line);
				config->index = CONFIG_NODE;
			} else if (config->index == RMAP_NODE
				   || config->index == INTERFACE_NODE
				   || config->index == LOGICALROUTER_NODE
				   || config->index == VTY_NODE
				   || config->index == VRF_NODE)
				config_add_line_uniq(config->line, line);
			else
				config_add_line(config->line, line);
		} else
			config_add_line(config_top, line);
		break;
	default:
		if (strncmp(line, "interface", strlen("interface")) == 0)
			config = config_get(INTERFACE_NODE, line);
		else if (strncmp(line, "pseudowire", strlen("pseudowire")) == 0)
			config = config_get(PW_NODE, line);
		else if (strncmp(line, "logical-router", strlen("logical-router")) == 0)
			config = config_get(LOGICALROUTER_NODE, line);
		else if (strncmp(line, "vrf", strlen("vrf")) == 0)
			config = config_get(VRF_NODE, line);
		else if (strncmp(line, "nexthop-group", strlen("nexthop-group"))
			 == 0)
			config = config_get(NH_GROUP_NODE, line);
		else if (strncmp(line, "router-id", strlen("router-id")) == 0)
			config = config_get(ZEBRA_NODE, line);
		else if (strncmp(line, "router rip", strlen("router rip")) == 0)
			config = config_get(RIP_NODE, line);
		else if (strncmp(line, "router ripng", strlen("router ripng"))
			 == 0)
			config = config_get(RIPNG_NODE, line);
		else if (strncmp(line, "router eigrp", strlen("router eigrp"))
			 == 0)
			config = config_get(EIGRP_NODE, line);
		else if (strncmp(line, "router babel", strlen("router babel"))
			 == 0)
			config = config_get(BABEL_NODE, line);
		else if (strncmp(line, "router ospf", strlen("router ospf"))
			 == 0)
			config = config_get(OSPF_NODE, line);
		else if (strncmp(line, "router ospf6", strlen("router ospf6"))
			 == 0)
			config = config_get(OSPF6_NODE, line);
		else if (strncmp(line, "mpls ldp", strlen("mpls ldp")) == 0)
			config = config_get(LDP_NODE, line);
		else if (strncmp(line, "l2vpn", strlen("l2vpn")) == 0)
			config = config_get(LDP_L2VPN_NODE, line);
		else if (strncmp(line, "router bgp", strlen("router bgp")) == 0)
			config = config_get(BGP_NODE, line);
		else if (strncmp(line, "router isis", strlen("router isis"))
			 == 0)
			config = config_get(ISIS_NODE, line);
		else if (strncmp(line, "route-map", strlen("route-map")) == 0)
			config = config_get(RMAP_NODE, line);
		else if (strncmp(line, "pbr-map", strlen("pbr-map")) == 0)
			config = config_get(PBRMAP_NODE, line);
		else if (strncmp(line, "access-list", strlen("access-list"))
			 == 0)
			config = config_get(ACCESS_NODE, line);
		else if (strncmp(line, "ipv6 access-list",
				 strlen("ipv6 access-list"))
			 == 0)
			config = config_get(ACCESS_IPV6_NODE, line);
		else if (strncmp(line, "mac access-list",
				 strlen("mac access-list"))
			 == 0)
			config = config_get(ACCESS_MAC_NODE, line);
		else if (strncmp(line, "ip prefix-list",
				 strlen("ip prefix-list"))
			 == 0)
			config = config_get(PREFIX_NODE, line);
		else if (strncmp(line, "ipv6 prefix-list",
				 strlen("ipv6 prefix-list"))
			 == 0)
			config = config_get(PREFIX_IPV6_NODE, line);
		else if (strncmp(line, "ip as-path access-list",
				 strlen("ip as-path access-list"))
			 == 0)
			config = config_get(AS_LIST_NODE, line);
		else if (strncmp(line, "ip community-list",
				 strlen("ip community-list"))
				 == 0
			 || strncmp(line, "ip extcommunity-list",
				    strlen("ip extcommunity-list"))
				    == 0
			 || strncmp(line, "ip large-community-list",
				    strlen("ip large-community-list"))
				    == 0)
			config = config_get(COMMUNITY_LIST_NODE, line);
		else if (strncmp(line, "ip route", strlen("ip route")) == 0)
			config = config_get(IP_NODE, line);
		else if (strncmp(line, "ipv6 route", strlen("ipv6 route")) == 0)
			config = config_get(IP_NODE, line);
		else if (strncmp(line, "key", strlen("key")) == 0)
			config = config_get(KEYCHAIN_NODE, line);
		else if (strncmp(line, "line", strlen("line")) == 0)
			config = config_get(VTY_NODE, line);
		else if ((strncmp(line, "ipv6 forwarding",
				  strlen("ipv6 forwarding"))
			  == 0)
			 || (strncmp(line, "ip forwarding",
				     strlen("ip forwarding"))
			     == 0))
			config = config_get(FORWARDING_NODE, line);
		else if (strncmp(line, "debug vrf", strlen("debug vrf")) == 0)
			config = config_get(VRF_DEBUG_NODE, line);
		else if (strncmp(line, "debug", strlen("debug")) == 0)
			config = config_get(DEBUG_NODE, line);
		else if (strncmp(line, "password", strlen("password")) == 0
			 || strncmp(line, "enable password",
				    strlen("enable password"))
				    == 0)
			config = config_get(AAA_NODE, line);
		else if (strncmp(line, "ip protocol", strlen("ip protocol"))
			 == 0)
			config = config_get(PROTOCOL_NODE, line);
		else if (strncmp(line, "ipv6 protocol", strlen("ipv6 protocol"))
			 == 0)
			config = config_get(PROTOCOL_NODE, line);
		else if (strncmp(line, "ip nht", strlen("ip nht")) == 0)
			config = config_get(PROTOCOL_NODE, line);
		else if (strncmp(line, "ipv6 nht", strlen("ipv6 nht")) == 0)
			config = config_get(PROTOCOL_NODE, line);
		else if (strncmp(line, "mpls", strlen("mpls")) == 0)
			config = config_get(MPLS_NODE, line);
		else {
			if (strncmp(line, "log", strlen("log")) == 0
			    || strncmp(line, "hostname", strlen("hostname"))
				       == 0
			    || strncmp(line, "frr", strlen("frr")) == 0
			    || strncmp(line, "agentx", strlen("agentx")) == 0
			    || strncmp(line, "no log", strlen("no log")) == 0)
				config_add_line_uniq(config_top, line);
			else
				config_add_line(config_top, line);
			config = NULL;
		}
		break;
	}
}

/* Macro to check delimiter is needed between each configuration line
 * or not. */
#define NO_DELIMITER(I)                                                        \
	((I) == ACCESS_NODE || (I) == PREFIX_NODE || (I) == IP_NODE            \
	 || (I) == AS_LIST_NODE || (I) == COMMUNITY_LIST_NODE                  \
	 || (I) == ACCESS_IPV6_NODE || (I) == ACCESS_MAC_NODE                  \
	 || (I) == PREFIX_IPV6_NODE || (I) == FORWARDING_NODE                  \
	 || (I) == DEBUG_NODE || (I) == AAA_NODE || (I) == VRF_DEBUG_NODE      \
	 || (I) == MPLS_NODE)

/* Display configuration to file pointer. */
void vtysh_config_dump(void)
{
	struct listnode *node, *nnode;
	struct listnode *mnode, *mnnode;
	struct config *config;
	struct list *master;
	char *line;
	unsigned int i;

	for (ALL_LIST_ELEMENTS(config_top, node, nnode, line))
		vty_out(vty, "%s\n", line);

	vty_out(vty, "!\n");

	for (i = 0; i < vector_active(configvec); i++)
		if ((master = vector_slot(configvec, i)) != NULL) {
			for (ALL_LIST_ELEMENTS(master, node, nnode, config)) {
				/* Don't print empty sections for interface.
				 * Route maps on the
				 * other hand could have a legitimate empty
				 * section at the end.
				 * VRF is handled in the backend, we could have
				 * "configured" VRFs with static routes which
				 * are not under the VRF node.
				 */
				if (config->index == INTERFACE_NODE
				    && list_isempty(config->line))
					continue;

				vty_out(vty, "%s\n", config->name);

				for (ALL_LIST_ELEMENTS(config->line, mnode,
						       mnnode, line))
					vty_out(vty, "%s\n", line);
				if (!NO_DELIMITER(i))
					vty_out(vty, "!\n");
			}
			if (NO_DELIMITER(i))
				vty_out(vty, "!\n");
		}

	for (i = 0; i < vector_active(configvec); i++)
		if ((master = vector_slot(configvec, i)) != NULL) {
			list_delete_and_null(&master);
			vector_slot(configvec, i) = NULL;
		}
	list_delete_all_node(config_top);
}

/* Read up configuration file from file_name. */
static int vtysh_read_file(FILE *confp)
{
	struct vty *vty;
	int ret;

	vty = vty_new();
	vty->wfd = STDERR_FILENO;
	vty->type = VTY_TERM;
	vty->node = CONFIG_NODE;

	vtysh_execute_no_pager("enable");
	vtysh_execute_no_pager("configure terminal");

	/* Execute configuration file. */
	ret = vtysh_config_from_file(vty, confp);

	vtysh_execute_no_pager("end");
	vtysh_execute_no_pager("disable");

	vty_close(vty);

	return (ret);
}

/* Read up configuration file from config_default_dir. */
int vtysh_read_config(const char *config_default_dir)
{
	FILE *confp = NULL;
	int ret;

	confp = fopen(config_default_dir, "r");
	if (confp == NULL) {
		fprintf(stderr,
			"%% Can't open configuration file %s due to '%s'.\n",
			config_default_dir, safe_strerror(errno));
		return (CMD_ERR_NO_FILE);
	}

	ret = vtysh_read_file(confp);
	fclose(confp);

	return (ret);
}

/* We don't write vtysh specific into file from vtysh. vtysh.conf should
 * be edited by hand. So, we handle only "write terminal" case here and
 * integrate vtysh specific conf with conf from daemons.
 */
void vtysh_config_write()
{
	char line[81];

	if (cmd_hostname_get()) {
		sprintf(line, "hostname %s", cmd_hostname_get());
		vtysh_config_parse_line(NULL, line);
	}

	if (cmd_domainname_get()) {
		sprintf(line, "domainname %s", cmd_domainname_get());
		vtysh_config_parse_line(NULL, line);
	}
	if (vtysh_write_integrated == WRITE_INTEGRATED_NO)
		vtysh_config_parse_line(NULL,
					"no service integrated-vtysh-config");
	if (vtysh_write_integrated == WRITE_INTEGRATED_YES)
		vtysh_config_parse_line(NULL,
					"service integrated-vtysh-config");

	user_config_write();
}

void vtysh_config_init()
{
	config_top = list_new();
	config_top->del = (void (*)(void *))line_del;
	configvec = vector_init(1);
}
