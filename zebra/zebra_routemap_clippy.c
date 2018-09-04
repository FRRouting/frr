/* ip_protocol => "[no] ip protocol RR_IP_PROTOCOL_MAP_STR_ZEBR $proto route-map ROUTE-MAP$rmap" */
DEFUN_CMD_FUNC_DECL(ip_protocol)
#define funcdecl_ip_protocol static int ip_protocol_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	const char * proto,\
	const char * rmap)
funcdecl_ip_protocol;
DEFUN_CMD_FUNC_TEXT(ip_protocol)
{
#if 3 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	const char *proto = NULL;
	const char *rmap = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "proto")) {
			proto = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rmap")) {
			rmap = argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ip_protocol_magic(self, vty, argc, argv, no, proto, rmap);
}

/* ip_protocol_vrf => "[no] ip protocol RR_IP_PROTOCOL_MAP_STR_ZEBR $proto route-map ROUTE-MAP$rmap" */
DEFUN_CMD_FUNC_DECL(ip_protocol_vrf)
#define funcdecl_ip_protocol_vrf static int ip_protocol_vrf_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	const char * proto,\
	const char * rmap)
funcdecl_ip_protocol_vrf;
DEFUN_CMD_FUNC_TEXT(ip_protocol_vrf)
{
#if 3 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	const char *proto = NULL;
	const char *rmap = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "proto")) {
			proto = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rmap")) {
			rmap = argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ip_protocol_vrf_magic(self, vty, argc, argv, no, proto, rmap);
}

/* ipv6_protocol => "[no] ipv6 protocol RR_IP6_PROTOCOL_MAP_STR_ZEBR $proto route-map ROUTE-MAP$rmap" */
DEFUN_CMD_FUNC_DECL(ipv6_protocol)
#define funcdecl_ipv6_protocol static int ipv6_protocol_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	const char * proto,\
	const char * rmap)
funcdecl_ipv6_protocol;
DEFUN_CMD_FUNC_TEXT(ipv6_protocol)
{
#if 3 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	const char *proto = NULL;
	const char *rmap = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "proto")) {
			proto = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rmap")) {
			rmap = argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ipv6_protocol_magic(self, vty, argc, argv, no, proto, rmap);
}

/* ipv6_protocol_vrf => "[no] ipv6 protocol RR_IP6_PROTOCOL_MAP_STR_ZEBR $proto route-map ROUTE-MAP$rmap" */
DEFUN_CMD_FUNC_DECL(ipv6_protocol_vrf)
#define funcdecl_ipv6_protocol_vrf static int ipv6_protocol_vrf_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	const char * proto,\
	const char * rmap)
funcdecl_ipv6_protocol_vrf;
DEFUN_CMD_FUNC_TEXT(ipv6_protocol_vrf)
{
#if 3 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	const char *proto = NULL;
	const char *rmap = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "proto")) {
			proto = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rmap")) {
			rmap = argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ipv6_protocol_vrf_magic(self, vty, argc, argv, no, proto, rmap);
}
/* ip_protocol_nht_rmap => "[no] ip nht RR_IP_PROTOCOL_MAP_STR_ZEBR $proto route-map ROUTE-MAP$rmap" */
DEFUN_CMD_FUNC_DECL(ip_protocol_nht_rmap)
#define funcdecl_ip_protocol_nht_rmap static int ip_protocol_nht_rmap_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	const char * proto,\
	const char * rmap)
funcdecl_ip_protocol_nht_rmap;
DEFUN_CMD_FUNC_TEXT(ip_protocol_nht_rmap)
{
#if 3 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	const char *proto = NULL;
	const char *rmap = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "proto")) {
			proto = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rmap")) {
			rmap = argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ip_protocol_nht_rmap_magic(self, vty, argc, argv, no, proto, rmap);
}

/* ip_protocol_nht_rmap_vrf => "[no] ip nht RR_IP_PROTOCOL_MAP_STR_ZEBR $proto route-map ROUTE-MAP$rmap" */
DEFUN_CMD_FUNC_DECL(ip_protocol_nht_rmap_vrf)
#define funcdecl_ip_protocol_nht_rmap_vrf static int ip_protocol_nht_rmap_vrf_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	const char * proto,\
	const char * rmap)
funcdecl_ip_protocol_nht_rmap_vrf;
DEFUN_CMD_FUNC_TEXT(ip_protocol_nht_rmap_vrf)
{
#if 3 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	const char *proto = NULL;
	const char *rmap = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "proto")) {
			proto = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rmap")) {
			rmap = argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ip_protocol_nht_rmap_vrf_magic(self, vty, argc, argv, no, proto, rmap);
}
/* ipv6_protocol_nht_rmap => "[no] ipv6 protocol RR_IP6_PROTOCOL_MAP_STR_ZEBR $proto route-map ROUTE-MAP$rmap" */
DEFUN_CMD_FUNC_DECL(ipv6_protocol_nht_rmap)
#define funcdecl_ipv6_protocol_nht_rmap static int ipv6_protocol_nht_rmap_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	const char * proto,\
	const char * rmap)
funcdecl_ipv6_protocol_nht_rmap;
DEFUN_CMD_FUNC_TEXT(ipv6_protocol_nht_rmap)
{
#if 3 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	const char *proto = NULL;
	const char *rmap = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "proto")) {
			proto = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rmap")) {
			rmap = argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ipv6_protocol_nht_rmap_magic(self, vty, argc, argv, no, proto, rmap);
}

/* ipv6_protocol_nht_rmap_vrf => "[no] ipv6 protocol RR_IP6_PROTOCOL_MAP_STR_ZEBR $proto route-map ROUTE-MAP$rmap" */
DEFUN_CMD_FUNC_DECL(ipv6_protocol_nht_rmap_vrf)
#define funcdecl_ipv6_protocol_nht_rmap_vrf static int ipv6_protocol_nht_rmap_vrf_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	const char * no,\
	const char * proto,\
	const char * rmap)
funcdecl_ipv6_protocol_nht_rmap_vrf;
DEFUN_CMD_FUNC_TEXT(ipv6_protocol_nht_rmap_vrf)
{
#if 3 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	const char *no = NULL;
	const char *proto = NULL;
	const char *rmap = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "no")) {
			no = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "proto")) {
			proto = argv[_i]->arg;
		}
		if (!strcmp(argv[_i]->varname, "rmap")) {
			rmap = argv[_i]->arg;
		}
#if 0 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 0 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ipv6_protocol_nht_rmap_vrf_magic(self, vty, argc, argv, no, proto, rmap);
}
