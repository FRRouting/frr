/* ospf_router_id => "ospf router-id A.B.C.D" */
DEFUN_CMD_FUNC_DECL(ospf_router_id)
#define funcdecl_ospf_router_id static int ospf_router_id_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	struct in_addr router_id,\
	const char * router_id_str __attribute__ ((unused)))
funcdecl_ospf_router_id;
DEFUN_CMD_FUNC_TEXT(ospf_router_id)
{
#if 1 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	struct in_addr router_id = { INADDR_ANY };
	const char *router_id_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "router_id")) {
			router_id_str = argv[_i]->arg;
			_fail = !inet_aton(argv[_i]->arg, &router_id);
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return ospf_router_id_magic(self, vty, argc, argv, router_id, router_id_str);
}

/* no_ospf_router_id => "no ospf router-id [A.B.C.D]" */
DEFUN_CMD_FUNC_DECL(no_ospf_router_id)
#define funcdecl_no_ospf_router_id static int no_ospf_router_id_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	struct in_addr router_id,\
	const char * router_id_str __attribute__ ((unused)))
funcdecl_no_ospf_router_id;
DEFUN_CMD_FUNC_TEXT(no_ospf_router_id)
{
#if 1 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	struct in_addr router_id = { INADDR_ANY };
	const char *router_id_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "router_id")) {
			router_id_str = argv[_i]->arg;
			_fail = !inet_aton(argv[_i]->arg, &router_id);
		}
#if 1 /* anything that can fail? */
		if (_fail)
			vty_out (vty, "%% invalid input for %s: %s\n",
				   argv[_i]->varname, argv[_i]->arg);
		_failcnt += _fail;
#endif
	}
#if 1 /* anything that can fail? */
	if (_failcnt)
		return CMD_WARNING;
#endif
#endif
	return no_ospf_router_id_magic(self, vty, argc, argv, router_id, router_id_str);
}

