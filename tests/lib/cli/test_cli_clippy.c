/* magic_test => "magic (0-100) {ipv4net A.B.C.D/M|X:X::X:X$ipv6}" */
DEFUN_CMD_FUNC_DECL(magic_test)
#define funcdecl_magic_test static int magic_test_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	long magic,\
	const char * magic_str __attribute__ ((unused)),\
	const struct prefix_ipv4 * ipv4net,\
	const char * ipv4net_str __attribute__ ((unused)),\
	struct in6_addr ipv6,\
	const char * ipv6_str __attribute__ ((unused)))
funcdecl_magic_test;
DEFUN_CMD_FUNC_TEXT(magic_test)
{
#if 3 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	long magic = 0;
	const char *magic_str = NULL;
	struct prefix_ipv4 ipv4net = { };
	const char *ipv4net_str = NULL;
	struct in6_addr ipv6 = IN6ADDR_ANY_INIT;
	const char *ipv6_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "magic")) {
			magic_str = argv[_i]->arg;
			char *_end;
			magic = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
		if (!strcmp(argv[_i]->varname, "ipv4net")) {
			ipv4net_str = argv[_i]->arg;
			_fail = !str2prefix_ipv4(argv[_i]->arg, &ipv4net);
		}
		if (!strcmp(argv[_i]->varname, "ipv6")) {
			ipv6_str = argv[_i]->arg;
			_fail = !inet_pton(AF_INET6, argv[_i]->arg, &ipv6);
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
	return magic_test_magic(self, vty, argc, argv, magic, magic_str, &ipv4net, ipv4net_str, ipv6, ipv6_str);
}

