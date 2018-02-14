/* pbr_map => "pbr-policy (1-100000)$seqno {src <A.B.C.D/M|X:X::X:X/M>$src|dest <A.B.C.D/M|X:X::X:X/M>$dst} nexthop-group NAME$nhgroup" */
DEFUN_CMD_FUNC_DECL(pbr_map)
#define funcdecl_pbr_map static int pbr_map_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	long seqno,\
	const char * seqno_str __attribute__ ((unused)),\
	const struct prefix * src,\
	const char * src_str __attribute__ ((unused)),\
	const struct prefix * dst,\
	const char * dst_str __attribute__ ((unused)),\
	const char * nhgroup)
funcdecl_pbr_map;
DEFUN_CMD_FUNC_TEXT(pbr_map)
{
#if 4 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	long seqno = 0;
	const char *seqno_str = NULL;
	struct prefix src = { };
	const char *src_str = NULL;
	struct prefix dst = { };
	const char *dst_str = NULL;
	const char *nhgroup = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "seqno")) {
			seqno_str = argv[_i]->arg;
			char *_end;
			seqno = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
		if (!strcmp(argv[_i]->varname, "src")) {
			src_str = argv[_i]->arg;
			_fail = !str2prefix(argv[_i]->arg, &src);
		}
		if (!strcmp(argv[_i]->varname, "dst")) {
			dst_str = argv[_i]->arg;
			_fail = !str2prefix(argv[_i]->arg, &dst);
		}
		if (!strcmp(argv[_i]->varname, "nhgroup")) {
			nhgroup = argv[_i]->arg;
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
	return pbr_map_magic(self, vty, argc, argv, seqno, seqno_str, &src, src_str, &dst, dst_str, nhgroup);
}

