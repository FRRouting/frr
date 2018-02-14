/* lsa_set => "lsa set (0-999999)$idx {type (0-65535)|id A.B.C.D|adv A.B.C.D}" */
DEFUN_CMD_FUNC_DECL(lsa_set)
#define funcdecl_lsa_set static int lsa_set_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	long idx,\
	const char * idx_str __attribute__ ((unused)),\
	long type,\
	const char * type_str __attribute__ ((unused)),\
	struct in_addr id,\
	const char * id_str __attribute__ ((unused)),\
	struct in_addr adv,\
	const char * adv_str __attribute__ ((unused)))
funcdecl_lsa_set;
DEFUN_CMD_FUNC_TEXT(lsa_set)
{
#if 4 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	long idx = 0;
	const char *idx_str = NULL;
	long type = 0;
	const char *type_str = NULL;
	struct in_addr id = { INADDR_ANY };
	const char *id_str = NULL;
	struct in_addr adv = { INADDR_ANY };
	const char *adv_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "idx")) {
			idx_str = argv[_i]->arg;
			char *_end;
			idx = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
		if (!strcmp(argv[_i]->varname, "type")) {
			type_str = argv[_i]->arg;
			char *_end;
			type = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
		if (!strcmp(argv[_i]->varname, "id")) {
			id_str = argv[_i]->arg;
			_fail = !inet_aton(argv[_i]->arg, &id);
		}
		if (!strcmp(argv[_i]->varname, "adv")) {
			adv_str = argv[_i]->arg;
			_fail = !inet_aton(argv[_i]->arg, &adv);
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
	return lsa_set_magic(self, vty, argc, argv, idx, idx_str, type, type_str, id, id_str, adv, adv_str);
}

/* lsa_drop => "lsa drop (0-999999)$idx" */
DEFUN_CMD_FUNC_DECL(lsa_drop)
#define funcdecl_lsa_drop static int lsa_drop_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	long idx,\
	const char * idx_str __attribute__ ((unused)))
funcdecl_lsa_drop;
DEFUN_CMD_FUNC_TEXT(lsa_drop)
{
#if 1 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	long idx = 0;
	const char *idx_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "idx")) {
			idx_str = argv[_i]->arg;
			char *_end;
			idx = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
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
	return lsa_drop_magic(self, vty, argc, argv, idx, idx_str);
}

/* lsdb_add => "lsdb add (0-999999)$idx" */
DEFUN_CMD_FUNC_DECL(lsdb_add)
#define funcdecl_lsdb_add static int lsdb_add_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	long idx,\
	const char * idx_str __attribute__ ((unused)))
funcdecl_lsdb_add;
DEFUN_CMD_FUNC_TEXT(lsdb_add)
{
#if 1 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	long idx = 0;
	const char *idx_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "idx")) {
			idx_str = argv[_i]->arg;
			char *_end;
			idx = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
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
	return lsdb_add_magic(self, vty, argc, argv, idx, idx_str);
}

/* lsdb_remove => "lsdb remove (0-999999)$idx" */
DEFUN_CMD_FUNC_DECL(lsdb_remove)
#define funcdecl_lsdb_remove static int lsdb_remove_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	long idx,\
	const char * idx_str __attribute__ ((unused)))
funcdecl_lsdb_remove;
DEFUN_CMD_FUNC_TEXT(lsdb_remove)
{
#if 1 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	long idx = 0;
	const char *idx_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "idx")) {
			idx_str = argv[_i]->arg;
			char *_end;
			idx = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
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
	return lsdb_remove_magic(self, vty, argc, argv, idx, idx_str);
}

/* lsdb_walk => "lsdb walk" */
DEFUN_CMD_FUNC_DECL(lsdb_walk)
#define funcdecl_lsdb_walk static int lsdb_walk_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)))
funcdecl_lsdb_walk;
DEFUN_CMD_FUNC_TEXT(lsdb_walk)
{
#if 0 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

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
	return lsdb_walk_magic(self, vty, argc, argv);
}

/* lsdb_walk_type => "lsdb walk type (0-65535)" */
DEFUN_CMD_FUNC_DECL(lsdb_walk_type)
#define funcdecl_lsdb_walk_type static int lsdb_walk_type_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	long type,\
	const char * type_str __attribute__ ((unused)))
funcdecl_lsdb_walk_type;
DEFUN_CMD_FUNC_TEXT(lsdb_walk_type)
{
#if 1 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	long type = 0;
	const char *type_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "type")) {
			type_str = argv[_i]->arg;
			char *_end;
			type = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
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
	return lsdb_walk_type_magic(self, vty, argc, argv, type, type_str);
}

/* lsdb_walk_type_adv => "lsdb walk type (0-65535) adv A.B.C.D" */
DEFUN_CMD_FUNC_DECL(lsdb_walk_type_adv)
#define funcdecl_lsdb_walk_type_adv static int lsdb_walk_type_adv_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	long type,\
	const char * type_str __attribute__ ((unused)),\
	struct in_addr adv,\
	const char * adv_str __attribute__ ((unused)))
funcdecl_lsdb_walk_type_adv;
DEFUN_CMD_FUNC_TEXT(lsdb_walk_type_adv)
{
#if 2 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	long type = 0;
	const char *type_str = NULL;
	struct in_addr adv = { INADDR_ANY };
	const char *adv_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "type")) {
			type_str = argv[_i]->arg;
			char *_end;
			type = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
		if (!strcmp(argv[_i]->varname, "adv")) {
			adv_str = argv[_i]->arg;
			_fail = !inet_aton(argv[_i]->arg, &adv);
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
	return lsdb_walk_type_adv_magic(self, vty, argc, argv, type, type_str, adv, adv_str);
}

/* lsdb_get => "lsdb <get-next|get> type (0-65535) adv A.B.C.D id A.B.C.D" */
DEFUN_CMD_FUNC_DECL(lsdb_get)
#define funcdecl_lsdb_get static int lsdb_get_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)),\
	long type,\
	const char * type_str __attribute__ ((unused)),\
	struct in_addr adv,\
	const char * adv_str __attribute__ ((unused)),\
	struct in_addr id,\
	const char * id_str __attribute__ ((unused)))
funcdecl_lsdb_get;
DEFUN_CMD_FUNC_TEXT(lsdb_get)
{
#if 3 /* anything to parse? */
	int _i;
#if 1 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif
	long type = 0;
	const char *type_str = NULL;
	struct in_addr adv = { INADDR_ANY };
	const char *adv_str = NULL;
	struct in_addr id = { INADDR_ANY };
	const char *id_str = NULL;

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 1 /* anything that can fail? */
		_fail = 0;
#endif

		if (!strcmp(argv[_i]->varname, "type")) {
			type_str = argv[_i]->arg;
			char *_end;
			type = strtol(argv[_i]->arg, &_end, 10);
			_fail = (_end == argv[_i]->arg) || (*_end != '\0');
		}
		if (!strcmp(argv[_i]->varname, "adv")) {
			adv_str = argv[_i]->arg;
			_fail = !inet_aton(argv[_i]->arg, &adv);
		}
		if (!strcmp(argv[_i]->varname, "id")) {
			id_str = argv[_i]->arg;
			_fail = !inet_aton(argv[_i]->arg, &id);
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
	return lsdb_get_magic(self, vty, argc, argv, type, type_str, adv, adv_str, id, id_str);
}

/* lsa_refcounts => "lsa refcounts" */
DEFUN_CMD_FUNC_DECL(lsa_refcounts)
#define funcdecl_lsa_refcounts static int lsa_refcounts_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)))
funcdecl_lsa_refcounts;
DEFUN_CMD_FUNC_TEXT(lsa_refcounts)
{
#if 0 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

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
	return lsa_refcounts_magic(self, vty, argc, argv);
}

/* lsdb_create => "lsdb create" */
DEFUN_CMD_FUNC_DECL(lsdb_create)
#define funcdecl_lsdb_create static int lsdb_create_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)))
funcdecl_lsdb_create;
DEFUN_CMD_FUNC_TEXT(lsdb_create)
{
#if 0 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

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
	return lsdb_create_magic(self, vty, argc, argv);
}

/* lsdb_delete => "lsdb delete" */
DEFUN_CMD_FUNC_DECL(lsdb_delete)
#define funcdecl_lsdb_delete static int lsdb_delete_magic(\
	const struct cmd_element *self __attribute__ ((unused)),\
	struct vty *vty __attribute__ ((unused)),\
	int argc __attribute__ ((unused)),\
	struct cmd_token *argv[] __attribute__ ((unused)))
funcdecl_lsdb_delete;
DEFUN_CMD_FUNC_TEXT(lsdb_delete)
{
#if 0 /* anything to parse? */
	int _i;
#if 0 /* anything that can fail? */
	unsigned _fail = 0, _failcnt = 0;
#endif

	for (_i = 0; _i < argc; _i++) {
		if (!argv[_i]->varname)
			continue;
#if 0 /* anything that can fail? */
		_fail = 0;
#endif

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
	return lsdb_delete_magic(self, vty, argc, argv);
}

