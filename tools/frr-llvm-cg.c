// SPDX-License-Identifier: Unlicense
/* based on example code: https://github.com/sheredom/llvm_bc_parsing_example
 * which came under the above (un-)license.  does not depend on any FRR
 * pieces, so no reason to change the license.
 *
 * please note that while included in the FRR sources, this tool is in no way
 * supported or maintained by the FRR community.  it is provided as a
 * "convenience";  while it worked at some point (using LLVM 8 / 9), it may
 * easily break with a future LLVM version or any other factors.
 *
 * 2020-05-04, David Lamparter
 */

#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <llvm-c/BitReader.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>

#include <json-c/json.h>

#include "frr-llvm-debuginfo.h"

/* if you want to use this without the special FRRouting defines,
 * remove the following #define
 */
#define FRR_SPECIFIC

static struct dbginfo *dbginfo;

static void dbgloc_add(struct json_object *jsobj, LLVMValueRef obj)
{
	unsigned file_len = 0;
	const char *file = LLVMGetDebugLocFilename(obj, &file_len);
	unsigned line = LLVMGetDebugLocLine(obj);

	if (!file)
		file = "???", file_len = 3;
	else if (file[0] == '.' && file[1] == '/')
		file += 2, file_len -= 2;

	json_object_object_add(jsobj, "filename",
			       json_object_new_string_len(file, file_len));
	json_object_object_add(jsobj, "line", json_object_new_int64(line));
}

static struct json_object *js_get_or_make(struct json_object *parent,
					  const char *key,
					  struct json_object *(*maker)(void))
{
	struct json_object *ret;

	ret = json_object_object_get(parent, key);
	if (ret)
		return ret;
	ret = maker();
	json_object_object_add(parent, key, ret);
	return ret;
}

static bool try_struct_fptr(struct json_object *js_call, LLVMValueRef gep,
			    const char *prefix)
{
	unsigned long long val = 0;
	bool ret = false;
	LLVMTypeRef ptrtype = LLVMTypeOf(LLVMGetOperand(gep, 0));
	LLVMValueRef idx;

	/* middle steps like struct a -> struct b a_member; -> fptr */
	for (int i = 1; ptrtype && i < LLVMGetNumOperands(gep) - 1; i++) {
		if (LLVMGetTypeKind(ptrtype) == LLVMPointerTypeKind
		    || LLVMGetTypeKind(ptrtype) == LLVMArrayTypeKind
		    || LLVMGetTypeKind(ptrtype) == LLVMVectorTypeKind) {
			ptrtype = LLVMGetElementType(ptrtype);
			continue;
		}

		if (LLVMGetTypeKind(ptrtype) != LLVMStructTypeKind)
			return false;

		idx = LLVMGetOperand(gep, i);
		if (!LLVMIsConstant(idx))
			return false;
		val = LLVMConstIntGetZExtValue(idx);

		unsigned n = LLVMGetNumContainedTypes(ptrtype);
		LLVMTypeRef arr[n];

		if (val > n)
			return false;

		LLVMGetSubtypes(ptrtype, arr);
		ptrtype = arr[val];
	}

	if (!ptrtype)
		return false;

	idx = LLVMGetOperand(gep, LLVMGetNumOperands(gep) - 1);
	if (!LLVMIsConstant(idx))
		return false;

	val = LLVMConstIntGetZExtValue(idx);

	char *sname = NULL, *mname = NULL;

	if (dbginfo_struct_member(dbginfo, ptrtype, val, &sname, &mname)) {
		fprintf(stderr, "%s: call to struct %s->%s\n", prefix, sname,
			mname);

		json_object_object_add(js_call, "type",
				       json_object_new_string("struct_memb"));
		json_object_object_add(js_call, "struct",
				       json_object_new_string(sname));
		json_object_object_add(js_call, "member",
				       json_object_new_string(mname));
		ret = true;
	}
	free(sname);
	free(mname);

	return ret;
}

static bool details_fptr_vars = false;
static bool details_fptr_consts = true;

enum called_fn {
	FN_GENERIC = 0,
	FN_NONAME,
	FN_INSTALL_ELEMENT,
	FN_THREAD_ADD,
};

static void walk_const_fptrs(struct json_object *js_call, LLVMValueRef value,
			     const char *prefix, bool *hdr_written)
{
	LLVMTypeRef type;
	LLVMValueKind kind;

	if (LLVMIsAGlobalVariable(value)) {
		type = LLVMGlobalGetValueType(value);
		value = LLVMGetInitializer(value);
	} else {
		type = LLVMTypeOf(value);
	}

	if (LLVMIsAFunction(value)) {
		struct json_object *js_fptrs;

		js_fptrs = js_get_or_make(js_call, "funcptrs",
					  json_object_new_array);

		size_t fn_len;
		const char *fn_name = LLVMGetValueName2(value, &fn_len);

		size_t curlen = json_object_array_length(js_fptrs);
		struct json_object *jsobj;
		const char *s;

		for (size_t i = 0; i < curlen; i++) {
			jsobj = json_object_array_get_idx(js_fptrs, i);
			s = json_object_get_string(jsobj);

			if (s && !strcmp(s, fn_name))
				return;
		}

		if (details_fptr_consts && !*hdr_written) {
			fprintf(stderr,
				"%s: calls function pointer from constant or global data\n",
				prefix);
			*hdr_written = true;
		}
		if (details_fptr_consts)
			fprintf(stderr, "%s-   constant: %.*s()\n",
				prefix, (int)fn_len, fn_name);

		json_object_array_add(js_fptrs,
				       json_object_new_string_len(fn_name,
								  fn_len));
		return;
	}

	kind = LLVMGetValueKind(value);

	unsigned len;
	char *dump;

	switch (kind) {
	case LLVMUndefValueValueKind:
	case LLVMConstantAggregateZeroValueKind:
	case LLVMConstantPointerNullValueKind:
		/* null pointer / array - ignore */
		break;

	case LLVMConstantIntValueKind:
		/* integer - ignore */
		break;

	case LLVMConstantStructValueKind:
		len = LLVMCountStructElementTypes(type);
		for (unsigned i = 0; i < len; i++)
			walk_const_fptrs(js_call, LLVMGetOperand(value, i),
					 prefix, hdr_written);
		break;

	case LLVMConstantArrayValueKind:
		len = LLVMGetArrayLength(type);
		for (unsigned i = 0; i < len; i++)
			walk_const_fptrs(js_call, LLVMGetOperand(value, i),
					 prefix, hdr_written);
		return;

	case LLVMConstantExprValueKind:
		switch (LLVMGetConstOpcode(value)) {
		case LLVMGetElementPtr:
			if (try_struct_fptr(js_call, value, prefix)) {
				*hdr_written = true;
				return;
			}

			fprintf(stderr,
				"%s: calls function pointer from unhandled const GEP\n",
				prefix);
			*hdr_written = true;
			fallthrough;
		default:
			/* to help the user / development */
			if (!*hdr_written) {
				fprintf(stderr,
					"%s: calls function pointer from constexpr\n",
					prefix);
				*hdr_written = true;
			}
			dump = LLVMPrintValueToString(value);
			fprintf(stderr, "%s-   [opcode=%d] %s\n", prefix,
				LLVMGetConstOpcode(value), dump);
			LLVMDisposeMessage(dump);
		}
		return;

	default:
		/* to help the user / development */
		if (!*hdr_written) {
			fprintf(stderr,
				"%s: calls function pointer from constant or global data\n",
				prefix);
			*hdr_written = true;
		}
		dump = LLVMPrintValueToString(value);
		fprintf(stderr,
			"%s-   value could not be processed:\n"
			"%s-   [kind=%d] %s\n",
			prefix, prefix, kind, dump);
		LLVMDisposeMessage(dump);
		return;
	}
	return;
}

#ifdef FRR_SPECIFIC
static bool is_thread_sched(const char *name, size_t len)
{
#define thread_prefix "_"
	static const char *const names[] = {
		thread_prefix "event_add_read_write",
		thread_prefix "event_add_timer",
		thread_prefix "event_add_timer_msec",
		thread_prefix "event_add_timer_tv",
		thread_prefix "event_add_event",
		thread_prefix "event_execute",
	};
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (strlen(names[i]) != len)
			continue;
		if (!memcmp(names[i], name, len))
			return true;
	}
	return false;
}
#endif

static bool _check_val(bool cond, const char *text, LLVMValueRef dumpval)
{
	if (cond)
		return true;

	char *dump = LLVMPrintValueToString(dumpval);
	fprintf(stderr, "check failed: %s\ndump:\n\t%s\n", text, dump);
	LLVMDisposeMessage(dump);
	return false;
}

#define check_val(cond, dump)                                                  \
	if (!_check_val(cond, #cond, dump))                                    \
		return;

static char *get_string(LLVMValueRef value)
{
	if (!LLVMIsAConstant(value))
		return strdup("!NOT-A-CONST");

	if (LLVMGetValueKind(value) == LLVMConstantExprValueKind
	    && LLVMGetConstOpcode(value) == LLVMGetElementPtr) {
		value = LLVMGetOperand(value, 0);

		if (!LLVMIsAConstant(value))
			return strdup("!NOT-A-CONST-2");
	}

	if (LLVMIsAGlobalVariable(value))
		value = LLVMGetInitializer(value);

	size_t len = 0;
	const char *sval = LLVMGetAsString(value, &len);

	return strndup(sval, len);
}

static void handle_yang_module(struct json_object *js_special,
			       LLVMValueRef yang_mod)
{
	check_val(LLVMIsAGlobalVariable(yang_mod), yang_mod);

	LLVMValueRef value;

	value = LLVMGetInitializer(yang_mod);
	LLVMValueKind kind = LLVMGetValueKind(value);

	check_val(kind == LLVMConstantStructValueKind, value);

	size_t var_len = 0;
	const char *var_name = LLVMGetValueName2(yang_mod, &var_len);
	char buf_name[var_len + 1];

	memcpy(buf_name, var_name, var_len);
	buf_name[var_len] = '\0';

	struct json_object *js_yang, *js_yangmod, *js_items;

	js_yang = js_get_or_make(js_special, "yang", json_object_new_object);
	js_yangmod = js_get_or_make(js_yang, buf_name, json_object_new_object);
	js_items = js_get_or_make(js_yangmod, "items", json_object_new_array);

	char *mod_name = get_string(LLVMGetOperand(value, 0));
	json_object_object_add(js_yangmod, "name",
			       json_object_new_string(mod_name));
	free(mod_name);

	value = LLVMGetOperand(value, 1);
	kind = LLVMGetValueKind(value);
	check_val(kind == LLVMConstantArrayValueKind, value);

	unsigned len = LLVMGetArrayLength(LLVMTypeOf(value));

	for (unsigned i = 0; i < len - 1; i++) {
		struct json_object *js_item, *js_cbs;
		LLVMValueRef item = LLVMGetOperand(value, i);
		char *xpath = get_string(LLVMGetOperand(item, 0));

		js_item = json_object_new_object();
		json_object_array_add(js_items, js_item);

		json_object_object_add(js_item, "xpath",
				       json_object_new_string(xpath));
		js_cbs = js_get_or_make(js_item, "cbs", json_object_new_object);

		free(xpath);

		LLVMValueRef cbs = LLVMGetOperand(item, 1);

		check_val(LLVMGetValueKind(cbs) == LLVMConstantStructValueKind,
			  value);

		LLVMTypeRef cbs_type = LLVMTypeOf(cbs);
		unsigned cblen = LLVMCountStructElementTypes(cbs_type);

		for (unsigned i = 0; i < cblen; i++) {
			LLVMValueRef cb = LLVMGetOperand(cbs, i);

			char *sname = NULL;
			char *mname = NULL;

			if (dbginfo_struct_member(dbginfo, cbs_type, i, &sname,
						  &mname)) {
				(void)0;
			}

			if (LLVMIsAFunction(cb)) {
				size_t fn_len;
				const char *fn_name;

				fn_name = LLVMGetValueName2(cb, &fn_len);

				json_object_object_add(
					js_cbs, mname,
					json_object_new_string_len(fn_name,
								   fn_len));
			}

			free(sname);
			free(mname);
		}
	}
}

static void handle_daemoninfo(struct json_object *js_special,
			      LLVMValueRef daemoninfo)
{
	check_val(LLVMIsAGlobalVariable(daemoninfo), daemoninfo);

	LLVMTypeRef type;
	LLVMValueRef value;
	unsigned len;

	type = LLVMGlobalGetValueType(daemoninfo);
	value = LLVMGetInitializer(daemoninfo);
	LLVMValueKind kind = LLVMGetValueKind(value);

	check_val(kind == LLVMConstantStructValueKind, value);

	int yang_idx = -1;

	len = LLVMCountStructElementTypes(type);

	LLVMTypeRef fieldtypes[len];
	LLVMGetSubtypes(type, fieldtypes);

	for (unsigned i = 0; i < len; i++) {
		LLVMTypeRef t = fieldtypes[i];

		if (LLVMGetTypeKind(t) != LLVMPointerTypeKind)
			continue;
		t = LLVMGetElementType(t);
		if (LLVMGetTypeKind(t) != LLVMPointerTypeKind)
			continue;
		t = LLVMGetElementType(t);
		if (LLVMGetTypeKind(t) != LLVMStructTypeKind)
			continue;

		const char *name = LLVMGetStructName(t);
		if (!strcmp(name, "struct.frr_yang_module_info"))
			yang_idx = i;
	}

	if (yang_idx == -1)
		return;

	LLVMValueRef yang_mods = LLVMGetOperand(value, yang_idx);
	LLVMValueRef yang_size = LLVMGetOperand(value, yang_idx + 1);

	check_val(LLVMIsConstant(yang_size), yang_size);

	unsigned long long ival = LLVMConstIntGetZExtValue(yang_size);

	check_val(LLVMGetValueKind(yang_mods) == LLVMConstantExprValueKind
			  && LLVMGetConstOpcode(yang_mods) == LLVMGetElementPtr,
		  yang_mods);

	yang_mods = LLVMGetOperand(yang_mods, 0);

	check_val(LLVMIsAGlobalVariable(yang_mods), yang_mods);

	yang_mods = LLVMGetInitializer(yang_mods);

	check_val(LLVMGetValueKind(yang_mods) == LLVMConstantArrayValueKind,
		  yang_mods);

	len = LLVMGetArrayLength(LLVMTypeOf(yang_mods));

	if (len != ival)
		fprintf(stderr, "length mismatch - %llu vs. %u\n", ival, len);

	for (unsigned i = 0; i < len; i++) {
		char *dump;

		LLVMValueRef item = LLVMGetOperand(yang_mods, i);
		LLVMValueKind kind = LLVMGetValueKind(item);

		check_val(kind == LLVMGlobalVariableValueKind
				  || kind == LLVMConstantExprValueKind,
			  item);

		if (kind == LLVMGlobalVariableValueKind)
			continue;

		LLVMOpcode opcode = LLVMGetConstOpcode(item);
		switch (opcode) {
		case LLVMBitCast:
			item = LLVMGetOperand(item, 0);
			handle_yang_module(js_special, item);
			break;

		default:
			dump = LLVMPrintValueToString(item);
			printf("[%u] = [opcode=%u] %s\n", i, opcode, dump);
			LLVMDisposeMessage(dump);
		}
	}
}

static void process_call(struct json_object *js_calls,
			 struct json_object *js_special,
			 LLVMValueRef instr,
			 LLVMValueRef function)
{
	struct json_object *js_call, *js_fptrs = NULL;

	LLVMValueRef called = LLVMGetCalledValue(instr);

	if (LLVMIsAInlineAsm(called))
		return;

	if (LLVMIsAConstantExpr(called)) {
		LLVMOpcode opcode = LLVMGetConstOpcode(called);

		if (opcode == LLVMBitCast) {
			LLVMValueRef op0 = LLVMGetOperand(called, 0);

			if (LLVMIsAFunction(op0))
				called = op0;
		}
	}

	size_t called_len = 0;
	const char *called_name = LLVMGetValueName2(called, &called_len);
	unsigned n_args = LLVMGetNumArgOperands(instr);

	bool is_external = LLVMIsDeclaration(called);

	js_call = json_object_new_object();
	json_object_array_add(js_calls, js_call);
	dbgloc_add(js_call, instr);
	json_object_object_add(js_call, "is_external",
			       json_object_new_boolean(is_external));

	if (!called_name || called_len == 0) {
		json_object_object_add(js_call, "type",
				       json_object_new_string("indirect"));

		LLVMValueRef last = called;

		size_t name_len = 0;
		const char *name_c = LLVMGetValueName2(function, &name_len);

#ifdef FRR_SPECIFIC
		/* information for FRR hooks is dumped for the registration
		 * in _hook_typecheck; we can safely ignore the funcptr here
		 */
		if (strncmp(name_c, "hook_call_", 10) == 0)
			return;
#endif

		unsigned file_len = 0;
		const char *file = LLVMGetDebugLocFilename(instr, &file_len);
		unsigned line = LLVMGetDebugLocLine(instr);

		char prefix[256];
		snprintf(prefix, sizeof(prefix), "%.*s:%d:%.*s()",
			 (int)file_len, file, line, (int)name_len, name_c);

		if (LLVMIsALoadInst(called)
		    && LLVMIsAGetElementPtrInst(LLVMGetOperand(called, 0))
		    && try_struct_fptr(js_call, LLVMGetOperand(called, 0),
				       prefix))
			goto out_struct_fptr;

		while (LLVMIsALoadInst(last) || LLVMIsAGetElementPtrInst(last))
			/* skipping over details for GEP here, but meh. */
			last = LLVMGetOperand(last, 0);

		if (LLVMIsAAllocaInst(last)) {
			/* "alloca" is just generically all variables on the
			 * stack, this does not refer to C alloca() calls
			 *
			 * looking at the control flow in the function can
			 * give better results here, it's just not implemented
			 * (yet?)
			 */
			fprintf(stderr,
				"%s: call to a function pointer variable\n",
				prefix);

			if (details_fptr_vars) {
				char *dump = LLVMPrintValueToString(called);
				printf("%s-   %s\n", prefix, dump);
				LLVMDisposeMessage(dump);
			}

			json_object_object_add(
				js_call, "type",
				json_object_new_string("stack_fptr"));
		} else if (LLVMIsACallInst(last)) {
			/* calling the a function pointer returned from
			 * another function.
			 */
			struct json_object *js_indirect;

			js_indirect = js_get_or_make(js_call, "return_of",
						     json_object_new_array);

			process_call(js_indirect, js_special, last, function);
		} else if (LLVMIsAConstant(last)) {
			/* function pointer is a constant (includes loading
			 * from complicated constants like structs or arrays.)
			 */
			bool hdr_written = false;
			walk_const_fptrs(js_call, last, prefix, &hdr_written);
			if (details_fptr_consts && !hdr_written)
				fprintf(stderr,
					"%s: calls function pointer from constant or global data, but no non-NULL function pointers found\n",
					prefix);
		} else {
			char *dump = LLVMPrintValueToString(called);
			fprintf(stderr, "%s: ??? %s\n", prefix, dump);
			LLVMDisposeMessage(dump);
		}
#ifdef FRR_SPECIFIC
	} else if (!strcmp(called_name, "_install_element")) {
		LLVMValueRef param0 = LLVMGetOperand(instr, 0);
		if (!LLVMIsAConstantInt(param0))
			goto out_nonconst;

		long long vty_node = LLVMConstIntGetSExtValue(param0);
		json_object_object_add(js_call, "vty_node",
				       json_object_new_int64(vty_node));

		LLVMValueRef param1 = LLVMGetOperand(instr, 1);
		if (!LLVMIsAGlobalVariable(param1))
			goto out_nonconst;

		LLVMValueRef intlz = LLVMGetInitializer(param1);
		assert(intlz && LLVMIsConstant(intlz));

		LLVMValueKind intlzkind = LLVMGetValueKind(intlz);
		assert(intlzkind == LLVMConstantStructValueKind);

		LLVMValueRef funcptr = LLVMGetOperand(intlz, 4);
		assert(LLVMIsAFunction(funcptr));

		size_t target_len = 0;
		const char *target;
		target = LLVMGetValueName2(funcptr, &target_len);

		json_object_object_add(
			js_call, "type",
			json_object_new_string("install_element"));
		json_object_object_add(
			js_call, "target",
			json_object_new_string_len(target, target_len));
		return;

	out_nonconst:
		json_object_object_add(
			js_call, "target",
			json_object_new_string("install_element"));
		return;
	} else if (is_thread_sched(called_name, called_len)) {
		json_object_object_add(js_call, "type",
				       json_object_new_string("thread_sched"));
		json_object_object_add(
			js_call, "subtype",
			json_object_new_string_len(called_name, called_len));

		LLVMValueRef fparam;
		fparam = LLVMGetOperand(instr, 2);
		assert(fparam);

		size_t target_len = 0;
		const char *target;
		target = LLVMGetValueName2(fparam, &target_len);

		json_object_object_add(js_call, "target",
				       !target_len ? NULL :
			       json_object_new_string_len(target, target_len));
		if (!LLVMIsAFunction(fparam))
			json_object_object_add(js_call, "target_unresolved",
					       json_object_new_boolean(true));
		return;
	} else if (!strncmp(called_name, "_hook_typecheck_",
			    strlen("_hook_typecheck_"))) {
		struct json_object *js_hook, *js_this;
		const char *hook_name;

		hook_name = called_name + strlen("_hook_typecheck_");

		json_object_object_add(js_call, "type",
				       json_object_new_string("hook"));

		LLVMValueRef param0 = LLVMGetOperand(instr, 0);
		if (!LLVMIsAFunction(param0))
			return;

		size_t target_len = 0;
		const char *target;
		target = LLVMGetValueName2(param0, &target_len);

		js_hook = js_get_or_make(js_special, "hooks",
					 json_object_new_object);
		js_hook = js_get_or_make(js_hook, hook_name,
					 json_object_new_array);

		js_this = json_object_new_object();
		json_object_array_add(js_hook, js_this);

		dbgloc_add(js_this, instr);
		json_object_object_add(
			js_this, "target",
			json_object_new_string_len(target, target_len));
		return;

		/* TODO (FRR specifics):
		 * - workqueues - not sure we can do much there
		 * - zclient->* ?
		 */
#endif /* FRR_SPECIFIC */
	} else if (!strcmp(called_name, "frr_preinit")) {
		LLVMValueRef daemoninfo = LLVMGetOperand(instr, 0);

		handle_daemoninfo(js_special, daemoninfo);

		json_object_object_add(
			js_call, "target",
			json_object_new_string_len(called_name, called_len));
	} else {
		json_object_object_add(
			js_call, "target",
			json_object_new_string_len(called_name, called_len));
	}

out_struct_fptr:
	for (unsigned argno = 0; argno < n_args; argno++) {
		LLVMValueRef param = LLVMGetOperand(instr, argno);
		size_t target_len;
		const char *target_name;

		if (LLVMIsAFunction(param)) {
			js_fptrs = js_get_or_make(js_call, "funcptrs",
						  json_object_new_array);

			target_name = LLVMGetValueName2(param, &target_len);

			json_object_array_add(js_fptrs,
					      json_object_new_string_len(
						      target_name, target_len));
		}
	}
}

static void process_fn(struct json_object *funcs,
		       struct json_object *js_special,
		       LLVMValueRef function)
{
	struct json_object *js_func, *js_calls;

	size_t name_len = 0;
	const char *name_c = LLVMGetValueName2(function, &name_len);
	char *name;

	name = strndup(name_c, name_len);

	js_func = json_object_object_get(funcs, name);
	if (js_func) {
		unsigned file_len = 0;
		const char *file = LLVMGetDebugLocFilename(function, &file_len);
		unsigned line = LLVMGetDebugLocLine(function);

		fprintf(stderr, "%.*s:%d:%s(): duplicate definition!\n",
			(int)file_len, file, line, name);
		free(name);
		return;
	}

	js_func = json_object_new_object();
	json_object_object_add(funcs, name, js_func);
	free(name);

	js_calls = json_object_new_array();
	json_object_object_add(js_func, "calls", js_calls);

	dbgloc_add(js_func, function);

	for (LLVMBasicBlockRef basicBlock = LLVMGetFirstBasicBlock(function);
	     basicBlock; basicBlock = LLVMGetNextBasicBlock(basicBlock)) {

		for (LLVMValueRef instr = LLVMGetFirstInstruction(basicBlock);
		     instr; instr = LLVMGetNextInstruction(instr)) {

			if (LLVMIsAIntrinsicInst(instr))
				continue;

			if (LLVMIsACallInst(instr) || LLVMIsAInvokeInst(instr))
				process_call(js_calls, js_special, instr,
					     function);
		}
	}
}

static void help(int retcode)
{
	fprintf(stderr,
		"FRR LLVM bitcode to callgraph analyzer\n"
		"\n"
		"usage:  frr-llvm-cg [-q|-v] [-o <JSONOUTPUT>] BITCODEINPUT\n"
		"\n"
		"\t-o FILENAME\twrite JSON output to file instead of stdout\n"
		"\t-v\t\tbe more verbose\n"
		"\t-q\t\tbe quiet\n"
		"\n"
		"BITCODEINPUT must be a LLVM binary bitcode file (not text\n"
		"representation.)  Use - to read from stdin.\n"
		"\n"
		"Note it may be necessary to build this binary tool against\n"
		"the specific LLVM version that created the bitcode file.\n");
	exit(retcode);
}

int main(int argc, char **argv)
{
	int opt;
	const char *out = NULL;
	const char *inp = NULL;
	char v_or_q = '\0';

	while ((opt = getopt(argc, argv, "hvqo:")) != -1) {
		switch (opt) {
		case 'o':
			if (out)
				help(1);
			out = optarg;
			break;
		case 'v':
			if (v_or_q && v_or_q != 'v')
				help(1);
			details_fptr_vars = true;
			details_fptr_consts = true;
			v_or_q = 'v';
			break;
		case 'q':
			if (v_or_q && v_or_q != 'q')
				help(1);
			details_fptr_vars = false;
			details_fptr_consts = false;
			v_or_q = 'q';
			break;
		case 'h':
			help(0);
			return 0;
		default:
			help(1);
		}
	}

	if (optind != argc - 1)
		help(1);

	inp = argv[optind];

	LLVMMemoryBufferRef memoryBuffer;
	char *message;
	int ret;

	// check if we are to read our input file from stdin
	if (!strcmp(inp, "-")) {
		inp = "<stdin>";
		ret = LLVMCreateMemoryBufferWithSTDIN(&memoryBuffer, &message);
	} else {
		ret = LLVMCreateMemoryBufferWithContentsOfFile(
			inp, &memoryBuffer, &message);
	}

	if (ret) {
		fprintf(stderr, "failed to open %s: %s\n", inp, message);
		free(message);
		return 1;
	}

	// now create our module using the memorybuffer
	LLVMModuleRef module;
	if (LLVMParseBitcode2(memoryBuffer, &module)) {
		fprintf(stderr, "%s: invalid bitcode\n", inp);
		LLVMDisposeMemoryBuffer(memoryBuffer);
		return 1;
	}

	// done with the memory buffer now, so dispose of it
	LLVMDisposeMemoryBuffer(memoryBuffer);

	dbginfo = dbginfo_load(module);

	struct json_object *js_root, *js_funcs, *js_special;

	js_root = json_object_new_object();
	js_funcs = json_object_new_object();
	json_object_object_add(js_root, "functions", js_funcs);
	js_special = json_object_new_object();
	json_object_object_add(js_root, "special", js_special);

	// loop through all the functions in the module
	for (LLVMValueRef function = LLVMGetFirstFunction(module); function;
	     function = LLVMGetNextFunction(function)) {
		if (LLVMIsDeclaration(function))
			continue;

		process_fn(js_funcs, js_special, function);
	}

	if (out) {
		char tmpout[strlen(out) + 5];

		snprintf(tmpout, sizeof(tmpout), "%s.tmp", out);
		ret = json_object_to_file_ext(tmpout, js_root,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_PRETTY_TAB |
					JSON_C_TO_STRING_NOSLASHESCAPE);
		if (ret < 0) {
			fprintf(stderr, "could not write JSON to file\n");
			return 1;
		}
		if (rename(tmpout, out)) {
			fprintf(stderr, "could not rename JSON output: %s\n",
				strerror(errno));
			unlink(tmpout);
			return 1;
		}
	} else {
		ret = json_object_to_fd(1, js_root,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_PRETTY_TAB |
					JSON_C_TO_STRING_NOSLASHESCAPE);
		if (ret < 0) {
			fprintf(stderr, "could not write JSON to stdout\n");
			return 1;
		}
	}

	LLVMDisposeModule(module);

	return 0;
}
