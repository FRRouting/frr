// SPDX-License-Identifier: Unlicense

#ifndef _FRR_LLVM_DEBUGINFO_H
#define _FRR_LLVM_DEBUGINFO_H

#include <stdbool.h>
#include <llvm-c/Core.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dbginfo;

extern struct dbginfo *dbginfo_load(LLVMModuleRef mod);
extern bool dbginfo_struct_member(struct dbginfo *di, LLVMTypeRef typ,
				  unsigned long long idx, char **struct_name,
				  char **member_name);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_LLVM_DEBUGINFO_H */
