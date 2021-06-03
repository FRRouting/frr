// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>

#include <llvm-c/BitReader.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>
#include <llvm-c/DebugInfo.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/Support/raw_ostream.h>

#include <map>

#include "frr-llvm-debuginfo.h"

/* llvm::DebugInfoFinder is unfortunately not exposed in the llvm-c API... */

struct dbginfo {
	llvm::DebugInfoFinder finder;
	std::map<std::string, llvm::DICompositeType *> tab;
};

struct dbginfo *dbginfo_load(LLVMModuleRef _mod)
{
	llvm::Module *mod = llvm::unwrap(_mod);
	struct dbginfo *info = new dbginfo();

	info->finder.processModule(*mod);

	for (auto ty : info->finder.types()) {
		if (ty->getMetadataID() != llvm::Metadata::DICompositeTypeKind)
			continue;

		llvm::DICompositeType *cty = (llvm::DICompositeType *)ty;
		/* empty forward declarations aka "struct foobar;" */
		if (cty->getElements().size() == 0)
			continue;

		info->tab.emplace(std::move(ty->getName().str()), cty);
	}

	return info;
}

bool dbginfo_struct_member(struct dbginfo *info, LLVMTypeRef _typ,
			   unsigned long long idx, char **struct_name,
			   char **member_name)
{
	*struct_name = NULL;
	*member_name = NULL;

	llvm::Type *typ = llvm::unwrap(_typ);

	if (!typ->isStructTy())
		return false;

	llvm::StructType *styp = (llvm::StructType *)typ;
	auto sname = styp->getStructName();

	if (!sname.startswith("struct."))
		return false;
	sname = sname.drop_front(7);

	size_t dot = sname.find_last_of(".");
	if (dot != sname.npos)
		sname = sname.take_front(dot);

	auto item = info->tab.find(sname.str());
	if (item == info->tab.end())
		return false;

	auto elements = item->second->getElements();
	if (idx >= elements.size())
		return false;

	auto elem = elements[idx];

	if (elem->getMetadataID() != llvm::Metadata::DIDerivedTypeKind)
		return false;

	llvm::DIDerivedType *dtyp = (llvm::DIDerivedType *)elem;

	*struct_name = strdup(sname.str().c_str());
	*member_name = strdup(dtyp->getName().str().c_str());
	return true;
}
