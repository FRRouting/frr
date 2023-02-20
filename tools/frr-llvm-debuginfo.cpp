// SPDX-License-Identifier: Unlicense

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
