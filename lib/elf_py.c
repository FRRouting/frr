// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * fast ELF file accessor
 * Copyright (C) 2018-2020  David Lamparter for NetDEF, Inc.
 */

/* Note: this wrapper is intended to be used as build-time helper.  While
 * it should be generally correct and proper, there may be the occasional
 * memory leak or SEGV for things that haven't been well-tested.
 *     _
 *    / \    This code is NOT SUITABLE FOR UNTRUSTED ELF FILES.  It's used
 *   / ! \   in FRR to read files created by its own build.  Don't take it out
 *  /_____\  of FRR and use it to parse random ELF files you found somewhere.
 *
 * If you're working with this code (or even reading it), you really need to
 * read a bunch of the ELF specs.  There's no way around it, things in here
 * just represent pieces of ELF pretty much 1:1.  Also, readelf & objdump are
 * your friends.
 *
 * Required reading:
 *   https://refspecs.linuxfoundation.org/elf/elf.pdf
 *   https://refspecs.linuxfoundation.org/elf/x86_64-SysV-psABI.pdf
 * Recommended reading:
 *   https://github.com/ARM-software/abi-aa/releases/download/2020Q4/aaelf64.pdf
 *
 * The core ELF spec is *not* enough, you should read at least one of the
 * processor specific (psABI) docs.  They define what & how relocations work.
 * Luckily we don't need to care about the processor specifics since this only
 * does data relocations, but without looking at the psABI, some things aren't
 * quite clear.
 */

/* the API of this module roughly follows a very small subset of the one
 * provided by the python elfutils package, which unfortunately is painfully
 * slow.
 */

#define PY_SSIZE_T_CLEAN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <Python.h>
#include "structmember.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#if defined(__sun__) && (__SIZEOF_POINTER__ == 4)
/* Solaris libelf bails otherwise ... */
#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 32
#endif

#include <elf.h>
#include <libelf.h>
#include <gelf.h>

#include "typesafe.h"
#include "jhash.h"
#include "clippy.h"

static bool debug;

#define debugf(...)                                                            \
	do {                                                                   \
		if (debug)                                                     \
			fprintf(stderr, __VA_ARGS__);                          \
	} while (0)

/* Exceptions */
static PyObject *ELFFormatError;
static PyObject *ELFAccessError;

/* most objects can only be created as return values from one of the methods */
static PyObject *refuse_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	PyErr_SetString(PyExc_ValueError,
			"cannot create instances of this type");
	return NULL;
}

struct elfreloc;
struct elfsect;

PREDECL_HASH(elfrelocs);

/* ELFFile and ELFSection intentionally share some behaviour, particularly
 * subscript[123:456] access to file data.  This is because relocatables
 * (.o files) do things section-based, but linked executables/libraries do
 * things file-based.  Having the two behave similar allows simplifying the
 * Python code.
 */

/* class ELFFile:
 *
 * overall entry point, instantiated by reading in an ELF file
 */
struct elffile {
	PyObject_HEAD

	char *filename;
	char *mmap, *mmend;
	size_t len;
	Elf *elf;

	/* note from here on there are several instances of
	 *
	 *   GElf_Something *x, _x;
	 *
	 * this is a pattern used by libelf's generic ELF routines; the _x
	 * field is used to create a copy of the ELF structure from the file
	 * with 32/64bit and endianness adjusted.
	 */

	GElf_Ehdr *ehdr, _ehdr;
	Elf_Scn *symtab;
	size_t nsym, symstridx;
	Elf_Data *symdata;

	PyObject **sects;
	size_t n_sect;

	struct elfrelocs_head dynrelocs;

	int elfclass;
	bool bigendian;
	bool has_symbols;
};

/* class ELFSection:
 *
 * note that executables and shared libraries can have their section headers
 * removed, though in practice this is only used as an obfuscation technique.
 */
struct elfsect {
	PyObject_HEAD

	const char *name;
	struct elffile *ef;

	GElf_Shdr _shdr, *shdr;
	Elf_Scn *scn;
	unsigned long idx, len;

	struct elfrelocs_head relocs;
};

/* class ELFReloc:
 *
 * note: relocations in object files (.o) are section-based while relocations
 * in executables and shared libraries are file-based.
 *
 * Whenever accessing something that is a pointer in the ELF file, the Python
 * code needs to check for a relocation;  if the pointer is pointing to some
 * unresolved symbol the file will generally contain 0 bytes.  The relocation
 * will tell what the pointer is actually pointing to.
 *
 * This represents both static (.o file) and dynamic (.so/exec) relocations.
 */
struct elfreloc {
	PyObject_HEAD

	struct elfrelocs_item elfrelocs_item;

	struct elfsect *es;
	struct elffile *ef;

	/* there's also old-fashioned GElf_Rel; we're converting that to
	 * GElf_Rela in elfsect_add_relocations()
	 */
	GElf_Rela _rela, *rela;
	GElf_Sym _sym, *sym;
	size_t symidx;
	const char *symname;

	/* documented below in python docstrings */
	bool symvalid, unresolved, relative;
	unsigned long long st_value;
};

static int elfreloc_cmp(const struct elfreloc *a, const struct elfreloc *b);
static uint32_t elfreloc_hash(const struct elfreloc *reloc);

DECLARE_HASH(elfrelocs, struct elfreloc, elfrelocs_item,
	     elfreloc_cmp, elfreloc_hash);

static Elf_Scn *elf_find_addr(struct elffile *ef, uint64_t addr, size_t *idx);
static PyObject *elffile_secbyidx(struct elffile *w, Elf_Scn *scn, size_t idx);
static PyObject *elfreloc_getsection(PyObject *self, PyObject *args);
static PyObject *elfreloc_getaddend(PyObject *obj, void *closure);

/* --- end of declarations -------------------------------------------------- */

/*
 * class ELFReloc:
 */

static const char elfreloc_doc[] =
	"Represents an ELF relocation record\n"
	"\n"
	"(struct elfreloc * in elf_py.c)";

#define member(name, type, doc)                                                \
	{                                                                      \
		(char *)#name, type, offsetof(struct elfreloc, name), READONLY,\
		(char *)doc "\n\n(\"" #name "\", " #type " in elf_py.c)"       \
	}
static PyMemberDef members_elfreloc[] = {
	member(symname, T_STRING,
	       "Name of symbol this relocation refers to.\n"
	       "\n"
	       "Will frequently be `None` in executables and shared libraries."
	),
	member(symvalid, T_BOOL,
	       "Target symbol has a valid type, i.e. not STT_NOTYPE"),
	member(unresolved, T_BOOL,
	       "Target symbol refers to an existing section"),
	member(relative, T_BOOL,
	       "Relocation is a REL (not RELA) record and thus relative."),
	member(st_value, T_ULONGLONG,
	       "Target symbol's value, if known\n\n"
	       "Will be zero for unresolved/external symbols."),
	{}
};
#undef member

static PyGetSetDef getset_elfreloc[] = {
	{ .name = (char *)"r_addend", .get = elfreloc_getaddend, .doc =
		(char *)"Relocation addend value"},
	{}
};

static PyMethodDef methods_elfreloc[] = {
	{"getsection", elfreloc_getsection, METH_VARARGS,
		"Find relocation target's ELF section\n\n"
		"Args: address of relocatee (TODO: fix/remove?)\n"
		"Returns: ELFSection or None\n\n"
		"Not possible if section headers have been stripped."},
	{}
};

static int elfreloc_cmp(const struct elfreloc *a, const struct elfreloc *b)
{
	if (a->rela->r_offset < b->rela->r_offset)
		return -1;
	if (a->rela->r_offset > b->rela->r_offset)
		return 1;
	return 0;
}

static uint32_t elfreloc_hash(const struct elfreloc *reloc)
{
	return jhash(&reloc->rela->r_offset, sizeof(reloc->rela->r_offset),
		     0xc9a2b7f4);
}

static struct elfreloc *elfrelocs_get(struct elfrelocs_head *head,
				      GElf_Addr offset)
{
	struct elfreloc dummy;

	dummy.rela = &dummy._rela;
	dummy.rela->r_offset = offset;
	return elfrelocs_find(head, &dummy);
}

static PyObject *elfreloc_getsection(PyObject *self, PyObject *args)
{
	struct elfreloc *w = (struct elfreloc *)self;
	long data;

	if (!PyArg_ParseTuple(args, "k", &data))
		return NULL;

	if (!w->es)
		Py_RETURN_NONE;

	if (!w->symvalid || w->symidx == 0) {
		size_t idx = 0;
		Elf_Scn *scn;

		data = (w->relative ? data : 0) + w->rela->r_addend;
		scn = elf_find_addr(w->es->ef, data, &idx);
		if (!scn)
			Py_RETURN_NONE;
		return elffile_secbyidx(w->es->ef, scn, idx);
	}
	return elffile_secbyidx(w->es->ef, NULL, w->sym->st_shndx);
}

static PyObject *elfreloc_getaddend(PyObject *obj, void *closure)
{
	struct elfreloc *w = (struct elfreloc *)obj;

	return Py_BuildValue("K", (unsigned long long)w->rela->r_addend);
}

static PyObject *elfreloc_repr(PyObject *arg)
{
	struct elfreloc *w = (struct elfreloc *)arg;

	return PyUnicode_FromFormat("<ELFReloc @%lu %s+%lu>",
				    (unsigned long)w->rela->r_offset,
				    (w->symname && w->symname[0]) ? w->symname
						: "[0]",
				    (unsigned long)w->rela->r_addend);
}

static void elfreloc_free(void *arg)
{
	struct elfreloc *w = arg;

	(void)w;
}

static PyTypeObject typeobj_elfreloc = {
	PyVarObject_HEAD_INIT(NULL, 0).tp_name = "_clippy.ELFReloc",
	.tp_basicsize = sizeof(struct elfreloc),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = elfreloc_doc,
	.tp_new = refuse_new,
	.tp_free = elfreloc_free,
	.tp_repr = elfreloc_repr,
	.tp_members = members_elfreloc,
	.tp_methods = methods_elfreloc,
	.tp_getset = getset_elfreloc,
};

/*
 * class ELFSection:
 */

static const char elfsect_doc[] =
	"Represents an ELF section\n"
	"\n"
	"To access section contents, use subscript notation, e.g.\n"
	"  section[123:456]\n"
	"To read null terminated C strings, replace the end with str:\n"
	"  section[123:str]\n\n"
	"(struct elfsect * in elf_py.c)";

static PyObject *elfsect_getaddr(PyObject *self, void *closure);

#define member(name, type, doc)                                                \
	{                                                                      \
		(char *)#name, type, offsetof(struct elfsect, name), READONLY, \
		(char *)doc "\n\n(\"" #name "\", " #type " in elf_py.c)"       \
	}
static PyMemberDef members_elfsect[] = {
	member(name, T_STRING,
	       "Section name, e.g. \".text\""),
	member(idx, T_ULONG,
	       "Section index in file"),
	member(len, T_ULONG,
	       "Section length in bytes"),
	{},
};
#undef member

static PyGetSetDef getset_elfsect[] = {
	{ .name = (char *)"sh_addr", .get = elfsect_getaddr, .doc =
		(char *)"Section virtual address (mapped program view)"},
	{}
};

static PyObject *elfsect_getaddr(PyObject *self, void *closure)
{
	struct elfsect *w = (struct elfsect *)self;

	return Py_BuildValue("K", (unsigned long long)w->shdr->sh_addr);
}


static PyObject *elfsect_getreloc(PyObject *self, PyObject *args)
{
	struct elfsect *w = (struct elfsect *)self;
	struct elfreloc *relw;
	unsigned long offs;
	PyObject *ret;

	if (!PyArg_ParseTuple(args, "k", &offs))
		return NULL;

	relw = elfrelocs_get(&w->relocs, offs + w->shdr->sh_addr);
	if (!relw)
		Py_RETURN_NONE;

	ret = (PyObject *)relw;
	Py_INCREF(ret);
	return ret;
}

static PyMethodDef methods_elfsect[] = {
	{"getreloc", elfsect_getreloc, METH_VARARGS,
		"Check for / get relocation at offset into section\n\n"
		"Args: byte offset into section to check\n"
		"Returns: ELFReloc or None"},
	{}
};

static PyObject *elfsect_subscript(PyObject *self, PyObject *key)
{
	Py_ssize_t start, stop, step, sllen;
	struct elfsect *w = (struct elfsect *)self;
	PySliceObject *slice;
	unsigned long offs, len = ~0UL;

	if (!PySlice_Check(key)) {
		PyErr_SetString(PyExc_IndexError,
				"ELFSection subscript must be slice");
		return NULL;
	}
	slice = (PySliceObject *)key;
	if (PyLong_Check(slice->stop)) {
		if (PySlice_GetIndicesEx(key, w->shdr->sh_size,
					 &start, &stop, &step, &sllen))
			return NULL;

		if (step != 1) {
			PyErr_SetString(PyExc_IndexError,
					"ELFSection subscript slice step must be 1");
			return NULL;
		}
		if ((GElf_Xword)stop > w->shdr->sh_size) {
			PyErr_Format(ELFAccessError,
				     "access (%lu) beyond end of section %lu/%s (%lu)",
				     stop, w->idx, w->name, w->shdr->sh_size);
			return NULL;
		}

		offs = start;
		len = sllen;
	} else {
		if (slice->stop != (void *)&PyUnicode_Type
		    || !PyLong_Check(slice->start)) {
			PyErr_SetString(PyExc_IndexError, "invalid slice");
			return NULL;
		}

		offs = PyLong_AsUnsignedLongLong(slice->start);
		len = ~0UL;
	}

	offs += w->shdr->sh_offset;
	if (offs > w->ef->len) {
		PyErr_Format(ELFAccessError,
			     "access (%lu) beyond end of file (%lu)",
			     offs, w->ef->len);
		return NULL;
	}
	if (len == ~0UL)
		len = strnlen(w->ef->mmap + offs, w->ef->len - offs);

	Py_ssize_t pylen = len;

#if PY_MAJOR_VERSION >= 3
	return Py_BuildValue("y#", w->ef->mmap + offs, pylen);
#else
	return Py_BuildValue("s#", w->ef->mmap + offs, pylen);
#endif
}

static PyMappingMethods mp_elfsect = {
	.mp_subscript = elfsect_subscript,
};

static void elfsect_free(void *arg)
{
	struct elfsect *w = arg;

	(void)w;
}

static PyObject *elfsect_repr(PyObject *arg)
{
	struct elfsect *w = (struct elfsect *)arg;

	return PyUnicode_FromFormat("<ELFSection %s>", w->name);
}

static PyTypeObject typeobj_elfsect = {
	PyVarObject_HEAD_INIT(NULL, 0).tp_name = "_clippy.ELFSection",
	.tp_basicsize = sizeof(struct elfsect),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = elfsect_doc,
	.tp_new = refuse_new,
	.tp_free = elfsect_free,
	.tp_repr = elfsect_repr,
	.tp_as_mapping = &mp_elfsect,
	.tp_members = members_elfsect,
	.tp_methods = methods_elfsect,
	.tp_getset = getset_elfsect,
};

static void elfsect_add_relocations(struct elfsect *w, Elf_Scn *rel,
				    GElf_Shdr *relhdr)
{
	size_t i, entries;
	Elf_Scn *symtab = elf_getscn(w->ef->elf, relhdr->sh_link);
	GElf_Shdr _symhdr, *symhdr = gelf_getshdr(symtab, &_symhdr);
	Elf_Data *symdata = elf_getdata(symtab, NULL);
	Elf_Data *reldata = elf_getdata(rel, NULL);

	entries = relhdr->sh_size / relhdr->sh_entsize;
	for (i = 0; i < entries; i++) {
		struct elfreloc *relw;
		size_t symidx;
		GElf_Rela *rela;
		GElf_Sym *sym;

		relw = (struct elfreloc *)typeobj_elfreloc.tp_alloc(
				&typeobj_elfreloc, 0);
		relw->es = w;

		if (relhdr->sh_type == SHT_REL) {
			GElf_Rel _rel, *rel;

			rel = gelf_getrel(reldata, i, &_rel);
			relw->rela = &relw->_rela;
			relw->rela->r_offset = rel->r_offset;
			relw->rela->r_info = rel->r_info;
			relw->rela->r_addend = 0;
			relw->relative = true;
		} else
			relw->rela = gelf_getrela(reldata, i, &relw->_rela);

		rela = relw->rela;
		if (rela->r_offset < w->shdr->sh_addr
		    || rela->r_offset >= w->shdr->sh_addr + w->shdr->sh_size)
			continue;

		symidx = relw->symidx = GELF_R_SYM(rela->r_info);
		sym = relw->sym = gelf_getsym(symdata, symidx, &relw->_sym);
		if (sym) {
			relw->symname = elf_strptr(w->ef->elf, symhdr->sh_link,
						   sym->st_name);
			relw->symvalid = GELF_ST_TYPE(sym->st_info)
					!= STT_NOTYPE;
			relw->unresolved = sym->st_shndx == SHN_UNDEF;
			relw->st_value = sym->st_value;
		} else {
			relw->symname = NULL;
			relw->symvalid = false;
			relw->unresolved = false;
			relw->st_value = 0;
		}

		debugf("reloc @ %016llx sym %5llu %016llx %s\n",
		       (long long)rela->r_offset, (unsigned long long)symidx,
		       (long long)rela->r_addend, relw->symname);

		elfrelocs_add(&w->relocs, relw);
	}
}

/*
 * bindings & loading code between ELFFile and ELFSection
 */

static PyObject *elfsect_wrap(struct elffile *ef, Elf_Scn *scn, size_t idx,
			      const char *name)
{
	struct elfsect *w;
	size_t i;

	w = (struct elfsect *)typeobj_elfsect.tp_alloc(&typeobj_elfsect, 0);
	if (!w)
		return NULL;

	w->name = name;
	w->ef = ef;
	w->scn = scn;
	w->shdr = gelf_getshdr(scn, &w->_shdr);
	w->len = w->shdr->sh_size;
	w->idx = idx;
	elfrelocs_init(&w->relocs);

	for (i = 0; i < ef->ehdr->e_shnum; i++) {
		Elf_Scn *scn = elf_getscn(ef->elf, i);
		GElf_Shdr _shdr, *shdr = gelf_getshdr(scn, &_shdr);

		if (shdr->sh_type != SHT_RELA && shdr->sh_type != SHT_REL)
			continue;
		if (shdr->sh_info && shdr->sh_info != idx)
			continue;
		elfsect_add_relocations(w, scn, shdr);
	}

	return (PyObject *)w;
}

static Elf_Scn *elf_find_section(struct elffile *ef, const char *name,
		size_t *idx)
{
	size_t i;
	const char *secname;

	for (i = 0; i < ef->ehdr->e_shnum; i++) {
		Elf_Scn *scn = elf_getscn(ef->elf, i);
		GElf_Shdr _shdr, *shdr = gelf_getshdr(scn, &_shdr);

		secname = elf_strptr(ef->elf, ef->ehdr->e_shstrndx,
				     shdr->sh_name);
		if (strcmp(secname, name))
			continue;
		if (idx)
			*idx = i;
		return scn;
	}
	return NULL;
}

static Elf_Scn *elf_find_addr(struct elffile *ef, uint64_t addr, size_t *idx)
{
	size_t i;

	for (i = 0; i < ef->ehdr->e_shnum; i++) {
		Elf_Scn *scn = elf_getscn(ef->elf, i);
		GElf_Shdr _shdr, *shdr = gelf_getshdr(scn, &_shdr);

		/* virtual address is kinda meaningless for TLS sections */
		if (shdr->sh_flags & SHF_TLS)
			continue;
		if (addr < shdr->sh_addr ||
		    addr >= shdr->sh_addr + shdr->sh_size)
			continue;

		if (idx)
			*idx = i;
		return scn;
	}
	return NULL;
}

/*
 * class ELFFile:
 */

static const char elffile_doc[] =
	"Represents an ELF file\n"
	"\n"
	"Args: filename to load\n"
	"\n"
	"To access raw file contents, use subscript notation, e.g.\n"
	"  file[123:456]\n"
	"To read null terminated C strings, replace the end with str:\n"
	"  file[123:str]\n\n"
	"(struct elffile * in elf_py.c)";


#define member(name, type, doc)                                                \
	{                                                                      \
		(char *)#name, type, offsetof(struct elffile, name), READONLY, \
		(char *)doc "\n\n(\"" #name "\", " #type " in elf_py.c)"       \
	}
static PyMemberDef members_elffile[] = {
	member(filename, T_STRING,
	       "Original file name as given when opening"),
	member(elfclass, T_INT,
	       "ELF class (architecture bit size)\n\n"
	       "Either 32 or 64, straight integer."),
	member(bigendian, T_BOOL,
	       "ELF file is big-endian\n\n"
	       "All internal ELF structures are automatically converted."),
	member(has_symbols, T_BOOL,
	       "A symbol section is present\n\n"
	       "Note: only refers to .symtab/SHT_SYMTAB section, not DT_SYMTAB"
	),
	{},
};
#undef member

static PyObject *elffile_secbyidx(struct elffile *w, Elf_Scn *scn, size_t idx)
{
	const char *name;
	PyObject *ret;

	if (!scn)
		scn = elf_getscn(w->elf, idx);
	if (!scn || idx >= w->n_sect)
		Py_RETURN_NONE;

	if (!w->sects[idx]) {
		GElf_Shdr _shdr, *shdr = gelf_getshdr(scn, &_shdr);

		name = elf_strptr(w->elf, w->ehdr->e_shstrndx, shdr->sh_name);
		w->sects[idx] = elfsect_wrap(w, scn, idx, name);
	}

	ret = w->sects[idx];
	Py_INCREF(ret);
	return ret;
}

static PyObject *elffile_get_section(PyObject *self, PyObject *args)
{
	const char *name;
	struct elffile *w = (struct elffile *)self;
	Elf_Scn *scn;
	size_t idx = 0;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	scn = elf_find_section(w, name, &idx);
	return elffile_secbyidx(w, scn, idx);
}

static PyObject *elffile_get_section_addr(PyObject *self, PyObject *args)
{
	unsigned long long addr;
	struct elffile *w = (struct elffile *)self;
	Elf_Scn *scn;
	size_t idx = 0;

	if (!PyArg_ParseTuple(args, "K", &addr))
		return NULL;

	scn = elf_find_addr(w, addr, &idx);
	return elffile_secbyidx(w, scn, idx);
}

static PyObject *elffile_get_section_idx(PyObject *self, PyObject *args)
{
	unsigned long long idx;
	struct elffile *w = (struct elffile *)self;

	if (!PyArg_ParseTuple(args, "K", &idx))
		return NULL;

	return elffile_secbyidx(w, NULL, idx);
}

static PyObject *elffile_get_symbol(PyObject *self, PyObject *args)
{
	const char *name, *symname;
	struct elffile *w = (struct elffile *)self;
	GElf_Sym _sym, *sym;
	size_t i;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	for (i = 0; i < w->nsym; i++) {
		sym = gelf_getsym(w->symdata, i, &_sym);
		if (sym->st_name == 0)
			continue;
		symname = elf_strptr(w->elf, w->symstridx, sym->st_name);
		if (strcmp(symname, name))
			continue;

		PyObject *pysect;
		Elf_Scn *scn = elf_getscn(w->elf, sym->st_shndx);

		if (scn)
			pysect = elffile_secbyidx(w, scn, sym->st_shndx);
		else {
			pysect = Py_None;
			Py_INCREF(pysect);
		}
		return Py_BuildValue("sKN", symname,
				(unsigned long long)sym->st_value, pysect);
	}
	Py_RETURN_NONE;
}

static PyObject *elffile_getreloc(PyObject *self, PyObject *args)
{
	struct elffile *w = (struct elffile *)self;
	struct elfreloc *relw;
	unsigned long offs;
	PyObject *ret;

	if (!PyArg_ParseTuple(args, "k", &offs))
		return NULL;

	relw = elfrelocs_get(&w->dynrelocs, offs);
	if (!relw)
		Py_RETURN_NONE;

	ret = (PyObject *)relw;
	Py_INCREF(ret);
	return ret;
}

static PyObject *elffile_find_note(PyObject *self, PyObject *args)
{
#if defined(HAVE_GELF_GETNOTE) && defined(HAVE_ELF_GETDATA_RAWCHUNK)
	const char *owner;
	const uint8_t *ids;
	GElf_Word id;
	struct elffile *w = (struct elffile *)self;
	size_t i;

	if (!PyArg_ParseTuple(args, "ss", &owner, &ids))
		return NULL;

	if (strlen((char *)ids) != 4) {
		PyErr_SetString(PyExc_ValueError,
				"ELF note ID must be exactly 4-byte string");
		return NULL;
	}
	if (w->bigendian)
		id = (ids[0] << 24) | (ids[1] << 16) | (ids[2] << 8) | ids[3];
	else
		id = (ids[3] << 24) | (ids[2] << 16) | (ids[1] << 8) | ids[0];

	for (i = 0; i < w->ehdr->e_phnum; i++) {
		GElf_Phdr _phdr, *phdr = gelf_getphdr(w->elf, i, &_phdr);
		Elf_Data *notedata;
		size_t offset;

		if (phdr->p_type != PT_NOTE)
			continue;

		notedata = elf_getdata_rawchunk(w->elf, phdr->p_offset,
						phdr->p_filesz, ELF_T_NHDR);

		GElf_Nhdr nhdr[1];
		size_t nameoffs, dataoffs;

		offset = 0;
		while ((offset = gelf_getnote(notedata, offset, nhdr,
					      &nameoffs, &dataoffs))) {
			if (phdr->p_offset + nameoffs >= w->len)
				continue;

			const char *name = w->mmap + phdr->p_offset + nameoffs;

			if (strcmp(name, owner))
				continue;
			if (id != nhdr->n_type)
				continue;

			PyObject *s, *e;

			s = PyLong_FromUnsignedLongLong(
				phdr->p_vaddr + dataoffs);
			e = PyLong_FromUnsignedLongLong(
				phdr->p_vaddr + dataoffs + nhdr->n_descsz);
			return PySlice_New(s, e, NULL);
		}
	}
#endif
	Py_RETURN_NONE;
}

#ifdef HAVE_ELF_GETDATA_RAWCHUNK
static bool elffile_virt2file(struct elffile *w, GElf_Addr virt,
			      GElf_Addr *offs)
{
	*offs = 0;

	for (size_t i = 0; i < w->ehdr->e_phnum; i++) {
		GElf_Phdr _phdr, *phdr = gelf_getphdr(w->elf, i, &_phdr);

		if (phdr->p_type != PT_LOAD)
			continue;

		if (virt < phdr->p_vaddr
		    || virt >= phdr->p_vaddr + phdr->p_memsz)
			continue;

		if (virt >= phdr->p_vaddr + phdr->p_filesz)
			return false;

		*offs = virt - phdr->p_vaddr + phdr->p_offset;
		return true;
	}

	return false;
}
#endif /* HAVE_ELF_GETDATA_RAWCHUNK */

static PyObject *elffile_subscript(PyObject *self, PyObject *key)
{
	Py_ssize_t start, stop, step;
	PySliceObject *slice;
	struct elffile *w = (struct elffile *)self;
	bool str = false;

	if (!PySlice_Check(key)) {
		PyErr_SetString(PyExc_IndexError,
				"ELFFile subscript must be slice");
		return NULL;
	}
	slice = (PySliceObject *)key;
	stop = -1;
	step = 1;
	if (PyLong_Check(slice->stop)) {
		start = PyLong_AsSsize_t(slice->start);
		if (PyErr_Occurred())
			return NULL;
		if (slice->stop != Py_None) {
			stop = PyLong_AsSsize_t(slice->stop);
			if (PyErr_Occurred())
				return NULL;
		}
		if (slice->step != Py_None) {
			step = PyLong_AsSsize_t(slice->step);
			if (PyErr_Occurred())
				return NULL;
		}
	} else {
		if (slice->stop != (void *)&PyUnicode_Type
		    || !PyLong_Check(slice->start)) {
			PyErr_SetString(PyExc_IndexError, "invalid slice");
			return NULL;
		}

		str = true;
		start = PyLong_AsUnsignedLongLong(slice->start);
	}
	if (step != 1) {
		PyErr_SetString(PyExc_IndexError,
				"ELFFile subscript slice step must be 1");
		return NULL;
	}

	GElf_Addr xstart = start, xstop = stop;

	for (size_t i = 0; i < w->ehdr->e_phnum; i++) {
		GElf_Phdr _phdr, *phdr = gelf_getphdr(w->elf, i, &_phdr);

		if (phdr->p_type != PT_LOAD)
			continue;

		if (xstart < phdr->p_vaddr
		    || xstart >= phdr->p_vaddr + phdr->p_memsz)
			continue;
		if (!str && (xstop < phdr->p_vaddr
		    || xstop > phdr->p_vaddr + phdr->p_memsz)) {
			PyErr_Format(ELFAccessError,
				     "access (%llu) beyond end of program header (%llu)",
				     (long long)xstop,
				     (long long)(phdr->p_vaddr +
						 phdr->p_memsz));
			return NULL;
		}

		xstart = xstart - phdr->p_vaddr + phdr->p_offset;

		if (str)
			xstop = strlen(w->mmap + xstart);
		else
			xstop = xstop - phdr->p_vaddr + phdr->p_offset;

		Py_ssize_t pylen = xstop - xstart;

#if PY_MAJOR_VERSION >= 3
		return Py_BuildValue("y#", w->mmap + xstart, pylen);
#else
		return Py_BuildValue("s#", w->mmap + xstart, pylen);
#endif
	};

	return PyErr_Format(ELFAccessError,
			    "virtual address (%llu) not found in program headers",
			    (long long)start);
}

static PyMethodDef methods_elffile[] = {
	{"find_note", elffile_find_note, METH_VARARGS,
		"find specific note entry"},
	{"getreloc", elffile_getreloc, METH_VARARGS,
		"find relocation"},
	{"get_symbol", elffile_get_symbol, METH_VARARGS,
		"find symbol by name"},
	{"get_section", elffile_get_section, METH_VARARGS,
		"find section by name"},
	{"get_section_addr", elffile_get_section_addr, METH_VARARGS,
		"find section by address"},
	{"get_section_idx", elffile_get_section_idx, METH_VARARGS,
		"find section by index"},
	{}
};

static PyObject *elffile_load(PyTypeObject *type, PyObject *args,
			     PyObject *kwds);

static void elffile_free(void *arg)
{
	struct elffile *w = arg;

	elf_end(w->elf);
	munmap(w->mmap, w->len);
	free(w->filename);
}

static PyMappingMethods mp_elffile = {
	.mp_subscript = elffile_subscript,
};

static PyTypeObject typeobj_elffile = {
	PyVarObject_HEAD_INIT(NULL, 0).tp_name = "_clippy.ELFFile",
	.tp_basicsize = sizeof(struct elffile),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = elffile_doc,
	.tp_new = elffile_load,
	.tp_free = elffile_free,
	.tp_as_mapping = &mp_elffile,
	.tp_members = members_elffile,
	.tp_methods = methods_elffile,
};

#ifdef HAVE_ELF_GETDATA_RAWCHUNK
static char *elfdata_strptr(Elf_Data *data, size_t offset)
{
	char *p;

	if (offset >= data->d_size)
		return NULL;

	p = (char *)data->d_buf + offset;
	if (strnlen(p, data->d_size - offset) >= data->d_size - offset)
		return NULL;

	return p;
}

static void elffile_add_dynreloc(struct elffile *w, Elf_Data *reldata,
				 size_t entries, Elf_Data *symdata,
				 Elf_Data *strdata, Elf_Type typ)
{
	size_t i;

	for (i = 0; i < entries; i++) {
		struct elfreloc *relw;
		size_t symidx;
		GElf_Rela *rela;
		GElf_Sym *sym;
		GElf_Addr rel_offs = 0;

		relw = (struct elfreloc *)typeobj_elfreloc.tp_alloc(
				&typeobj_elfreloc, 0);
		relw->ef = w;

		if (typ == ELF_T_REL) {
			GElf_Rel _rel, *rel;
			GElf_Addr offs;

			rel = gelf_getrel(reldata, i, &_rel);
			relw->rela = &relw->_rela;
			relw->rela->r_offset = rel->r_offset;
			relw->rela->r_info = rel->r_info;
			relw->rela->r_addend = 0;
			relw->relative = true;

			/* REL uses the pointer contents itself instead of the
			 * RELA addend field :( ... theoretically this could
			 * be some weird platform specific encoding, but since
			 * we only care about data relocations it should
			 * always be a pointer...
			 */
			if (elffile_virt2file(w, rel->r_offset, &offs)) {
				Elf_Data *ptr;

				/* NB: this endian-converts! */
				ptr = elf_getdata_rawchunk(w->elf, offs,
							   w->elfclass / 8,
							   ELF_T_ADDR);

				if (ptr) {
					char *dst = (char *)&rel_offs;

					/* sigh.  it endian-converts.  but
					 * doesn't size-convert.
					 */
					if (BYTE_ORDER == BIG_ENDIAN &&
					    ptr->d_size < sizeof(rel_offs))
						dst += sizeof(rel_offs) -
						       ptr->d_size;

					memcpy(dst, ptr->d_buf, ptr->d_size);

					relw->relative = false;
					relw->rela->r_addend = rel_offs;
				}
			}
		} else
			relw->rela = gelf_getrela(reldata, i, &relw->_rela);

		rela = relw->rela;
		symidx = relw->symidx = GELF_R_SYM(rela->r_info);
		sym = relw->sym = gelf_getsym(symdata, symidx, &relw->_sym);
		if (sym) {
			if (strdata)
				relw->symname = elfdata_strptr(strdata,
							       sym->st_name);
			relw->symvalid = GELF_ST_TYPE(sym->st_info)
					!= STT_NOTYPE;
			relw->unresolved = sym->st_shndx == SHN_UNDEF;
			relw->st_value = sym->st_value;
		} else {
			relw->symname = NULL;
			relw->symvalid = false;
			relw->unresolved = false;
			relw->st_value = 0;
		}

		if (typ == ELF_T_RELA)
			debugf("dynrela @ %016llx sym %5llu %016llx %s\n",
			       (long long)rela->r_offset,
			       (unsigned long long)symidx,
			       (long long)rela->r_addend, relw->symname);
		else
			debugf("dynrel @ %016llx sym %5llu (%016llx) %s\n",
			       (long long)rela->r_offset,
			       (unsigned long long)symidx,
			       (unsigned long long)rel_offs, relw->symname);

		elfrelocs_add(&w->dynrelocs, relw);
	}

}
#endif /* HAVE_ELF_GETDATA_RAWCHUNK */

/* primary (only, really) entry point to anything in this module */
static PyObject *elffile_load(PyTypeObject *type, PyObject *args,
			      PyObject *kwds)
{
	const char *filename;
	static const char * const kwnames[] = {"filename", NULL};
	struct elffile *w;
	struct stat st;
	int fd, err;

	w = (struct elffile *)typeobj_elffile.tp_alloc(&typeobj_elffile, 0);
	if (!w)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", (char **)kwnames,
					 &filename))
		return NULL;

	w->filename = strdup(filename);
	fd = open(filename, O_RDONLY | O_NOCTTY);
	if (fd < 0 || fstat(fd, &st)) {
		PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
		if (fd >= 0)
			close(fd);
		goto out;
	}
	w->len = st.st_size;
	w->mmap = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (!w->mmap) {
		PyErr_SetFromErrnoWithFilename(PyExc_IOError, filename);
		close(fd);
		goto out;
	}
	close(fd);
	w->mmend = w->mmap + st.st_size;

	if (w->len < EI_NIDENT || memcmp(w->mmap, ELFMAG, SELFMAG)) {
		PyErr_SetString(ELFFormatError, "invalid ELF signature");
		goto out;
	}

	switch (w->mmap[EI_CLASS]) {
	case ELFCLASS32:
		w->elfclass = 32;
		break;
	case ELFCLASS64:
		w->elfclass = 64;
		break;
	default:
		PyErr_SetString(ELFFormatError, "invalid ELF class");
		goto out;
	}
	switch (w->mmap[EI_DATA]) {
	case ELFDATA2LSB:
		w->bigendian = false;
		break;
	case ELFDATA2MSB:
		w->bigendian = true;
		break;
	default:
		PyErr_SetString(ELFFormatError, "invalid ELF byte order");
		goto out;
	}

	w->elf = elf_memory(w->mmap, w->len);
	if (!w->elf)
		goto out_elferr;
	w->ehdr = gelf_getehdr(w->elf, &w->_ehdr);
	if (!w->ehdr)
		goto out_elferr;

	for (size_t i = 0; i < w->ehdr->e_shnum; i++) {
		Elf_Scn *scn = elf_getscn(w->elf, i);
		GElf_Shdr _shdr, *shdr = gelf_getshdr(scn, &_shdr);

		if (shdr->sh_type == SHT_SYMTAB) {
			w->symtab = scn;
			w->nsym = shdr->sh_size / shdr->sh_entsize;
			w->symdata = elf_getdata(scn, NULL);
			w->symstridx = shdr->sh_link;
			break;
		}
	}
	w->has_symbols = w->symtab && w->symstridx;
	elfrelocs_init(&w->dynrelocs);

#ifdef HAVE_ELF_GETDATA_RAWCHUNK
	for (size_t i = 0; i < w->ehdr->e_phnum; i++) {
		GElf_Phdr _phdr, *phdr = gelf_getphdr(w->elf, i, &_phdr);

		if (phdr->p_type != PT_DYNAMIC)
			continue;

		Elf_Data *dyndata = elf_getdata_rawchunk(w->elf,
				phdr->p_offset, phdr->p_filesz, ELF_T_DYN);

		GElf_Addr dynrela = 0, dynrel = 0, symtab = 0, strtab = 0;
		size_t dynrelasz = 0, dynrelaent = 0;
		size_t dynrelsz = 0, dynrelent = 0;
		size_t strsz = 0;
		GElf_Dyn _dyn, *dyn;

		for (size_t j = 0;; j++) {
			dyn = gelf_getdyn(dyndata, j, &_dyn);

			if (dyn->d_tag == DT_NULL)
				break;

			switch (dyn->d_tag) {
			case DT_SYMTAB:
				symtab = dyn->d_un.d_ptr;
				break;

			case DT_STRTAB:
				strtab = dyn->d_un.d_ptr;
				break;
			case DT_STRSZ:
				strsz = dyn->d_un.d_val;
				break;

			case DT_RELA:
				dynrela = dyn->d_un.d_ptr;
				break;
			case DT_RELASZ:
				dynrelasz = dyn->d_un.d_val;
				break;
			case DT_RELAENT:
				dynrelaent = dyn->d_un.d_val;
				break;

			case DT_REL:
				dynrel = dyn->d_un.d_ptr;
				break;
			case DT_RELSZ:
				dynrelsz = dyn->d_un.d_val;
				break;
			case DT_RELENT:
				dynrelent = dyn->d_un.d_val;
				break;
			}
		}

		GElf_Addr offset;
		Elf_Data *symdata = NULL, *strdata = NULL;

		if (elffile_virt2file(w, symtab, &offset))
			symdata = elf_getdata_rawchunk(w->elf, offset,
						       w->len - offset,
						       ELF_T_SYM);
		if (elffile_virt2file(w, strtab, &offset))
			strdata = elf_getdata_rawchunk(w->elf, offset,
						       strsz, ELF_T_BYTE);

		size_t c;

		if (dynrela && dynrelasz && dynrelaent
		    && elffile_virt2file(w, dynrela, &offset)) {
			Elf_Data *reladata = NULL;

			debugf("dynrela @%llx/%llx+%llx\n", (long long)dynrela,
			       (long long)offset, (long long)dynrelasz);

			reladata = elf_getdata_rawchunk(w->elf, offset,
							dynrelasz, ELF_T_RELA);

			c = dynrelasz / dynrelaent;
			elffile_add_dynreloc(w, reladata, c, symdata, strdata,
					     ELF_T_RELA);
		}

		if (dynrel && dynrelsz && dynrelent
		    && elffile_virt2file(w, dynrel, &offset)) {
			Elf_Data *reldata = NULL;

			debugf("dynrel @%llx/%llx+%llx\n", (long long)dynrel,
			       (long long)offset, (long long)dynrelsz);

			reldata = elf_getdata_rawchunk(w->elf, offset, dynrelsz,
						       ELF_T_REL);

			c = dynrelsz / dynrelent;
			elffile_add_dynreloc(w, reldata, c, symdata, strdata,
					     ELF_T_REL);
		}
	}
#endif

	w->sects = calloc(sizeof(PyObject *), w->ehdr->e_shnum);
	w->n_sect = w->ehdr->e_shnum;

	return (PyObject *)w;

out_elferr:
	err = elf_errno();

	PyErr_Format(ELFFormatError, "libelf error %d: %s",
		     err, elf_errmsg(err));
out:
	if (w->elf)
		elf_end(w->elf);
	free(w->filename);
	return NULL;
}

static PyObject *elfpy_debug(PyObject *self, PyObject *args)
{
	int arg;

	if (!PyArg_ParseTuple(args, "p", &arg))
		return NULL;

	debug = arg;

	Py_RETURN_NONE;
}

static PyMethodDef methods_elfpy[] = {
	{"elfpy_debug", elfpy_debug, METH_VARARGS, "switch debuging on/off"},
	{}
};

bool elf_py_init(PyObject *pymod)
{
	if (PyType_Ready(&typeobj_elffile) < 0)
		return false;
	if (PyType_Ready(&typeobj_elfsect) < 0)
		return false;
	if (PyType_Ready(&typeobj_elfreloc) < 0)
		return false;
	if (elf_version(EV_CURRENT) == EV_NONE)
		return false;

#if PY_MAJOR_VERSION >= 3 && PY_MINOR_VERSION >= 5
	PyModule_AddFunctions(pymod, methods_elfpy);
#else
	(void)methods_elfpy;
#endif

	ELFFormatError = PyErr_NewException("_clippy.ELFFormatError",
					    PyExc_ValueError, NULL);
	PyModule_AddObject(pymod, "ELFFormatError", ELFFormatError);
	ELFAccessError = PyErr_NewException("_clippy.ELFAccessError",
					    PyExc_IndexError, NULL);
	PyModule_AddObject(pymod, "ELFAccessError", ELFAccessError);

	Py_INCREF(&typeobj_elffile);
	PyModule_AddObject(pymod, "ELFFile", (PyObject *)&typeobj_elffile);
	Py_INCREF(&typeobj_elfsect);
	PyModule_AddObject(pymod, "ELFSection", (PyObject *)&typeobj_elfsect);
	Py_INCREF(&typeobj_elfreloc);
	PyModule_AddObject(pymod, "ELFReloc", (PyObject *)&typeobj_elfreloc);
	return true;
}
