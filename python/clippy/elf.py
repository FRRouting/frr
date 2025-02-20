# SPDX-License-Identifier: GPL-2.0-or-later
# FRR libelf wrapper
#
# Copyright (C) 2020  David Lamparter for NetDEF, Inc.

"""
Wrapping layer and additional utility around _clippy.ELFFile.

Essentially, the C bits have the low-level ELF access bits that should be
fast while this has the bits that string everything together (and would've
been a PITA to do in C.)

Surprisingly - or maybe through proper engineering - this actually works
across architecture, word size and even endianness boundaries.  Both the C
module (through GElf_*) and this code (cf. struct.unpack format mangling
in ELFDissectStruct) will take appropriate measures to flip and resize
fields as needed.
"""

import struct
from collections import OrderedDict
from weakref import WeakValueDictionary

from _clippy import ELFFile, ELFAccessError

#
# data access
#


class ELFNull(object):
    """
    NULL pointer, returned instead of ELFData
    """

    def __init__(self):
        self.symname = None
        self._dstsect = None

    def __repr__(self):
        return "<ptr: NULL>"

    def __hash__(self):
        return hash(None)

    def get_string(self):
        return None


class ELFUnresolved(object):
    """
    Reference to an unresolved external symbol, returned instead of ELFData

    :param symname: name of the referenced symbol
    :param addend:  offset added to the symbol, normally zero
    """

    def __init__(self, symname, addend):
        self.addend = addend
        self.symname = symname
        self._dstsect = None

    def __repr__(self):
        return "<unresolved: %s+%d>" % (self.symname, self.addend)

    def __hash__(self):
        return hash((self.symname, self.addend))


class ELFData(object):
    """
    Actual data somewhere in the ELF file.

    :type dstsect:  ELFSubset
    :param dstsect: container data area (section or entire file)
    :param dstoffs: byte offset into dstsect
    :param dstlen:  byte size of object, or None if unknown, open-ended or string
    """

    def __init__(self, dstsect, dstoffs, dstlen):
        self._dstsect = dstsect
        self._dstoffs = dstoffs
        self._dstlen = dstlen
        self.symname = None

    def __repr__(self):
        return "<ptr: %s+0x%05x/%d>" % (
            self._dstsect.name,
            self._dstoffs,
            self._dstlen or -1,
        )

    def __hash__(self):
        return hash((self._dstsect, self._dstoffs))

    def get_string(self):
        """
        Interpret as C string / null terminated UTF-8 and get the actual text.
        """
        try:
            return self._dstsect[self._dstoffs : str].decode("UTF-8")
        except:
            import pdb

            pdb.set_trace()

    def get_data(self, reflen):
        """
        Interpret as some structure (and check vs. expected length)

        :param reflen: expected size of the object, compared against actual
            size (which is only known in rare cases, mostly when directly
            accessing a symbol since symbols have their destination object
            size recorded)
        """
        if self._dstlen is not None and self._dstlen != reflen:
            raise ValueError(
                "symbol size mismatch (got %d, expected %d)" % (self._dstlen, reflen)
            )
        return self._dstsect[self._dstoffs : self._dstoffs + reflen]

    def offset(self, offs, within_symbol=False):
        """
        Get another ELFData at an offset

        :param offs:          byte offset, can be negative (e.g. in container_of)
        :param within_symbol: retain length information
        """
        if self._dstlen is None or not within_symbol:
            return ELFData(self._dstsect, self._dstoffs + offs, None)
        else:
            return ELFData(self._dstsect, self._dstoffs + offs, self._dstlen - offs)


#
# dissection data items
#


class ELFDissectData(object):
    """
    Common bits for ELFDissectStruct and ELFDissectUnion
    """

    def __init__(self):
        self._data = None
        self.elfclass = None

    def __len__(self):
        """
        Used for boolean evaluation, e.g. "if struct: ..."
        """
        return not (
            isinstance(self._data, ELFNull) or isinstance(self._data, ELFUnresolved)
        )

    def container_of(self, parent, fieldname):
        """
        Assume this struct is embedded in a larger struct and get at the larger

        Python ``self.container_of(a, b)`` = C ``container_of(self, a, b)``

        :param parent:    class (not instance) of the larger struct
        :param fieldname: fieldname that refers back to this
        :returns:         instance of parent, with fieldname set to this object
        """
        offset = 0
        if not hasattr(parent, "_efields"):
            parent._setup_efields()

        for field in parent._efields[self.elfclass]:
            if field[0] == fieldname:
                break
            spec = field[1]
            if spec == "P":
                spec = "I" if self.elfclass == 32 else "Q"
            offset += struct.calcsize(spec)
        else:
            raise AttributeError("%r not found in %r.fields" % (fieldname, parent))

        return parent(self._data.offset(-offset), replace={fieldname: self})


class ELFDissectStruct(ELFDissectData):
    """
    Decode and provide access to a struct somewhere in the ELF file

    Handles pointers and strings somewhat nicely.  Create a subclass for each
    struct that is to be accessed, and give a field list in a "fields"
    class-member.

    :param dataptr: ELFData referring to the data bits to decode.
    :param parent:  where this was instantiated from; only for reference, has
        no functional impact.
    :param replace: substitute data values for specific fields.  Used by
        `container_of` to replace the inner struct when creating the outer
        one.

    .. attribute:: fields

       List of tuples describing the struct members.  Items can be:
       - ``('name', ELFDissectData)`` - directly embed another struct
       - ``('name', 'I')`` - simple data types; second item for struct.unpack
       - ``('name', 'I', None)`` - field to ignore
       - ``('name', 'P', str)`` - pointer to string
       - ``('name', 'P', ELFDissectData)`` - pointer to another struct

       ``P`` is added as unpack format for pointers (sized appropriately for
       the ELF file.)

       Refer to tiabwarfo.py for extracting this from ``pahole``.

       TBD: replace tuples with a class.

    .. attribute:: fieldrename

       Dictionary to rename fields, useful if fields comes from tiabwarfo.py.
    """

    class Pointer(object):
        """
        Quick wrapper for pointers to further structs

        This is just here to avoid going into infinite loops when loading
        structs that have pointers to each other (e.g. struct xref <-->
        struct xrefdata.)  The pointer destination is only instantiated when
        actually accessed.
        """

        def __init__(self, cls, ptr):
            self.cls = cls
            self.ptr = ptr

        def __repr__(self):
            return "<Pointer:%s %r>" % (self.cls.__name__, self.ptr)

        def __call__(self):
            if isinstance(self.ptr, ELFNull):
                return None
            return self.cls(self.ptr)

    def __new__(cls, dataptr, parent=None, replace=None):
        if dataptr._dstsect is None:
            return super().__new__(cls)

        obj = dataptr._dstsect._pointers.get((cls, dataptr))
        if obj is not None:
            return obj
        obj = super().__new__(cls)
        dataptr._dstsect._pointers[(cls, dataptr)] = obj
        return obj

    replacements = "lLnN"

    @classmethod
    def _preproc_structspec(cls, elfclass, spec):
        elfbits = elfclass

        if hasattr(spec, "calcsize"):
            spec = "%ds" % (spec.calcsize(elfclass),)

        if elfbits == 32:
            repl = ["i", "I"]
        else:
            repl = ["q", "Q"]
        for c in cls.replacements:
            spec = spec.replace(c, repl[int(c.isupper())])
        return spec

    @classmethod
    def _setup_efields(cls):
        cls._efields = {}
        cls._esize = {}
        for elfclass in [32, 64]:
            cls._efields[elfclass] = []
            size = 0
            for f in cls.fields:
                newf = (f[0], cls._preproc_structspec(elfclass, f[1])) + f[2:]
                cls._efields[elfclass].append(newf)
                size += struct.calcsize(newf[1])
            cls._esize[elfclass] = size

    def __init__(self, dataptr, parent=None, replace=None):
        if not hasattr(self.__class__, "_efields"):
            self._setup_efields()

        self._fdata = None
        self._data = dataptr
        self._parent = parent
        self.symname = dataptr.symname
        if isinstance(dataptr, ELFNull) or isinstance(dataptr, ELFUnresolved):
            self._fdata = {}
            return

        self._elfsect = dataptr._dstsect
        self.elfclass = self._elfsect._elffile.elfclass
        self.offset = dataptr._dstoffs

        pspecl = [f[1] for f in self._efields[self.elfclass]]

        # need to correlate output from struct.unpack with extra metadata
        # about the particular fields, so note down byte offsets (in locs)
        # and tuple indices of pointers (in ptrs)
        pspec = ""
        locs = {}
        ptrs = set()

        for idx, spec in enumerate(pspecl):
            if spec == "P":
                ptrs.add(idx)
                spec = self._elfsect.ptrtype

            locs[idx] = struct.calcsize(pspec)
            pspec = pspec + spec

        self._total_size = struct.calcsize(pspec)

        def replace_ptrs(v):
            idx, val = v[0], v[1]
            if idx not in ptrs:
                return val
            return self._elfsect.pointer(self.offset + locs[idx])

        data = dataptr.get_data(struct.calcsize(pspec))
        unpacked = struct.unpack(self._elfsect.endian + pspec, data)
        unpacked = list(map(replace_ptrs, enumerate(unpacked)))
        self._fraw = unpacked
        self._fdata = OrderedDict()
        replace = replace or {}

        for i, item in enumerate(unpacked):
            name = self.fields[i][0]
            if name is None:
                continue

            if name in replace:
                self._fdata[name] = replace[name]
                continue

            if isinstance(self.fields[i][1], type) and issubclass(
                self.fields[i][1], ELFDissectData
            ):
                dataobj = self.fields[i][1](dataptr.offset(locs[i]), self)
                self._fdata[name] = dataobj
                continue
            if len(self.fields[i]) == 3:
                if self.fields[i][2] == str:
                    self._fdata[name] = item.get_string()
                    continue
                elif self.fields[i][2] is None:
                    pass
                elif issubclass(self.fields[i][2], ELFDissectData):
                    cls = self.fields[i][2]
                    dataobj = self.Pointer(cls, item)
                    self._fdata[name] = dataobj
                    continue

            self._fdata[name] = item

    def __getattr__(self, attrname):
        if attrname not in self._fdata:
            raise AttributeError(attrname)
        if isinstance(self._fdata[attrname], self.Pointer):
            self._fdata[attrname] = self._fdata[attrname]()
        return self._fdata[attrname]

    def __repr__(self):
        if not isinstance(self._data, ELFData):
            return "<%s: %r>" % (self.__class__.__name__, self._data)
        return "<%s: %s>" % (
            self.__class__.__name__,
            ", ".join(["%s=%r" % t for t in self._fdata.items()]),
        )

    @classmethod
    def calcsize(cls, elfclass):
        """
        Sum up byte size of this struct

        Wraps struct.calcsize with some extra features.
        """
        if not hasattr(cls, "_efields"):
            cls._setup_efields()

        pspec = "".join([f[1] for f in cls._efields[elfclass]])

        ptrtype = "I" if elfclass == 32 else "Q"
        pspec = pspec.replace("P", ptrtype)

        return struct.calcsize(pspec)


class ELFDissectUnion(ELFDissectData):
    """
    Decode multiple structs in the same place.

    Not currently used (and hence not tested.)  Worked at some point but not
    needed anymore and may be borked now.  Remove this comment when using.
    """

    members = {}

    def __init__(self, dataptr, parent=None):
        self._dataptr = dataptr
        self._parent = parent
        self.members = []
        for name, membercls in self.__class__.members:
            item = membercls(dataptr, parent)
            self.members.append(item)
            setattr(self, name, item)

    def __repr__(self):
        return "<%s: %s>" % (
            self.__class__.__name__,
            ", ".join([repr(i) for i in self.members]),
        )

    @classmethod
    def calcsize(cls, elfclass):
        return max([member.calcsize(elfclass) for name, member in cls.members])


#
# wrappers for spans of ELF data
#


class ELFSubset(object):
    """
    Common abstract base for section-level and file-level access.
    """

    def __init__(self):
        super().__init__()

        self.name = None
        self._obj = None
        self._elffile = None
        self.ptrtype = None
        self.endian = None
        self._pointers = WeakValueDictionary()

    def _wrap_data(self, data, dstsect):
        raise NotImplementedError()

    def __hash__(self):
        return hash(self.name)

    def __getitem__(self, k):
        """
        Read data from slice

        Subscript **must** be a slice; a simple index will not return a byte
        but rather throw an exception.  Valid slice syntaxes are defined by
        the C module:

        - `this[123:456]` - extract specific range
        - `this[123:str]` - extract until null byte.  The slice stop value is
            the `str` type (or, technically, `unicode`.)
        """
        if k.start < getattr(self._obj, "len", float("+Inf")):
            return self._obj[k]

        real_sect = self._elffile.get_section_addr(self._obj.sh_addr + k.start)
        offs = self._obj.sh_addr - real_sect.sh_addr
        if k.stop is str:
            new_k = slice(k.start + offs, str)
        else:
            new_k = slice(k.start + offs, k.stop + offs)
        return real_sect[new_k]

    def getreloc(self, offset):
        """
        Check for a relocation record at the specified offset.
        """
        return self._obj.getreloc(offset)

    def iter_data(self, scls, slice_=slice(None)):
        """
        Assume an array of structs present at a particular slice and decode

        :param scls:   ELFDissectData subclass for the struct
        :param slice_: optional range specification
        """
        size = scls.calcsize(self._elffile.elfclass)

        offset = slice_.start or 0
        stop = slice_.stop or self._obj.len
        if stop < 0:
            stop = self._obj.len - stop

        while offset < stop:
            yield scls(ELFData(self, offset, size))
            offset += size

    def pointer(self, offset):
        """
        Try to dereference a pointer value

        This checks whether there's a relocation at the given offset and
        uses that;  otherwise (e.g. in a non-PIE executable where the pointer
        is already resolved by the linker) the data at the location is used.

        :param offset: byte offset from beginning of section,
            or virtual address in file
        :returns:      ELFData wrapping pointed-to object
        """

        ptrsize = struct.calcsize(self.ptrtype)
        data = struct.unpack(
            self.endian + self.ptrtype, self[offset : offset + ptrsize]
        )[0]

        reloc = self.getreloc(offset)
        dstsect = None
        if reloc:
            # section won't be available in whole-file operation
            dstsect = reloc.getsection(data)
            addend = reloc.r_addend

            if reloc.relative:
                # old-style ELF REL instead of RELA, not well-tested
                addend += data

            if reloc.unresolved and reloc.symvalid:
                return ELFUnresolved(reloc.symname, addend)
            elif reloc.symvalid:
                data = addend + reloc.st_value
            else:
                data = addend

        # 0 could technically be a valid pointer for a shared library,
        # since libraries may use 0 as default virtual start address (it'll
        # be adjusted on loading)
        # That said, if the library starts at 0, that's where the ELF header
        # would be so it's still an invalid pointer.
        if data == 0 and dstsect == None:
            return ELFNull()

        # wrap_data is different between file & section
        return self._wrap_data(data, dstsect)


class ELFDissectSection(ELFSubset):
    """
    Access the contents of an ELF section like ``.text`` or ``.data``

    :param elfwrap: ELFDissectFile wrapper for the file
    :param idx:     section index in section header table
    :param section: section object from C module
    """

    def __init__(self, elfwrap, idx, section):
        super().__init__()

        self._elfwrap = elfwrap
        self._elffile = elfwrap._elffile
        self._idx = idx
        self._section = self._obj = section
        self.name = section.name
        self.ptrtype = elfwrap.ptrtype
        self.endian = elfwrap.endian

    def _wrap_data(self, data, dstsect):
        if dstsect is None:
            dstsect = self._elfwrap._elffile.get_section_addr(data)
        offs = data - dstsect.sh_addr
        dstsect = self._elfwrap.get_section(dstsect.idx)
        return ELFData(dstsect, offs, None)


class ELFDissectFile(ELFSubset):
    """
    Access the contents of an ELF file.

    Note that offsets for array subscript and relocation/pointer access are
    based on the file's virtual address space and are NOT offsets to the
    start of the file on disk!

    (Shared libraries frequently have a virtual address space starting at 0,
    but non-PIE executables have an architecture specific default loading
    address like 0x400000 on x86.

    :param filename: ELF file to open
    """

    def __init__(self, filename):
        super().__init__()

        self.name = filename
        self._elffile = self._obj = ELFFile(filename)
        self._sections = {}

        self.ptrtype = "I" if self._elffile.elfclass == 32 else "Q"
        self.endian = ">" if self._elffile.bigendian else "<"

    @property
    def _elfwrap(self):
        return self

    def _wrap_data(self, data, dstsect):
        return ELFData(self, data, None)

    def get_section(self, secname):
        """
        Look up section by name or index
        """
        if isinstance(secname, int):
            sh_idx = secname
            section = self._elffile.get_section_idx(secname)
        else:
            section = self._elffile.get_section(secname)

        if section is None:
            return None

        sh_idx = section.idx

        if sh_idx not in self._sections:
            self._sections[sh_idx] = ELFDissectSection(self, sh_idx, section)

        return self._sections[sh_idx]
