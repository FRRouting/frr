# SPDX-License-Identifier: GPL-2.0-or-later
# FRR Mach-O reader for xrelfo
#
# Copyright (C) 2026  FRRouting

"""
Minimal read-only Mach-O reader, exposing the same duck-typed interface that
python/clippy/elf.py expects from the ``_clippy.ELFFile`` C module (which wraps
libelf and therefore can't open Mach-O binaries.)

Only what xrelfo needs is implemented:

- thin and fat/universal 64-bit little-endian images (arm64 / x86_64)
- executables, dylibs and bundles (``MH_EXECUTE`` / ``MH_DYLIB`` / ``MH_BUNDLE``)
- section lookup by name and by address
- pointer fixups, as a "relocation" lookup, from either

  - ``LC_DYLD_CHAINED_FIXUPS`` (default since Xcode 13), pointer formats
    ``DYLD_CHAINED_PTR_64`` and ``DYLD_CHAINED_PTR_64_OFFSET`` or
  - ``LC_DYLD_INFO(_ONLY)`` (``-Wl,-no_fixup_chains``), where data slots hold
    final virtual addresses and no relocation lookup is needed

Not implemented:  relocatable object files (``MH_OBJECT``), 32-bit and
big-endian Mach-O, arm64e pointer authentication formats, and bind opcodes of
the classic ``LC_DYLD_INFO`` encoding (external pointers read as NULL there.)

xrelfo only ever reads fully linked programs, libraries and modules (see the
``%.xref`` rule in lib/subdir.am), so none of that is needed.
"""

import mmap
import os
import platform
import struct

try:
    from _clippy import ELFAccessError as _AccessBase
except ImportError:
    # clippy built without libelf (e.g. on macOS)
    _AccessBase = IndexError


class MachOAccessError(_AccessBase):
    """Out of bounds read, analog of _clippy.ELFAccessError"""


class MachOFormatError(ValueError):
    """Malformed or unsupported Mach-O file, analog of _clippy.ELFFormatError"""


MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

# first 4 bytes on disk, for cheap sniffing without opening the file twice
_MACHO_HDRS = {
    struct.pack("<I", MH_MAGIC_64),
    struct.pack("<I", MH_MAGIC),
    struct.pack(">I", MH_MAGIC_64),
    struct.pack(">I", MH_MAGIC),
    struct.pack(">I", FAT_MAGIC),
    struct.pack(">I", FAT_MAGIC_64),
}


def is_macho_header(hdr):
    """
    Check whether the first 4 bytes of a file look like a Mach-O image

    (This is true for Mach-O of any flavor, including those that can't be read
    by this module.  Fat binary magic is shared with Java class files, but
    those won't be found next to FRR binaries.)
    """
    return bytes(hdr[:4]) in _MACHO_HDRS


MH_OBJECT = 0x1
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_BUNDLE = 0x8

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034

SECTION_TYPE_MASK = 0xFF
S_ZEROFILL = 0x1
S_GB_ZEROFILL = 0xC
S_THREAD_LOCAL_ZEROFILL = 0x12
_ZEROFILL_TYPES = (S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL)
S_THREAD_LOCAL_REGULAR = 0x11
S_THREAD_LOCAL_VARIABLES = 0x13

# dyld_chained_ptr_format
DYLD_CHAINED_PTR_64 = 2
DYLD_CHAINED_PTR_64_OFFSET = 6

DYLD_CHAINED_PTR_START_NONE = 0xFFFF
DYLD_CHAINED_PTR_START_MULTI = 0x8000
DYLD_CHAINED_PTR_START_LAST = 0x8000

# dyld_chained_import_format
DYLD_CHAINED_IMPORT = 1
DYLD_CHAINED_IMPORT_ADDEND = 2
DYLD_CHAINED_IMPORT_ADDEND64 = 3

# chained pointers are always 4-byte strided for the 64-bit formats we handle
_CHAIN_STRIDE = 4


def _cstr(buf, off):
    end = buf.find(b"\0", off)
    if end < 0:
        end = len(buf)
    return bytes(buf[off:end]).decode("UTF-8", "replace")


def _clean_name(raw):
    return raw.split(b"\0", 1)[0].decode("UTF-8", "replace")


class MachOReloc(object):
    """
    Pointer fixup, analog of _clippy.ELFReloc

    For a rebase, ``r_addend`` is the (virtual address) target and ``symvalid``
    is false.  For a bind, ``symname`` names the imported symbol, ``symvalid``
    and ``unresolved`` are true and ``r_addend`` holds the addend.
    """

    relative = False
    st_value = 0

    def __init__(self, macho, target=None, symname=None, addend=0):
        self._macho = macho
        self.symname = symname
        self.r_addend = target if symname is None else addend
        self.symvalid = symname is not None
        self.unresolved = symname is not None

    def getsection(self, data):
        if self.unresolved:
            return None
        return self._macho.get_section_addr(self.r_addend)

    def __repr__(self):
        if self.symname is None:
            return "<MachOReloc rebase -> 0x%x>" % (self.r_addend,)
        return "<MachOReloc bind %s+%d>" % (self.symname, self.r_addend)


class MachOSection(object):
    """
    A Mach-O section, analog of _clippy.ELFSection

    Subscripting returns bytes, same as for ELF; ``section[a:b]`` reads a range
    and ``section[a:str]`` reads a NUL terminated string.  ``idx`` is the
    1-based section ordinal (the same numbering as nlist ``n_sect``.)
    """

    def __init__(self, macho, idx, segname, name, addr, size, offset, flags):
        self._macho = macho
        self.idx = idx
        self.segname = segname
        self.name = name
        self.sh_addr = addr
        self.len = size
        self.sh_offset = offset
        self.flags = flags

    @property
    def _zerofill(self):
        return (self.flags & SECTION_TYPE_MASK) in _ZEROFILL_TYPES

    def getreloc(self, offset):
        return self._macho.getreloc(self.sh_addr + offset)

    def __getitem__(self, key):
        if not isinstance(key, slice):
            raise IndexError("MachOSection subscript must be slice")

        if key.stop is str:
            if not isinstance(key.start, int):
                raise IndexError("invalid slice")
            start = key.start
            if start > self.len:
                raise MachOAccessError(
                    "access (%d) beyond end of section %d/%s (%d)"
                    % (start, self.idx, self.name, self.len)
                )
            if self._zerofill:
                return b""
            return self._macho._read_cstr(self.sh_offset + start)

        start = key.start or 0
        stop = self.len if key.stop is None else key.stop
        step = key.step or 1
        if step != 1:
            raise IndexError("MachOSection subscript slice step must be 1")
        if stop > self.len:
            raise MachOAccessError(
                "access (%d) beyond end of section %d/%s (%d)"
                % (stop, self.idx, self.name, self.len)
            )
        if stop < start:
            return b""
        if self._zerofill:
            return b"\0" * (stop - start)
        return self._macho._read(self.sh_offset + start, stop - start)

    def __repr__(self):
        return "<MachOSection %s,%s>" % (self.segname, self.name)


class _Segment(object):
    def __init__(self, name, vmaddr, vmsize, fileoff, filesize):
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.fileoff = fileoff
        self.filesize = filesize


class MachOFile(object):
    """
    A Mach-O image, analog of _clippy.ELFFile

    :param filename: file to open.  Fat binaries are accepted, the slice
        matching the host CPU is used (or the first one if none matches.)

    Subscripting reads from the image's virtual address space (like ELFFile
    does for its PT_LOAD segments), i.e. ``file[addr:addr + n]``.
    """

    #: no ELF-style note support, xref data is found through its section
    supports_notes = False
    is_macho = True

    elfclass = 64
    bigendian = False

    def __init__(self, filename):
        self.filename = filename
        self.has_symbols = False

        self._fd = open(filename, "rb")
        try:
            self._mm = mmap.mmap(self._fd.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            self._fd.close()
            raise MachOFormatError("%s: empty file" % (filename,))

        self._base = 0
        self._select_slice()

        self.filetype = None
        self.segments = []
        self.sections = []
        self._by_name = {}
        self._symtab = None
        self._chained = None
        self._fixups = None
        self._parse()

    # -- raw access --------------------------------------------------------

    def _read(self, off, size):
        off += self._base
        if off < 0 or off + size > len(self._mm):
            raise MachOAccessError(
                "access (%d) beyond end of file (%d)" % (off + size, len(self._mm))
            )
        return self._mm[off : off + size]

    def _read_cstr(self, off):
        off += self._base
        if off < 0 or off > len(self._mm):
            raise MachOAccessError(
                "access (%d) beyond end of file (%d)" % (off, len(self._mm))
            )
        end = self._mm.find(b"\0", off)
        if end < 0:
            end = len(self._mm)
        return self._mm[off:end]

    def _unpack(self, fmt, off):
        return struct.unpack(fmt, self._read(off, struct.calcsize(fmt)))

    # -- header / load commands -------------------------------------------

    def _select_slice(self):
        magic = struct.unpack(">I", self._mm[0:4])[0]
        if magic not in (FAT_MAGIC, FAT_MAGIC_64):
            return

        is64 = magic == FAT_MAGIC_64
        nfat = struct.unpack(">I", self._mm[4:8])[0]
        entsize = 32 if is64 else 20
        archs = []
        for i in range(nfat):
            ent = self._mm[8 + i * entsize : 8 + (i + 1) * entsize]
            if is64:
                cpu, _, off, size = struct.unpack(">iiQQ", ent[:24])
            else:
                cpu, _, off, size = struct.unpack(">iiII", ent[:16])
            archs.append((cpu & 0xFFFFFFFF, off, size))

        if not archs:
            raise MachOFormatError("%s: empty fat binary" % (self.filename,))

        host = {"arm64": CPU_TYPE_ARM64, "x86_64": CPU_TYPE_X86_64}.get(
            platform.machine()
        )
        for cpu, off, size in archs:
            if cpu == host:
                break
        else:
            cpu, off, size = archs[0]
        self._base = off

    def _parse(self):
        magic = struct.unpack("<I", self._read(0, 4))[0]
        if magic == MH_MAGIC_64:
            pass
        elif magic == MH_MAGIC:
            raise MachOFormatError("%s: 32-bit Mach-O not supported" % self.filename)
        else:
            raise MachOFormatError(
                "%s: not a little-endian 64-bit Mach-O (magic 0x%08x)"
                % (self.filename, magic)
            )

        _, cputype, _, self.filetype, ncmds, _, _, _ = self._unpack("<IiiIIIII", 0)

        if self.filetype == MH_OBJECT:
            raise MachOFormatError(
                "%s: relocatable Mach-O object files are not supported, "
                "only linked images" % (self.filename,)
            )

        off = 32
        chained = None
        symtab = None
        for _ in range(ncmds):
            cmd, size = self._unpack("<II", off)

            if cmd == LC_SEGMENT_64:
                self._parse_segment(off)
            elif cmd == LC_SYMTAB:
                symtab = self._unpack("<IIII", off + 8)
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                chained = self._unpack("<II", off + 8)
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                # classic encoding:  data slots already hold final addresses
                pass

            off += size

        self._chained = chained
        if symtab is not None:
            self._symtab = symtab
            self.has_symbols = symtab[1] > 0

    def _parse_segment(self, off):
        raw = self._read(off + 8, 16)
        segname = _clean_name(raw)
        vmaddr, vmsize, fileoff, filesize = self._unpack("<QQQQ", off + 24)
        nsects = self._unpack("<I", off + 64)[0]
        self.segments.append(_Segment(segname, vmaddr, vmsize, fileoff, filesize))

        sec_off = off + 72
        for _ in range(nsects):
            sectname = _clean_name(self._read(sec_off, 16))
            sec_segname = _clean_name(self._read(sec_off + 16, 16))
            addr, size, offset, _, _, _, flags = self._unpack("<QQIIIII", sec_off + 32)
            sec_off += 80

            sect = MachOSection(
                self,
                len(self.sections) + 1,
                sec_segname,
                sectname,
                addr,
                size,
                offset,
                flags,
            )
            self.sections.append(sect)
            self._by_name.setdefault(sectname, sect)
            self._by_name.setdefault("%s,%s" % (sec_segname, sectname), sect)

    # -- ELFFile API ---------------------------------------------------------

    def find_note(self, owner, ident):
        """Mach-O has no ELF notes"""
        return None

    def get_section(self, name):
        """
        Find section by name, either ``"xref_array"`` or ``"__DATA,xref_array"``
        """
        return self._by_name.get(name)

    def get_section_addr(self, addr):
        """Find section containing the given virtual address"""
        for sect in self.sections:
            if sect.flags & SECTION_TYPE_MASK in (
                S_THREAD_LOCAL_REGULAR,
                S_THREAD_LOCAL_VARIABLES,
                S_THREAD_LOCAL_ZEROFILL,
            ):
                # like for ELF, addresses in TLS sections aren't meaningful
                continue
            if sect.sh_addr <= addr < sect.sh_addr + sect.len:
                return sect
        return None

    def get_section_idx(self, idx):
        """Find section by (1-based) ordinal"""
        if idx < 1 or idx > len(self.sections):
            return None
        return self.sections[idx - 1]

    def get_symbol(self, name):
        """
        Find symbol by name

        Both "foo" and "_foo" will find the symbol Mach-O calls "_foo".

        :returns: (name, value, section or None) or None
        """
        if self._symtab is None:
            return None

        symoff, nsyms, stroff, strsize = self._symtab
        wanted = (name, "_" + name)
        for i in range(nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = self._unpack(
                "<IBBHQ", symoff + i * 16
            )
            if n_strx == 0 or n_type & 0xE0:  # skip stabs (N_STAB bits)
                continue
            symname = _cstr(self._mm, self._base + stroff + n_strx)
            if symname not in wanted:
                continue
            return (symname, n_value, self.get_section_idx(n_sect))
        return None

    def getreloc(self, addr):
        """Find pointer fixup at the given virtual address"""
        if self._fixups is None:
            self._fixups = self._load_fixups()
        return self._fixups.get(addr)

    def _addr_to_off(self, addr, length=1):
        for seg in self.segments:
            if seg.filesize == 0:
                continue
            if seg.vmaddr <= addr and addr + length <= seg.vmaddr + seg.filesize:
                return seg.fileoff + addr - seg.vmaddr
        return None

    def __getitem__(self, key):
        if not isinstance(key, slice):
            raise IndexError("MachOFile subscript must be slice")

        if key.stop is str:
            if not isinstance(key.start, int):
                raise IndexError("invalid slice")
            start = key.start
            off = self._addr_to_off(start)
            if off is None:
                raise MachOAccessError(
                    "virtual address (%d) not found in segments" % (start,)
                )
            return self._read_cstr(off)

        start, stop, step = key.start or 0, key.stop, key.step or 1
        if step != 1:
            raise IndexError("MachOFile subscript slice step must be 1")
        if stop is None:
            raise IndexError("MachOFile subscript needs an end")

        for seg in self.segments:
            if seg.filesize == 0:
                continue
            if start < seg.vmaddr or start >= seg.vmaddr + seg.vmsize:
                continue
            if stop > seg.vmaddr + seg.vmsize:
                raise MachOAccessError(
                    "access (%d) beyond end of segment (%d)"
                    % (stop, seg.vmaddr + seg.vmsize)
                )
            fstart = start - seg.vmaddr
            fstop = stop - seg.vmaddr
            data = b""
            if fstart < seg.filesize:
                data = self._read(
                    seg.fileoff + fstart, min(fstop, seg.filesize) - fstart
                )
            # zero-fill the part of the segment not backed by the file
            return data + b"\0" * ((stop - start) - len(data))

        raise MachOAccessError("virtual address (%d) not found in segments" % (start,))

    # -- chained fixups --------------------------------------------------------

    def _image_base(self):
        # DYLD_CHAINED_PTR_64_OFFSET targets are relative to the vmaddr of the
        # segment holding the mach header, i.e. __TEXT, not the first segment
        # (which is __PAGEZERO for executables.)
        for seg in self.segments:
            if seg.fileoff == 0 and seg.filesize > 0:
                return seg.vmaddr
        raise MachOFormatError("%s: cannot determine image base" % (self.filename,))

    def _load_fixups(self):
        fixups = {}
        if self._chained is None:
            # classic LC_DYLD_INFO (or no fixups at all):  nothing to translate
            return fixups

        dataoff, datasize = self._chained
        (
            _version,
            starts_off,
            imports_off,
            symbols_off,
            imports_count,
            imports_fmt,
            _symbols_fmt,
        ) = self._unpack("<IIIIIII", dataoff)

        imports = self._load_imports(
            dataoff + imports_off, dataoff + symbols_off, imports_count, imports_fmt
        )

        base = self._image_base()
        starts = dataoff + starts_off
        seg_count = self._unpack("<I", starts)[0]
        seg_infos = self._unpack("<%dI" % seg_count, starts + 4)

        for seg_info in seg_infos:
            if seg_info == 0:
                continue
            sis = starts + seg_info
            _size, page_size, fmt, seg_offset, _maxvalid, page_count = self._unpack(
                "<IHHQIH", sis
            )
            if fmt not in (DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET):
                raise MachOFormatError(
                    "%s: unsupported chained fixup pointer format %d "
                    "(only 64 and 64_OFFSET are handled)" % (self.filename, fmt)
                )
            page_starts = self._unpack("<%dH" % page_count, sis + 22)

            for page_idx, ps in enumerate(page_starts):
                if ps == DYLD_CHAINED_PTR_START_NONE:
                    continue

                chain_starts = []
                if ps & DYLD_CHAINED_PTR_START_MULTI:
                    # chain starts spill over to extra entries after page_start[]
                    ovf = ps & ~DYLD_CHAINED_PTR_START_MULTI
                    while True:
                        (entry,) = self._unpack("<H", sis + 22 + ovf * 2)
                        chain_starts.append(entry & ~DYLD_CHAINED_PTR_START_LAST)
                        if entry & DYLD_CHAINED_PTR_START_LAST:
                            break
                        ovf += 1
                else:
                    chain_starts.append(ps)

                for cs in chain_starts:
                    vm = base + seg_offset + page_idx * page_size + cs
                    self._walk_chain(fixups, vm, fmt, base, imports)

        return fixups

    def _walk_chain(self, fixups, vm, fmt, base, imports):
        while True:
            off = self._addr_to_off(vm, 8)
            if off is None:
                raise MachOFormatError(
                    "%s: fixup chain leaves image at 0x%x" % (self.filename, vm)
                )
            (raw,) = self._unpack("<Q", off)

            nxt = (raw >> 51) & 0xFFF
            if raw >> 63:
                ordinal = raw & 0xFFFFFF
                addend = (raw >> 24) & 0xFF
                if ordinal >= len(imports):
                    raise MachOFormatError(
                        "%s: fixup bind ordinal %d out of range"
                        % (self.filename, ordinal)
                    )
                name, imp_addend = imports[ordinal]
                fixups[vm] = MachOReloc(self, symname=name, addend=addend + imp_addend)
            else:
                target = raw & ((1 << 36) - 1)
                high8 = (raw >> 36) & 0xFF
                if fmt == DYLD_CHAINED_PTR_64_OFFSET:
                    target += base
                target |= high8 << 56
                fixups[vm] = MachOReloc(self, target=target)

            if nxt == 0:
                return
            vm += nxt * _CHAIN_STRIDE

    def _load_imports(self, imports_off, symbols_off, count, fmt):
        imports = []
        if fmt == DYLD_CHAINED_IMPORT:
            for i in range(count):
                (val,) = self._unpack("<I", imports_off + i * 4)
                name_off = val >> 9
                imports.append(
                    (_cstr(self._mm, self._base + symbols_off + name_off), 0)
                )
        elif fmt == DYLD_CHAINED_IMPORT_ADDEND:
            for i in range(count):
                val, addend = self._unpack("<Ii", imports_off + i * 8)
                name_off = val >> 9
                imports.append(
                    (_cstr(self._mm, self._base + symbols_off + name_off), addend)
                )
        elif fmt == DYLD_CHAINED_IMPORT_ADDEND64:
            for i in range(count):
                val, addend = self._unpack("<Qq", imports_off + i * 16)
                name_off = val >> 32
                imports.append(
                    (_cstr(self._mm, self._base + symbols_off + name_off), addend)
                )
        else:
            raise MachOFormatError(
                "%s: unknown chained import format %d" % (self.filename, fmt)
            )
        return imports

    def __repr__(self):
        return "<MachOFile %s>" % (os.path.basename(self.filename),)
