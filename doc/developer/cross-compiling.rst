Cross-Compiling
===============

FRR is capable of being cross-compiled to a number of different architectures.
With an adequate toolchain this process is fairly straightforward, though one
must exercise caution to validate this toolchain's correctness before attempting
to compile FRR or its dependencies; small oversights in the construction of the
build tools may lead to problems which quickly become difficult to diagnose.

Toolchain Preliminary
---------------------

The first step to cross-compiling any program is to identify the system which
the program (FRR) will run on. From here on this will be called the "host"
machine, following autotools' convention, while the machine building FRR will be
called the "build" machine. The toolchain will of course be installed onto the
build machine and be leveraged to build FRR for the host machine to run.

.. note::

   The build machine used while writing this guide was ``x86_64-pc-linux-gnu``
   and the target machine was ``arm-linux-gnueabihf`` (a Raspberry Pi 3B+).
   Replace this with your targeted tuple below if you plan on running the
   commands from this guide:

      .. code-block:: shell

      export HOST_ARCH="arm-linux-gnueabihf"

   For your given target, the build system's OS may have some support for
   building cross compilers natively, or may even offer binary toolchains built
   upstream for the target architecture. Check your package manager or OS
   documentation before committing to building a toolchain from scratch.

This guide will not detail *how* to build a cross-compiling toolchain but
will instead assume one already exists and is installed on the build system.
The methods for building the toolchain itself may differ between operating
systems so consult the OS documentation for any particulars regarding
cross-compilers. The OSDev wiki has a `pleasant tutorial`_ on cross-compiling in
the context of operating system development which bootstraps from only the
native GCC and binutils on the build machine. This may be useful if the build
machine's OS does not offer existing tools to build a cross-compiler targeting
the host.

.. _pleasant tutorial: https://wiki.osdev.org/GCC_Cross-Compiler

This guide will also not demonstrate how to build all of FRR's dependencies for the
target architecture. Instead, general instructions for using a cross-compiling
toolchain to compile packages using CMake, Autotools, and Makefiles are
provided; these three cases apply to almost all FRR dependencies.

.. _glibc mismatch:

.. warning::

   Ensure the versions and implementations of the C standard library (glibc or
   what have you) match on the host and the build toolchain. ``ldd --version``
   will help you here. Upgrade one or the other if the they do not match.

Testing the Toolchain
---------------------

Before any cross-compilation begins it would be prudent to test the new
toolchain by writing, compiling and linking a simple program.

.. code-block:: shell

   # A small program
   cat > nothing.c <<EOF
   int main() { return 0; }
   EOF

   # Build and link with the cross-compiler
   ${HOST_ARCH}-gcc -o nothing nothing.c

   # Inspect the resulting binary, results may vary
   file ./nothing

   # nothing: ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV),
   # dynamically linked, interpreter /lib/ld-linux-armhf.so.3,
   # for GNU/Linux 3.2.0, not stripped

If this produced no errors then the installed toolchain is probably ready to
start compiling the build dependencies and eventually FRR itself. There still
may be lurking issues but fundamentally the toolchain can produce binaries and
that's good enough to start working with it.

.. warning::

   If any errors occurred during the previous functional test please look back
   and address them before moving on; this indicates your cross-compiling
   toolchain is *not* in a position to build FRR or its dependencies. Even if
   everything was fine, keep in mind that many errors from here on *may still
   be related* to your toolchain (e.g. libstdc++.so or other components) and this
   small test is not a guarantee of complete toolchain coherence.

Cross-compiling Dependencies
----------------------------

When compiling FRR it is necessary to compile some of its dependencies alongside
it on the build machine. This is so symbols from the shared libraries (which
will be loaded at run-time on the host machine) can be linked to the FRR
binaries at compile time; additionally, headers for these libraries are needed
during the compile stage for a successful build.

Sysroot Overview
^^^^^^^^^^^^^^^^

All build dependencies should be installed into a "root" directory on the build
computer, hereafter called the "sysroot". This directory will be prefixed to
paths while searching for requisite libraries and headers during the build
process. Often this may be set via a ``--prefix`` flag when building the
dependent packages, meaning a ``make install`` will copy compiled libraries into
(e.g.) ``/usr/${HOST_ARCH}/usr``.

If the toolchain was built on the build machine then there is likely already a
sysroot where those tools and standard libraries were installed; it may be
helpful to use that directory as the sysroot for this build as well.

Basic Workflow
^^^^^^^^^^^^^^

Before compiling or building any dependencies, make note of which daemons are
being targeted and which libraries will be needed. Not all dependencies are
necessary if only building with a subset of the daemons.

The following workflow will compile and install any libraries which can be built
with Autotools. The resultant library will be installed into the sysroot
``/usr/${HOST_ARCH}``.

.. code-block:: shell

   ./configure \
      CC=${HOST_ARCH}-gcc \
      CXX=${HOST_ARCH}-g++ \
      --build=${HOST_ARCH} \
      --prefix=/usr/${HOST_ARCH}
   make
   make install

Some libraries like ``json-c`` and ``libyang`` are packaged with CMake and can
be built and installed generally like:

.. code-block:: shell

   mkdir build
   cd build
   CC=${HOST_ARCH}-gcc \
   CXX=${HOST_ARCH}-g++ \
   cmake \
       --install-prefix /usr/${HOST_ARCH} \
       ..
   make
   make install

For programs with only a Makefile (e.g. ``libcap``) the process may look still a
little different:

.. code-block:: shell

   CC=${HOST_ARCH}-gcc make
   make install DESTDIR=/usr/${HOST_ARCH}

These three workflows should handle the bulk of building and installing the
build-time dependencies for FRR. Verify that the installed files are being
placed correctly into the sysroot and were actually built using the
cross-compile toolchain, not by the native toolchain by accident.

Dependency Notes
^^^^^^^^^^^^^^^^

There are a lot of things that can go wrong during a cross-compilation. Some of
the more common errors and a few special considerations are collected below for
reference.

libyang
"""""""

``-DENABLE_LYD_PRIV=ON`` should be provided during the CMake step.

Ensure also that the version of ``libyang`` being installed corresponds to the
version required by the targeted FRR version.

gRPC
""""

This piece is requisite only if the ``--enable-grpc`` flag will be passed
later on to FRR. One may get burned when compiling gRPC if the ``protoc``
version on the build machine differs from the version of ``protoc`` being linked
to during a gRPC build. The error messages from this defect look like:

.. code-block:: shell

   gens/src/proto/grpc/channelz/channelz.pb.h: In member function ‘void grpc::channelz::v1::ServerRef::set_name(const char*, size_t)’:
   gens/src/proto/grpc/channelz/channelz.pb.h:9127:64: error: ‘EmptyDefault’ is not a member of ‘google::protobuf::internal::ArenaStringPtr’
    9127 |   name_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, ::std::string(

This happens because protocol buffer code generation uses ``protoc`` to create
classes with different getters and setters corresponding to the protobuf data
defined by the source tree's ``.proto`` files. Clearly the cross-compiled
``protoc`` cannot be used for this code generation because that binary is built
for a different CPU.

The solution is to install matching versions of native and cross-compiled
protocol buffers; this way the native binary will generate code and the
cross-compiled library will be linked to by gRPC and these versions will not
disagree.

----

The ``-latomic`` linker flag may also be necessary here if using ``libstdc++``
since GCC's C++11 implementation makes library calls in certain cases for
``<atomic>`` so ``-latomic`` cannot be assumed.

Cross-compiling FRR Itself
--------------------------

With all the necessary libraries cross-compiled and installed into the sysroot,
the last thing to actually build is FRR itself:

.. code-block:: shell

   # Clone and bootstrap the build
   git clone 'https://github.com/FRRouting/frr.git'
   # (e.g.) git checkout stable/7.5
   ./bootstrap.sh

   # Build clippy using the native toolchain
   mkdir build-clippy
   cd build-clippy
   ../configure --enable-clippy-only
   make clippy-only
   cd ..

   # Next, configure FRR and use the clippy we just built
   ./configure \
      CC=${HOST_ARCH}-gcc \
      CXX=${HOST_ARCH}-g++ \
      --host=${HOST_ARCH} \
      --with-sysroot=/usr/${HOST_ARCH} \
      --with-clippy=./build-clippy/lib/clippy \
      --sysconfdir=/etc \
      --localstatedir=/var \
      --sbindir="\${prefix}/lib/frr" \
      --prefix=/usr \
      --enable-user=frr \
      --enable-group=frr \
      --enable-vty-group=frrvty \
      --disable-doc \
      --enable-grpc

   # Send it
   make

Installation to Host Machine
----------------------------

If no errors were observed during the previous steps it is safe to ``make
install`` FRR into its own directory.

.. code-block:: shell

   # Install FRR its own "sysroot"
   make install DESTDIR=/some/path/to/sysroot

After running the above command, FRR binaries, modules and example configuration
files will be installed into some path on the build machine. The directory
will have folders like ``/usr`` and ``/etc``; this "root" should now be copied
to the host and installed on top of the root directory there.

.. code-block:: shell

   # Tar this sysroot (preserving permissions)
   tar -C /some/path/to/sysroot -cpvf frr-${HOST_ARCH}.tar .

   # Transfer tar file to host machine
   scp frr-${HOST_ARCH}.tar me@host-machine:

   # Overlay the tarred sysroot on top of the host machine's root
   ssh me@host-machine <<-EOF
      # May need to elevate permissions here
      tar -C / -xpvf frr-${HOST_ARCH}.tar.gz .
   EOF

Now FRR should be installed just as if ``make install`` had been run on the host
machine. Create configuration files and assign permissions as needed. Lastly,
ensure the correct users and groups exist for FRR on the host machine.

Troubleshooting
---------------

Even when every precaution has been taken some things may still go wrong! This
section details some common runtime problems.

Mismatched Libraries
^^^^^^^^^^^^^^^^^^^^

If you see something like this after installing on the host:

.. code-block:: console

   /usr/lib/frr/zebra: error while loading shared libraries: libyang.so.1: cannot open shared object file: No such file or directory

... at least one of FRR's dependencies which was linked to the binary earlier is
not available on the host OS. Even if it has been installed the host
repository's version may lag what is needed for more recent FRR builds (this is
likely to happen with YANG at the moment).

If the matching library is not available from the host OS package manager it may
be possible to compile them using the same toolchain used to compile FRR. The
library may have already been built earlier when compiling FRR on the build
machine, in which case it may be as simple as following the same workflow laid
out during the `Installation to Host Machine`_.

Mismatched Glibc Versions
^^^^^^^^^^^^^^^^^^^^^^^^^

The version and implementation of the C standard library must match on both the
host and build toolchain. The error corresponding to this misconfiguration will
look like:

.. code-block:: console

   /usr/lib/frr/zebra: /lib/${HOST_ARCH}/libc.so.6: version `GLIBC_2.32' not found (required by /usr/lib/libfrr.so.0)

See the earlier warning about preventing a `glibc mismatch`_.
