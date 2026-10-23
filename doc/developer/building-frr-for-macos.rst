.. _building-macos:

Building FRR on macOS
=====================

macOS Support Status
--------------------

**Important Notice:** FRR has limited support for macOS due to fundamental 
differences between macOS's Mach-O binary format and the ELF format used on 
Linux and BSD systems. FRR's build system and some runtime features rely on 
ELF-specific capabilities that are not available on macOS.

Known Limitations
-----------------

The main limitation is that FRR uses ``__start`` and ``__stop`` section symbols,
which are ELF-specific features. The configure script will fail with an error 
message about these symbols not working. This is expected behavior on macOS.

Additionally, FRR uses libelf to introspect its own binaries at runtime, which
does not work with Mach-O format binaries.

Current Recommendations
-----------------------

For developers who want to contribute to FRR on macOS, we recommend:

**Option 1: Use Docker** (Recommended)
   Build and run FRR inside a Linux container. See :ref:`building-docker`.

**Option 2: Use a Virtual Machine**
   Set up a Linux VM using tools like:
   
   - VirtualBox
   - VMware Fusion
   - Parallels Desktop
   - UTM (for Apple Silicon)

**Option 3: Documentation & Non-Build Contributions**
   Many valuable contributions don't require building FRR:
   
   - Documentation improvements
   - Issue triage and testing
   - Configuration examples
   - Python scripts and tools

Installing Dependencies
-----------------------

Even though a native build won't complete, you may want to install dependencies
for Docker-based builds or for development tools:

.. code-block:: console

   # Install Homebrew if not already installed
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

   # Install basic dependencies
   brew install autoconf automake libtool pkg-config
   brew install json-c bison flex c-ares readline python3
   brew install pcre2 libssh2

   # Add bison and flex to PATH (macOS versions are outdated)
   export PATH="/opt/homebrew/opt/bison/bin:$PATH"
   export PATH="/opt/homebrew/opt/flex/bin:$PATH"

Building with Docker
--------------------

The recommended way to build FRR on macOS is using Docker:

1. Install Docker Desktop for Mac

2. Clone the FRR repository:

   .. code-block:: console

      git clone https://github.com/FRRouting/frr.git
      cd frr

3. Build using Docker (see :ref:`building-docker` for detailed instructions)

Contributing from macOS
------------------------

macOS users can make valuable contributions:

**Documentation**
   Improve user guides, developer documentation, and examples.

**Issue Reports**
   Test FRR in Docker/VM environments and report bugs with detailed reproduction
   steps.

**Code Review**
   Review pull requests, provide feedback on code changes.

**Tools & Scripts**
   Develop Python scripts, automation tools, and test frameworks.

**Testing**
   Write and run topotests, unit tests, and integration tests.

Getting Help
------------

- **Slack**: https://frrouting.slack.com
- **Mailing List**: dev@lists.frrouting.org
- **Developer Guide**: http://docs.frrouting.org/projects/dev-guide/

See Also
--------

- :ref:`building-docker`
- :ref:`process-and-workflow`
- :ref:`testing`
