Building Documentation
======================

To build FRR documentation, first install the dependencies.
Notice that if you plan to only build html documentation, you only
need the package ``python3-sphinx``.

.. code-block:: console

   sudo apt-get install -y python3-sphinx \
      texlive-latex-base texlive-latex-extra latexmk

To prepare for building both user and developer documentation, do:

.. code-block:: console

   cd doc
   make

User documentation
------------------

To build html user documentation:

.. code-block:: console

   cd user
   make html

This will generate html documentation files under ``_build/html/``.
With the main page named ``index.html``.

PDF can then be built by:

.. code-block:: console

   cd user
   make pdf

The generated PDF file will be saved at ``_build/latex/FRR.pdf``

Developer documentation
-----------------------

To build the developer documentation:

.. code-block:: console

   cd developer
   make html

This will generate html documentation files under ``_build/html/``.
With the main page named ``index.html``.

PDF can then be built by:

.. code-block:: console

   cd developer
   make pdf

The generated PDF file will be saved at ``_build/latex/FRR.pdf``

Building HTML without configuring FRR
-------------------------------------

The ``make html`` targets under ``doc/user`` and ``doc/developer`` call into the
top-level build system and expect a tree that has been through ``./configure``
(and usually ``./bootstrap.sh`` first if you build from Git).

If you only need HTML and have **not** configured the repository, run Sphinx
from the **repository root**. Install ``python3-sphinx`` as above. For the
developer manual you should also install ``graphviz`` (diagrams) and, if you
want the same HTML theme as a full build, ``python3-sphinx-rtd-theme``.

.. code-block:: console

   cd frr
   python3 -m sphinx -b html -d doc/user/_build/.doctrees \
      doc/user doc/user/_build/html
   python3 -m sphinx -b html -d doc/developer/_build/.doctrees \
      doc/developer doc/developer/_build/html

The generated trees are ``doc/user/_build/html/`` and
``doc/developer/_build/html/``, each with ``index.html`` at the top.

When ``config.status`` is absent, ``conf.py`` uses built-in defaults for version
and install-path substitutions; values are filled from ``config.status`` when
you build inside a configured tree.

PDF, Info, and other formats are still built through ``make`` in a configured
build directory, since those flows rely on the Automake/Sphinx integration.
