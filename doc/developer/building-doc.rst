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
