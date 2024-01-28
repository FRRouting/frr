Yang Tools
==========

Here's some information about various tools for working with yang
models.

yanglint cheat sheet
~~~~~~~~~~~~~~~~~~~~

   libyang project includes a feature-rich tool called yanglint(1) for
   validation and conversion of the schemas and YANG modeled data. The
   source codes are located at /tools/lint and can be used to explore
   how an application is supposed to use the libyang library.
   yanglint(1) binary as well as its man page are installed together
   with the library itself.

Validate a YANG module:

.. code:: sh

   $ yanglint -p <yang-search-path> module.yang

Generate tree representation of a YANG module:

.. code:: sh

   $ yanglint -p <yang-search-path> -f tree module.yang

Validate JSON/XML instance data:

.. code:: sh

   $ yanglint -p <yang-search-path> module.yang data.{json,xml}

Convert JSON/XML instance data to another format:

.. code:: sh

   $ yanglint -p <yang-search-path> -f xml module.yang data.json
   $ yanglint -p <yang-search-path> -f json module.yang data.xml

*yanglint* also features an interactive mode which is very useful when
needing to validate data from multiple modules at the same time. The
*yanglint* README provides several examples:
https://github.com/CESNET/libyang/blob/master/tools/lint/examples/README.md

Man page (groff):
https://github.com/CESNET/libyang/blob/master/tools/lint/yanglint.1

pyang cheat sheet
~~~~~~~~~~~~~~~~~

   pyang is a YANG validator, transformator and code generator, written
   in python. It can be used to validate YANG modules for correctness,
   to transform YANG modules into other formats, and to generate code
   from the modules.

Obtaining and installing pyang:

.. code:: sh

   $ git clone https://github.com/mbj4668/pyang.git
   $ cd pyang/
   $ sudo python setup.py install

Validate a YANG module:

.. code:: sh

   $ pyang --ietf -p <yang-search-path> module.yang

Generate tree representation of a YANG module:

.. code:: sh

   $ pyang -f tree -p <yang-search-path> module.yang

Indent a YANG file:

.. code:: sh

   $ pyang -p <yang-search-path> \
       --keep-comments -f yang --yang-canonical \
       module.yang -o module.yang

Generate skeleton instance data:

* XML:

   .. code:: sh

   $ pyang -p <yang-search-path> \
       -f sample-xml-skeleton --sample-xml-skeleton-defaults \
       module.yang [augmented-module1.yang ...] -o module.xml

*  JSON:

   .. code:: sh

   $ pyang -p <yang-search-path> \
       -f jsonxsl module.yang -o module.xsl
   $ xsltproc -o module.json module.xsl module.xml

Validate XML instance data (works only with YANG 1.0):

.. code:: sh

   $ yang2dsdl -v module.xml module.yang

vim
~~~

YANG syntax highlighting for vim:
https://github.com/nathanalderson/yang.vim
