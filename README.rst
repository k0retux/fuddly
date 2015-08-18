fuddly: a fuzzing and data manipulation framework
=================================================

|docs|

.. |docs| image:: https://readthedocs.org/projects/fuddly/badge/?version=develop
   :target: https://readthedocs.org/projects/fuddly/?badge=develop
   :alt: Documentation


List of features
----------------
+ Graph-based data model that enables:

  - to represent complex data formats and also to mix them
  - complex data manipulations
  - to dissect/absorb existing data
  - generation & mutation fuzzing strategy

+ Fuzzing automation framework:

  - target abstraction
  - monitoring means based on independant probes
  - replay & logging
  - data manipulation based on disruptors (objects that implement
    specific data transformation)
  - virtual operator abstraction

+ and so on...

What's still missing
--------------------
+ Full documentation
+ Refer to TODO file

About documentation
-------------------
+ Documentation is available `here`_.
+ In order to generate the documentation from the source, follow these steps:

  #. go to the folder ``docs/``
  #. execute ``make html`` to generate HTML documentation
  #. execute ``make latexpdf`` to generate PDF documentation
  #. generated documentation is located in ``docs/build/``

.. _here: http://fuddly.readthedocs.org

Miscellaneous
-------------
+ Don't forget to populate ./imported_data/ with sample files for data
  models that need it

Dependencies
------------
+ Compatible with Python2 and Python3
+ Mandatory:

  - `six`_: Python 2/3 compatibility

+ Optional:

  - `xtermcolor`_: Terminal color support
  - `cups`_: Python bindings for libcups
  - `rpyc`_: Remote Python Call (RPyC), a transparent and symmetric RPC library

+ For documentation generation:

  - `sphinx`_: sphinx >= 1.3 (with builtin napoleon extension)
  - `texlive`_ (optional): Needed to generate PDF documentation
  - `readthedocs theme`_ (optional): Privileged html theme for sphinx

.. _six: http://pythonhosted.org/six/
.. _xtermcolor: https://github.com/broadinstitute/xtermcolor "xtermcolor"
.. _cups: https://pypi.python.org/pypi/pycups "cups"
.. _rpyc: https://pypi.python.org/pypi/rpyc "rpyc"
.. _sphinx: http://sphinx-doc.org/ "sphinx"
.. _texlive: https://www.tug.org/texlive/
.. _readthedocs theme: https://github.com/snide/sphinx_rtd_theme
