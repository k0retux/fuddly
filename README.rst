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
  - scenario infrastructure (for modeling protocol logic)
  - virtual operator abstraction

+ and so on...

What's still missing
--------------------
+ Refer to TODO file

About documentation
-------------------
+ Documentation is available `here`_.
+ In order to generate the documentation from the source, follow these steps:

  #. go to the folder ``docs/``
  #. execute ``make html`` to generate HTML documentation
  #. execute ``make latexpdf`` to generate PDF documentation
  #. generated documentation is located in ``docs/build/``

.. _here: http://fuddly.readthedocs.io


Launch fuddly test cases
------------------------

The file ``framework/test.py`` include all unit & integration test cases
of ``fuddly`` itself. Usage is as follows:

- To launch all the test, issue the command::

    >> python framework/test.py -a

- To launch all the test but the longer ones, issue the command::

    >> python framework/test.py

- To avoid data model specific test cases use the option ``--ignore-dm-specifics``

- To launch a specific test category issue the folowing command::

    >> python framework/test.py <Test_Class>.<test_method>


Miscellaneous
-------------
+ Don't forget to populate ``~/fuddly_data/imported_data/`` with sample files for data
  models that need it

Dependencies
------------
+ Compatible with Python2 and Python3
+ Mandatory:

  - `six`_: Python 2/3 compatibility
  - `sqlite3`_: SQLite3 data base

+ Optional:

  - `xtermcolor`_: Terminal color support
  - `cups`_: Python bindings for libcups
  - `rpyc`_: Remote Python Call (RPyC), a transparent and symmetric RPC library
  - `paramiko`_: Python implementation of the SSHv2 protocol
  - `serial`_: For serial port access

+ For testing:

  - `ddt`_: Used for data-driven tests
  - `mock`_: Used for mocking (only needed in Python2)

+ For documentation generation:

  - `sphinx`_: sphinx >= 1.3 (with builtin napoleon extension)
  - `texlive`_ (optional): Needed to generate PDF documentation
  - `readthedocs theme`_ (optional): Privileged html theme for sphinx

.. _six: http://pythonhosted.org/six/
.. _sqlite3: https://www.sqlite.org/
.. _xtermcolor: https://github.com/broadinstitute/xtermcolor
.. _cups: https://pypi.python.org/pypi/pycups
.. _rpyc: https://pypi.python.org/pypi/rpyc
.. _paramiko: http://www.paramiko.org/
.. _serial: https://github.com/pyserial/pyserial
.. _ddt: https://github.com/txels/ddt
.. _mock: https://pypi.python.org/pypi/mock
.. _sphinx: http://sphinx-doc.org/
.. _texlive: https://www.tug.org/texlive/
.. _readthedocs theme: https://github.com/snide/sphinx_rtd_theme
