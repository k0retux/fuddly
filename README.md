fuddly is a fuzzing and data manipulation framework.

List of features
----------------
* Graph-based data model that enables:
  - to represent complex data formats and also to mix them
  - complex data manipulations
  - to dissect/absorb existing data
  - generation & mutation fuzzing strategy

* Fuzzing automation framework:
  - target abstraction
  - monitoring means based on independant probes
  - replay & logging
  - data manipulation based on disruptors (objects that implement
    specific data transformation)
  - virtual operator abstraction

* and so on...

What's still missing
--------------------
* Documentation

* refer to TODO file

Miscellaneous
-------------
* Don't forget to populate ./imported_data/ with sample files for data
  models that need it

Dependencies
------------
* Compatible with Python2 and Python3
* Mandatory:
  - [six] [1]: Python 2/3 compatibility
* Optional:
  - [xtermcolor] [2]: terminal color support
  - [cups] [3]: Python bindings for libcups
  - [rpyc] [4]: Remote Python Call (RPyC), a transparent and symmetric RPC library

[1]: http://pythonhosted.org/six/ "six"
[2]: https://github.com/broadinstitute/xtermcolor "xtermcolor"
[3]: https://pypi.python.org/pypi/pycups "cups"
[4]: https://pypi.python.org/pypi/rpyc "rpyc"
