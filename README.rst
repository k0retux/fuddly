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
  - data manipulation based on operators (objects that implement
    specific data transformation)
  - scenario infrastructure (for modeling protocol logic)
  - virtual directors

+ and so on...

What's still missing
--------------------
+ Refer to TODO file

About the Documentation
-----------------------
+ The documentation is available `here`_.
+ In order to generate the documentation from the source, follow these steps:

  #. go to the folder ``docs/``
  #. execute ``make html`` to generate HTML documentation
  #. execute ``make latexpdf`` to generate PDF documentation
  #. generated documentation is located in ``docs/build/``

.. _here: http://fuddly.readthedocs.io

Basic Installation Instructions
-------------------------------

Installation with `pipenv`::

    $ cd <path_to_fuddly>
    $ pipenv install   # or pipenv sync (if you want to match exactly the environment
                       # described in fuddly Pipfile.lock)
    $ pipenv shell

Refer to the documentation for more information

Launch fuddly shell
-------------------

- If `fuddly` is installed either through pip/pipenv or a package from your distribution::

    $ fuddly shell

- If `fuddly` is not installed::

    $ python -m fuddly.cli shell


Launch fuddly Test Cases
------------------------

The package ``test`` include all unit & integration test cases
of ``fuddly`` itself. From the ``src/`` directory, usage is as follows:

- To launch all the tests, issue the command::

    $ python -m fuddly.test -a

- To launch all the tests but the longer ones, issue the command::

    $ python -m fuddly.test

- To avoid data model specific test cases use the option ``--ignore-dm-specifics``

- To launch a specific test category issue the following command::

    $ python -m fuddly.test fuddly.test.<test_package>.<test_module>.<Test_Class>.<test_method>

