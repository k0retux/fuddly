.. _packaging:

Packaging
*********


Third party module
==================

Having your data_models/projects/targets in fuddly's data folder is useful when
developing them, but it can quickly become a disorganized mess. 
It is also not very practical if you want to distribute you project to a wider audience.

Therefore, it is possible to package your code and install it alongside the other python 
packages on your system.

For this, you will need to configure entry points that fuddly will be able to look-up to 
find your objects.

These entry points are identified by group names that are known to fuddly. They are the following:

.. TODO:: Strategies might be merged into data_models and project script + info might need groups of their own

* fuddly.projects
* fuddly.data_models
* fuddly.data_models_strategies

Using the tutorial as an example, you would package it by creating the following pyproject.toml 

:ref:`dm:mydf` 

.. code-block:: toml

   [project]
   name = "modulename"
   description = "The best data format"
   version = "0.1"
   authors = [
     { name="Steve Harwell", email="somebody@once.told.me" },
   ]
   dependencies=["fuddly"]
   
   [project.entry-points."fuddly.data_models"]
   mydf = "modulename.mydf"
   
   [project.entry-points."fuddly.data_models_strategies"]
   mydf = "modulename.mydf_strategy"


Given the current implementation, the strategy and data_model need to use the same name/key on the left side 
of the key-value pairs in the entry point sections.

.. note:: When build a package like this, your source files need to be either in directory named like your module, 
          or in a src directory with a subdirectory named like your module, this second format is prefered.
          You also need to include __init__.py file in every directory where python is to be looking for modules.
          (Even if the __init__.py files are are empty)
          See https://packaging.python.org/en/latest/ for more general information about python packaging.

You can then produce a python .whl with ``python -m build --wheel`` and install it with ``pip install dist/*.whl`` 
(or better yet, package it properly for you distribution and install it using your distribution's package 
manager)


Load order
----------

When fuddly loads data_models and projects, it first looks at it's data folder, then looks for python modules.
If a naming conflict appear during the python module loading, they will be ignored, and a warning will be printed.

Loading objects like this means that you can override python modules by redefining their data modules, projects, 
targets, etc, in fuddly's data folder.

.. note:: A side effect of this is that fuddly cannot differentiate between 2 python modules defining objects with 
          the same name and a module and an object in the data folder sharing the same name.


Fuddly
======

Fuddly itself is also itself packageable. 

It's done in the conventional python way of producing a whl package with ``python -m build --wheel`` that can be install
by ``pip install`` it.

You can also see that fuddly's pyproject.toml declare entry points for it's internal data_models and projects in 
the same way a third party package could.

