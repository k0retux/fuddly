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

* fuddly.projects
* fuddly.data_models

Using the tutorial as an example, you would package it by creating the following pyproject.toml 

See :ref:`dm:mydf` for the implementation.

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


.. note:: When build a package like this, your source files need to be either in directory named like your module, 
          or in a src directory with a subdirectory named like your module, this second format is prefered.
          You also need to include __init__.py file in every directory where python is to be looking for modules.
          (Even if the __init__.py files are are empty)
          See https://packaging.python.org/en/latest/ for more general information about python packaging.

You can then produce a python .whl with ``python -m build --wheel`` and install it with ``pip install dist/*.whl`` 
(or better yet, package it properly for you distribution and install it using your distribution's package 
manager)


.. _pkg:samples:
Samples
-------

When you packages you data model, you can add a ``samples`` folder to your ``data_model`` modules.
In this namespace, you can add samples that your model can use to instantiate atoms.
(This is simply a python namespace and not a module, trying to import from it will fail but it can
be used to get the path of the resource so it can then be read from your code)

This folder will automatically be found by fuddly when it load the data model through the 
:meth:`fuddly.framework.data_model.DataModel.import_file_content()` method.


Load order
----------

When fuddly loads data_models and projects, it first looks at it's data folder, then looks for python modules.
If a naming conflict appear during the python module loading, they will be ignored, and a warning will be printed.

Loading objects like this means that you can override python modules by redefining their data modules, projects, 
targets, etc, in fuddly's data folder.

.. note:: A side effect of this is that fuddly cannot differentiate between 2 python modules defining objects with 
          the same name and a module and an object in the data folder sharing the same name.

Similarly, samples have a priority/load order.
They are loaded from a module first, then the user's ``imported_data`` folder in fuddly's data folder.
When files have the same name in different locations, the latest will override earlier files, i.e. the user's 
``imported_data`` folder override any other sample with the same name.


Fuddly
======

Fuddly itself is also itself packageable. 

It's done in the conventional python way of producing a whl package with ``python -m build --wheel`` that can be install
by ``pip install`` it.

You can also see that fuddly's pyproject.toml declare entry points for it's internal data_models and projects in 
the same way a third party package could.

