.. _packaging:

Packaging
*********


Third party module
==================

Having your data_models/projects/targets/info in `fuddly`'s data folder is useful when
developing them, but it can quickly become a disorganized mess. 
It is also not very practical if you want to distribute you project to a wider audience.

Therefore, it is possible to package your code and install it alongside the other python 
packages on your system.

For this, you will need to configure entry points that `fuddly` will be able to look-up to 
find your objects.

These entry points are identified by group names that are known to `fuddly`. They are the following:

* fuddly.projects
* fuddly.data_models
* fuddly.targets
* fuddly.info

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
   dependencies=["fuddly@git+https://github.com/k0retux/fuddly"]
   
   [project.entry-points."fuddly.data_models"]
   modulename__root__ = "modulename"
   mydf = "modulename.mydf"


A special value in the entry_points needs to be added for `fuddly` to be able to find where the root of your module is.
The name should end in `__root__`, the first part will be used during imports.
With the example above, you would import the module with ``import fuddly.data_models.modulename.mydf``.
It's value should point to the namespace in which the module can be found. This is usually the parent directory to 
your data_model, project, target or info.
In case of a package containing only your module, the name of the module should be used.

.. note:: When building a package like this, your source files need to be either in a directory named like your module, 
          or in a `src` directory with a subdirectory named like your module, this second format is preferred.
          Your package should not actually contain a module in the python sense, it should be a namespace. Therefore
          you should not include any __init__.py files outside of where you have your data_model, project, target or info.
          See https://packaging.python.org/en/latest/ for more general information about python packaging.

You can then produce a python `.whl` with ``python -m build --wheel`` and install it with ``pip install dist/*.whl`` 
(or better yet, package it properly for you distribution and install it using your distribution's package 
manager)

.. _pkg:samples:

Samples
-------

When you packages your data model (or your project), you can add a ``samples`` folder to your ``data_model`` (or ``project``) modules.
In this namespace, you can add samples that your model (or the models used by the projects) can use to instantiate atoms.
(This is simply a python namespace and not a module, trying to import from it will fail but it can
be used to get the path of the resource so it can then be read from your code)

This folder will automatically be found by fuddly when it load the data model (or the data models used by the project) through the 
:meth:`fuddly.framework.data_model.DataModel.import_file_content()` method.


Load order
----------

When `fuddly` loads data models and projects, it first looks at it's data folder, then in `fuddly`'s internal modules, 
then finally looks for python modules.
If a naming conflict appear during the python module loading, they will be ignored, and a warning will be printed.

Loading objects like this means that you can override python modules by redefining their data models, projects, 
targets, info, and so on, in `fuddly`'s data folder.

.. note:: A side effect of this is that fuddly cannot differentiate between 2 python modules defining objects with 
          the same name and a module and an object in the data folder sharing the same name.

Similarly, samples have a priority/load order.
They are loaded in this order:

#. from a data model module first;
#. then from the user's ``data_models`` folder in fuddly's data folder (if the data model is available there);
#. then the user's ``imported_data`` folder in fuddly's data folder;
#. then from the user's ``projects`` folder in fuddly's data folder or project module (depending on how the project module is deployed).

When files have the same name in different locations, the latest will override earlier files, i.e. the user's 
``projects`` folder override any other sample with the same name.


Fuddly
======

`Fuddly` itself is also itself packageable. 

It's done in the conventional python way of producing a wheel package with ``python -m build --wheel`` that can be installed
with ``pip install dist/<file_name>.whl``.

You can also see that `fuddly`'s `pyproject.toml` declare entry points for it's internal data_models, projects, targets and
info in the same way a third party package could.

If you are lucky, you might also find a build script to create a native package for your distribution.
They are located in the `contrib/build/<distribution_name>` folder.

