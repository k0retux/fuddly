Tutorial
********

In this tutorial we will first walk through basic steps to create a
new data model and the way to define specific disruptors. Then we will
see how to use the basic UI of `fuddly`, and finally see how to use
`fuddly` directly from an advanced python interpreter like `IPython`.

Implementing a Data Model and Defining the Associated Fuzzing Environment
=========================================================================

Assuming we want to model an imaginary data format called `myDF`.  Two
files need to be created within ``<root of
fuddly>/data_models/[file_formats|protocol]``:

  - ``mydf.py``
  - ``mydf_strategy.py``


.. note:: Within the file names, ``mydf`` is not really important. However,
   what is important is to use the same prefix for these two
   files, and to conform to the template.


Defining the Data Model
-----------------------

.. note:: Defined within ``mydf.py``

.. code-block:: python
   :linenos:

   from fuzzfmk.data_model import *
   from fuzzfmk.value_types import *
   from fuzzfmk.data_model_helpers import *

   class MyDF_DataModel(DataModel):

      file_extension = 'myd'
      name = 'mydf_overload_iyw'

      def dissect(self, data, idx):
         ''' PUT YOUR CODE HERE '''
	 

      def build_data_model(self):
         ''' PUT YOUR CODE HERE '''


   data_model = MyDF_DataModel()


You first need to define a class that inherits from the :class:`DataModel` class.


Initiating the Fuzzing Environment
----------------------------------

.. note:: Defined within ``mydf_strategy.py``

.. code-block:: python
   :linenos:

   from fuzzfmk.plumbing import *
   from fuzzfmk.tactics_helper import *

   tactics = Tactics()


.. _targets-def:

Defining the Targets
--------------------

Generic Targets
+++++++++++++++


Specific Targets
++++++++++++++++


Defining the Logger
-------------------


Defining Specific Disruptors
----------------------------

.. note:: Also look at :ref:`useful-examples`



Defining Probes and Operators
--------------------------------



Using `fuddly` simple UI: FuzzShell
===================================

A simple UI---called FuzzShell---allows to interact with fuddly in an
easy way. In this tutorial we present the usual commands that can be
used during a fuzzing session. But first we have to launch it by
running the ``./client.py`` script.

.. note::
   This script basically does the following:

   .. code-block:: python
      :linenos:

       fuzzer = Fuzzer()
       shell = FuzzShell("FuzzShell", fuzzer)
       shell.cmdloop()

Start a fuzzing session
-----------------------

After running this script you should be prompted with something like
this:

.. code-block:: none
   :linenos:
   :emphasize-lines: 10

   ...
   >>> Look for Data Models within 'data_models/file_formats' directory
   *** Loaded Data Model: 'png' ***
   *** Loaded Data Model: 'jpg' ***
   *** Loaded Data Model: 'pdf' ***
   *** Loaded Data Model: 'zip' ***

   -=[ FuzzShell ]=- (with Fuzzer FmK 0.18)

   >>

.. note:: The ``help`` command shows you every defined command within
   ``FuzzShell``. You can also look at a brief command description and
   syntax by typing ``help <command_name>``

You can first list the available data models:

.. code-block:: none
   :linenos:
   :emphasize-lines: 1

   >> show_data_models

   -=[ Data Models ]=-

   [0] example
   [1] usb
   [2] png
   [3] jpg
   [4] pdf
   [5] zip

Let's say you want to perform ZIP fuzzing. You can select this data
model thanks to the following command:

.. code-block:: none
   :linenos:
   :emphasize-lines: 1

   >> use_data_model zip

Now, you want to choose the target to fuzz among the defined ones:

.. code-block:: none
   :linenos:
   :emphasize-lines: 1

   >> show_targets

   -=[ Available Targets ]=-

   [0] EmptyTarget
   [1] LocalTarget [Program: unzip]

By default, the ``EmptyTarget`` is selected in order to let you
experiment without a real target. But let's say you want to fuzz the
``unzip`` program. You first have to select it, then you can go on
with your fuzzing session:

.. code-block:: none
   :linenos:
   :emphasize-lines: 1

   >> set_target 1

   >> enable_fuzzing
   *** Logger is started
   *** Target initialization
   *** Monitor is started

   *** [ Fuzz delay = 0 ] ***
   *** [ Number of data sent in burst = 1 ] ***
   *** [ Target health-check timeout = 10 ] ***
   >> 

.. seealso::

   In order to define new targets, look at :ref:`targets-def`.

.. seealso::
   
   ``Target`` configuration cannot be changed within ``FuzzShell``, but you
   can do it through any python interpreter, by directly manipulating
   the related ``Target`` object. Look at :ref:`fuddly-advanced`.

.. note::

   If you already know the data model and the target to use, you can
   directly launch your session thanks to the command
   ``enable_data_model``. The previous commands collapse then to
   ``enable_data_model zip 1``.

We see that internal parameters take default values, namely:

- The fuzzing delay, which allows you to set a minimum delay between
  two data emission. (Can be changed through the command
  ``set_delay``).

- The maximum number of data that will be sent in burst, thus
  ignoring the fuzzing delay. (Can be changed through the command
  ``set_burst``)

- The timeout value for checking target's health. (Can be changed
  through the command ``set_timeout``)


Send malformed ZIP files to the target (manually)
-------------------------------------------------

How to send a ZIP file
++++++++++++++++++++++

In order to send a ZIP file to the target, type the following::

>> send ZIP

which will invoke the ``unzip`` program with a ZIP file:

.. code-block:: none

   __ setup generator 'g_zip' __

   ========[ 1 ]==[ 18/08/2015 - 19:24:34 ]=======================
   ### Target ack received at: None
   ### Fuzzing (step 1):Archive:  /home/tuxico/Tools/fuddly/workspace/fuzz_test_003770469732.zip

    |- generator type: ZIP | generator name: g_zip | User input: G=[ ], S=[ ]
   ### Data size: 47360 bytes
   ### Emitted data is stored in the file:
   /home/tuxico/Tools/fuddly/exported_data/zip/2015_08_18_192434_00.zip
   >> 

Note that a :class:`DataModel` can define any number of data
types---to model for instance the various atoms within a data format,
or to represent some specific use cases, ...

When a data model is loaded, a dynamic `generator` is built for each
data types registered within this data model. A generator is the basic
block for generating data. In our case, let us consult the generators
available for the ZIP data model:

.. code-block:: none
   :emphasize-lines: 1

   >> show_generators

   -=[ SPECIFIC GENERATORS ]=-

   *** Available generators of type 'ZIP' ***
     name: g_zip (weight: 1, valid: True)
     generic args: 
       |_ random
       |      | desc: make the data model random
       |      | default: False [type: bool]
       |_ determinist
       |      | desc: make the data model determinist
       |      | default: False [type: bool]
       |_ finite
       |      | desc: make the data model finite
       |      | default: False [type: bool]

   *** Available generators of type 'ZIP_00' ***
     name: g_zip_00 (weight: 1, valid: True)
     generic args: 
       |_ random
       |      | desc: make the data model random
       |      | default: False [type: bool]
       |_ determinist
       |      | desc: make the data model determinist
       |      | default: False [type: bool]
       |_ finite
       |      | desc: make the data model finite
       |      | default: False [type: bool]

   ...


You can see that two generators are available for this data model. In
this case---the ZIP data model---the first one will generate modeled
ZIP archive based uniquely on the data model, whereas the other ones
(``ZIP_00``, ``ZIP_01``, ...)  generate modeled ZIP archives based on
the sample files available within the directory
``imported_data/zip/``.

For each one of these generators, some parameters are associated:

- ``random``: Enforce the generator to generate data in a
  random way;

- ``determinist``: Enforce the generator to generate data in a
  deterministic way;

- ``finite``: Enforce the generator to generate a finite number
  of data.

To send in a loop, five ZIP archives generated from the data model in
a deterministic way---that is by walking through the data model---you
can use the following command:

.. code-block:: none
   :linenos:
   :emphasize-lines: 1

   >> send_loop 5 ZIP<determinist=True> tWALK

We use for this example, the generic disruptor ``tWALK`` whose purpose
is to simply walk through the data model.  Note that disruptors are
chainable, each one consuming what comes from the left.


How to perform automatic modification on the file
+++++++++++++++++++++++++++++++++++++++++++++++++

In order to perform modification on a generated data, you can use
`disruptors` (look at :ref:`dis:generic-disruptors`), which are the
basic blocks for this task. You can look at the available
disruptors---either specific to the data model or generic--by typing
the command ``show_disruptors``, which will print a brief description
of each disruptor along with their parameters.

.. note::

   The following command allows to briefly look at all the defined
   generators and disruptors (called data makers), usable within the
   frame of the current data model. Note that specific data makers are
   separated from the generic ones by ``...``.

   .. code-block:: none
      :linenos:
      :emphasize-lines: 1

      >> show_dmaker_types

      ==[ Generator types ]=====
      ZIP | ZIP_00 | ... | 

      ==[ Disruptor types ]========
      ... | ALT | C | Cp | EXT | SIZE | STRUCT | tALT | tTERM | tTYPE | tWALK |



Use an Operator to send malformed ZIP files
-------------------------------------------





.. _fuddly-advanced:

Using `fuddly` Through Advanced Python Interpreter
==================================================
