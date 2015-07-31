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


.. note:: In the file name ``mydf`` is not really important. However,
   what is important is to use the same prefix for this to
   files, and respect the template.


1. Defining the Data Model
--------------------------

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


2. Initiating the Fuzzing Environment
-------------------------------------

.. note:: Defined within ``mydf_strategy.py``

.. code-block:: python
   :linenos:

   from fuzzfmk.plumbing import *
   from fuzzfmk.tactics_helper import *

   tactics = Tactics()



3. Defining the Targets
-----------------------

3.1 Generic Targets
+++++++++++++++++++


3.1 Specific Targets
++++++++++++++++++++


4. Defining the Logger
----------------------


5. Defining Specific Disruptors
-------------------------------

.. note:: Also look at :ref:`useful-examples`



6. Defining Probes and Operators
--------------------------------



Using `fuddly` simple UI: FuzzShell
===================================





Using `fuddly` Through Advanced Python Interpreter
==================================================
