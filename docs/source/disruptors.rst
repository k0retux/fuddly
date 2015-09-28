.. _dis:generic-disruptors:

Generic Disruptor List
**********************

The current generic disruptors are presented within the following
sections.

Stateless Disruptors
====================

ALT - Alternative Node Configuration
------------------------------------

.. code-block:: none

   *** Generic disruptors of type 'ALT' ***                                                                                                                       
     name: d_switch_to_alternate_conf  (weight: 1, valid: False) [stateless disruptor]

       Switch to an alternate configuration.                                                                                                                      

     specific args: 
       |_ path
       |      | desc: graph path regexp to select nodes on which the disruptor should 
       |      |       apply
       |      | default: None [type: str]
       |_ recursive
       |      | desc: does the reachable nodes from the selected ones need also to 
       |      |       be changed?
       |      | default: True [type: bool]
       |_ conf
       |      | desc: change the configuration, with the one provided (by name), of 
       |      |       all subnodes fetched by @path, one-by-one. [default value is 
       |      |       set dynamically with the first-found existing alternate configuration]
       |      | default: None [type: str]


C - Node Corruption
-------------------

.. code-block:: none

   *** Generic disruptors of type 'C' ***                                                                                                                         
     name: d_corrupt_node_bits  (weight: 4, valid: False) [stateless disruptor]

       Corrupt bits on some nodes of the data model.                                                                                                              

     specific args: 
       |_ path
       |      | desc: graph path regexp to select nodes on which the disruptor should 
       |      |       apply
       |      | default: None [type: str]
       |_ nb
       |      | desc: apply corruption on @nb Nodes fetched randomly within the data 
       |      |       model
       |      | default: 2 [type: int]
       |_ ascii
       |      | desc: enforce all outputs to be ascii 7bits
       |      | default: False [type: bool]
       |_ new_val
       |      | desc: if provided change the selected byte with the new one
       |      | default: None [type: str]


Cp - Corruption at Specific Position
------------------------------------

.. code-block:: none

   *** Generic disruptors of type 'Cp' ***                                                                                                                        
     name: d_corrupt_bits_by_position  (weight: 4, valid: False) [stateless disruptor]

       Corrupt bit at a specific byte .                                                                                                                           

     specific args: 
       |_ new_val
       |      | desc: if provided change the selected byte with the new one
       |      | default: None [type: str]
       |_ ascii
       |      | desc: enforce all outputs to be ascii 7bits
       |      | default: False [type: bool]
       |_ idx
       |      | desc: byte index to be corrupted (from 1 to data length)
       |      | default: 1 [type: int]


EXT - Make Use of an External Program
-------------------------------------

.. code-block:: none

   *** Generic disruptors of type 'EXT' ***                                                                                                                       
     name: d_call_external_program  (weight: 1, valid: False) [stateless disruptor]

       Call an external program to deal with the data.                                                                                                            

     specific args: 
       |_ path
       |      | desc: graph path regexp to select nodes on which the disruptor should 
       |      |       apply
       |      | default: None [type: str]
       |_ cmd
       |      | desc: the command
       |      | default: None [type: list, tuple, str]
       |_ file_mode
       |      | desc: if True the data will be provided through a file to the external 
       |      |       program, otherwise it will be provided on the command line directly
       |      | default: True [type: bool]


SIZE - Truncate
---------------

.. code-block:: none

   *** Generic disruptors of type 'SIZE' ***
     name: d_max_size  (weight: 4, valid: False) [stateless disruptor]

       Truncate the data (or part of the data) to the provided size.

     specific args: 
       |_ sz
       |      | desc: truncate the data (or part of the data) to the provided size
       |      | default: 10 [type: int]
       |_ path
       |      | desc: graph path regexp to select nodes on which the disruptor should 
       |      |       apply
       |      | default: None [type: str]


STRUCT - Shake Up Data Structure
--------------------------------

.. code-block:: none

   *** Generic disruptors of type 'STRUCT' ***
     name: d_fuzz_model_structure  (weight: 1, valid: False) [stateless disruptor]

       Disrupt the data model structure (replace ordered sections by
       unordered ones).

     specific args: 
       |_ path
       |      | desc: graph path regexp to select nodes on which the disruptor should 
       |      |       apply
       |      | default: None [type: str]


Stateful Disruptors
===================

tALT - Walk Through Alternative Node Configurations
---------------------------------------------------

.. code-block:: none

   *** Generic disruptors of type 'tALT' ***
     name: d_switch_to_alternate_conf  (weight: 1, valid: False) [stateful disruptor]

       Switch the configuration of each node, one by one, with the         
       provided alternate configuration.

     generic args: 
       |_ clone_node
       |      | desc: if True the dmaker will always return a copy of the node. (for 
       |      |       stateless diruptors dealing with big data it can be usefull 
       |      |       to it to False)
       |      | default: True [type: bool]
       |_ init
       |      | desc: make the model walker ignore all the steps until the provided 
       |      |       one
       |      | default: 1 [type: int]
       |_ max_steps
       |      | desc: maximum number of steps (-1 means until the end)
       |      | default: -1 [type: int]
       |_ runs_per_node
       |      | desc: maximum number of test cases for a single node (-1 means until 
       |      |       the end)
       |      | default: -1 [type: int]
     specific args: 
       |_ conf
       |      | desc: change the configuration, with the one provided (by name), of 
       |      |       all subnodes fetched by @path, one-by-one. [default value is 
       |      |       set dynamically with the first-found existing alternate configuration]
       |      | default: None [type: str, list, tuple]


tTERM (OBSOLETE) - Basic Alteration of Terminal Node
-----------------------------------------

.. code-block:: none

   *** Generic disruptors of type 'tTERM' ***
     name: d_fuzz_terminal_nodes  (weight: 1, valid: False) [stateful disruptor]

       Perform alterations on terminal nodes (one at a time),
       without considering its type.                              

     generic args: 
       |_ clone_node
       |      | desc: if True the dmaker will always return a copy of the node. (for 
       |      |       stateless diruptors dealing with big data it can be usefull 
       |      |       to it to False)
       |      | default: True [type: bool]
       |_ init
       |      | desc: make the model walker ignore all the steps until the provided 
       |      |       one
       |      | default: 1 [type: int]
       |_ max_steps
       |      | desc: maximum number of steps (-1 means until the end)
       |      | default: -1 [type: int]
       |_ runs_per_node
       |      | desc: maximum number of test cases for a single node (-1 means until 
       |      |       the end)
       |      | default: -1 [type: int]
     specific args: 
       |_ determinist
       |      | desc: make the disruptor determinist
       |      | default: True [type: bool]
       |_ alt_values
       |      | desc: list of alternative values to be tested (replace the current 
       |      |       base list used by the disruptor)
       |      | default: None [type: list]
       |_ ascii
       |      | desc: enforce all outputs to be ascii 7bits
       |      | default: False [type: bool]

tTYPE - Advanced Alteration of Terminal Typed Node
--------------------------------------------------

.. code-block:: none

   *** Generic disruptors of type 'tTYPE' ***
     name: d_fuzz_typed_nodes  (weight: 1, valid: False) [stateful disruptor]

       Perform alterations on typed nodes (one at a time) accordingly to
       its type and various complementary information (such as size,
       allowed values, ...).

     generic args: 
       |_ clone_node
       |      | desc: if True the dmaker will always return a copy of the node. (for 
       |      |       stateless diruptors dealing with big data it can be usefull 
       |      |       to it to False)
       |      | default: True [type: bool]
       |_ init
       |      | desc: make the model walker ignore all the steps until the provided 
       |      |       one
       |      | default: 1 [type: int]
       |_ max_steps
       |      | desc: maximum number of steps (-1 means until the end)
       |      | default: -1 [type: int]
       |_ runs_per_node
       |      | desc: maximum number of test cases for a single node (-1 means until 
       |      |       the end)
       |      | default: -1 [type: int]
     specific args: 
       |_ path
       |      | desc: graph path regexp to select nodes on which the disruptor should 
       |      |       apply
       |      | default: None [type: str]
       |_ order
       |      | desc: when set to True, the fuzzing order is strictly guided by the 
       |      |       data structure. Otherwise, fuzz weight (if specified in the 
       |      |       data model) is used for ordering
       |      | default: False [type: bool]
       |_ deep
       |      | desc: when set to True, if a node structure has changed, the modelwalker 
       |      |       will reset its walk through the children nodes
       |      | default: True [type: bool]


tSEP - Alteration of Separator Node
-----------------------------------

.. code-block:: none

   *** Generic disruptors of type 'tSEP' ***
     name: d_fuzz_separator_nodes  (weight: 1, valid: False) [stateful disruptor]

       Perform alterations on separators (one at a time). Each time a
       separator is encountered in the provided data, it will be replaced
       by another separator picked from the ones existing within the
       provided data.

     generic args: 
       |_ clone_node
       |      | desc: if True the dmaker will always return a copy of the node. (for 
       |      |       stateless diruptors dealing with big data it can be usefull 
       |      |       to it to False)
       |      | default: True [type: bool]
       |_ init
       |      | desc: make the model walker ignore all the steps until the provided 
       |      |       one
       |      | default: 1 [type: int]
       |_ max_steps
       |      | desc: maximum number of steps (-1 means until the end)
       |      | default: -1 [type: int]
       |_ runs_per_node
       |      | desc: maximum number of test cases for a single node (-1 means until 
       |      |       the end)
       |      | default: -1 [type: int]
     specific args: 
       |_ path
       |      | desc: graph path regexp to select nodes on which the disruptor should 
       |      |       apply
       |      | default: None [type: str]
       |_ order
       |      | desc: when set to True, the fuzzing order is strictly guided by the 
       |      |       data structure. Otherwise, fuzz weight (if specified in the 
       |      |       data model) is used for ordering
       |      | default: False [type: bool]
       |_ deep
       |      | desc: when set to True, if a node structure has changed, the modelwalker 
       |      |       will reset its walk through the children nodes
       |      | default: True [type: bool]



tWALK - Walk Through a Data Model
---------------------------------

.. code-block:: none

   *** Generic disruptors of type 'tWALK' ***
     name: d_iter_over_data  (weight: 1, valid: False) [stateful disruptor]

       Walk through the provided data and for each visited node, iterates
       over the allowed values (with respect to the data model).
       Note: *no alteration* is performed by this disruptor.

     generic args: 
       |_ clone_node
       |      | desc: if True the dmaker will always return a copy of the node. (for 
       |      |       stateless diruptors dealing with big data it can be usefull 
       |      |       to it to False)
       |      | default: True [type: bool]
       |_ init
       |      | desc: make the model walker ignore all the steps until the provided 
       |      |       one
       |      | default: 1 [type: int]
       |_ max_steps
       |      | desc: maximum number of steps (-1 means until the end)
       |      | default: -1 [type: int]
       |_ runs_per_node
       |      | desc: maximum number of test cases for a single node (-1 means until 
       |      |       the end)
       |      | default: -1 [type: int]
     specific args: 
       |_ singleton
       |      | desc: consume also terminal nodes with only one possible value
       |      | default: False [type: bool]
       |_ nt_only
       |      | desc: walk through non-terminal nodes only
       |      | default: False [type: bool]
