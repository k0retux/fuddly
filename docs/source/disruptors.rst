.. _dis:generic-disruptors:

Generic Disruptors
******************

The current generic disruptors are presented within the following
sections.

Stateless Disruptors
====================

FIX - Fix Data Constraints
--------------------------

Description:
  Release constraints from input data or from only a piece of it (if
  the parameter `path` is provided), then recompute them. By
  constraints we mean every generator (or function) nodes that may
  embeds constraints between nodes, and every node *existence
  conditions*.

  .. seealso:: Refer to :ref:`dm:pattern:existence-cond` for insight
	       into existence conditions.

Reference:
  :class:`fuzzfmk.generic_data_makers.d_fix_constraints`

Parameters:
  .. code-block:: none

	specific args: 
	  |_ path
	  |      | desc: graph path regexp to select nodes on which the disruptor should 
	  |      |       apply
	  |      | default: None [type: str]
	  |_ clone_node
	  |      | desc: if True the dmaker will always return a copy of the node. (for 
	  |      |       stateless diruptors dealing with big data it can be usefull 
	  |      |       to it to False)
	  |      | default: False [type: bool]


ALT - Alternative Node Configuration
------------------------------------

Description:
  Switch to an alternate configuration.

Reference:
  :class:`fuzzfmk.generic_data_makers.d_switch_to_alternate_conf`

Parameters:
  .. code-block:: none

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

Description:
  Corrupt bits on some nodes of the data model.

Reference:
  :class:`fuzzfmk.generic_data_makers.d_corrupt_node_bits`

Parameters:
  .. code-block:: none

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

Description:
  Corrupt bit at a specific byte.

Reference:
  :class:`fuzzfmk.generic_data_makers.d_corrupt_bits_by_position`

Parameters:
  .. code-block:: none

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

Description:
  Call an external program to deal with the data.

Reference:
  :class:`fuzzfmk.generic_data_makers.d_call_external_program`

Parameters:
  .. code-block:: none

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

Description:
  Truncate the data (or part of the data) to the provided size.

Reference:
  :class:`fuzzfmk.generic_data_makers.d_max_size`

Parameters:
  .. code-block:: none

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

Description:
  Disrupt the data model structure (replace ordered sections by
  unordered ones).

Reference:
  :class:`fuzzfmk.generic_data_makers.d_fuzz_model_structure`

Parameters:
  .. code-block:: none

       specific args: 
	 |_ path
	 |      | desc: graph path regexp to select nodes on which the disruptor should 
	 |      |       apply
	 |      | default: None [type: str]


Stateful Disruptors
===================

tALT - Walk Through Alternative Node Configurations
---------------------------------------------------

Description:
  Switch the configuration of each node, one by one, with the provided
  alternate configuration.

Reference:
  :class:`fuzzfmk.generic_data_makers.sd_switch_to_alternate_conf`

Parameters:
  .. code-block:: none

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
----------------------------------------------------

Description:
  Perform alterations on terminal nodes (one at a time), without
  considering its type.

Reference:
  :class:`fuzzfmk.generic_data_makers.sd_fuzz_terminal_nodes`

Parameters:
  .. code-block:: none

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

Description:
  Perform alterations on typed nodes (one at a time) accordingly to
  its type and various complementary information (such as size,
  allowed values, ...).

Reference:
  :class:`fuzzfmk.generic_data_makers.sd_fuzz_typed_nodes`

Parameters:
  .. code-block:: none

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

Description:
  Perform alterations on separators (one at a time). Each time a
  separator is encountered in the provided data, it will be replaced
  by another separator picked from the ones existing within the
  provided data.

Reference:
  :class:`fuzzfmk.generic_data_makers.sd_fuzz_separator_nodes`

Parameters:
  .. code-block:: none

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

Description:
  Walk through the provided data and for each visited node, iterates
  over the allowed values (with respect to the data model).  Note: *no
  alteration* is performed by this disruptor.

Reference:
  :class:`fuzzfmk.generic_data_makers.sd_iter_over_data`

Parameters:
  .. code-block:: none

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
	 |_ singleton
	 |      | desc: consume also terminal nodes with only one possible value
	 |      | default: False [type: bool]
	 |_ nt_only
	 |      | desc: walk through non-terminal nodes only
	 |      | default: False [type: bool]
