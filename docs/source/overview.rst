Overview
********

Among the variety of complementary approaches used in the security
evaluation of a *target* (*e.g.*, software, an embedded equipment,
*etc.*), fuzz testing---abbreviated *fuzzing*---is widely recognized
as an effective means to help discovering security weaknesses in a
target.

Fuzzing is a software testing approach, which consists in finding
design or implementation flaws by stepping outside the expectations
the target may have relative to its input data, while looking out for
any unexpected behavior. This approach strives to confuse the target
in a way to specifically avoid rejection by possible conformity
tests---performed by the target---while still having a chance to
trigger more subtle bugs.  For such purpose, various ways are worth
considering like using malformed data, playing around the protocol
sequencing, and so on.  Fuzzing is similar to what is termed *fault
injection* in the field of *dependability*.

Our main objective are:

- To allow users to build a unique data model mixing very accurate
  representations for certain aspects with much coarser ones for
  others that are outside the focus of the testing; leaving open the
  way of refining the other parts should the need arise. We also imply
  with this objective to be able to mix up generation and mutation
  fuzzing techniques.

- To represent the data in a way that simplify the process of
  fuzzing and especially to enable the implementation of sophisticated
  transformations. By ''sophisticated'' we mean the capability to act
  on any data part (that is not necessarily contiguous) while
  preserving consistency of dependent parts if so desired. This
  amounts to allowing transformations to be articulated around
  syntactic criteria---*e.g.*, modification a specific field---or
  semantic ones---*e.g.*, transformation of the *n*:sup:`th`
  page of a PDF file.

- To be able to follow a protocol in order to put the target in
  a specific state before starting the fuzzing, while keeping the
  capability to deviate from the protocol requirements. This last
  option is especially useful to allow exploring other fuzzing facets
  based on protocol sequencing, timing constraints, and so on.


.. todo:: Add & translate part of SSTIC article
