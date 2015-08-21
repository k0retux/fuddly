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

``fuddly`` is a fuzzing and data manipulation framework whose main
objectives are:

* To allow users to build data model that:

  - mix very accurate representations for certain aspects with much
    coarser ones for others that are outside the focus of the testing;
    leaving open the way of refining the other parts should the need
    arise;

  - may be combined with each other;

  - enable to dissect raw data for analyzing them and enable to absorb
    them within the data model for manipulation;

  - enable to mix up generation and mutation
    fuzzing techniques.

* To represent the data in a way that simplify the process of fuzzing
  and especially to enable the implementation of elaborated
  transformations. By ''elaborated'' we mean the capability to act on
  any data part (that is not necessarily contiguous) while preserving
  consistency of dependent parts if so desired. This amounts to
  allowing transformations to be articulated around syntactic
  criteria---*e.g.*, modification of an integer depending on the size
  of the field hosting it---or semantic ones---*e.g.*, alteration of a
  value regarding its meaning for a given data format or protocol,
  alteration of specific data sub-parts forming a sound group for a
  given data format or protocol.


* To automate the fuzzing process relying on various fuddly's
  sub-systems enabling: the communication with the target, to follow
  and monitor its behavior and to act accordingly (*e.g.*, deviate
  from the protocol requirements like sequencing, timing constraints,
  and so on), thanks to data model search and modification
  primitives, while recording every piece of information generated
  during this process and enabling to replay it. 
