# Introduction

This directory is intended to contain examples of PTF tests that run
automated tests of P4_16 programs written for the v1model architecture
implemented by the BMv2 software switch.  Each has simple test
controller software written in Python for adding table entries, and
sometimes also other features provided by the P4Runtime API.  Each PTF
test also typically sends packets to the switch, and checks that the
packets with the expected contents are sent out by the software
switch.

See the [demo1 PTF README](../demo1/README-ptf.md) for a first simple
example of doing this, along with some explanation of the kind of
output that running a successful PTF test looks like.


# Exercising all supported match kinds

+ `lpm`, `exact` - see the PTF test in the directory
  [`demo1`](../demo1/README-ptf.md)
+ `range`, `ternary`, `optional` - see the PTF test in the directory
  [`ptf-tests/matchkinds`](matchkinds)
  + TODO: I wouldn't be surprised if range entries on key fields of
    type `int<W>` work as if they were cast to type `bit<W>` instead.
    True?  If so, that seems tricky to change, unless the field's most
    significant, i.e. sign, bit is negated, as well as all min/max
    values installed by the control plane.


# Multicast configuration and packet replication

+ multicast group
  + configure from controller - see the PTF test in the directory
    [`demo7`](../demo7)
  + verify changes in data packet processing as a result of controller changes
  + read multicast group config from switch - TODO add to demo7 PTF test


# PacketIn and PacketOut messages between controller and switch

See P4 program and PTF test in the directory
[`ptf-tests/packetinout`](packetintout/).


# P4 register array access, with read/write from controller via PacketOut/In messages

See P4 program and PTF test in the directory
[`ptf-tests/registeraccess`](registeraccess/).


# Idle timeout notification messages from switch to controller

See P4 program and PTF test in the directory
[`ptf-tests/idletimeout`](idletimeout/).

It would be a more thorough test if it also exercised a situation
where there were say 5 entries in the table with `support_timeout =
true`, and configured those 5 entries with different idle timeout
durations, then say sent a packet per second matching all 5 entries
for a while, then stopped sending matching entries for 2 or 3 of them,
but continued sending matching entries for the rest.  Then verify that
the idle timeout notifications were generated at approximately the
correct times for the entries it should, but not for the entries it
should not.


# Things not demonstrated yet

+ mirror sessions
  + configure from controller
  + verify changes in data packet processing as a result of controller changes
  + read mirror session info from switch
+ read counters from controller
  + indirect counter
  + direct counter - partially done in demo2 directory
  + packets only
  + bytes only
  + packets and bytes
+ configure a meter
  + note: difficult to write precise automated tests for meters.
    Probably better to try to create a test that reports what fraction
    of the packets sent in are forwarded out.
  + indirect meter
  + direct meter
  + packets
  + bytes
+ digest
  + generate from P4 data plane, verify received as expected by controller
+ register
  + PI does not yet support reading or writing register arrays.  That
    must be implemented before such a PTF test can be successfully run.
    See [this p4lang/PI issue](https://github.com/p4lang/PI/issues/376)
  + There _is_ a demo program with PTF test that does register read/write
    from controller using PacketOut and PacketIn messages instead.
    See directory [`ptf-tests/registeraccess`](registeraccess/).
+ action profile extern - configure and forwarding packets
+ action selector extern - configure and forwarding packets
  + 1 element in a group
  + 3-4 elements in a group
  + attempting to exceed max # of elements in a group
  + attempting to add two different action names in a single group
    (supported by p4c and simple_switch_grpc?)
  + attempting to use watch port feature - supported?
    + using watch port feature and having a watched port go down.  Not
      sure if there is even a way with simple_switch_grpc to make a
      port go down?
+ There is nothing to configure from controller for these v1model externs:
  + hash
  + random
  + Checksum16
