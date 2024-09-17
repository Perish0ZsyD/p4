# Comparison of variants for implementating action selectors

There are 3 slightly different implementations of action selectors
given in these documents:

+ variant 1 [here](README-action-selector-variant1.md)
+ variant 2 [here](README-action-selector-variant2.md)
+ variant 3 [here](README-action-selector-variant3.md)

Here we summarize the advantages and disadvantages of each.

Note 1: I am certain someone can devise additional variants that have
different advantages and disadvantages as compared to one of these
three.  These examples are not intended to include all possibilities.
The intent is to show that there are some implementation choices, each
choice providing the same packet processing behavior, but with some
consequences when implementing the device driver software that handles
control plane API operations.

Note 2: There are at least some implementations of action selectors
for switch ASICs that provide additional behavior _not_ described
in any of these variants.  See section [Action selectors with watch
ports](#action-selectors-with-watch-ports) for more details.

+ Variant 1
  + critical path: 3 dependent table lookups plus 1 integer modulo
    calculation (hash calculation can be done in parallel with first
    table lookup)
  + Disadvantages:
    + Can require large number of table updates to change the size of a
      group (see article on variant 1 for some details).
  + Advantages:
    + Critical path is only 3 dependent table lookups
+ Variant 2
  + critical path: 4 dependent table lookups plus 1 integer modulo
    calculation (hash calculation can be done in parallel with first
    and second table lookups)
  + Disadvantages:
    + Critical path is 4 dependent table lookups
  + Advantages:
    + Changing the number of members in a group requires at most O(1)
      table add/delete/modify operations.
+ Variant 3
  + critical path: 3 dependent table lookups plus 1 modulo calculation
    and 1 integer addition (hash calculation can be done in parallel
    with first and second table lookups)
  + Advantages:
    + Critical path is only 3 dependent table lookups
    + Changing the number of members in a group often requires at most
      O(1) table add/delete/modify operations, but in some cases
      requires more.  When it requires more, the number of operations
      should be possible to keep as low as the size of the group being
      modified, or some low multiple of that.
  + Disadvantages:
    + Driver software must implement some memory management techniques
      for maintaining all group members in contiguous entries of the
      member table.

Having a short critical path is better for achieving a low latency
implementation.  Dependent table lookups cannot begin the later table
lookup until the earlier table's action is complete.  Parallelism in
an implementation (whether hardware or software) can enable
independent calculations (such as the hash calculation) to be done in
parallel with other operations, but cannot reduce start-to-finish
latency of this critical path for an individual packet.


# What if my target device cannot do integer modulo operations?

Some target devices do not have a capability to calculate an integer
modulo operation with an arbitrary divisor.  For example, several
switch ASICs implement integer modulo for selecting one among several
equal cost paths (ECMP) for any number of members from 1 up to 32, but
not for larger groups, because of the cost in silicon die area of
implementing the integer modulo operation.  Some very small and cheap
CPU cores do not implement integer multiply and divide instructions.

The main purpose of the integer modulo operation shown in the action
selector implementation is to select one member of a group of size N,
with each member selected as often as any other.

For example, if the input values we select for a hash function are
evenly distributed, and we use a hash function with 16 bits of result,
such that all values in the range [0, 65535] are evenly distributed,
then integer modulo gives exactly evenly distributed member selection
for group sizes that are a power of 2, and for group sizes up to 1K
gives very close to equal distribution of members.

For example, for a group with 6 members, here are the number of values
in the range [0, 65535] that give each of the results 0 through 5 when
you divide them by 6 and take the remainder:

+ remainder 0: 10923 hash values
+ remainder 1: 10923 hash values
+ remainder 2: 10923 hash values
+ remainder 3: 10922 hash values
+ remainder 4: 10922 hash values
+ remainder 5: 10922 hash values

This is so close to an equal distribution that it is unlikely to
concern anyone.  It is significantly more likely that the set of
packet flows passing through a device near the same time have unequal
packet or bit rates, or that there are few enough of them, that the
resulting distribution is unequal for those reasons, than that the
modulo operation is introducing problems.

    Aside: Note that the evenness of distribution gracefully degrades
    for larger groups, but can be as bad as a 2-to-1 ratio of
    unevenness if you have groups with size of 32769 or larger, when
    the hash function used has a 16-bit result.  Action selectors are
    typically used in packet processing for selecting among groups
    that are much smaller than that, e.g. up to 256 or so.  If you
    want close-to-equal selection among larger groups than that, it is
    likely that some P4 action selector implementations will not
    support such large groups.  If you find yourself in such a
    situation, you as a P4 developer could choose to implement your
    own solution, perhaps based upon one of the variants linked above
    with multiple P4 tables, and a hash function with more than 16
    bits of output.

So what can one do in a restricted computing situation where one
cannot do an integer modulo operation for arbitrary divisors?

Let us suppose that you _can_ still do integer modulo by any power of
2.  Those restricted modulo operations are all equivalent to selecting
the least significant K bits of a value (e.g. modulo 256 is the same
as a bitwise AND operation with 0xff).  If your device cannot even do
that, then this article will not help you.

The technique described below allows one to make a tradeoff between:

+ larger table sizes and more even distribution selecting group members
+ smaller table sizes and less even distribution selecting group members

It can be used in combination with any of the three variants of action
selectors linked above.

The basic idea is that whenever the control plane API requests a group
with N members, we implement it using a larger group with a number of
members that is a power of 2.

To give a small example, suppose that we consider it acceptable if
some members are selected 5/4 times more often than other members, but
we do not want any unevenness larger than that.

If we want a group of 1 or 2 members, those are small special cases
where we can perform the modulo by 1 or 2 exactly, since those are
powers of 2.  It seems reasonable to make those special cases, and not
increase the number of members.

For 3 members, though, that will not work.  If we make a table of
members with at least 3*4 = 12 members, rounding that up to the next
power of 2, which is 16, we can create a group of 16 members with
multiple copies of the 3 members, such that each member occurs at
least 4 times, but none more than 5 times.  For example:

| Remainder | member action to use |
| --------- | -------------------- |
|  0 | 1 |
|  1 | 2 |
|  2 | 3 |
|  3 | 1 |
|  4 | 2 |
|  5 | 3 |
|  6 | 1 |
|  7 | 2 |
|  8 | 3 |
|  9 | 1 |
| 10 | 2 |
| 11 | 3 |
| 12 | 1 |
| 13 | 2 |
| 14 | 3 |
| 15 | 1 |

Member 1 occurs 5 times, and members 2 and 3 occur 4 times each.  If
calculating the hash value modulo 16 results in the values 0 through
15 with equal frequency, then member 1 will be selected 5/4 times more
than members 2 or 3.

More generally, for N members, if you want a ratio of at most 5/4
between the most frequently used member and the least frequently used
member, you should increase the number of members-with-duplicates to
4*N, then rounded up to the next power of 2.

| desired # of members N | actual # of members after duplication |
| ---------------------- | ------------------------------------- |
|          1 |   1 |
|          2 |   2 |
|  3 ...   4 |  16 |
|  5 ...   8 |  32 |
|  9 ...  16 |  64 |
| 17 ...  32 | 128 |
| 33 ...  64 | 256 |
| 65 ... 128 | 512 |

If you want a ratio of at most (K+1)/K between the most frequently
used member and the least frequently used member, you should increase
the number of members-with-duplicates to K*N, then round up to the
next power of 2.

Adding and removing members can be implemented by taking the physical
table of members with duplicates, and modifying only a few of its
members.  For example, to add a 4th member to the 3-member example
shown above, see the table below for the original members, and which
ones can be modified so that the resulting 4 members are as evenly
distributed as possible.  In this example, only 4 members need to be
overwritten, marked with arrows.  It does not matter exactly which
members are modified, as long as the final relative frequency is
correct.  In particular, while the 3-member configuration example
shows the members being distributed "round robin" order, i.e. 1, 2, 3,
1, 2, 3, 1, 2, 3, ..., that order is not significant at all.

| Remainder | member action to use for group of 3 | member action to use for group of 4 |
| --------- | ----------------------------------- | ----------------------------------- |
|  0 | 1 | 4 <-- |
|  1 | 2 | 4 <-- |
|  2 | 3 | 4 <-- |
|  3 | 1 | 4 <-- |
|  4 | 2 | 2 |
|  5 | 3 | 3 |
|  6 | 1 | 1 |
|  7 | 2 | 2 |
|  8 | 3 | 3 |
|  9 | 1 | 1 |
| 10 | 2 | 2 |
| 11 | 3 | 3 |
| 12 | 1 | 1 |
| 13 | 2 | 2 |
| 14 | 3 | 3 |
| 15 | 1 | 1 |

I do not know of any technique here that will help one to calculate
the physical members to update that uses some math formula.  The most
straightfward way I know of is to have driver software maintain a data
structure that contains a list of which slot numbers each member is
currently stored in, and a count of the slots.

The invariant to maintain is that by the time you are done doing
modifies, every member occurs either X or X+1 times, for some integer
X.

Thus when adding a new member, always overwrite slots of members that
currently have the most duplicates, not ones with the fewest
duplicates.

When removing a member, overwrite all places where that member occurs,
and always overwrite it with a member that currently has the fewest
number of duplicates.

If we do not need to create a new physical group of members that is
double or half of the current size, then the method above never needs
to modify more than X+1 entries.

Such a sequence of multiple modify operations is not atomic relative
to packet processing, but that might be perfectly acceptable in many
implementations.  If you want even these operations to appear atomic
relative to processing data packets, see the next paragraph.

If the number of members ever grows above the point where the current
physical group size is too small to preserve the desired level of
unevenness, because we need to double the physical group size, that
can be done atomically relative to packet processing for at least
variant 3, using the technique described in the article on [variant
3](README-action-selector-variant3.md) (search for the word
"atomically").

A small change to [variant 2](README-action-selector-variant2.md)
would make it possible for it to make such atomic changes to groups,
too: adding to the action `T_set_group_size` an assignment to a new
variable, which could be named `T_remapped_group_id`, and then in the
table `T_group_to_member_id` replacing the key `T_group_id` with
`T_remapped_group_id`.  That level of indirection would enable driver
software to change `T_remapped_group_id` in the data plane via a
single atomic modify operation on table `T_group_id_to_size`, enabling
arbitrary changes to a group's membership in the same way as described
for variant 3.


# Action selectors with watch ports

There are multiple ways to implement this behavior.  Two approaches
are described below (one with only partial details).

The goal here is to react as quickly as possible to a switch port
changing from up to down state by no longer sending packets to those
ports, since those packets would then be lost.  This mechanism is most
often used for the part of the data plane that implements selecting a
physical port in a LAG (Link Aggregation Group), because that is the
point that an actual physical port is selected.

One could consider using this feature for layer 3 forwarding decisions
that use ECMP.  This is likely to be more expensive to implement than
doing it only for LAG port selection, because the number of groups and
their sizes tends to be far larger.

The idea is that when the control plane API adds a member to the
action selector, it associates a particular physical port with that
member.  The intent is that if that port should later change state
from up to down, all members associated with that port should become
disabled/unselectable as soon as possible.  The assumption is that the
control plane associates members with ports only when selecting that
member would cause the packet to be sent out of that port.

It is typical for low level port monitoring driver software to
maintain the up/down state of the ports.  This is the first part of
the system that detects and determines that a port will transition
from state up to down.

Below are two basic approaches for implementing this watch port
behavior.

(action selector with "watch port" approach #1)

When the driver software detects an up to down transition on a port,
it finds all action selector members associated with that port, and
removes those members from the groups they are in.  It uses the same
modifications of tables in the target that would be done if the
control plane API requested removing those members.

This removes from the reaction time the latency of the following
steps:

+ notify the control plane about the port going down
+ the control plane determining what API calls to make in response
+ the control plane making those API calls

With this approach, it can still take potentially many update
operations in the target to reach the desired state of all such
members being removed.  Using variants 2 or 3 described above, it
should be usually O(1) updates for a LAG action selector, since a
physical port would only be a member of one group.

(action selector with "watch port" approach #2)

When the driver software detects an up to down transition on a port,
it writes a constant number of locations in the target device, perhaps
as few as one, to indicate this change in port state.  All action
selectors read that state for each packet being processed, and the
data plane implementation of those action selectors has additional
logic to select a member that prevents it from selecting a member
whose watch port is down.  The details of how this can be done are
beyond the scope of this article.

This approach can potentially have somewhat lower latency of reaction
time versus the previous one above, but for LAG selection, any
potential difference seems to me quite small.

Advantages of approach #1, as compared to approach #2:
+ No additional data plane logic for selecting members than those
  already described for variants 1, 2, and 3.

Disadvantages of approach #1, as compared to approach #2:
+ Somewhat longer latency to react to ports going down for LAG, but
  only a little bit.  If an action selector with watch ports were used
  for some use case other than port selection in a LAG, perhaps there
  would be a bigger difference here, but more investigation of the
  details of how approach #2 is implemented in the data plane would be
  needed, and a better idea of the number and size of action selector
  groups required.

The advantages and disadvantages of approach #2 compared to approach
#1 are just the converse of those described above.

A new potential case resulting from this feature is: What should the
packet processing behavior be if an action selector group becomes
empty, because its _last_ member is removed, or disabled?

The PSA architecture proposes a table property
`psa_empty_group_action` (see the [Action
Selector](https://p4.org/p4-spec/docs/PSA-v1.1.0.html#sec-action-selector)
of the PSA spec), which is assigned an action that should be executed
if an empty group is ever encountered while looking up a table that
uses an action selector.  Such a feature is straightforward to
implement for any of the action selector variants described: simply
change the group's members not to 0 members, but to the single member
specified by the `psa_empty_group_action`.  If you implement an action
selector variant that that enables atomically changing the members of
a group, this change can also be done atomically.
