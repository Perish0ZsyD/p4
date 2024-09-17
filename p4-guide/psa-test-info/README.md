# Portable Switch Architecture (PSA) test programs for p4c and behavioral-model

This document is intended to list PSA features and any existing test
programs that exercise those features.


# PSA features, and which test programs exercise them

The PSA features here were a list created by hand by Andy Fingerhut,
by skimming the PSA specification and thinking about the kinds of test
that had been written so far, and which had not.  Suggestions welcome
for any other features that would be nice to have test programs
written to exercise them.

| PSA feature | Test programs | STF test fully automated checking of results? | Notes |
| ----------- | ------------- | --------------------------------------------- | ----- |
| unicast vs. drop, with correct setting of egress_port, instance, packet_path, class_of_service metadata in egress | psa-unicast-or-drop-bmv2.{p4,stf} | yes | |
| multicast, with correct setting of egress_port, instance, packet_path, class_of_service metadata in egress | psa-multicast-basic-2-bmv2.{p4,stf} | yes | |
| resubmit, with correct setting of packet_path metadata in ingress | psa-resubmit-bmv2.{p4,stf} | yes | |
| recirculate, with correct setting of packet_path metadata in ingress and egress, and recirculated packet's ingress_port equals PSA_RECIRCULATE_PORT | psa-recirculate-no-meta-bmv2.{p4,stf} | yes | |
| ingress to egress clone | psa-i2e-cloning-basic-bmv2.{p4,stf} | yes | |
| egress to egress clone | psa-e2e-cloning-basic-bmv2.{p4,stf} | yes | |
| verify the proper end-of-ingress behavior for drop vs. resubmit vs. multicast vs. unicast operations, combined in all ways with ingress-to-egress clone yes vs. no | psa-end-of-ingress-test-bmv2.{p4,stf} covers most of this.  See Note column. | yes | No ingress-to-egress clone functionality tested yet.  TBD: add later when implemented. |
| verify proper end-of-egress behavior for drop vs. recirculate vs. one-packet-out, combined in all ways with egress-to-egress clone yes vs. no | psa-e2e-cloning-basic-bmv2.{p4,stf} covers most of these cases | yes | |
| verify ingress_timestamp is updated for resubmitted and recirculated packets, i.e. not always same as original packet | tbd | | |
| verify egress class_of_service copied from PRE configuration for cloned packets | tbd | | |
| verify parser_error filled in correctly at beginning of ingress and egress controls for no-error and at least one kind of parser error | psa-parser-error-test-bmv2.{p4,stf} in PR https://github.com/p4lang/p4c/pull/2571 | yes | |
| unicast and multicast packets with preservation of bridged metadata, including use of psa_normal extern function | not yet implemented in p4c and bmv2 | | |
| resubmit with preservation of user-defined metadata, including use of psa_resubmit extern function | not yet implemented in p4c and bmv2 | | |
| recirculate with preservation of user-defined metadata, including use of psa_recirculate extern function | not yet implemented in p4c and bmv2 | | |
| ingress-to-egress clone with preservation of user-defined metadata, including use of psa_clone_i2e extern function | not yet implemented in p4c and bmv2 | | |
| egress-to-egress clone with preservation of user-defined metadata, including use of psa_clone_e2e extern function | not yet implemented in p4c and bmv2 | | |
| ActionProfile extern | Han at least partially implemented this for PSA based on v1model implementation, but no test yet that Thrift API can configure an action profile and data packets are processed appropriately.  p4c PSA back end seems to have some part that looks for table property 'implementation' rather than PSA's 'psa_implementation'. | | |
| ActionSelector extern | same status as ActionProfile extern | | |
| ActionSelector extern with watch port feature enabled | tbd | | |
| Checksum extern | tbd | | |
| Counter extern | psa-basic-counter-bmv2.{p4,stf} | yes for output packets, no for reading and checking counters after they are updated, since p4lang/p4c STF tests do not provide a way to do that | |
| Counter extern silently allows updates to out-of-range index, with no state change | psa-counter1.p4 | no STF test yet | |
| Digest extern | tbd | | |
| DirectCounter extern | tbd | | |
| DirectMeter extern | tbd | | |
| Hash extern | tbd | | |
| InternetChecksum extern | tbd | | |
| Meter extern | psa-meter7-bmv2.{p4,stf} test that packet gets result GREEN from updating a color-blind meter.  TBD: Implement and create a test case for a color-aware meter that gets back GREEN when given GREEN, YELLOW when given YELLOW, and RED when given RED. | yes | |
| Random extern | not implemented in psa_switch yet, but Yunhe Liu has these PRs and p4c one has a test program https://github.com/p4lang/behavioral-model/pull/931 https://github.com/p4lang/p4c/pull/2477 | | |
| Register extern | psa-register-read-write-bmv2.{p4,stf} psa-register-read-write-2-bmv2.{p4,stf} | yes for output packet contents, no for control plane API to read/write Register array elements | | |
| psa_idle_timeout table property | tbd | | |
| psa_empty_group_action table property | tbd | | |

# Version details

As of the commit to the p4lang/p4c repository shown below:

```
$ git clone https://github.com/p4lang/p4c
$ cd p4c
$ git checkout e3d00878698f7acdf57fba13260e086eef7aac1f
$ git log -n 1 | head -n 5
commit e3d00878698f7acdf57fba13260e086eef7aac1f
Author: Peter J. Li <pl488@cornell.edu>
Date:   Wed Sep 2 15:34:04 2020 -0700

    [psa] i2e cloning bmv2 stf tests (#2499)

$ git clone https://github.com/p4lang/behavioral-model
$ cd behavioral-model
$ git checkout 51dae313390e3613f37fb8233ad493a306c0613b
$ git log -n 1 | head -n 5
commit 51dae313390e3613f37fb8233ad493a306c0613b
Author: Peter J. Li <pl488@cornell.edu>
Date:   Mon Aug 31 12:13:14 2020 -0700

    [psa_switch] first pass at i2e cloning  (#935)
```

most of the test programs for the PSA architecture are in files
matching these Bash shell patterns:

```
testdata/p4_16_samples/psa-*.p4
testdata/p4_16_errors/psa-*.p4
```

There are a few exceptions to this.  The following programs match one
of the shell patterns above, but do _not_ include the `psa.p4` include
file, and thus are not using the PSA architecture:

```
$ grep -c 'psa.p4' testdata/p4_16_samples/psa-*.p4 testdata/p4_16_errors/psa-*.p4 | grep ':0$'
testdata/p4_16_errors/psa-type-hdr.p4:0
```

The following test programs in the `testdata/p4_16_samples`,
`testdata/p4_16_errors`, and `testdata/p4_16_bmv_errors` directories
do include the psa.p4 file, and thus are written for the PSA
architecture, but do not have file names that begin with `psa-`:


```
for dir in testdata/p4_16_samples testdata/p4_16_errors testdata/p4_16_bmv_errors
do
    cd $dir
    echo "Files in directory: $dir"
    echo "----- begin -----"
    find . -name '*.p4' | xargs grep --files-with-matches psa.p4 | grep -v 'psa-'
    echo "------ end ------"
    cd ../..
done

Files in directory: testdata/p4_16_samples
----- begin -----
./issue1208-1.p4
./p4rt_digest_complex.p4
------ end ------
Files in directory: testdata/p4_16_errors
----- begin -----
------ end ------
Files in directory: testdata/p4_16_bmv_errors
----- begin -----
------ end ------
```

This might be near to the shortest shell command one can write to find
all PSA test programs, and no others:

```
$ find testdata/p4_16_samples testdata/p4_16_errors testdata/p4_16_bmv_errors -name '*.p4' | xargs grep --files-with-matches psa.p4 | sort
testdata/p4_16_errors/psa-meter2.p4
testdata/p4_16_samples/issue1208-1.p4
testdata/p4_16_samples/p4rt_digest_complex.p4
testdata/p4_16_samples/psa-action-profile1.p4
testdata/p4_16_samples/psa-action-profile2.p4
testdata/p4_16_samples/psa-action-profile3.p4
testdata/p4_16_samples/psa-action-profile4.p4
testdata/p4_16_samples/psa-action-selector1.p4
testdata/p4_16_samples/psa-action-selector2.p4
testdata/p4_16_samples/psa-action-selector3.p4
testdata/p4_16_samples/psa-basic-counter-bmv2.p4
testdata/p4_16_samples/psa-counter1.p4
testdata/p4_16_samples/psa-counter2.p4
testdata/p4_16_samples/psa-counter3.p4
testdata/p4_16_samples/psa-counter4.p4
testdata/p4_16_samples/psa-counter6.p4
testdata/p4_16_samples/psa-custom-type-counter-index.p4
testdata/p4_16_samples/psa-drop-all-bmv2.p4
testdata/p4_16_samples/psa-drop-all-corrected-bmv2.p4
testdata/p4_16_samples/psa-end-of-ingress-test-bmv2.p4
testdata/p4_16_samples/psa-example-counters-bmv2.p4
testdata/p4_16_samples/psa-example-digest-bmv2.p4
testdata/p4_16_samples/psa-example-parser-checksum.p4
testdata/p4_16_samples/psa-example-register2-bmv2.p4
testdata/p4_16_samples/psa-fwd-bmv2.p4
testdata/p4_16_samples/psa-hash.p4
testdata/p4_16_samples/psa-meter1.p4
testdata/p4_16_samples/psa-meter3.p4
testdata/p4_16_samples/psa-meter4.p4
testdata/p4_16_samples/psa-meter5.p4
testdata/p4_16_samples/psa-meter6.p4
testdata/p4_16_samples/psa-meter7-bmv2.p4
testdata/p4_16_samples/psa-multicast-basic-2-bmv2.p4
testdata/p4_16_samples/psa-multicast-basic-bmv2.p4
testdata/p4_16_samples/psa-multicast-basic-corrected-bmv2.p4
testdata/p4_16_samples/psa-portid-using-newtype2.p4
testdata/p4_16_samples/psa-random.p4
testdata/p4_16_samples/psa-recirculate-no-meta-bmv2.p4
testdata/p4_16_samples/psa-register1.p4
testdata/p4_16_samples/psa-register2.p4
testdata/p4_16_samples/psa-register3.p4
testdata/p4_16_samples/psa-register-complex-bmv2.p4
testdata/p4_16_samples/psa-register-read-write-2-bmv2.p4
testdata/p4_16_samples/psa-register-read-write-bmv2.p4
testdata/p4_16_samples/psa-resubmit-bmv2.p4
testdata/p4_16_samples/psa-test.p4
testdata/p4_16_samples/psa-top-level-assignments-bmv2.p4
testdata/p4_16_samples/psa-unicast-or-drop-bmv2.p4
testdata/p4_16_samples/psa-unicast-or-drop-corrected-bmv2.p4
```

There are multiple files named `CMakeLists.txt` in the p4lang/p4c
repository that are used to control which test program run what kinds
of automated tests.

There are several mentions of test program file names in those files,
which suppress running certain tests on the programs, or run the test,
but expect them to fail, instead of expecting them to succeed.

None of the `CMakeLists.txt` files mention the file names
`p4rt_digest_complex.p4` or `issue1208-1.p4`, so any mention of the
test programs above will include the `psa-` as part of the file name:

```
$ find . -name CMakeLists.txt | xargs grep p4rt_digest
$ find . -name CMakeLists.txt | xargs grep issue1208

[ no output from either command above ]
```

Below are all mentions of `psa-` in the `CMakeLists.txt` files:

```
$ find . -name CMakeLists.txt | xargs grep psa-
./backends/p4test/CMakeLists.txt:  testdata/p4_16_samples/psa-meter1.p4
./backends/p4test/CMakeLists.txt:  testdata/p4_16_samples/psa-example-parser-checksum.p4
./backends/p4test/CMakeLists.txt:  testdata/p4_16_samples/psa-counter6.p4
./backends/bmv2/CMakeLists.txt:  testdata/p4_16_samples/psa-example-digest-bmv2.p4
```

The tables below gives some notes on each of the PSA test programs.
The first table contains only those programs that are not mentioned in
any of the `CMakeLists.txt` files, and the one after that contains
only that are are mentioned in at least one of the `CMakeLists.txt`
files (only a few are so mentioned).

`psa-counter6.p4` has comments in the `CMakeLists.txt` file where it
is mentioned, explaining why it should give an error when you attempt
to compile it.  It is marked XFAIL, as it should be for such a test
program.

PSA test programs not mentioned in any `CMakeLists.txt` files:

| Test program file name | Has STF test? | Summary of features exercised |
| ---------------------- | ------------- | ----------------------------- |
| psa-meter2.p4 | no  | tbd |
| issue1208-1.p4 | no  | basic instantiation of top level package with empty parsers, controls, and deparsers |
| p4rt_digest_complex.p4 | no  | Support for (limited) structs inside of a header, which is really a P4_16 language feature that is not specific to the PSA architecture, but still a useful test. |
| psa-action-profile1.p4 | no  | tbd |
| psa-action-profile2.p4 | no  | tbd |
| psa-action-profile3.p4 | no  | tbd |
| psa-action-profile4.p4 | no  | tbd |
| psa-action-selector1.p4 | no  | tbd |
| psa-action-selector2.p4 | no  | tbd |
| psa-action-selector3.p4 | no  | tbd |
| psa-basic-counter-bmv2.p4 | yes | Indexed (aka indirect) counter instantiation and updating.  STF test as of 2020-Aug does not actually read the counters to check that they are updated, but if p4c and psa_switch are correct the counters should be updated. |
| psa-counter1.p4 | no  | Looks extremely similar, but not identical, to psa-basic-counter-bmv2.p4.  No additional features executed more than what psa-basic-counter-bmv2.p4 does, except that it attempts to update index 1024 of an indexed counter with 1024 elements, so out of range and should be a no-op. |
| psa-counter2.p4 | no  | Same as psa-counter1.p4 except that a single action should update two indexed counters, not only one. |
| psa-counter3.p4 | no  | Same as psa-counter2.p4 except that it only updates one indexed counter, and does it by a call directly in ingress control apply block, rather than in an action of a table. |
| psa-counter4.p4 | no  | Basic use of DirectCounter extern |
| psa-counter6.p4 | no  | see table below |
| psa-custom-type-counter-index.p4 | no  | Nearly identical to psa-counter1.p4, but uses P4_16 `type` declaration to declare a type that is used as the index to the indexed Counter extern. |
| psa-drop-all-bmv2.p4 | yes | Empty ingress and egress, so all received packets should be dropped, confirmed by testing with a couple of input packets in STF file. |
| psa-drop-all-corrected-bmv2.p4 | yes | Nearly identical to psa-drop-all-bmv2.p4.  Could probably be removed without any real loss of test coverage. |
| psa-example-counters-bmv2.p4 | no  | tbd |
| psa-example-digest-bmv2.p4 | no  | see table below |
| psa-example-parser-checksum.p4 | no  | see table below |
| psa-example-register2-bmv2.p4 | yes | tbd |
| psa-fwd-bmv2.p4 | yes | Empty ingress and egress, so should drop all received packets.  Seems that psa-drop-all-bmv2.p4 covers this functionality better, since it has non-empty STF test that actually sends in a few packets. |
| psa-hash.p4   | no  | tbd |
| psa-meter1.p4 | no  | see table below |
| psa-meter3.p4 | no  | tbd |
| psa-meter4.p4 | no  | tbd |
| psa-meter5.p4 | no  | tbd |
| psa-meter6.p4 | no  | tbd |
| psa-meter7-bmv2.p4 | yes | tbd |
| psa-multicast-basic-bmv2.p4 | yes | Test sending a packet multicast to several output ports, but STF test does not verify that intrinsic metadata fields egress_port, instance, and packet_path are correct. |
| psa-multicast-basic-corrected-bmv2.p4 | yes | Nearly identical to psa-multicast-basic-bmv2.p4 |
| psa-portid-using-newtype2.p4    | no  | tbd |
| psa-random.p4                   | no  | tbd |
| psa-recirculate-no-meta-bmv2.p4 | yes | tbd |
| psa-register1.p4                | no  | tbd |
| psa-register2.p4                | no  | tbd |
| psa-register3.p4                | no  | tbd |
| psa-register-complex-bmv2.p4 | yes | Basic read/write tests on a PSA Register extern, with STF tests. |
| psa-register-read-write-bmv2.p4 | yes | Basic read/write tests on a PSA Register extern, with STF tests. |
| psa-resubmit-bmv2.p4 | yes | tbd |
| psa-test.p4 | no  | tbd |
| psa-top-level-assignments-bmv2.p4 | yes | Tests top level assignments in the ingress control, i.e. not performed within the action of a table.  A very early version of the PSA implementation in p4c produced incorrect output for this program. |
| psa-unicast-or-drop-bmv2.p4 | yes | Tests sending a packet unicast to a single output port that is a function of a header field, or dropping the packet for some values of fields in the input packet. |
| psa-unicast-or-drop-corrected-bmv2.p4 | yes | Nearly identical test program to psa-unicast-or-drop-bmv2.p4, with identical STF tests covering nearly the same functionality.  One of these two test programs did expose a bug in an early version of the BMv2 PSA implementation, so both are worth keeping. |


PSA test programs mentioned in at least one `CMakeLists.txt` file:

| Test program file name | Has STF test? | Summary of features exercised | Reason it is mentioned in CMakeLists.txt file |
| ---------------------- | ------------- | ----------------------------- | --------------------------------------------- |
| psa-counter6.p4 | no  | Basic use of DirectCounter in a way that should ideally cause a compile-time error, intended to test that compiler catches this incorrect program. | There are comments in backends/p4test/CMakeLists.txt explaining why it should give an error when you attempt to compile it.  It is marked XFAIL in that file, as it should be for such a test program. |
| psa-example-digest-bmv2.p4 | no  | tbd | This test program uses an if statement in a deparser, which is needed for PSA 1.x digests and a few other features, but is not implemented in p4c yet.  Han Wang might implement this in Aug 2020 or soon afterwards. |
| psa-example-parser-checksum.p4 | no  | tbd | Table parser_error_count_and_convert key named istd.parser_error is type error, which P4Runtime API 1.x does not support as the type of a table key.  Long term solution is for a future P4Runtime API version to support type error as table keys. |
| psa-meter1.p4 | no  | tbd | It seems that the best approach to making a program like this work with the P4Runtime API is to enhance the P4Runtime API to support action parameters that have enum types: https://github.com/p4lang/p4runtime/issues/191 |



# Manual testing of program psa-basic-counter-bmv2.p4

Manual testing of counter updates in test program psa-basic-counter-bmv2.p4


```
sudo ~/p4-guide/bin/veth_setup.sh
cd p4c/build
./p4c-bm2-psa ../testdata/p4_16_samples/psa-basic-counter-bmv2.p4 -o psa-basic-counter-bmv2.json
sudo psa_switch --log-console -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 psa-basic-counter-bmv2.json
```

In psa_switch_CLI:
```
counter_read cIngress.counter 256
```

In scapy:
```
pkt1=Ether(dst='00:00:00:00:00:01', src='00:00:00:00:00:00', type=0xffff)
sendp(pkt1,iface='veth8')
```

I observed that after sending in each of 4 identical packets, the
packet count at index 256 increased by 1, and the byte count by 14.
That looks correct to me.


# Miscellaneous commands

```
./p4test --pp ./tmp-foo/psa-example-parser-checksum.p4 --dump ./tmp-foo --top4 MidEndLast,FrontEndLast,FrontEndDump --testJson --maxErrorCount 100 --arch psa --p4runtime-files ./tmp-foo/psa-example-parser-checksum.p4.p4info.txt --p4runtime-entries-files ./tmp-foo/psa-example-parser-checksum.p4.entries.txt /home/andy/p4c/testdata/p4_16_samples/psa-example-parser-checksum.p4
```
