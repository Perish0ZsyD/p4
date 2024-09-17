/*
Copyright 2020 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <core.p4>
#include <v1model.p4>
#include <boost/preprocessor.hpp>

typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header cmd_hdr_t {
    bit<8> op1_index;
    bit<8> op2_index;
    bit<8> result_index;
    // 1 if op1_index is out of range, 2 for op2_index, 3 for result_index.
    // 0 if they are all in range
    bit<8> first_out_of_range_index;
}

#define NUM_FIELDS 32

header my_custom_hdr_t {
    // The preprocessor directives below generate lines like:
    // bit<8> f0;
    // up to:
    // bit<8> f31;
#define BOOST_PP_LOCAL_MACRO(n) bit<8> f ## n;
#define BOOST_PP_LOCAL_LIMITS (0,NUM_FIELDS-1)
#include BOOST_PP_LOCAL_ITERATE()

#define BOOST_PP_LOCAL_MACRO(n) bit<8> baz_ ## n;
#define BOOST_PP_LOCAL_LIMITS (5,10)
#include BOOST_PP_LOCAL_ITERATE()
}

struct headers_t {
    ethernet_t    ethernet;
    cmd_hdr_t     cmd_hdr;
    my_custom_hdr_t my_custom_hdr;
}

struct metadata_t {
}

parser parserImpl(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t stdmeta)
{
    state start {
        packet.extract(hdr.ethernet);
        packet.extract(hdr.cmd_hdr);
        packet.extract(hdr.my_custom_hdr);
        transition accept;
    }
}

control verifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control read_custom_header_at_index (in my_custom_hdr_t my_custom_hdr,
                                     in bit<8> index,
				     out bit<16> result,
                                     out bool index_in_range)
{
    // TODO: loop here
    action read_offset_0 () {
        result = my_custom_hdr.f0 ++ my_custom_hdr.f1;
    }

    table read_from_index {
        key = {
            index : exact;
        }
        actions = {
            // TODO: loop here
            read_offset_0;
            @defaultonly index_out_of_range;
        }
        const entries = {
            // TODO: loop here
            0 : read_offset_0();
        }
        const default_action = index_out_of_range;
    }

    apply {
        index_in_range = true;
        read_from_index.apply();
    }
}

control ingressImpl(inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t stdmeta)
{
    read_custom_header_at_index() read_inst1;
    read_custom_header_at_index() read_inst2;
    write_custom_header_at_index() write_inst1;
    bit<16> op1;
    bool op1_valid;
    bit<16> op2;
    bool op2_valid;
    bit<16> result;
    bool result_written;
    apply {
        // Read two 16-bit operands at indexes that appear in the
        // received packet, add them to get a result, and write the
        // 16-bit result into the header at an index that also appears
        // in the received packet.

        // Also do error checking to verify whether the index values
        // are in range or not.
        read_inst1.apply(hdr.my_custom_hdr, hdr.cmd_hdr.op1_index,
            op1, op1_valid);
        read_inst2.apply(hdr.my_custom_hdr, hdr.cmd_hdr.op2_index,
            op2, op2_valid);
        hdr.cmd_hdr.first_out_of_range_index = 0;
        if (!op1_valid) {
            hdr.cmd_hdr.first_out_of_range_index = 1;
        } else if (!op2_valid) {
            hdr.cmd_hdr.first_out_of_range_index = 2;
        } else {
            result = op1 + op2;
            write_inst1.apply(hdr.my_custom_hdr, hdr.cmd_hdr.result_index,
                result, result_written);
            if (!result_written) {
                hdr.cmd_hdr.first_out_of_range_index = 3;
            }
        }

        stdmeta.egress_spec = 1;
    }
}

control egressImpl(inout headers_t hdr,
                   inout metadata_t meta,
                   inout standard_metadata_t stdmeta)
{
    apply { }
}

control updateChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control deparserImpl(packet_out packet,
                     in headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cmd_hdr);
        packet.emit(hdr.my_custom_hdr);
    }
}

V1Switch(parserImpl(),
         verifyChecksum(),
         ingressImpl(),
         egressImpl(),
         updateChecksum(),
         deparserImpl()) main;
