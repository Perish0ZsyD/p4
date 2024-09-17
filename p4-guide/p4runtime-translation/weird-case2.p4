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

@p4runtime_translation("com.fingerhutpress/andysp4arch/v1/EthernetAddr_t", 32)
type bit<48>         EthernetAddr_t;

@p4runtime_translation("com.fingerhutpress/andysp4arch/v1/IPv4Addr_t", 32)
type bit<32>         IPv4Addr_t;

@p4runtime_translation("com.fingerhutpress/andysp4arch/v1/CustomAddr_t", 32)
type bit<32>         CustomAddr_t;

header ethernet_t {
    EthernetAddr_t  dstAddr;
    EthernetAddr_t  srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    IPv4Addr_t srcAddr;
    IPv4Addr_t dstAddr;
}

header andycustom_t {
    // No one is proposing this as any kind of standard.  I just made
    // this up.  What else is P4 for?  :-)
    bit<2>       version;
    bit<6>       dscp;
    bit<16>      totalLen;
    bit<8>       ttl;

    bit<8>       protocol;
    bit<8>       l4Offset;
    bit<8>       flags;
    bit<8>       rsvd;

    CustomAddr_t srcAddr;
    CustomAddr_t dstAddr;
}

struct headers_t {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    andycustom_t  andycustom;
}

struct metadata_t {
}

parser parserImpl(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t stdmeta)
{
    const bit<16> ETHERTYPE_IPV4       = 16w0x0800;
    const bit<16> ETHERTYPE_ANDYCUSTOM = 16w0xd00d;

    const bit<8>  IP_PROTOCOLS_IPV4    = 4;

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ANDYCUSTOM: parse_andycustom;
            default: accept;
        }
    }
    state parse_andycustom {
        packet.extract(hdr.andycustom);
        transition select(hdr.andycustom.protocol) {
            IP_PROTOCOLS_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control verifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control ingressImpl(inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t stdmeta)
{
    action my_drop() {
        mark_to_drop(stdmeta);
    }
    action set_output(bit<9> output_port) {
        stdmeta.egress_spec = output_port;
    }
    table t1 {
        key = {
            // This is legal P4_16 as of spec v1.2.0, and has type
            // bit<32>
            (bit<32>) hdr.andycustom.srcAddr + (bit<32>) hdr.ipv4.srcAddr: exact @name("myaddress");
        }
        actions = {
            set_output;
            my_drop;
            NoAction;
        }
        const default_action = NoAction;
    }
    apply {
        if (hdr.ethernet.isValid() && hdr.andycustom.isValid() && hdr.ipv4.isValid()) {
            t1.apply();
        }
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
    }
}

V1Switch(parserImpl(),
         verifyChecksum(),
         ingressImpl(),
         egressImpl(),
         updateChecksum(),
         deparserImpl()) main;
