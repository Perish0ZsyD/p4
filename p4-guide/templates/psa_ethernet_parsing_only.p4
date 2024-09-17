/*
Copyright 2019 Cisco Systems, Inc.

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
#include <psa.p4>

#include <stdheaders.p4>

struct headers_t {
    ethernet_h       ethernet;
}

struct empty_metadata_t {
}

struct metadata_t {
/*
    bit<4>  a;
    bit<4>  b;
*/
}

parser ingressParserImpl(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t umd,
    in psa_ingress_parser_input_metadata_t istd,
    in empty_metadata_t resubmit_meta,
    in empty_metadata_t recirculate_meta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control ingressImpl(
    inout headers_t hdr,
    inout metadata_t umd,
    in    psa_ingress_input_metadata_t  istd,
    inout psa_ingress_output_metadata_t ostd)
{
/*
    action foo() {
        umd.b = umd.b + 5;
    }
    table guh {
        key = {
            hdr.ethernet.src_addr : exact;
        }
        actions = {
            foo;
            ingress_drop(ostd);
            NoAction;
        }
        const default_action = ingress_drop(ostd);
    }
*/
    apply {
/*
        guh.apply();
*/
    }
}

parser egressParserImpl(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t umd,
    in psa_egress_parser_input_metadata_t istd,
    in empty_metadata_t normal_meta,
    in empty_metadata_t clone_i2e_meta,
    in empty_metadata_t clone_e2e_meta)
{
    state start {
        transition accept;
    }
}

control egressImpl(
    inout headers_t hdr,
    inout metadata_t umd,
    in    psa_egress_input_metadata_t  istd,
    inout psa_egress_output_metadata_t ostd)
{
    apply { }
}

control CommonDeparserImpl(
    packet_out pkt,
    inout headers_t hdr)
{
    apply {
        pkt.emit(hdr.ethernet);
    }
}

control ingressDeparserImpl(
    packet_out pkt,
    out empty_metadata_t clone_i2e_meta,
    out empty_metadata_t resubmit_meta,
    out empty_metadata_t normal_meta,
    inout headers_t hdr,
    in metadata_t umd,
    in psa_ingress_output_metadata_t istd)
{
    CommonDeparserImpl() cp;
    apply {
        cp.apply(pkt, hdr);
    }
}

control egressDeparserImpl(
    packet_out pkt,
    out empty_metadata_t clone_e2e_meta,
    out empty_metadata_t recirculate_meta,
    inout headers_t hdr,
    in metadata_t umd,
    in psa_egress_output_metadata_t istd,
    in psa_egress_deparser_input_metadata_t edstd)
{
    CommonDeparserImpl() cp;
    apply {
        cp.apply(pkt, hdr);
    }
}

IngressPipeline(
    ingressParserImpl(),
    ingressImpl(),
    ingressDeparserImpl()) ip;

EgressPipeline(
    egressParserImpl(),
    egressImpl(),
    egressDeparserImpl()) ep;

PSA_Switch(
    ip,
    PacketReplicationEngine(),
    ep,
    BufferingQueueingEngine()) main;
