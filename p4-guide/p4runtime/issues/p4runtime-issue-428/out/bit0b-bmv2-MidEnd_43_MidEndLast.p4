#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> eth_type;
}

header H {
    bit<0> b0a;
    bit<8> b8;
    bit<0> b0b;
    int<8> i8;
}

struct Meta {
}

struct Headers {
    ethernet_t eth_hdr;
    H          h;
}

parser p(packet_in pkt, out Headers hdr, inout Meta m, inout standard_metadata_t sm) {
    state start {
        pkt.extract<ethernet_t>(hdr.eth_hdr);
        pkt.extract<H>(hdr.h);
        transition accept;
    }
}

control vrfy(inout Headers h, inout Meta m) {
    apply {
    }
}

control update(inout Headers h, inout Meta m) {
    apply {
    }
}

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    @noWarn("unused") @name(".NoAction") action NoAction_1() {
    }
    @name("ingress.a1") action a1(@name("x") bit<0> x, @name("y") bit<48> y) {
        h.eth_hdr.dst_addr = y;
    }
    @name("ingress.match_on_bit0_test") table match_on_bit0_test_0 {
        key = {
            h.eth_hdr.dst_addr: exact @name("h.eth_hdr.dst_addr");
            h.h.b8            : exact @name("h.h.b8");
            h.h.b0b           : exact @name("h.h.b0b");
        }
        actions = {
            a1();
            @defaultonly NoAction_1();
        }
        size = 16;
        default_action = NoAction_1();
    }
    @hidden action bit0bbmv2l60() {
        h.h.setValid();
        h.h.b0a = 0;
        h.h.b8 = 8w0;
        h.h.b0b = 0;
        h.h.i8 = 8s0;
        h.h.b8 = 8w0;
    }
    @hidden action bit0bbmv2l71() {
        h.h.b0a = 0;
        h.h.b0b = 0;
        h.h.i8 = 8s0;
    }
    @hidden table tbl_bit0bbmv2l60 {
        actions = {
            bit0bbmv2l60();
        }
        const default_action = bit0bbmv2l60();
    }
    @hidden table tbl_bit0bbmv2l71 {
        actions = {
            bit0bbmv2l71();
        }
        const default_action = bit0bbmv2l71();
    }
    apply {
        tbl_bit0bbmv2l60.apply();
        if (h.eth_hdr.isValid()) {
            match_on_bit0_test_0.apply();
        }
        tbl_bit0bbmv2l71.apply();
    }
}

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    apply {
    }
}

control deparser(packet_out b, in Headers h) {
    apply {
        b.emit<ethernet_t>(h.eth_hdr);
        b.emit<H>(h.h);
    }
}

V1Switch<Headers, Meta>(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
