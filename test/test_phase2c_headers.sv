// test/test_phase2c_headers.sv
`include "packet_defines.sv"
`include "packet_utils.sv"
`include "protocol_base.sv"
`include "l2/mpls_header.sv"
`include "l3/ipv6_ext_header.sv"

program test_phase2c_headers;

    int pass_count = 0;
    int fail_count = 0;

    task automatic check(string name, bit condition);
        if (condition) begin
            $display("[PASS] %s", name);
            pass_count++;
        end else begin
            $display("[FAIL] %s", name);
            fail_count++;
        end
    endtask

    initial begin
        $display("=== test_phase2c_headers ===");

        // ---- MPLS: basic construction ----
        begin
            mpls_header m = new();

            check("mpls_basic: proto_type",    m.proto_type == PROTO_MPLS);
            check("mpls_basic: header_length", m.get_header_length() == 4);
            check("mpls_basic: default s_bit", m.s_bit == 1'b1);
            check("mpls_basic: default ttl",   m.ttl == 8'd64);
        end

        // ---- MPLS: pack ----
        begin
            mpls_header m = new();
            byte unsigned packed[$];

            m.label = 20'd1000;
            m.tc    = 3'd5;
            m.s_bit = 1'b1;
            m.ttl   = 8'd128;
            m.pack_header(packed);
            check("mpls_pack: size", packed.size() == 4);
        end

        // ---- MPLS: unpack round-trip ----
        begin
            mpls_header m = new();
            byte unsigned packed[$];
            int offset;

            m.label = 20'd1000;
            m.tc    = 3'd5;
            m.s_bit = 1'b1;
            m.ttl   = 8'd128;
            m.pack_header(packed);

            begin
                mpls_header m2 = new();
                offset = 0;
                m2.unpack_header(packed, offset);
                check("mpls_unpack: label",  m2.label == 20'd1000);
                check("mpls_unpack: tc",     m2.tc    == 3'd5);
                check("mpls_unpack: s_bit",  m2.s_bit == 1'b1);
                check("mpls_unpack: ttl",    m2.ttl   == 8'd128);
                check("mpls_unpack: offset", offset   == 4);
            end
        end

        // ---- MPLS: clone+compare ----
        begin
            mpls_header m = new();
            m.label = 20'd1000;
            m.tc    = 3'd5;
            m.s_bit = 1'b1;
            m.ttl   = 8'd128;

            begin
                protocol_base m2 = m.clone();
                check("mpls_clone: compare", m.compare(m2));
            end
        end

        // ---- MPLS: calc_fields with next_proto=PROTO_MPLS -> s_bit==0 ----
        begin
            mpls_header m = new();
            byte unsigned empty[$];

            m.s_bit = 1'b1;
            m.calc_fields(empty, PROTO_MPLS);
            check("mpls_calc: s_bit=0 when next is MPLS", m.s_bit == 1'b0);
        end

        // ---- MPLS: calc_fields with next_proto=PROTO_IPV4 -> s_bit==1 ----
        begin
            mpls_header m = new();
            byte unsigned empty[$];

            m.s_bit = 1'b0;
            m.calc_fields(empty, PROTO_IPV4);
            check("mpls_calc: s_bit=1 when next is IPV4", m.s_bit == 1'b1);
        end

        // ---- MPLS: static create ----
        begin
            mpls_header m = mpls_header::create(20'd500, 8'd32);
            check("mpls_create: label", m.label == 20'd500);
            check("mpls_create: ttl",   m.ttl   == 8'd32);
        end

        // ---- ipv6_hbh_header: basic construction ----
        begin
            ipv6_hbh_header h = new();

            check("hbh_basic: proto_type",     h.proto_type == PROTO_IPV6_HBH);
            check("hbh_basic: header_length",  h.get_header_length() == 8);
            check("hbh_basic: default nh",     h.next_header == 8'd59);
            check("hbh_basic: default ext_len",h.hdr_ext_len == 8'd0);
        end

        // ---- ipv6_hbh_header: pack ----
        begin
            ipv6_hbh_header h = new();
            byte unsigned packed[$];

            h.pack_header(packed);
            check("hbh_pack: size", packed.size() == 8);
        end

        // ---- ipv6_hbh_header: unpack round-trip ----
        begin
            ipv6_hbh_header h = new();
            byte unsigned packed[$];
            int offset;

            h.next_header = 8'd6; // TCP
            h.hdr_ext_len = 8'd0;
            h.pack_header(packed);

            begin
                ipv6_hbh_header h2 = new();
                offset = 0;
                h2.unpack_header(packed, offset);
                check("hbh_unpack: next_header", h2.next_header == 8'd6);
                check("hbh_unpack: hdr_ext_len", h2.hdr_ext_len == 8'd0);
                check("hbh_unpack: offset",      offset == 8);
            end
        end

        // ---- ipv6_hbh_header: calc_fields sets next_header ----
        begin
            ipv6_hbh_header h = new();
            byte unsigned empty[$];

            h.calc_fields(empty, PROTO_TCP);
            check("hbh_calc: next_header TCP",    h.next_header == 8'd6);
            h.calc_fields(empty, PROTO_UDP);
            check("hbh_calc: next_header UDP",    h.next_header == 8'd17);
            h.calc_fields(empty, PROTO_ICMPV6);
            check("hbh_calc: next_header ICMPv6", h.next_header == 8'd58);
        end

        // ---- ipv6_routing_header: basic construction ----
        begin
            ipv6_routing_header h = new();

            check("routing_basic: proto_type",     h.proto_type == PROTO_IPV6_ROUTING);
            check("routing_basic: header_length",  h.get_header_length() == 8);
            check("routing_basic: routing_type",   h.routing_type == 8'd0);
            check("routing_basic: segments_left",  h.segments_left == 8'd0);
        end

        // ---- ipv6_routing_header: pack/unpack round-trip ----
        begin
            ipv6_routing_header h = new();
            byte unsigned packed[$];
            int offset;

            h.next_header   = 8'd6;
            h.hdr_ext_len   = 8'd0;
            h.routing_type  = 8'd2;
            h.segments_left = 8'd3;
            h.pack_header(packed);
            check("routing_pack: size", packed.size() == 8);

            begin
                ipv6_routing_header h2 = new();
                offset = 0;
                h2.unpack_header(packed, offset);
                check("routing_unpack: next_header",   h2.next_header   == 8'd6);
                check("routing_unpack: routing_type",  h2.routing_type  == 8'd2);
                check("routing_unpack: segments_left", h2.segments_left == 8'd3);
                check("routing_unpack: offset",        offset == 8);
            end
        end

        // ---- ipv6_routing_header: calc_fields ----
        begin
            ipv6_routing_header h = new();
            byte unsigned empty[$];

            h.calc_fields(empty, PROTO_UDP);
            check("routing_calc: next_header UDP", h.next_header == 8'd17);
        end

        // ---- ipv6_fragment_header: basic construction ----
        begin
            ipv6_fragment_header h = new();

            check("fragment_basic: proto_type",    h.proto_type == PROTO_IPV6_FRAGMENT);
            check("fragment_basic: header_length", h.get_header_length() == 8);
            check("fragment_basic: default nh",    h.next_header == 8'd59);
        end

        // ---- ipv6_fragment_header: pack/unpack round-trip with fields ----
        begin
            ipv6_fragment_header h = new();
            byte unsigned packed[$];
            int offset;

            h.next_header     = 8'd6;
            h.fragment_offset = 13'd100;
            h.m_flag          = 1'b1;
            h.identification  = 32'h12345678;
            h.pack_header(packed);
            check("fragment_pack: size", packed.size() == 8);

            begin
                ipv6_fragment_header h2 = new();
                offset = 0;
                h2.unpack_header(packed, offset);
                check("fragment_unpack: next_header",     h2.next_header     == 8'd6);
                check("fragment_unpack: fragment_offset", h2.fragment_offset == 13'd100);
                check("fragment_unpack: m_flag",          h2.m_flag          == 1'b1);
                check("fragment_unpack: identification",  h2.identification  == 32'h12345678);
                check("fragment_unpack: offset",          offset == 8);
            end
        end

        // ---- ipv6_fragment_header: calc_fields ----
        begin
            ipv6_fragment_header h = new();
            byte unsigned empty[$];

            h.calc_fields(empty, PROTO_TCP);
            check("fragment_calc: next_header TCP", h.next_header == 8'd6);
        end

        // ---- ipv6_dest_header: basic construction ----
        begin
            ipv6_dest_header h = new();

            check("dest_basic: proto_type",    h.proto_type == PROTO_IPV6_DEST);
            check("dest_basic: header_length", h.get_header_length() == 8);
            check("dest_basic: default nh",    h.next_header == 8'd59);
        end

        // ---- ipv6_dest_header: pack/unpack round-trip ----
        begin
            ipv6_dest_header h = new();
            byte unsigned packed[$];
            int offset;

            h.next_header = 8'd17; // UDP
            h.hdr_ext_len = 8'd0;
            h.pack_header(packed);
            check("dest_pack: size", packed.size() == 8);

            begin
                ipv6_dest_header h2 = new();
                offset = 0;
                h2.unpack_header(packed, offset);
                check("dest_unpack: next_header", h2.next_header == 8'd17);
                check("dest_unpack: hdr_ext_len", h2.hdr_ext_len == 8'd0);
                check("dest_unpack: offset",      offset == 8);
            end
        end

        // ---- ipv6_dest_header: calc_fields ----
        begin
            ipv6_dest_header h = new();
            byte unsigned empty[$];

            h.calc_fields(empty, PROTO_ICMPV6);
            check("dest_calc: next_header ICMPv6", h.next_header == 8'd58);
        end

        // ---- ipv6_hbh_header: clone+compare ----
        begin
            ipv6_hbh_header h = new();
            h.next_header = 8'd6;

            begin
                protocol_base h2 = h.clone();
                check("hbh_clone: compare", h.compare(h2));
            end
        end

        // ---- ipv6_routing_header: clone+compare ----
        begin
            ipv6_routing_header h = new();
            h.next_header   = 8'd17;
            h.routing_type  = 8'd2;
            h.segments_left = 8'd1;

            begin
                protocol_base h2 = h.clone();
                check("routing_clone: compare", h.compare(h2));
            end
        end

        // ---- ipv6_fragment_header: clone+compare ----
        begin
            ipv6_fragment_header h = new();
            h.fragment_offset = 13'd50;
            h.m_flag          = 1'b1;
            h.identification  = 32'hDEADBEEF;

            begin
                protocol_base h2 = h.clone();
                check("fragment_clone: compare", h.compare(h2));
            end
        end

        // ---- ipv6_dest_header: clone+compare ----
        begin
            ipv6_dest_header h = new();
            h.next_header = 8'd58;

            begin
                protocol_base h2 = h.clone();
                check("dest_clone: compare", h.compare(h2));
            end
        end

        $display("=== Results: %0d passed, %0d failed ===", pass_count, fail_count);
        if (fail_count > 0) $fatal(1, "TESTS FAILED");
    end

endprogram
