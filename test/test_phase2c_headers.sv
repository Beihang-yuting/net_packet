// test/test_phase2c_headers.sv
`include "packet_defines.sv"
`include "packet_utils.sv"
`include "protocol_base.sv"
`include "l2/mpls_header.sv"

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

        $display("=== Results: %0d passed, %0d failed ===", pass_count, fail_count);
        if (fail_count > 0) $fatal(1, "TESTS FAILED");
    end

endprogram
