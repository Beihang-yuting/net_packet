// test/test_tunnel_headers.sv
`include "packet_defines.sv"
`include "packet_utils.sv"
`include "protocol_base.sv"
`include "tunnel/vxlan_header.sv"

program test_tunnel_headers;

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
        $display("=== test_tunnel_headers ===");

        // ---- VXLAN ----
        begin
            vxlan_header vx = new();
            byte unsigned packed[$];
            int offset;

            // proto_type and header_length
            check("vxlan: proto_type",     vx.proto_type == PROTO_VXLAN);
            check("vxlan: header_length",  vx.get_header_length() == 8);

            // default field values
            check("vxlan: default flags",     vx.flags == 8'h08);
            check("vxlan: default reserved1", vx.reserved1 == 24'h0);
            check("vxlan: default vni",       vx.vni == 24'd100);
            check("vxlan: default reserved2", vx.reserved2 == 8'h0);

            // pack
            vx.pack_header(packed);
            check("vxlan: pack size",       packed.size() == 8);
            check("vxlan: pack flags",      packed[0] == 8'h08);
            check("vxlan: pack reserved1[0]", packed[1] == 8'h00);
            check("vxlan: pack reserved1[1]", packed[2] == 8'h00);
            check("vxlan: pack reserved1[2]", packed[3] == 8'h00);
            // vni=100 = 0x000064
            check("vxlan: pack vni[0]",     packed[4] == 8'h00);
            check("vxlan: pack vni[1]",     packed[5] == 8'h00);
            check("vxlan: pack vni[2]",     packed[6] == 8'h64);
            check("vxlan: pack reserved2",  packed[7] == 8'h00);

            // unpack round-trip
            begin
                vxlan_header vx2 = new();
                offset = 0;
                vx2.unpack_header(packed, offset);
                check("vxlan: unpack flags",     vx2.flags == 8'h08);
                check("vxlan: unpack reserved1", vx2.reserved1 == 24'h0);
                check("vxlan: unpack vni",       vx2.vni == 24'd100);
                check("vxlan: unpack reserved2", vx2.reserved2 == 8'h0);
                check("vxlan: unpack offset",    offset == 8);
            end

            // clone and compare
            begin
                protocol_base vx3 = vx.clone();
                check("vxlan: clone compare",    vx.compare(vx3));

                // modify vni and verify compare fails
                begin
                    vxlan_header vx4 = new();
                    vx4.vni = 24'd999;
                    check("vxlan: compare different vni", !vx.compare(vx4));
                end
            end

            // static create with custom vni
            begin
                vxlan_header vx5 = vxlan_header::create(24'd200);
                check("vxlan: create vni",   vx5.vni == 24'd200);
                check("vxlan: create flags", vx5.flags == 8'h08);
            end

            // static create default
            begin
                vxlan_header vx6 = vxlan_header::create();
                check("vxlan: create default vni", vx6.vni == 24'd100);
            end

            // calc_fields sets flags when auto_calc=1
            begin
                vxlan_header vx7 = new();
                vx7.flags = 8'h00;
                vx7.auto_calc = 1;
                vx7.calc_fields('{}, PROTO_ETHERNET);
                check("vxlan: calc_fields sets flags", vx7.flags == 8'h08);
            end

            // calc_fields does nothing when auto_calc=0
            begin
                vxlan_header vx8 = new();
                vx8.flags = 8'h00;
                vx8.auto_calc = 0;
                vx8.calc_fields('{}, PROTO_ETHERNET);
                check("vxlan: auto_calc=0 preserves flags", vx8.flags == 8'h00);
            end

            // pack with non-default vni
            begin
                vxlan_header vx9 = vxlan_header::create(24'hABCDEF);
                byte unsigned p2[$];
                vx9.pack_header(p2);
                check("vxlan: pack custom vni[0]", p2[4] == 8'hAB);
                check("vxlan: pack custom vni[1]", p2[5] == 8'hCD);
                check("vxlan: pack custom vni[2]", p2[6] == 8'hEF);
            end
        end

        $display("=== Results: %0d passed, %0d failed ===", pass_count, fail_count);
        if (fail_count > 0) $fatal(1, "TESTS FAILED");
    end

endprogram
