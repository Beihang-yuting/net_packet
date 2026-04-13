// test/test_tunnel_headers.sv
`include "packet_defines.sv"
`include "packet_utils.sv"
`include "protocol_base.sv"
`include "tunnel/vxlan_header.sv"
`include "tunnel/gre_header.sv"
`include "tunnel/geneve_header.sv"
`include "tunnel/erspan_header.sv"

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

        // ---- GRE ----
        begin
            gre_header gre = new();

            // 1. proto_type
            check("gre: proto_type", gre.proto_type == PROTO_GRE);

            // 2. basic header_length (no optional fields)
            check("gre: header_length basic", gre.get_header_length() == 4);

            // 3. default protocol_type == ETHERTYPE_IPV4
            check("gre: default protocol_type", gre.protocol_type == ETHERTYPE_IPV4);

            // 4. Basic GRE pack (size==4) + unpack
            begin
                byte unsigned packed[$];
                gre.pack_header(packed);
                check("gre: basic pack size", packed.size() == 4);
                begin
                    gre_header gre2 = new();
                    int offset = 0;
                    gre2.unpack_header(packed, offset);
                    check("gre: basic unpack protocol_type", gre2.protocol_type == ETHERTYPE_IPV4);
                    check("gre: basic unpack offset", offset == 4);
                    check("gre: basic unpack flags==0", (gre2.c_flag == 0) && (gre2.k_flag == 0) && (gre2.s_flag == 0));
                end
            end

            // 5. GRE with key
            begin
                gre_header gre_k = new();
                byte unsigned packed[$];
                int offset;
                gre_k.k_flag = 1'b1;
                gre_k.key    = 32'hAABBCCDD;
                check("gre: k_flag header_length", gre_k.get_header_length() == 8);
                gre_k.pack_header(packed);
                check("gre: k_flag pack size", packed.size() == 8);
                begin
                    gre_header gre_k2 = new();
                    offset = 0;
                    gre_k2.unpack_header(packed, offset);
                    check("gre: k_flag unpack k_flag", gre_k2.k_flag == 1'b1);
                    check("gre: k_flag unpack key", gre_k2.key == 32'hAABBCCDD);
                    check("gre: k_flag unpack offset", offset == 8);
                end
            end

            // 6. GRE with all options (c_flag, k_flag, s_flag)
            begin
                gre_header gre_all = new();
                byte unsigned packed[$];
                int offset;
                gre_all.c_flag          = 1'b1;
                gre_all.k_flag          = 1'b1;
                gre_all.s_flag          = 1'b1;
                gre_all.key             = 32'h12345678;
                gre_all.sequence_number = 32'd1;
                check("gre: all opts header_length", gre_all.get_header_length() == 16);
                gre_all.pack_header(packed);
                check("gre: all opts pack size", packed.size() == 16);
                begin
                    gre_header gre_all2 = new();
                    offset = 0;
                    gre_all2.unpack_header(packed, offset);
                    check("gre: all opts unpack c_flag", gre_all2.c_flag == 1'b1);
                    check("gre: all opts unpack k_flag", gre_all2.k_flag == 1'b1);
                    check("gre: all opts unpack s_flag", gre_all2.s_flag == 1'b1);
                    check("gre: all opts unpack key", gre_all2.key == 32'h12345678);
                    check("gre: all opts unpack seq", gre_all2.sequence_number == 32'd1);
                    check("gre: all opts unpack offset", offset == 16);
                end
            end

            // 7. Clone + compare with all options
            begin
                gre_header gre_c = new();
                protocol_base gre_clone;
                gre_c.c_flag          = 1'b1;
                gre_c.k_flag          = 1'b1;
                gre_c.s_flag          = 1'b1;
                gre_c.key             = 32'hDEADBEEF;
                gre_c.sequence_number = 32'd42;
                gre_clone = gre_c.clone();
                check("gre: clone compare", gre_c.compare(gre_clone));
                begin
                    gre_header gre_diff = new();
                    gre_diff.k_flag = 1'b1;
                    gre_diff.key    = 32'hCAFEBABE;
                    check("gre: compare different key", !gre_c.compare(gre_diff));
                end
            end

            // 8. calc_fields protocol_type mapping
            begin
                gre_header gre_cf = new();
                gre_cf.auto_calc = 1;
                gre_cf.calc_fields('{}, PROTO_IPV6);
                check("gre: calc_fields IPv6", gre_cf.protocol_type == ETHERTYPE_IPV6);
                gre_cf.calc_fields('{}, PROTO_ETHERNET);
                check("gre: calc_fields Ethernet", gre_cf.protocol_type == 16'h6558);
                gre_cf.calc_fields('{}, PROTO_ERSPAN_II);
                check("gre: calc_fields ERSPAN_II", gre_cf.protocol_type == 16'h88BE);
            end
        end

        // ---- Geneve ----
        begin
            geneve_header gn = new();

            // 1. proto_type
            check("geneve: proto_type", gn.proto_type == PROTO_GENEVE);

            // 2. Basic defaults: header_length==8, vni==100, protocol_type==0x6558
            check("geneve: header_length basic",      gn.get_header_length() == 8);
            check("geneve: default vni",              gn.vni == 24'd100);
            check("geneve: default protocol_type",    gn.protocol_type == 16'h6558);

            // 3. Pack without options (vni=0xABCDEF), size==8
            begin
                geneve_header gn_p = new();
                byte unsigned packed[$];
                gn_p.vni = 24'hABCDEF;
                gn_p.pack_header(packed);
                check("geneve: pack no-opt size",  packed.size() == 8);
                check("geneve: pack vni[0]",       packed[4] == 8'hAB);
                check("geneve: pack vni[1]",       packed[5] == 8'hCD);
                check("geneve: pack vni[2]",       packed[6] == 8'hEF);
            end

            // 4. Unpack: vni, protocol_type, offset==8
            begin
                geneve_header gn_u = new();
                byte unsigned packed[$];
                int offset;
                gn_u.vni = 24'hABCDEF;
                gn_u.pack_header(packed);
                begin
                    geneve_header gn_u2 = new();
                    offset = 0;
                    gn_u2.unpack_header(packed, offset);
                    check("geneve: unpack vni",           gn_u2.vni == 24'hABCDEF);
                    check("geneve: unpack protocol_type", gn_u2.protocol_type == 16'h6558);
                    check("geneve: unpack offset",        offset == 8);
                end
            end

            // 5. With options (4 bytes): header_length==12, pack size==12,
            //    unpack opt_len==1, options.size()==4, options[0]==0x01, offset==12
            begin
                geneve_header gn_o = new();
                byte unsigned packed[$];
                int offset;
                gn_o.options    = new[4];
                gn_o.options[0] = 8'h01;
                gn_o.options[1] = 8'h02;
                gn_o.options[2] = 8'h03;
                gn_o.options[3] = 8'h04;
                gn_o.opt_len    = 6'h1;
                check("geneve: with options header_length", gn_o.get_header_length() == 12);
                gn_o.pack_header(packed);
                check("geneve: with options pack size", packed.size() == 12);
                begin
                    geneve_header gn_o2 = new();
                    offset = 0;
                    gn_o2.unpack_header(packed, offset);
                    check("geneve: with options unpack opt_len",      gn_o2.opt_len == 6'h1);
                    check("geneve: with options unpack options.size", gn_o2.options.size() == 4);
                    check("geneve: with options unpack options[0]",   gn_o2.options[0] == 8'h01);
                    check("geneve: with options unpack offset",       offset == 12);
                end
            end

            // 6. Clone + compare
            begin
                geneve_header gn_c = new();
                protocol_base gn_clone;
                gn_c.vni = 24'd999;
                gn_clone = gn_c.clone();
                check("geneve: clone compare", gn_c.compare(gn_clone));
                begin
                    geneve_header gn_diff = new();
                    gn_diff.vni = 24'd1;
                    check("geneve: compare different vni", !gn_c.compare(gn_diff));
                end
            end

            // 7. calc_fields: PROTO_ETHERNET -> 0x6558
            begin
                geneve_header gn_cf = new();
                gn_cf.auto_calc = 1;
                gn_cf.protocol_type = 16'h0000;
                gn_cf.calc_fields('{}, PROTO_ETHERNET);
                check("geneve: calc_fields PROTO_ETHERNET", gn_cf.protocol_type == 16'h6558);
                gn_cf.calc_fields('{}, PROTO_IPV4);
                check("geneve: calc_fields PROTO_IPV4", gn_cf.protocol_type == ETHERTYPE_IPV4);
                gn_cf.calc_fields('{}, PROTO_IPV6);
                check("geneve: calc_fields PROTO_IPV6", gn_cf.protocol_type == ETHERTYPE_IPV6);
            end
        end

        // ---- ERSPAN Type II ----
        begin
            erspan_ii_header e2 = new();

            // proto_type, header_length, default version
            check("erspan_ii: proto_type",     e2.proto_type == PROTO_ERSPAN_II);
            check("erspan_ii: header_length",  e2.get_header_length() == 8);
            check("erspan_ii: default version", e2.version == 4'd1);

            // Set fields, pack, verify size
            begin
                erspan_ii_header e2p = erspan_ii_header::create(10'd100, 12'd200);
                byte unsigned packed[$];
                e2p.index = 20'h12345;
                e2p.pack_header(packed);
                check("erspan_ii: pack size", packed.size() == 8);

                // Unpack round-trip
                begin
                    erspan_ii_header e2u = new();
                    int offset = 0;
                    e2u.unpack_header(packed, offset);
                    check("erspan_ii: unpack version",    e2u.version == 4'd1);
                    check("erspan_ii: unpack session_id", e2u.session_id == 10'd100);
                    check("erspan_ii: unpack vlan",       e2u.vlan == 12'd200);
                    check("erspan_ii: unpack index",      e2u.index == 20'h12345);
                    check("erspan_ii: unpack offset",     offset == 8);
                end

                // Clone + compare
                begin
                    protocol_base e2c = e2p.clone();
                    check("erspan_ii: clone compare", e2p.compare(e2c));
                end
            end
        end

        // ---- ERSPAN Type III ----
        begin
            erspan_iii_header e3 = new();

            // proto_type, header_length, default version
            check("erspan_iii: proto_type",      e3.proto_type == PROTO_ERSPAN_III);
            check("erspan_iii: header_length",   e3.get_header_length() == 12);
            check("erspan_iii: default version", e3.version == 4'd2);

            // Set fields, pack, verify size
            begin
                erspan_iii_header e3p = erspan_iii_header::create(10'd50);
                byte unsigned packed[$];
                e3p.vlan      = 12'd300;
                e3p.timestamp = 32'hDEADBEEF;
                e3p.hw_id     = 6'd10;
                e3p.direction = 1'b1;
                e3p.pack_header(packed);
                check("erspan_iii: pack size", packed.size() == 12);

                // Unpack round-trip
                begin
                    erspan_iii_header e3u = new();
                    int offset = 0;
                    e3u.unpack_header(packed, offset);
                    check("erspan_iii: unpack version",    e3u.version == 4'd2);
                    check("erspan_iii: unpack session_id", e3u.session_id == 10'd50);
                    check("erspan_iii: unpack vlan",       e3u.vlan == 12'd300);
                    check("erspan_iii: unpack timestamp",  e3u.timestamp == 32'hDEADBEEF);
                    check("erspan_iii: unpack hw_id",      e3u.hw_id == 6'd10);
                    check("erspan_iii: unpack direction",  e3u.direction == 1'b1);
                    check("erspan_iii: unpack offset",     offset == 12);
                end

                // Clone + compare
                begin
                    protocol_base e3c = e3p.clone();
                    check("erspan_iii: clone compare", e3p.compare(e3c));
                end
            end
        end

        $display("=== Results: %0d passed, %0d failed ===", pass_count, fail_count);
        if (fail_count > 0) $fatal(1, "TESTS FAILED");
    end

endprogram
