// test/test_protocol_headers.sv
`include "packet_defines.sv"
`include "packet_utils.sv"
`include "protocol_base.sv"
`include "l2/eth_header.sv"
`include "l2/vlan_header.sv"
`include "l3/ipv4_header.sv"
`include "l3/ipv6_header.sv"
`include "l3/arp_header.sv"
`include "l4/tcp_header.sv"
`include "l4/udp_header.sv"
`include "l4/icmp_header.sv"
`include "l4/icmpv6_header.sv"

program test_protocol_headers;

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
        $display("=== test_protocol_headers ===");

        // ---- Ethernet ----
        begin
            eth_header eth = new();
            byte unsigned packed[$];
            byte unsigned raw[$];
            int offset;

            check("eth: proto_type", eth.proto_type == PROTO_ETHERNET);
            check("eth: header_length", eth.get_header_length() == 14);

            eth.dst_mac = 48'h001122334455;
            eth.src_mac = 48'h665544332211;
            eth.ethertype = ETHERTYPE_IPV4;
            eth.calc_fields('{}, PROTO_IPV4);
            eth.pack_header(packed);

            check("eth: pack size", packed.size() == 14);
            check("eth: pack dst_mac[0]", packed[0] == 8'h00);
            check("eth: pack dst_mac[5]", packed[5] == 8'h55);
            check("eth: pack src_mac[0]", packed[6] == 8'h66);
            check("eth: pack ethertype", {packed[12], packed[13]} == 16'h0800);

            begin
                eth_header eth2 = new();
                offset = 0;
                eth2.unpack_header(packed, offset);
                check("eth: unpack dst_mac", eth2.dst_mac == 48'h001122334455);
                check("eth: unpack src_mac", eth2.src_mac == 48'h665544332211);
                check("eth: unpack ethertype", eth2.ethertype == ETHERTYPE_IPV4);
                check("eth: unpack offset", offset == 14);
            end

            begin
                protocol_base eth3 = eth.clone();
                check("eth: clone compare", eth.compare(eth3));
            end

            eth.auto_calc = 1;
            eth.calc_fields('{}, PROTO_IPV6);
            check("eth: calc_fields ethertype IPv6", eth.ethertype == ETHERTYPE_IPV6);

            eth.calc_fields('{}, PROTO_ARP);
            check("eth: calc_fields ethertype ARP", eth.ethertype == ETHERTYPE_ARP);

            eth.auto_calc = 0;
            eth.ethertype = 16'hDEAD;
            eth.calc_fields('{}, PROTO_IPV4);
            check("eth: auto_calc=0 preserves ethertype", eth.ethertype == 16'hDEAD);
        end

        $display("=== Results: %0d passed, %0d failed ===", pass_count, fail_count);
        if (fail_count > 0) $fatal(1, "TESTS FAILED");
    end
endprogram
