// test/test_protocol_sequences.sv
`include "sequence/tcp_sequences.sv"

program test_protocol_sequences;

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
        $display("=== test_protocol_sequences ===");

        // ---- TCP Handshake ----
        begin
            tcp_handshake_seq hs = new();
            packet pkts[$];

            hs.src_ip   = 32'hC0A80001;
            hs.dst_ip   = 32'hC0A80002;
            hs.src_port = 16'd10000;
            hs.dst_port = 16'd443;
            hs.isn_client = 32'd100;
            hs.isn_server = 32'd200;
            hs.generate();
            hs.get_packets(pkts);

            check("hs: 3 packets", pkts.size() == 3);

            // SYN
            begin
                tcp_header tcp;
                $cast(tcp, pkts[0].get_layer(PROTO_TCP));
                check("hs: pkt[0] SYN flag", tcp.flags == 9'h002);
                check("hs: pkt[0] seq", tcp.seq_num == 32'd100);
                check("hs: pkt[0] src_port", tcp.src_port == 16'd10000);
                check("hs: pkt[0] dst_port", tcp.dst_port == 16'd443);
            end

            // SYN-ACK
            begin
                tcp_header tcp;
                $cast(tcp, pkts[1].get_layer(PROTO_TCP));
                check("hs: pkt[1] SYN+ACK flag", tcp.flags == 9'h012);
                check("hs: pkt[1] seq", tcp.seq_num == 32'd200);
                check("hs: pkt[1] ack", tcp.ack_num == 32'd101);
                // Reversed ports
                check("hs: pkt[1] src_port", tcp.src_port == 16'd443);
                check("hs: pkt[1] dst_port", tcp.dst_port == 16'd10000);
            end

            // ACK
            begin
                tcp_header tcp;
                $cast(tcp, pkts[2].get_layer(PROTO_TCP));
                check("hs: pkt[2] ACK flag", tcp.flags == 9'h010);
                check("hs: pkt[2] seq", tcp.seq_num == 32'd101);
                check("hs: pkt[2] ack", tcp.ack_num == 32'd201);
            end

            // Verify IP addresses
            begin
                ipv4_header ip0, ip1;
                $cast(ip0, pkts[0].get_layer(PROTO_IPV4));
                $cast(ip1, pkts[1].get_layer(PROTO_IPV4));
                check("hs: pkt[0] src_ip", ip0.src_addr == 32'hC0A80001);
                check("hs: pkt[1] src_ip reversed", ip1.src_addr == 32'hC0A80002);
            end
        end

        // ---- TCP Full Session ----
        begin
            tcp_full_session_seq sess = new();
            packet pkts[$];

            sess.src_ip          = 32'hAC100001;
            sess.dst_ip          = 32'hAC100002;
            sess.src_port        = 16'd55555;
            sess.dst_port        = 16'd80;
            sess.data_pkt_count  = 3;
            sess.data_pkt_length = 100;
            sess.generate();
            sess.get_packets(pkts);

            // 3 handshake + 3 data + 4 teardown = 10
            check("sess: 10 packets", pkts.size() == 10);

            // First 3: handshake
            begin
                tcp_header tcp;
                $cast(tcp, pkts[0].get_layer(PROTO_TCP));
                check("sess: pkt[0] SYN", tcp.flags == 9'h002);
            end
            begin
                tcp_header tcp;
                $cast(tcp, pkts[1].get_layer(PROTO_TCP));
                check("sess: pkt[1] SYN-ACK", tcp.flags == 9'h012);
            end
            begin
                tcp_header tcp;
                $cast(tcp, pkts[2].get_layer(PROTO_TCP));
                check("sess: pkt[2] ACK", tcp.flags == 9'h010);
            end

            // Data packets (3-5): PSH+ACK
            begin
                tcp_header tcp;
                $cast(tcp, pkts[3].get_layer(PROTO_TCP));
                check("sess: pkt[3] PSH+ACK", tcp.flags == 9'h018);
            end

            // Check data packet size
            check("sess: pkt[3] size", pkts[3].raw_data.size() == 100);

            // Last 4: teardown
            begin
                tcp_header tcp;
                $cast(tcp, pkts[6].get_layer(PROTO_TCP));
                check("sess: pkt[6] FIN+ACK", tcp.flags == 9'h011);
            end
            begin
                tcp_header tcp;
                $cast(tcp, pkts[9].get_layer(PROTO_TCP));
                check("sess: pkt[9] final ACK", tcp.flags == 9'h010);
            end
        end

        $display("=== Results: %0d passed, %0d failed ===", pass_count, fail_count);
        if (fail_count > 0) $fatal(1, "TESTS FAILED");
    end

endprogram
