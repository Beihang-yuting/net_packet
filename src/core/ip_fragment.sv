// src/core/ip_fragment.sv
`ifndef IP_FRAGMENT_SV
`define IP_FRAGMENT_SV

`include "core/packet.sv"

class ip_fragment;

    // Fragment a packet into multiple fragments based on MTU
    // MTU is the maximum size of the IP payload (not including L2 header)
    // Returns fragments in order
    static function void fragment(packet pkt, int unsigned mtu, ref packet fragments[$]);
        ipv4_header orig_ip;
        int ip_hdr_len;
        int ip_layer_idx;
        byte unsigned orig_payload[$];
        int payload_len;
        int max_frag_payload;
        int offset;
        int frag_id;

        fragments.delete();

        // Find IPv4 layer
        ip_layer_idx = -1;
        foreach (pkt.layer_stack[i]) begin
            if (pkt.layer_stack[i].proto_type == PROTO_IPV4) begin
                ip_layer_idx = i;
                break;
            end
        end

        if (ip_layer_idx < 0) begin
            $warning("ip_fragment::fragment: no IPv4 layer found");
            fragments.push_back(pkt);
            return;
        end

        if (!$cast(orig_ip, pkt.layer_stack[ip_layer_idx])) begin
            fragments.push_back(pkt);
            return;
        end

        ip_hdr_len = orig_ip.get_header_length();

        // Ensure packet is packed
        if (pkt.raw_data.size() == 0) pkt.do_pack();

        // Extract the IP payload (everything after the IP header, from the raw data)
        // Calculate where IP payload starts
        begin
            int ip_payload_start = 0;
            for (int i = 0; i <= ip_layer_idx; i++)
                ip_payload_start += pkt.layer_stack[i].get_header_length();

            payload_len = pkt.raw_data.size() - ip_payload_start;
            orig_payload.delete();
            for (int i = ip_payload_start; i < pkt.raw_data.size(); i++)
                orig_payload.push_back(pkt.raw_data[i]);
        end

        // Check if fragmentation is needed
        if (ip_hdr_len + payload_len <= mtu) begin
            fragments.push_back(pkt);
            return;
        end

        // max_frag_payload must be multiple of 8
        max_frag_payload = ((mtu - ip_hdr_len) / 8) * 8;
        if (max_frag_payload <= 0) begin
            $warning("ip_fragment::fragment: MTU too small for fragmentation");
            fragments.push_back(pkt);
            return;
        end

        frag_id = orig_ip.identification;
        offset = 0;

        while (offset < payload_len) begin
            packet frag = new();
            int this_frag_len;
            bit is_last;

            this_frag_len = payload_len - offset;
            if (this_frag_len > max_frag_payload)
                this_frag_len = max_frag_payload;
            is_last = (offset + this_frag_len >= payload_len);

            // Clone layers up to and including IP
            for (int i = 0; i <= ip_layer_idx; i++) begin
                frag.force_mode = 1;
                frag.add_layer(pkt.layer_stack[i].clone());
            end

            // Update IP header for this fragment
            begin
                ipv4_header frag_ip;
                $cast(frag_ip, frag.layer_stack[ip_layer_idx]);
                frag_ip.identification  = frag_id;
                frag_ip.fragment_offset = offset / 8;
                frag_ip.flags           = is_last ? 3'b000 : 3'b001;  // MF flag
                frag_ip.total_length    = ip_hdr_len + this_frag_len;
                frag_ip.auto_calc       = 0;  // Don't auto-calc, we set fields manually
            end

            // Pack: clone headers + fragment payload
            frag.raw_data.delete();
            foreach (frag.layer_stack[i])
                frag.layer_stack[i].pack_header(frag.raw_data);

            for (int i = offset; i < offset + this_frag_len; i++)
                frag.raw_data.push_back(orig_payload[i]);

            fragments.push_back(frag);
            offset += this_frag_len;
        end
    endfunction

    // Reassemble fragments into a single packet
    // Fragments must belong to the same flow (same identification, src, dst)
    // Fragments should be in order
    static function packet reassemble(packet fragments[$]);
        packet result;
        ipv4_header first_ip;
        int ip_layer_idx;
        byte unsigned full_payload[$];
        int total_payload_len;

        if (fragments.size() == 0) return null;
        if (fragments.size() == 1) return fragments[0];

        // Find IP layer in first fragment
        ip_layer_idx = -1;
        foreach (fragments[0].layer_stack[i]) begin
            if (fragments[0].layer_stack[i].proto_type == PROTO_IPV4) begin
                ip_layer_idx = i;
                break;
            end
        end

        if (ip_layer_idx < 0) begin
            $warning("ip_fragment::reassemble: no IPv4 layer found");
            return fragments[0];
        end

        // Collect payloads from all fragments in order
        full_payload.delete();
        foreach (fragments[j]) begin
            int ip_payload_start = 0;
            for (int i = 0; i <= ip_layer_idx; i++)
                ip_payload_start += fragments[j].layer_stack[i].get_header_length();

            // Extract payload from raw_data
            if (fragments[j].raw_data.size() == 0) fragments[j].do_pack();
            for (int i = ip_payload_start; i < fragments[j].raw_data.size(); i++)
                full_payload.push_back(fragments[j].raw_data[i]);
        end

        // Build result: clone first fragment's layers up to IP, then append full payload
        result = new();
        result.force_mode = 1;
        for (int i = 0; i <= ip_layer_idx; i++)
            result.add_layer(fragments[0].layer_stack[i].clone());

        // Fix IP header
        begin
            $cast(first_ip, result.layer_stack[ip_layer_idx]);
            first_ip.flags           = 3'b000;  // No MF
            first_ip.fragment_offset = 0;
            first_ip.total_length    = first_ip.get_header_length() + full_payload.size();
            first_ip.auto_calc       = 0;
        end

        // Pack result
        result.raw_data.delete();
        foreach (result.layer_stack[i])
            result.layer_stack[i].pack_header(result.raw_data);
        foreach (full_payload[i])
            result.raw_data.push_back(full_payload[i]);

        return result;
    endfunction

    // help — print usage guide
    static function void help();
        $display("============================================================================");
        $display(" IP Fragmentation Guide (ip_fragment)");
        $display("============================================================================");
        $display("");
        $display(" Fragment a packet by MTU:");
        $display("   packet pkt = new();");
        $display("   pkt.randomize() with {");
        $display("       pkt_kind == ETH_IPV4_TCP;");
        $display("       outer_ipv4.identification == 16'hABCD;");
        $display("       pkt_len == 4000;");
        $display("   };");
        $display("   packet frags[$];");
        $display("   ip_fragment::fragment(pkt, 1500, frags);");
        $display("   // frags[0]: MF=1, offset=0,    len=1500");
        $display("   // frags[1]: MF=1, offset=185,   len=1500");
        $display("   // frags[2]: MF=0, offset=370,   len=1040");
        $display("");
        $display(" Reassemble fragments:");
        $display("   packet reassembled = ip_fragment::reassemble(frags);");
        $display("");
        $display(" Fragment fields:");
        $display("   IPv4.flags[0]       — MF (More Fragments): 1=more, 0=last");
        $display("   IPv4.fragment_offset — offset in 8-byte units");
        $display("   IPv4.identification  — same across all fragments");
        $display("   IPv4.total_length    — per-fragment IP length");
        $display("============================================================================");
    endfunction

endclass

`endif // IP_FRAGMENT_SV
