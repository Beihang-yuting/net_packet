// src/parser/packet_comparator.sv
`ifndef PACKET_COMPARATOR_SV
`define PACKET_COMPARATOR_SV

`include "core/packet.sv"

class packet_comparator;

    // Compare two packets, return list of differences
    function void compare(packet a, packet b, ref diff_entry_t diffs[$]);
        diffs.delete();

        // Check layer count
        if (a.layer_stack.size() != b.layer_stack.size()) begin
            diff_entry_t d;
            d.layer = PROTO_RAW_PAYLOAD;
            d.field_name = "layer_count";
            d.val_a = $sformatf("%0d", a.layer_stack.size());
            d.val_b = $sformatf("%0d", b.layer_stack.size());
            diffs.push_back(d);
        end

        // Compare each layer
        begin
            int min_layers = (a.layer_stack.size() < b.layer_stack.size()) ?
                              a.layer_stack.size() : b.layer_stack.size();

            for (int i = 0; i < min_layers; i++) begin
                // Check proto_type mismatch
                if (a.layer_stack[i].proto_type != b.layer_stack[i].proto_type) begin
                    diff_entry_t d;
                    d.layer = a.layer_stack[i].proto_type;
                    d.field_name = "proto_type";
                    d.val_a = a.layer_stack[i].proto_type.name();
                    d.val_b = b.layer_stack[i].proto_type.name();
                    diffs.push_back(d);
                    continue;  // Can't compare fields of different types
                end

                // Use protocol_base.compare() for field-level comparison
                if (!a.layer_stack[i].compare(b.layer_stack[i])) begin
                    // Layers differ — pack both and compare bytes to report specific diffs
                    byte unsigned bytes_a[$], bytes_b[$];
                    a.layer_stack[i].pack_header(bytes_a);
                    b.layer_stack[i].pack_header(bytes_b);

                    // Report as a single diff with packed hex
                    begin
                        diff_entry_t d;
                        string hex_a, hex_b;
                        d.layer = a.layer_stack[i].proto_type;
                        d.field_name = "header_data";
                        // Build hex strings
                        hex_a = "";
                        foreach (bytes_a[j]) hex_a = {hex_a, $sformatf("%02x", bytes_a[j])};
                        hex_b = "";
                        foreach (bytes_b[j]) hex_b = {hex_b, $sformatf("%02x", bytes_b[j])};
                        d.val_a = hex_a;
                        d.val_b = hex_b;
                        diffs.push_back(d);
                    end
                end
            end
        end

        // Compare raw_data lengths
        if (a.raw_data.size() != b.raw_data.size()) begin
            diff_entry_t d;
            d.layer = PROTO_RAW_PAYLOAD;
            d.field_name = "raw_data_size";
            d.val_a = $sformatf("%0d", a.raw_data.size());
            d.val_b = $sformatf("%0d", b.raw_data.size());
            diffs.push_back(d);
        end
    endfunction

    // Print diffs in human-readable format
    function string diff_to_string(diff_entry_t diffs[$]);
        string s = "";
        if (diffs.size() == 0) begin
            s = "Packets are identical\n";
        end else begin
            s = $sformatf("Found %0d difference(s):\n", diffs.size());
            foreach (diffs[i]) begin
                s = {s, $sformatf("  DIFF [%s.%s] a: %s, b: %s\n",
                    diffs[i].layer.name(), diffs[i].field_name,
                    diffs[i].val_a, diffs[i].val_b)};
            end
        end
        return s;
    endfunction

endclass

`endif // PACKET_COMPARATOR_SV
