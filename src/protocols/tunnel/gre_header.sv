// src/protocols/tunnel/gre_header.sv
`ifndef GRE_HEADER_SV
`define GRE_HEADER_SV

`include "protocol_base.sv"

class gre_header extends protocol_base;

    rand bit        c_flag;
    rand bit        k_flag;
    rand bit        s_flag;
    rand bit [9:0]  reserved0;
    rand bit [2:0]  version;
    rand bit [15:0] protocol_type;
    rand bit [15:0] checksum;
    rand bit [15:0] reserved1;
    rand bit [31:0] key;
    rand bit [31:0] sequence_number;

    constraint c_default {
        soft c_flag        == 1'b0;
        soft k_flag        == 1'b0;
        soft s_flag        == 1'b0;
        soft reserved0     == 10'h0;
        soft version       == 3'h0;
        soft reserved1     == 16'h0;
    }

    function new();
        proto_type    = PROTO_GRE;
        c_flag        = 1'b0;
        k_flag        = 1'b0;
        s_flag        = 1'b0;
        reserved0     = 10'h0;
        version       = 3'h0;
        protocol_type = ETHERTYPE_IPV4;
        checksum      = 16'h0;
        reserved1     = 16'h0;
        key           = 32'h0;
        sequence_number = 32'h0;
    endfunction

    // Wire format of first 16-bit word: {c_flag, 1'b0, k_flag, s_flag, reserved0, version}
    virtual function void pack_header(ref byte unsigned data[$]);
        bit [15:0] flags_ver;
        flags_ver = {c_flag, 1'b0, k_flag, s_flag, reserved0, version};
        packet_utils::pack_bytes_16(data, flags_ver);
        packet_utils::pack_bytes_16(data, protocol_type);
        if (c_flag) begin
            packet_utils::pack_bytes_16(data, checksum);
            packet_utils::pack_bytes_16(data, reserved1);
        end
        if (k_flag) begin
            packet_utils::pack_bytes_32(data, key);
        end
        if (s_flag) begin
            packet_utils::pack_bytes_32(data, sequence_number);
        end
    endfunction

    virtual function void unpack_header(ref byte unsigned data[$], ref int offset);
        bit [15:0] flags_ver;
        flags_ver     = packet_utils::unpack_bytes_16(data, offset);
        c_flag        = flags_ver[15];
        // bit 14 is reserved (always 0)
        k_flag        = flags_ver[13];
        s_flag        = flags_ver[12];
        reserved0     = flags_ver[11:3];
        version       = flags_ver[2:0];
        protocol_type = packet_utils::unpack_bytes_16(data, offset);
        if (c_flag) begin
            checksum  = packet_utils::unpack_bytes_16(data, offset);
            reserved1 = packet_utils::unpack_bytes_16(data, offset);
        end
        if (k_flag) begin
            key       = packet_utils::unpack_bytes_32(data, offset);
        end
        if (s_flag) begin
            sequence_number = packet_utils::unpack_bytes_32(data, offset);
        end
    endfunction

    virtual function int get_header_length();
        return 4 + (c_flag ? 4 : 0) + (k_flag ? 4 : 0) + (s_flag ? 4 : 0);
    endfunction

    virtual function void calc_fields(byte unsigned payload_data[$], protocol_type_e next_proto);
        if (!auto_calc) return;
        case (next_proto)
            PROTO_IPV4:      protocol_type = ETHERTYPE_IPV4;
            PROTO_IPV6:      protocol_type = ETHERTYPE_IPV6;
            PROTO_ETHERNET:  protocol_type = 16'h6558;
            PROTO_ERSPAN_II: protocol_type = 16'h88BE;
            PROTO_ERSPAN_III:protocol_type = 16'h22EB;
            default: ;
        endcase
        // Compute GRE checksum when c_flag is set
        if (c_flag) begin
            byte unsigned all_data[$];
            checksum = 0;
            reserved1 = 0;
            pack_header(all_data);
            foreach (payload_data[i]) all_data.push_back(payload_data[i]);
            checksum = packet_utils::ones_complement_checksum(all_data);
        end
    endfunction

    virtual function protocol_base clone();
        gre_header h = new();
        h.c_flag          = c_flag;
        h.k_flag          = k_flag;
        h.s_flag          = s_flag;
        h.reserved0       = reserved0;
        h.version         = version;
        h.protocol_type   = protocol_type;
        h.checksum        = checksum;
        h.reserved1       = reserved1;
        h.key             = key;
        h.sequence_number = sequence_number;
        h.auto_calc       = auto_calc;
        return h;
    endfunction

    virtual function bit compare(protocol_base other);
        gre_header o;
        if (!$cast(o, other)) return 0;
        if (c_flag != o.c_flag) return 0;
        if (k_flag != o.k_flag) return 0;
        if (s_flag != o.s_flag) return 0;
        if (protocol_type != o.protocol_type) return 0;
        if (c_flag && (checksum != o.checksum)) return 0;
        if (k_flag && (key != o.key)) return 0;
        if (s_flag && (sequence_number != o.sequence_number)) return 0;
        return 1;
    endfunction

    virtual function string to_string();
        string s;
        s = $sformatf("=== %s ===\n", proto_type.name());
        s = {s, $sformatf("  c_flag       : %0b\n",  c_flag)};
        s = {s, $sformatf("  k_flag       : %0b\n",  k_flag)};
        s = {s, $sformatf("  s_flag       : %0b\n",  s_flag)};
        s = {s, $sformatf("  reserved0    : 0x%03x\n", reserved0)};
        s = {s, $sformatf("  version      : %0d\n",  version)};
        s = {s, $sformatf("  protocol_type: 0x%04x\n", protocol_type)};
        if (c_flag) begin
            s = {s, $sformatf("  checksum     : 0x%04x\n", checksum)};
            s = {s, $sformatf("  reserved1    : 0x%04x\n", reserved1)};
        end
        if (k_flag)
            s = {s, $sformatf("  key          : 0x%08x\n", key)};
        if (s_flag)
            s = {s, $sformatf("  sequence_num : %0d\n", sequence_number)};
        return s;
    endfunction

    virtual function string to_brief();
        return $sformatf("GRE proto:0x%04x c:%0b k:%0b s:%0b", protocol_type, c_flag, k_flag, s_flag);
    endfunction

    // help — print GRE options usage guide
    static function void help();
        $display("============================================================================");
        $display(" GRE Optional Fields Guide (RFC 2784/2890)");
        $display("============================================================================");
        $display("");
        $display(" Optional fields (controlled by flags):");
        $display("   c_flag=1 → Checksum(16b) + Reserved1(16b)  [+4 bytes]");
        $display("   k_flag=1 → Key(32b)                        [+4 bytes]");
        $display("   s_flag=1 → Sequence Number(32b)             [+4 bytes]");
        $display("");
        $display(" Header size: 4 (base) + 4*(c_flag+k_flag+s_flag) = 4~16 bytes");
        $display("");
        $display(" Usage:");
        $display("   pkt.randomize() with {");
        $display("       pkt_kind == ETH_IPV4_GRE_IPV4_TCP;");
        $display("       gre.k_flag == 1;");
        $display("       gre.key    == 32'h0000_ABCD;");
        $display("       gre.s_flag == 1;");
        $display("       gre.sequence_number == 32'd1;");
        $display("   };");
        $display("");
        $display("   // With checksum (auto-computed in calc_fields):");
        $display("   pkt.randomize() with {");
        $display("       pkt_kind == ETH_IPV4_GRE_IPV4_TCP;");
        $display("       gre.c_flag == 1;  // checksum auto-calculated");
        $display("       gre.k_flag == 1;");
        $display("       gre.key == 32'hDEAD_BEEF;");
        $display("   };");
        $display("");
        $display(" NVGRE (Network Virtualization using GRE):");
        $display("   pkt.randomize() with {");
        $display("       pkt_kind == ETH_IPV4_GRE_ETH_IPV4_TCP;  // GRE L2");
        $display("       gre.k_flag == 1;");
        $display("       gre.key == {24'h001234, 8'h00};  // VSID=0x1234, FlowID=0");
        $display("   };");
        $display("============================================================================");
    endfunction

endclass

`endif // GRE_HEADER_SV
