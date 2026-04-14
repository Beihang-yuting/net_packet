// src/protocols/l4/tcp_header.sv
`ifndef TCP_HEADER_SV
`define TCP_HEADER_SV

`include "protocol_base.sv"

class tcp_header extends protocol_base;

    rand bit [15:0] src_port;
    rand bit [15:0] dst_port;
    rand bit [31:0] seq_num;
    rand bit [31:0] ack_num;
    rand bit [3:0]  data_offset;
    rand bit [2:0]  reserved;
    rand bit [8:0]  flags;
         byte unsigned options[$];
    rand bit [15:0] window_size;
    rand bit [15:0] checksum;
    rand bit [15:0] urgent_ptr;

    // Flag bit positions within the 9-bit flags field
    // flags[8]=NS, [7]=CWR, [6]=ECE, [5]=URG, [4]=ACK, [3]=PSH, [2]=RST, [1]=SYN, [0]=FIN

    constraint c_default {
        src_port inside {[1024:65535]};
        dst_port inside {[1:65535]};
        reserved == 0;
        window_size == 16'hFFFF;
    }

    function new();
        proto_type   = PROTO_TCP;
        src_port     = 0;
        dst_port     = 0;
        seq_num      = 0;
        ack_num      = 0;
        data_offset  = 5;
        reserved     = 0;
        flags        = 0;
        window_size  = 16'hFFFF;
        checksum     = 0;
        urgent_ptr   = 0;
    endfunction

    static function tcp_header create(bit [15:0] sp = 0, bit [15:0] dp = 0,
                                       bit [8:0] f = 0);
        tcp_header h = new();
        h.src_port = sp;
        h.dst_port = dp;
        h.flags    = f;
        return h;
    endfunction

    // Flag accessors
    function bit get_fin(); return flags[0]; endfunction
    function bit get_syn(); return flags[1]; endfunction
    function bit get_rst(); return flags[2]; endfunction
    function bit get_psh(); return flags[3]; endfunction
    function bit get_ack(); return flags[4]; endfunction
    function bit get_urg(); return flags[5]; endfunction
    function bit get_ece(); return flags[6]; endfunction
    function bit get_cwr(); return flags[7]; endfunction
    function bit get_ns();  return flags[8]; endfunction

    function void set_fin(bit v); flags[0] = v; endfunction
    function void set_syn(bit v); flags[1] = v; endfunction
    function void set_rst(bit v); flags[2] = v; endfunction
    function void set_psh(bit v); flags[3] = v; endfunction
    function void set_ack(bit v); flags[4] = v; endfunction
    function void set_urg(bit v); flags[5] = v; endfunction
    function void set_ece(bit v); flags[6] = v; endfunction
    function void set_cwr(bit v); flags[7] = v; endfunction
    function void set_ns(bit v);  flags[8] = v; endfunction

    virtual function void pack_header(ref byte unsigned data[$]);
        bit [7:0] doff_res_flags_hi;
        bit [7:0] flags_lo;

        packet_utils::pack_bytes_16(data, src_port);
        packet_utils::pack_bytes_16(data, dst_port);
        packet_utils::pack_bytes_32(data, seq_num);
        packet_utils::pack_bytes_32(data, ack_num);

        // data_offset(4) + reserved(3) + NS(1) = byte 12
        // CWR,ECE,URG,ACK,PSH,RST,SYN,FIN = byte 13
        doff_res_flags_hi = {data_offset, reserved, flags[8]};
        flags_lo = flags[7:0];
        data.push_back(doff_res_flags_hi);
        data.push_back(flags_lo);

        packet_utils::pack_bytes_16(data, window_size);
        packet_utils::pack_bytes_16(data, checksum);
        packet_utils::pack_bytes_16(data, urgent_ptr);
        foreach (options[i]) data.push_back(options[i]);
    endfunction

    virtual function void unpack_header(ref byte unsigned data[$], ref int offset);
        bit [7:0] doff_res_ns;
        bit [7:0] flags_lo;

        src_port = packet_utils::unpack_bytes_16(data, offset);
        dst_port = packet_utils::unpack_bytes_16(data, offset);
        seq_num  = packet_utils::unpack_bytes_32(data, offset);
        ack_num  = packet_utils::unpack_bytes_32(data, offset);

        doff_res_ns = data[offset]; offset++;
        flags_lo    = data[offset]; offset++;
        data_offset = doff_res_ns[7:4];
        reserved    = doff_res_ns[3:1];
        flags       = {doff_res_ns[0], flags_lo};

        window_size = packet_utils::unpack_bytes_16(data, offset);
        checksum    = packet_utils::unpack_bytes_16(data, offset);
        urgent_ptr  = packet_utils::unpack_bytes_16(data, offset);

        // Read options if data_offset > 5
        options.delete();
        if (data_offset > 5) begin
            int opt_bytes = (data_offset - 5) * 4;
            for (int i = 0; i < opt_bytes; i++) begin
                options.push_back(data[offset]);
                offset++;
            end
        end
    endfunction

    virtual function int get_header_length();
        return 20 + options.size();
    endfunction

    virtual function void calc_fields(byte unsigned payload_data[$], protocol_type_e next_proto);
        if (!auto_calc) return;
        // Auto-set well-known dst_port if not already set by user
        if (dst_port == 0) begin
            case (next_proto)
                PROTO_NVME_TCP: dst_port = 16'd4420;
                PROTO_ISCSI:    dst_port = 16'd3260;
                PROTO_HTTP:     dst_port = 16'd80;
                PROTO_BGP:      dst_port = 16'd179;
                default: ;
            endcase
        end
        data_offset = 5 + options.size() / 4;
        checksum = 0;
    endfunction

    virtual function protocol_base clone();
        tcp_header h = new();
        h.src_port    = src_port;
        h.dst_port    = dst_port;
        h.seq_num     = seq_num;
        h.ack_num     = ack_num;
        h.data_offset = data_offset;
        h.reserved    = reserved;
        h.flags       = flags;
        h.window_size = window_size;
        h.checksum    = checksum;
        h.urgent_ptr  = urgent_ptr;
        h.options     = options;
        h.auto_calc   = auto_calc;
        return h;
    endfunction

    virtual function bit compare(protocol_base other);
        tcp_header o;
        if (!$cast(o, other)) return 0;
        return (src_port == o.src_port) && (dst_port == o.dst_port) &&
               (seq_num == o.seq_num) && (ack_num == o.ack_num) &&
               (data_offset == o.data_offset) && (reserved == o.reserved) &&
               (flags == o.flags) && (window_size == o.window_size) &&
               (checksum == o.checksum) && (urgent_ptr == o.urgent_ptr);
    endfunction

    virtual function string to_string();
        string s;
        s = $sformatf("=== %s ===\n", proto_type.name());
        s = {s, $sformatf("  src_port : %0d\n", src_port)};
        s = {s, $sformatf("  dst_port : %0d\n", dst_port)};
        s = {s, $sformatf("  seq_num  : 0x%08x\n", seq_num)};
        s = {s, $sformatf("  ack_num  : 0x%08x\n", ack_num)};
        s = {s, $sformatf("  doff     : %0d\n", data_offset)};
        s = {s, $sformatf("  flags    : 0x%03x [%s%s%s%s%s%s%s%s%s]\n", flags,
            get_ns()  ? "NS "  : "",
            get_cwr() ? "CWR " : "",
            get_ece() ? "ECE " : "",
            get_urg() ? "URG " : "",
            get_ack() ? "ACK " : "",
            get_psh() ? "PSH " : "",
            get_rst() ? "RST " : "",
            get_syn() ? "SYN " : "",
            get_fin() ? "FIN " : "")};
        s = {s, $sformatf("  win_size : %0d\n", window_size)};
        s = {s, $sformatf("  checksum : 0x%04x\n", checksum)};
        s = {s, $sformatf("  urg_ptr  : %0d\n", urgent_ptr)};
        return s;
    endfunction

    virtual function string to_brief();
        return $sformatf("%0d -> %0d seq:0x%08x flags:0x%03x", src_port, dst_port, seq_num, flags);
    endfunction

endclass

`endif // TCP_HEADER_SV
