// src/protocols/tunnel/gtp_header.sv
`ifndef GTP_HEADER_SV
`define GTP_HEADER_SV

`include "protocol_base.sv"

// ============================================================
// GTP-U header (3GPP TS 29.281): 8 or 12 bytes
// Wire format:
//   Byte 0: {version[2:0], pt, reserved, e_flag, s_flag, pn_flag}
//   Byte 1: message_type
//   Bytes 2-3: length (16-bit big-endian)
//   Bytes 4-7: teid (32-bit big-endian)
//   Optional (when e_flag|s_flag|pn_flag):
//     Bytes 8-9: sequence_number (16-bit)
//     Byte 10:   n_pdu_number
//     Byte 11:   next_ext_hdr_type
// ============================================================
class gtp_u_header extends protocol_base;

    rand bit [2:0]  version;
    rand bit        pt;
    rand bit        reserved;
    rand bit        e_flag;
    rand bit        s_flag;
    rand bit        pn_flag;
    rand bit [7:0]  message_type;
    rand bit [15:0] length;
    rand bit [31:0] teid;
    rand bit [15:0] sequence_number;
    rand bit [7:0]  n_pdu_number;
    rand bit [7:0]  next_ext_hdr_type;

    constraint c_default {
        soft version      == 3'b001;
        soft pt           == 1'b1;
        soft reserved     == 1'b0;
        soft e_flag       == 1'b0;
        soft s_flag       == 1'b0;
        soft pn_flag      == 1'b0;
        soft message_type == 8'hFF;
    }

    function new();
        proto_type       = PROTO_GTP_U;
        version          = 3'b001;
        pt               = 1'b1;
        reserved         = 1'b0;
        e_flag           = 1'b0;
        s_flag           = 1'b0;
        pn_flag          = 1'b0;
        message_type     = 8'hFF;
        length           = 16'd0;
        teid             = 32'd0;
        sequence_number  = 16'd0;
        n_pdu_number     = 8'd0;
        next_ext_hdr_type = 8'd0;
    endfunction

    static function gtp_u_header create(bit [31:0] t = 32'd0);
        gtp_u_header h = new();
        h.teid = t;
        return h;
    endfunction

    function bit has_optional_fields();
        return (e_flag || s_flag || pn_flag);
    endfunction

    virtual function int get_header_length();
        return has_optional_fields() ? 12 : 8;
    endfunction

    virtual function void pack_header(ref byte unsigned data[$]);
        byte unsigned b0;
        b0 = {version, pt, reserved, e_flag, s_flag, pn_flag};
        data.push_back(b0);
        data.push_back(message_type);
        packet_utils::pack_bytes_16(data, length);
        packet_utils::pack_bytes_32(data, teid);
        if (has_optional_fields()) begin
            packet_utils::pack_bytes_16(data, sequence_number);
            data.push_back(n_pdu_number);
            data.push_back(next_ext_hdr_type);
        end
    endfunction

    virtual function void unpack_header(ref byte unsigned data[$], ref int offset);
        byte unsigned b0;
        b0             = data[offset]; offset++;
        version        = b0[7:5];
        pt             = b0[4];
        reserved       = b0[3];
        e_flag         = b0[2];
        s_flag         = b0[1];
        pn_flag        = b0[0];
        message_type   = data[offset]; offset++;
        length         = packet_utils::unpack_bytes_16(data, offset);
        teid           = packet_utils::unpack_bytes_32(data, offset);
        if (has_optional_fields()) begin
            sequence_number   = packet_utils::unpack_bytes_16(data, offset);
            n_pdu_number      = data[offset]; offset++;
            next_ext_hdr_type = data[offset]; offset++;
        end
    endfunction

    virtual function void calc_fields(byte unsigned payload_data[$], protocol_type_e next_proto);
        if (!auto_calc) return;
        length = payload_data.size();
        if (has_optional_fields()) length += 4;
    endfunction

    virtual function protocol_base clone();
        gtp_u_header h = new();
        h.version           = version;
        h.pt                = pt;
        h.reserved          = reserved;
        h.e_flag            = e_flag;
        h.s_flag            = s_flag;
        h.pn_flag           = pn_flag;
        h.message_type      = message_type;
        h.length            = length;
        h.teid              = teid;
        h.sequence_number   = sequence_number;
        h.n_pdu_number      = n_pdu_number;
        h.next_ext_hdr_type = next_ext_hdr_type;
        h.auto_calc         = auto_calc;
        return h;
    endfunction

    virtual function bit compare(protocol_base other);
        gtp_u_header o;
        if (!$cast(o, other)) return 0;
        if (version      != o.version)      return 0;
        if (pt           != o.pt)           return 0;
        if (message_type != o.message_type) return 0;
        if (teid         != o.teid)         return 0;
        if (has_optional_fields()) begin
            if (sequence_number != o.sequence_number) return 0;
            if (n_pdu_number    != o.n_pdu_number)    return 0;
        end
        return 1;
    endfunction

    virtual function string to_string();
        string s;
        s = $sformatf("=== %s ===\n", proto_type.name());
        s = {s, $sformatf("  version          : %0d\n",    version)};
        s = {s, $sformatf("  pt               : %0d\n",    pt)};
        s = {s, $sformatf("  e_flag           : %0d\n",    e_flag)};
        s = {s, $sformatf("  s_flag           : %0d\n",    s_flag)};
        s = {s, $sformatf("  pn_flag          : %0d\n",    pn_flag)};
        s = {s, $sformatf("  message_type     : 0x%02x\n", message_type)};
        s = {s, $sformatf("  length           : %0d\n",    length)};
        s = {s, $sformatf("  teid             : 0x%08x\n", teid)};
        if (has_optional_fields()) begin
            s = {s, $sformatf("  sequence_number  : 0x%04x\n", sequence_number)};
            s = {s, $sformatf("  n_pdu_number     : 0x%02x\n", n_pdu_number)};
            s = {s, $sformatf("  next_ext_hdr_type: 0x%02x\n", next_ext_hdr_type)};
        end
        return s;
    endfunction

    virtual function string to_brief();
        return $sformatf("GTP-U teid:0x%08x msg_type:0x%02x len:%0d", teid, message_type, length);
    endfunction

endclass

`endif // GTP_HEADER_SV
