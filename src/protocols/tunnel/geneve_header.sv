// src/protocols/tunnel/geneve_header.sv
`ifndef GENEVE_HEADER_SV
`define GENEVE_HEADER_SV

`include "protocol_base.sv"

class geneve_header extends protocol_base;

    rand bit [1:0]  version;
    rand bit [5:0]  opt_len;
    rand bit        o_flag;
    rand bit        c_flag;
    rand bit [5:0]  reserved0;
    rand bit [15:0] protocol_type;
    rand bit [23:0] vni;
    rand bit [7:0]  reserved1;
    byte unsigned   options[];

    constraint c_default {
        version   == 2'h0;
        o_flag    == 1'b0;
        c_flag    == 1'b0;
        reserved0 == 6'h0;
        reserved1 == 8'h0;
        opt_len   == 6'h0;
    }

    function new();
        proto_type    = PROTO_GENEVE;
        version       = 2'h0;
        opt_len       = 6'h0;
        o_flag        = 1'b0;
        c_flag        = 1'b0;
        reserved0     = 6'h0;
        protocol_type = 16'h6558;
        vni           = 24'd100;
        reserved1     = 8'h0;
        options       = new[0];
    endfunction

    virtual function void pack_header(ref byte unsigned data[$]);
        int i;
        data.push_back({version, opt_len});
        data.push_back({o_flag, c_flag, reserved0});
        data.push_back(protocol_type[15:8]);
        data.push_back(protocol_type[7:0]);
        data.push_back(vni[23:16]);
        data.push_back(vni[15:8]);
        data.push_back(vni[7:0]);
        data.push_back(reserved1);
        for (i = 0; i < options.size(); i++) begin
            data.push_back(options[i]);
        end
    endfunction

    virtual function void unpack_header(ref byte unsigned data[$], ref int offset);
        byte unsigned b0, b1;
        int i;
        int opt_bytes;
        b0            = data[offset]; offset++;
        version       = b0[7:6];
        opt_len       = b0[5:0];
        b1            = data[offset]; offset++;
        o_flag        = b1[7];
        c_flag        = b1[6];
        reserved0     = b1[5:0];
        protocol_type[15:8] = data[offset]; offset++;
        protocol_type[7:0]  = data[offset]; offset++;
        vni[23:16]    = data[offset]; offset++;
        vni[15:8]     = data[offset]; offset++;
        vni[7:0]      = data[offset]; offset++;
        reserved1     = data[offset]; offset++;
        opt_bytes = int'(opt_len) * 4;
        options = new[opt_bytes];
        for (i = 0; i < opt_bytes; i++) begin
            options[i] = data[offset]; offset++;
        end
    endfunction

    virtual function int get_header_length();
        return 8 + int'(opt_len) * 4;
    endfunction

    virtual function void calc_fields(byte unsigned payload_data[$], protocol_type_e next_proto);
        if (!auto_calc) return;
        opt_len = options.size() / 4;
        case (next_proto)
            PROTO_ETHERNET: protocol_type = 16'h6558;
            PROTO_IPV4:     protocol_type = ETHERTYPE_IPV4;
            PROTO_IPV6:     protocol_type = ETHERTYPE_IPV6;
            default:        protocol_type = 16'h6558;
        endcase
    endfunction

    virtual function protocol_base clone();
        geneve_header h = new();
        h.version       = version;
        h.opt_len       = opt_len;
        h.o_flag        = o_flag;
        h.c_flag        = c_flag;
        h.reserved0     = reserved0;
        h.protocol_type = protocol_type;
        h.vni           = vni;
        h.reserved1     = reserved1;
        h.options       = new[options.size()](options);
        h.auto_calc     = auto_calc;
        return h;
    endfunction

    virtual function bit compare(protocol_base other);
        geneve_header o;
        if (!$cast(o, other)) return 0;
        if (version       != o.version)       return 0;
        if (opt_len       != o.opt_len)       return 0;
        if (protocol_type != o.protocol_type) return 0;
        if (vni           != o.vni)           return 0;
        if (options.size() != o.options.size()) return 0;
        for (int i = 0; i < options.size(); i++) begin
            if (options[i] != o.options[i]) return 0;
        end
        return 1;
    endfunction

    virtual function string to_string();
        string s;
        s = $sformatf("=== %s ===\n", proto_type.name());
        s = {s, $sformatf("  version      : %0d\n",    version)};
        s = {s, $sformatf("  opt_len      : %0d\n",    opt_len)};
        s = {s, $sformatf("  o_flag       : %0b\n",    o_flag)};
        s = {s, $sformatf("  c_flag       : %0b\n",    c_flag)};
        s = {s, $sformatf("  protocol_type: 0x%04x\n", protocol_type)};
        s = {s, $sformatf("  vni          : %0d\n",    vni)};
        s = {s, $sformatf("  options_bytes: %0d\n",    options.size())};
        return s;
    endfunction

    virtual function string to_brief();
        return $sformatf("Geneve vni:%0d proto:0x%04x opt_len:%0d", vni, protocol_type, opt_len);
    endfunction

endclass

`endif // GENEVE_HEADER_SV
