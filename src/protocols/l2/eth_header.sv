// src/protocols/l2/eth_header.sv
`ifndef ETH_HEADER_SV
`define ETH_HEADER_SV

`include "protocol_base.sv"

class eth_header extends protocol_base;

    rand bit [47:0] dst_mac;
    rand bit [47:0] src_mac;
    rand bit [15:0] ethertype;

    constraint c_default {
        dst_mac inside {[0:48'hFFFFFFFFFFFF]};
        src_mac inside {[0:48'hFFFFFFFFFFFF]};
    }

    function new();
        proto_type = PROTO_ETHERNET;
        dst_mac    = 48'h0;
        src_mac    = 48'h0;
        ethertype  = ETHERTYPE_IPV4;
    endfunction

    static function eth_header create(bit [47:0] dst = 0, bit [47:0] src = 0,
                                       bit [15:0] etype = ETHERTYPE_IPV4);
        eth_header h = new();
        h.dst_mac   = dst;
        h.src_mac   = src;
        h.ethertype = etype;
        return h;
    endfunction

    virtual function void pack_header(ref byte unsigned data[$]);
        packet_utils::pack_bytes_48(data, dst_mac);
        packet_utils::pack_bytes_48(data, src_mac);
        packet_utils::pack_bytes_16(data, ethertype);
    endfunction

    virtual function void unpack_header(ref byte unsigned data[$], ref int offset);
        dst_mac   = packet_utils::unpack_bytes_48(data, offset);
        src_mac   = packet_utils::unpack_bytes_48(data, offset);
        ethertype = packet_utils::unpack_bytes_16(data, offset);
    endfunction

    virtual function int get_header_length();
        return 14;
    endfunction

    virtual function void calc_fields(byte unsigned payload_data[$], protocol_type_e next_proto);
        if (!auto_calc) return;
        case (next_proto)
            PROTO_IPV4:     ethertype = ETHERTYPE_IPV4;
            PROTO_IPV6:     ethertype = ETHERTYPE_IPV6;
            PROTO_ARP:      ethertype = ETHERTYPE_ARP;
            PROTO_VLAN:     ethertype = ETHERTYPE_VLAN;
            PROTO_QINQ:     ethertype = ETHERTYPE_QINQ;
            PROTO_MPLS:     ethertype = ETHERTYPE_MPLS_UNI;
            PROTO_LLDP:     ethertype = ETHERTYPE_LLDP;
            PROTO_LACP:     ethertype = ETHERTYPE_SLOW;
            PROTO_PTP:      ethertype = ETHERTYPE_PTP;
            PROTO_MACSEC:   ethertype = ETHERTYPE_MACSEC;
            PROTO_EAP:      ethertype = ETHERTYPE_EAP;
            PROTO_STP:      ethertype = 16'h0000;
            PROTO_MAC_CONTROL: ethertype = 16'h8808;
            default: ;
        endcase
    endfunction

    virtual function protocol_base clone();
        eth_header h = new();
        h.dst_mac   = dst_mac;
        h.src_mac   = src_mac;
        h.ethertype = ethertype;
        h.auto_calc = auto_calc;
        return h;
    endfunction

    virtual function bit compare(protocol_base other);
        eth_header o;
        if (!$cast(o, other)) return 0;
        return (dst_mac == o.dst_mac) && (src_mac == o.src_mac) && (ethertype == o.ethertype);
    endfunction

    virtual function string to_string();
        string s;
        s = $sformatf("=== %s ===\n", proto_type.name());
        s = {s, $sformatf("  dst_mac  : %s\n", packet_utils::format_mac(dst_mac))};
        s = {s, $sformatf("  src_mac  : %s\n", packet_utils::format_mac(src_mac))};
        s = {s, $sformatf("  ethertype: 0x%04x\n", ethertype)};
        return s;
    endfunction

    virtual function string to_brief();
        return $sformatf("%s -> %s type:0x%04x",
                         packet_utils::format_mac(src_mac),
                         packet_utils::format_mac(dst_mac),
                         ethertype);
    endfunction

endclass

`endif // ETH_HEADER_SV
