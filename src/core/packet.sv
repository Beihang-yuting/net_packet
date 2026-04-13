// src/core/packet.sv
`ifndef PACKET_SV
`define PACKET_SV

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
`include "tunnel/vxlan_header.sv"
`include "tunnel/gre_header.sv"
`include "tunnel/geneve_header.sv"
`include "tunnel/erspan_header.sv"
`include "tunnel/gtp_header.sv"
`include "tunnel/ip_in_ip_header.sv"
`include "core/protocol_graph.sv"
`include "core/template_registry.sv"

class packet;

    // ----- Layer stack -----
    protocol_base layer_stack[$];

    // ----- Raw data (result of do_pack) -----
    byte unsigned raw_data[$];

    // ----- Instance control -----
    bit              force_mode        = 0;
    int              pkt_length        = 0;   // 0 = headers only (no payload)
    payload_mode_e   payload_mode      = PAYLOAD_RANDOM;
    byte unsigned    payload_fixed_val = 8'h00;
    byte unsigned    payload_pattern[$];

    // ----- Shared static instances -----
    static protocol_graph    s_graph    = new();
    static template_registry s_registry = new();

    // =========================================================================
    // Factory: create_header
    // =========================================================================
    static function protocol_base create_header(protocol_type_e proto);
        case (proto)
            PROTO_ETHERNET: begin
                eth_header h = new();
                return h;
            end
            PROTO_VLAN: begin
                vlan_header h = new();
                return h;
            end
            PROTO_QINQ: begin
                vlan_header h = new();
                h.proto_type = PROTO_QINQ;
                h.ethertype  = ETHERTYPE_VLAN;
                return h;
            end
            PROTO_IPV4: begin
                ipv4_header h = new();
                return h;
            end
            PROTO_IPV6: begin
                ipv6_header h = new();
                return h;
            end
            PROTO_ARP: begin
                arp_header h = new();
                return h;
            end
            PROTO_TCP: begin
                tcp_header h = new();
                return h;
            end
            PROTO_UDP: begin
                udp_header h = new();
                return h;
            end
            PROTO_ICMP: begin
                icmp_header h = new();
                return h;
            end
            PROTO_ICMPV6: begin
                icmpv6_header h = new();
                return h;
            end
            PROTO_VXLAN: begin
                vxlan_header h = new();
                return h;
            end
            PROTO_GRE: begin
                gre_header h = new();
                return h;
            end
            PROTO_GENEVE: begin
                geneve_header h = new();
                return h;
            end
            PROTO_ERSPAN_II: begin
                erspan_ii_header h = new();
                return h;
            end
            PROTO_ERSPAN_III: begin
                erspan_iii_header h = new();
                return h;
            end
            PROTO_GTP_U: begin
                gtp_u_header h = new();
                return h;
            end
            PROTO_IP_IN_IP: begin
                ip_in_ip_header h = new();
                return h;
            end
            default: return null;
        endcase
    endfunction

    // =========================================================================
    // build_from_template
    // =========================================================================
    function void build_from_template(packet_template_e tmpl);
        protocol_type_e chain[$];
        s_registry.get_chain(tmpl, chain);
        layer_stack.delete();
        foreach (chain[i]) begin
            protocol_base hdr = create_header(chain[i]);
            if (hdr != null) begin
                layer_stack.push_back(hdr);
            end else begin
                $warning("packet::build_from_template: unsupported protocol %s in template %s",
                         chain[i].name(), tmpl.name());
            end
        end
    endfunction

    // =========================================================================
    // add_layer
    // =========================================================================
    function bit add_layer(protocol_base layer);
        if (layer == null) return 0;
        if (!force_mode && layer_stack.size() > 0) begin
            protocol_type_e prev = layer_stack[layer_stack.size()-1].proto_type;
            if (!s_graph.is_valid_next(prev, layer.proto_type)) begin
                $warning("packet::add_layer: invalid transition %s -> %s (use force_mode to override)",
                         prev.name(), layer.proto_type.name());
                return 0;
            end
        end
        layer_stack.push_back(layer);
        return 1;
    endfunction

    // =========================================================================
    // get_layer — returns first matching layer or null
    // =========================================================================
    function protocol_base get_layer(protocol_type_e proto);
        foreach (layer_stack[i]) begin
            if (layer_stack[i].proto_type == proto) return layer_stack[i];
        end
        return null;
    endfunction

    // =========================================================================
    // get_all_layers
    // =========================================================================
    function void get_all_layers(ref protocol_base layers[$]);
        layers = layer_stack;
    endfunction

    // =========================================================================
    // get_all_headers_length
    // =========================================================================
    function int get_all_headers_length();
        int total = 0;
        foreach (layer_stack[i]) begin
            total += layer_stack[i].get_header_length();
        end
        return total;
    endfunction

    // =========================================================================
    // do_pack
    // =========================================================================
    function void do_pack();
        int headers_len;
        int payload_len;
        byte unsigned payload[$];

        headers_len = get_all_headers_length();

        // Determine payload length
        if (pkt_length == 0) begin
            payload_len = 0;
        end else if (pkt_length > headers_len) begin
            payload_len = pkt_length - headers_len;
        end else if (pkt_length == headers_len) begin
            payload_len = 0;
        end else begin
            $warning("packet::do_pack: pkt_length (%0d) < headers_length (%0d), no payload generated",
                     pkt_length, headers_len);
            payload_len = 0;
        end

        // Generate payload
        payload.delete();
        for (int i = 0; i < payload_len; i++) begin
            case (payload_mode)
                PAYLOAD_RANDOM:    payload.push_back($urandom_range(0, 255));
                PAYLOAD_FIXED:     payload.push_back(payload_fixed_val);
                PAYLOAD_INCREMENT: payload.push_back(i % 256);
                PAYLOAD_PATTERN: begin
                    if (payload_pattern.size() > 0)
                        payload.push_back(payload_pattern[i % payload_pattern.size()]);
                    else
                        payload.push_back(8'h00);
                end
            endcase
        end

        // calc_fields: innermost to outermost
        // For layer[i], remaining_data = packed(layer[i+1]..layer[N-1]) + payload
        // We build this from inside out.
        begin
            byte unsigned remaining_data[$];
            remaining_data = payload;

            for (int i = int'(layer_stack.size()) - 1; i >= 0; i--) begin
                protocol_type_e next_proto;

                if (i < int'(layer_stack.size()) - 1)
                    next_proto = layer_stack[i+1].proto_type;
                else
                    next_proto = PROTO_RAW_PAYLOAD;

                layer_stack[i].calc_fields(remaining_data, next_proto);

                // Prepend this header's packed bytes to remaining_data for the next outer layer
                if (i > 0) begin
                    byte unsigned hdr_bytes[$];
                    layer_stack[i].pack_header(hdr_bytes);
                    foreach (remaining_data[j])
                        hdr_bytes.push_back(remaining_data[j]);
                    remaining_data = hdr_bytes;
                end
            end
        end

        // Pack all headers + payload into raw_data
        raw_data.delete();
        foreach (layer_stack[i]) begin
            layer_stack[i].pack_header(raw_data);
        end
        foreach (payload[i]) begin
            raw_data.push_back(payload[i]);
        end
    endfunction

    // =========================================================================
    // identify_next_proto — used by unpack
    // =========================================================================
    static function protocol_type_e identify_next_proto(protocol_base hdr,
                                                         byte unsigned data[$],
                                                         int offset);
        case (hdr.proto_type)
            PROTO_ETHERNET: begin
                eth_header eth;
                if ($cast(eth, hdr)) begin
                    return ethertype_to_proto(eth.ethertype);
                end
            end
            PROTO_VLAN, PROTO_QINQ: begin
                vlan_header v;
                if ($cast(v, hdr)) begin
                    return ethertype_to_proto(v.ethertype);
                end
            end
            PROTO_IPV4: begin
                ipv4_header ip4;
                if ($cast(ip4, hdr)) begin
                    return ip_proto_to_proto(ip4.protocol);
                end
            end
            PROTO_IPV6: begin
                ipv6_header ip6;
                if ($cast(ip6, hdr)) begin
                    return ipv6_nh_to_proto(ip6.next_header);
                end
            end
            PROTO_UDP: begin
                udp_header u;
                if ($cast(u, hdr)) begin
                    return udp_dstport_to_proto(u.dst_port);
                end
            end
            PROTO_GRE: begin
                gre_header g;
                if ($cast(g, hdr)) begin
                    return gre_proto_to_proto(g.protocol_type);
                end
            end
            PROTO_VXLAN: begin
                return PROTO_ETHERNET;
            end
            PROTO_GENEVE: begin
                geneve_header gn;
                if ($cast(gn, hdr)) begin
                    if (gn.protocol_type == 16'h6558) return PROTO_ETHERNET;
                    return ethertype_to_proto(gn.protocol_type);
                end
            end
            PROTO_ERSPAN_II, PROTO_ERSPAN_III: begin
                return PROTO_ETHERNET;
            end
            PROTO_GTP_U: begin
                if (offset < data.size()) begin
                    bit [3:0] ip_ver = data[offset][7:4];
                    if (ip_ver == 4) return PROTO_IPV4;
                    if (ip_ver == 6) return PROTO_IPV6;
                end
                return PROTO_RAW_PAYLOAD;
            end
            default: return PROTO_RAW_PAYLOAD;
        endcase
        return PROTO_RAW_PAYLOAD;
    endfunction

    // =========================================================================
    // ethertype -> protocol mapping
    // =========================================================================
    static function protocol_type_e ethertype_to_proto(bit [15:0] etype);
        case (etype)
            ETHERTYPE_IPV4:   return PROTO_IPV4;
            ETHERTYPE_IPV6:   return PROTO_IPV6;
            ETHERTYPE_ARP:    return PROTO_ARP;
            ETHERTYPE_VLAN:   return PROTO_VLAN;
            ETHERTYPE_QINQ:   return PROTO_QINQ;
            default:          return PROTO_RAW_PAYLOAD;
        endcase
    endfunction

    // =========================================================================
    // IP protocol -> protocol mapping
    // =========================================================================
    static function protocol_type_e ip_proto_to_proto(bit [7:0] proto);
        case (proto)
            IP_PROTO_TCP:      return PROTO_TCP;
            IP_PROTO_UDP:      return PROTO_UDP;
            IP_PROTO_ICMP:     return PROTO_ICMP;
            IP_PROTO_GRE:      return PROTO_GRE;
            IP_PROTO_ICMPV6:   return PROTO_ICMPV6;
            IP_PROTO_IGMP:     return PROTO_IGMP;
            IP_PROTO_SCTP:     return PROTO_SCTP;
            IP_PROTO_IP_IN_IP: return PROTO_IP_IN_IP;
            IP_PROTO_IPV6:     return PROTO_IPV6;
            IP_PROTO_OSPF:     return PROTO_OSPF;
            IP_PROTO_L2TP:     return PROTO_L2TP;
            default:           return PROTO_RAW_PAYLOAD;
        endcase
    endfunction

    // =========================================================================
    // IPv6 next_header -> protocol mapping
    // =========================================================================
    static function protocol_type_e ipv6_nh_to_proto(bit [7:0] nh);
        case (nh)
            IPV6_NH_TCP:      return PROTO_TCP;
            IPV6_NH_UDP:      return PROTO_UDP;
            IPV6_NH_ICMPV6:   return PROTO_ICMPV6;
            IPV6_NH_HBH:      return PROTO_IPV6_HBH;
            IPV6_NH_ROUTING:  return PROTO_IPV6_ROUTING;
            IPV6_NH_FRAGMENT: return PROTO_IPV6_FRAGMENT;
            IPV6_NH_DEST:     return PROTO_IPV6_DEST;
            IPV6_NH_GRE:      return PROTO_GRE;
            IPV6_NH_IPV6:     return PROTO_IPV6;
            IPV6_NH_OSPF:     return PROTO_OSPF;
            IPV6_NH_SCTP:     return PROTO_SCTP;
            default:          return PROTO_RAW_PAYLOAD;
        endcase
    endfunction

    // =========================================================================
    // UDP dst_port -> protocol mapping
    // =========================================================================
    static function protocol_type_e udp_dstport_to_proto(bit [15:0] port);
        case (port)
            16'd4789: return PROTO_VXLAN;
            16'd6081: return PROTO_GENEVE;
            16'd2152: return PROTO_GTP_U;
            16'd2123: return PROTO_GTP_C;
            16'd4791: return PROTO_ROCEV2;
            default:  return PROTO_RAW_PAYLOAD;
        endcase
    endfunction

    // =========================================================================
    // GRE protocol_type -> protocol mapping
    // =========================================================================
    static function protocol_type_e gre_proto_to_proto(bit [15:0] proto);
        case (proto)
            ETHERTYPE_IPV4:  return PROTO_IPV4;
            ETHERTYPE_IPV6:  return PROTO_IPV6;
            16'h6558:        return PROTO_ETHERNET;
            16'h88BE:        return PROTO_ERSPAN_II;
            16'h22EB:        return PROTO_ERSPAN_III;
            default:         return PROTO_RAW_PAYLOAD;
        endcase
    endfunction

    // =========================================================================
    // unpack — parse byte stream into layer_stack
    // =========================================================================
    function void unpack(byte unsigned data[$]);
        int offset = 0;
        protocol_type_e cur_proto;
        protocol_base hdr;

        layer_stack.delete();
        raw_data = data;

        if (data.size() < 14) return;  // minimum Ethernet

        // Start with Ethernet
        cur_proto = PROTO_ETHERNET;

        while (offset < data.size() && cur_proto != PROTO_RAW_PAYLOAD) begin
            hdr = create_header(cur_proto);
            if (hdr == null) break;

            if (offset + hdr.get_header_length() > data.size()) break;

            hdr.unpack_header(data, offset);
            layer_stack.push_back(hdr);

            cur_proto = identify_next_proto(hdr, data, offset);
        end
    endfunction

    // =========================================================================
    // to_proto_chain
    // =========================================================================
    function string to_proto_chain();
        string s = "";
        foreach (layer_stack[i]) begin
            if (i > 0) s = {s, " -> "};
            s = {s, layer_stack[i].proto_type.name()};
        end
        return s;
    endfunction

    // =========================================================================
    // to_brief
    // =========================================================================
    function string to_brief();
        string s;
        s = $sformatf("Packet [%0d layers, %0d bytes]: ", layer_stack.size(), raw_data.size());
        s = {s, to_proto_chain()};
        return s;
    endfunction

    // =========================================================================
    // to_detail
    // =========================================================================
    function string to_detail();
        string s = "";
        s = {s, to_brief(), "\n"};
        foreach (layer_stack[i]) begin
            s = {s, layer_stack[i].to_string()};
        end
        if (raw_data.size() > 0) begin
            s = {s, "--- Raw Data ---\n"};
            s = {s, packet_utils::hex_dump(raw_data), "\n"};
        end
        return s;
    endfunction

endclass

`endif // PACKET_SV
