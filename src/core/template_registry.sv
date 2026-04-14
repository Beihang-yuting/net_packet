// src/core/template_registry.sv
`ifndef TEMPLATE_REGISTRY_SV
`define TEMPLATE_REGISTRY_SV

`include "packet_defines.sv"

class template_registry;

    protected protocol_type_e chains[packet_template_e][$];

    function new();
        init_default_templates();
    endfunction

    function void register_template(packet_template_e tmpl, protocol_type_e chain[$]);
        chains[tmpl] = chain;
    endfunction

    function void get_chain(packet_template_e tmpl, ref protocol_type_e chain[$]);
        chain.delete();
        if (chains.exists(tmpl)) begin
            chain = chains[tmpl];
        end
    endfunction

    protected function void init_default_templates();
        protocol_type_e c[$];

        // =========================================================
        // Basic: ETH + L3 + L4 (no tunnel)
        // =========================================================

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_ICMP};
        register_template(ETH_IPV4_ICMP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_SCTP};
        register_template(ETH_IPV4_SCTP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV6_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_ICMPV6};
        register_template(ETH_IPV6_ICMPV6, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_SCTP};
        register_template(ETH_IPV6_SCTP, c);

        c = '{PROTO_ETHERNET, PROTO_ARP};
        register_template(ETH_ARP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_IGMP};
        register_template(ETH_IGMP, c);

        // =========================================================
        // MPLS: ETH + MPLS + L3 + L4
        // =========================================================

        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_MPLS_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_MPLS_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV4, PROTO_ICMP};
        register_template(ETH_MPLS_IPV4_ICMP, c);

        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV4, PROTO_SCTP};
        register_template(ETH_MPLS_IPV4_SCTP, c);

        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_MPLS_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_MPLS_IPV6_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV6, PROTO_ICMPV6};
        register_template(ETH_MPLS_IPV6_ICMPV6, c);

        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV6, PROTO_SCTP};
        register_template(ETH_MPLS_IPV6_SCTP, c);

        // =========================================================
        // IPsec ESP: ETH + L3 + ESP
        // =========================================================

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_ESP};
        register_template(ETH_IPV4_ESP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_ESP};
        register_template(ETH_IPV6_ESP, c);

        // =========================================================
        // VXLAN: ETH + outer_L3 + UDP + VXLAN + ETH + inner_L3 + inner_L4
        // =========================================================

        // Outer IPv4
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_UDP_VXLAN_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_UDP_VXLAN_ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV4_UDP_VXLAN_ETH_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV4_UDP_VXLAN_ETH_IPV6_UDP, c);

        // Outer IPv6
        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV6_UDP_VXLAN_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV6_UDP_VXLAN_ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV6_UDP_VXLAN_ETH_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV6_UDP_VXLAN_ETH_IPV6_UDP, c);

        // =========================================================
        // Geneve: ETH + outer_L3 + UDP + Geneve + ETH + inner_L3 + inner_L4
        // =========================================================

        // Outer IPv4
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_UDP_GENEVE_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_UDP_GENEVE_ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV4_UDP_GENEVE_ETH_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV4_UDP_GENEVE_ETH_IPV6_UDP, c);

        // Outer IPv6
        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV6_UDP_GENEVE_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV6_UDP_GENEVE_ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV6_UDP_GENEVE_ETH_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV6_UDP_GENEVE_ETH_IPV6_UDP, c);

        // =========================================================
        // GRE L3: ETH + outer_L3 + GRE + inner_L3 + inner_L4 (no inner ETH)
        // =========================================================

        // Outer IPv4
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_GRE_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_GRE_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV4_GRE_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV4_GRE_IPV6_UDP, c);

        // Outer IPv6
        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV6_GRE_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV6_GRE_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV6_GRE_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV6_GRE_IPV6_UDP, c);

        // =========================================================
        // NVGRE (GRE L2): ETH + outer_L3 + GRE + ETH + inner_L3 + inner_L4
        // =========================================================

        // Outer IPv4
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_GRE_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_GRE_ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV4_GRE_ETH_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV4_GRE_ETH_IPV6_UDP, c);

        // Outer IPv6
        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV6_GRE_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV6_GRE_ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV6_GRE_ETH_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV6_GRE_ETH_IPV6_UDP, c);

        // =========================================================
        // GTP-U: ETH + outer_L3 + UDP + GTP-U + inner_L3 + inner_L4
        // =========================================================

        // Outer IPv4
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GTP_U, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_UDP_GTP_U_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GTP_U, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_UDP_GTP_U_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GTP_U, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV4_UDP_GTP_U_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GTP_U, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV4_UDP_GTP_U_IPV6_UDP, c);

        // Outer IPv6
        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_GTP_U, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV6_UDP_GTP_U_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_GTP_U, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV6_UDP_GTP_U_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_GTP_U, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV6_UDP_GTP_U_IPV6_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_GTP_U, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV6_UDP_GTP_U_IPV6_UDP, c);

        // =========================================================
        // ERSPAN: ETH + outer_L3 + GRE + ERSPAN + ETH + inner_L3 + inner_L4
        // =========================================================

        // ERSPAN Type II
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ERSPAN_II, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_GRE_ERSPAN_II_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ERSPAN_II, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_GRE_ERSPAN_II_ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_ERSPAN_II, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV6_GRE_ERSPAN_II_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_ERSPAN_II, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV6_GRE_ERSPAN_II_ETH_IPV4_UDP, c);

        // ERSPAN Type III
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ERSPAN_III, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_GRE_ERSPAN_III_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ERSPAN_III, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_GRE_ERSPAN_III_ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_ERSPAN_III, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV6_GRE_ERSPAN_III_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_GRE, PROTO_ERSPAN_III, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV6_GRE_ERSPAN_III_ETH_IPV4_UDP, c);

        // =========================================================
        // VXLAN-GPE: ETH + outer_L3 + UDP + VXLAN-GPE + [ETH] + inner_L3 + inner_L4
        // =========================================================

        // With inner ETH (L2 mode)
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN_GPE, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_UDP_VXLAN_GPE_ETH_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN_GPE, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_UDP_VXLAN_GPE_ETH_IPV4_UDP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_VXLAN_GPE, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV6_UDP_VXLAN_GPE_ETH_IPV4_TCP, c);

        // Without inner ETH (L3 mode)
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN_GPE, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_UDP_VXLAN_GPE_IPV4_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN_GPE, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV4_UDP_VXLAN_GPE_IPV6_TCP, c);

        // =========================================================
        // RDMA: ETH + L3 + UDP + RoCEv2 [+ NVMe-RDMA]
        // =========================================================

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_ROCEV2};
        register_template(ETH_IPV4_UDP_ROCEV2, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_ROCEV2};
        register_template(ETH_IPV6_UDP_ROCEV2, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_ROCEV2, PROTO_NVME_RDMA};
        register_template(ETH_IPV4_UDP_ROCEV2_NVME_RDMA, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_ROCEV2, PROTO_NVME_RDMA};
        register_template(ETH_IPV6_UDP_ROCEV2_NVME_RDMA, c);

        // =========================================================
        // Storage over TCP: ETH + L3 + TCP + {NVMe-TCP, iSCSI, iWARP}
        // =========================================================

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP, PROTO_NVME_TCP};
        register_template(ETH_IPV4_TCP_NVME_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP, PROTO_NVME_TCP};
        register_template(ETH_IPV6_TCP_NVME_TCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP, PROTO_ISCSI};
        register_template(ETH_IPV4_TCP_ISCSI, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP, PROTO_ISCSI};
        register_template(ETH_IPV6_TCP_ISCSI, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP, PROTO_IWARP};
        register_template(ETH_IPV4_TCP_IWARP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP, PROTO_IWARP};
        register_template(ETH_IPV6_TCP_IWARP, c);

        // =========================================================
        // Mgmt/Control
        // =========================================================

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_DHCP};
        register_template(ETH_IPV4_UDP_DHCP, c);

        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_DHCPV6};
        register_template(ETH_IPV6_UDP_DHCPV6, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_DNS};
        register_template(ETH_IPV4_UDP_DNS, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_BFD};
        register_template(ETH_IPV4_UDP_BFD, c);

        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_PTP};
        register_template(ETH_IPV4_UDP_PTP, c);

        c = '{PROTO_ETHERNET, PROTO_PTP};
        register_template(ETH_PTP_L2, c);

        c = '{PROTO_ETHERNET, PROTO_LLDP};
        register_template(ETH_LLDP, c);

        c = '{PROTO_ETHERNET, PROTO_LACP};
        register_template(ETH_LACP, c);

        c = '{PROTO_ETHERNET, PROTO_STP};
        register_template(ETH_STP, c);

        c = '{PROTO_ETHERNET, PROTO_MAC_CONTROL};
        register_template(ETH_MAC_CONTROL, c);

    endfunction

endclass

`endif // TEMPLATE_REGISTRY_SV
