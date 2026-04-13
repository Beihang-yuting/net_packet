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

        // --- Basic ---

        // ETH_IPV4_TCP = 0
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_TCP, c);

        // ETH_IPV4_UDP = 1
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_UDP, c);

        // ETH_IPV6_TCP = 2
        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV6_TCP, c);

        // ETH_IPV6_UDP = 3
        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_IPV6_UDP, c);

        // ETH_ARP = 4
        c = '{PROTO_ETHERNET, PROTO_ARP};
        register_template(ETH_ARP, c);

        // ETH_IPV4_ICMP = 5
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_ICMP};
        register_template(ETH_IPV4_ICMP, c);

        // ETH_IPV6_ICMPV6 = 6
        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_ICMPV6};
        register_template(ETH_IPV6_ICMPV6, c);

        // --- VLAN ---

        // ETH_VLAN_IPV4_TCP = 10
        c = '{PROTO_ETHERNET, PROTO_VLAN, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_VLAN_IPV4_TCP, c);

        // ETH_VLAN_IPV4_UDP = 11
        c = '{PROTO_ETHERNET, PROTO_VLAN, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_VLAN_IPV4_UDP, c);

        // ETH_VLAN_IPV6_TCP = 12
        c = '{PROTO_ETHERNET, PROTO_VLAN, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_VLAN_IPV6_TCP, c);

        // ETH_VLAN_IPV6_UDP = 13
        c = '{PROTO_ETHERNET, PROTO_VLAN, PROTO_IPV6, PROTO_UDP};
        register_template(ETH_VLAN_IPV6_UDP, c);

        // ETH_QINQ_IPV4_TCP = 14
        c = '{PROTO_ETHERNET, PROTO_QINQ, PROTO_VLAN, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_QINQ_IPV4_TCP, c);

        // ETH_QINQ_IPV4_UDP = 15
        c = '{PROTO_ETHERNET, PROTO_QINQ, PROTO_VLAN, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_QINQ_IPV4_UDP, c);

        // --- Tunnel ---

        // ETH_IPV4_UDP_VXLAN_ETH_IPV4_TCP = 20
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_UDP_VXLAN_ETH_IPV4_TCP, c);

        // ETH_IPV4_UDP_VXLAN_ETH_IPV4_UDP = 21
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_UDP_VXLAN_ETH_IPV4_UDP, c);

        // ETH_IPV4_UDP_VXLAN_ETH_IPV6_TCP = 22
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV6, PROTO_TCP};
        register_template(ETH_IPV4_UDP_VXLAN_ETH_IPV6_TCP, c);

        // ETH_IPV4_GRE_IPV4_TCP = 23
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_GRE_IPV4_TCP, c);

        // ETH_IPV4_GRE_IPV4_UDP = 24
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_IPV4_GRE_IPV4_UDP, c);

        // ETH_IPV4_UDP_GENEVE_ETH_IPV4_TCP = 25
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GENEVE, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_UDP_GENEVE_ETH_IPV4_TCP, c);

        // ETH_IPV4_GRE_ETH_IPV4_TCP = 26
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_GRE_ETH_IPV4_TCP, c);

        // ETH_IPV4_GRE_ERSPAN_II_ETH_IPV4_TCP = 27
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_GRE, PROTO_ERSPAN_II, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_GRE_ERSPAN_II_ETH_IPV4_TCP, c);

        // ETH_IPV4_UDP_GTP_U_IPV4_TCP = 28
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_GTP_U, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_IPV4_UDP_GTP_U_IPV4_TCP, c);

        // --- VLAN + Tunnel ---

        // ETH_VLAN_IPV4_UDP_VXLAN_ETH_IPV4_TCP = 30
        c = '{PROTO_ETHERNET, PROTO_VLAN, PROTO_IPV4, PROTO_UDP, PROTO_VXLAN, PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_VLAN_IPV4_UDP_VXLAN_ETH_IPV4_TCP, c);

        // --- RDMA ---

        // ETH_IPV4_UDP_ROCEV2 = 40
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_ROCEV2};
        register_template(ETH_IPV4_UDP_ROCEV2, c);

        // ETH_VLAN_IPV4_UDP_ROCEV2 = 41
        c = '{PROTO_ETHERNET, PROTO_VLAN, PROTO_IPV4, PROTO_UDP, PROTO_ROCEV2};
        register_template(ETH_VLAN_IPV4_UDP_ROCEV2, c);

        // --- Storage ---

        // ETH_IPV4_TCP_NVME_TCP = 50
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP, PROTO_NVME_TCP};
        register_template(ETH_IPV4_TCP_NVME_TCP, c);

        // ETH_IPV4_UDP_ROCEV2_NVME_RDMA = 51
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_ROCEV2, PROTO_NVME_RDMA};
        register_template(ETH_IPV4_UDP_ROCEV2_NVME_RDMA, c);

        // ETH_IPV4_TCP_ISCSI = 52
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP, PROTO_ISCSI};
        register_template(ETH_IPV4_TCP_ISCSI, c);

        // ETH_IPV4_TCP_IWARP = 53
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_TCP, PROTO_IWARP};
        register_template(ETH_IPV4_TCP_IWARP, c);

        // --- Mgmt/Control ---

        // ETH_IPV4_UDP_DHCP = 60
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_DHCP};
        register_template(ETH_IPV4_UDP_DHCP, c);

        // ETH_IPV6_UDP_DHCPV6 = 61
        c = '{PROTO_ETHERNET, PROTO_IPV6, PROTO_UDP, PROTO_DHCPV6};
        register_template(ETH_IPV6_UDP_DHCPV6, c);

        // ETH_IPV4_UDP_DNS = 62
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_DNS};
        register_template(ETH_IPV4_UDP_DNS, c);

        // ETH_IPV4_UDP_BFD = 63
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_BFD};
        register_template(ETH_IPV4_UDP_BFD, c);

        // ETH_IPV4_UDP_PTP = 64
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_UDP, PROTO_PTP};
        register_template(ETH_IPV4_UDP_PTP, c);

        // ETH_PTP_L2 = 65
        c = '{PROTO_ETHERNET, PROTO_PTP};
        register_template(ETH_PTP_L2, c);

        // ETH_IGMP = 66
        c = '{PROTO_ETHERNET, PROTO_IPV4, PROTO_IGMP};
        register_template(ETH_IGMP, c);

        // ETH_LLDP = 67
        c = '{PROTO_ETHERNET, PROTO_LLDP};
        register_template(ETH_LLDP, c);

        // ETH_LACP = 68
        c = '{PROTO_ETHERNET, PROTO_LACP};
        register_template(ETH_LACP, c);

        // ETH_STP = 69
        c = '{PROTO_ETHERNET, PROTO_STP};
        register_template(ETH_STP, c);

        // ETH_MAC_CONTROL = 70
        c = '{PROTO_ETHERNET, PROTO_MAC_CONTROL};
        register_template(ETH_MAC_CONTROL, c);

        // --- MPLS ---

        // ETH_MPLS_IPV4_TCP = 80
        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV4, PROTO_TCP};
        register_template(ETH_MPLS_IPV4_TCP, c);

        // ETH_MPLS_IPV4_UDP = 81
        c = '{PROTO_ETHERNET, PROTO_MPLS, PROTO_IPV4, PROTO_UDP};
        register_template(ETH_MPLS_IPV4_UDP, c);

    endfunction

endclass

`endif // TEMPLATE_REGISTRY_SV
