// src/common/packet_defines.sv
`ifndef PACKET_DEFINES_SV
`define PACKET_DEFINES_SV

typedef enum int {
    // L2
    PROTO_ETHERNET      = 0,
    PROTO_VLAN          = 1,
    PROTO_QINQ          = 2,
    PROTO_MPLS          = 3,
    PROTO_MAC_CONTROL   = 4,
    PROTO_LLDP          = 5,
    PROTO_LACP          = 6,
    PROTO_STP           = 7,
    PROTO_MACSEC        = 8,
    PROTO_EAP           = 9,
    // L3
    PROTO_IPV4          = 10,
    PROTO_IPV6          = 11,
    PROTO_ARP           = 12,
    PROTO_IGMP          = 13,
    PROTO_IPV6_HBH      = 14,
    PROTO_IPV6_ROUTING  = 15,
    PROTO_IPV6_FRAGMENT = 16,
    PROTO_IPV6_DEST     = 17,
    PROTO_DHCP          = 18,
    PROTO_DHCPV6        = 19,
    PROTO_OSPF          = 20,
    PROTO_BGP           = 21,
    PROTO_ISIS          = 22,
    // L4
    PROTO_TCP           = 30,
    PROTO_UDP           = 31,
    PROTO_ICMP          = 32,
    PROTO_ICMPV6        = 33,
    PROTO_SCTP          = 34,
    // Tunnel
    PROTO_VXLAN         = 40,
    PROTO_GRE           = 41,
    PROTO_NVGRE         = 42,
    PROTO_GENEVE        = 43,
    PROTO_ERSPAN_I      = 44,
    PROTO_ERSPAN_II     = 45,
    PROTO_ERSPAN_III    = 46,
    PROTO_IP_IN_IP      = 47,
    PROTO_L2TP          = 48,
    PROTO_GTP_U         = 49,
    PROTO_GTP_C         = 50,
    PROTO_MPLS_GRE      = 51,
    PROTO_MPLS_UDP      = 52,
    // App/Mgmt
    PROTO_DNS           = 60,
    PROTO_HTTP          = 61,
    PROTO_SNMP          = 62,
    PROTO_BFD           = 63,
    PROTO_PTP           = 64,
    // Storage/RDMA
    PROTO_ROCEV2        = 70,
    PROTO_IWARP         = 71,
    PROTO_NVME_TCP      = 72,
    PROTO_NVME_RDMA     = 73,
    PROTO_ISCSI         = 74,
    // Special
    PROTO_RAW_PAYLOAD   = 99
} protocol_type_e;

typedef enum int {
    // Basic
    ETH_IPV4_TCP                        = 0,
    ETH_IPV4_UDP                        = 1,
    ETH_IPV6_TCP                        = 2,
    ETH_IPV6_UDP                        = 3,
    ETH_ARP                             = 4,
    ETH_IPV4_ICMP                       = 5,
    ETH_IPV6_ICMPV6                     = 6,
    // VLAN
    ETH_VLAN_IPV4_TCP                   = 10,
    ETH_VLAN_IPV4_UDP                   = 11,
    ETH_VLAN_IPV6_TCP                   = 12,
    ETH_VLAN_IPV6_UDP                   = 13,
    ETH_QINQ_IPV4_TCP                  = 14,
    ETH_QINQ_IPV4_UDP                  = 15,
    // Tunnel
    ETH_IPV4_UDP_VXLAN_ETH_IPV4_TCP    = 20,
    ETH_IPV4_UDP_VXLAN_ETH_IPV4_UDP    = 21,
    ETH_IPV4_UDP_VXLAN_ETH_IPV6_TCP    = 22,
    ETH_IPV4_GRE_IPV4_TCP              = 23,
    ETH_IPV4_GRE_IPV4_UDP              = 24,
    ETH_IPV4_UDP_GENEVE_ETH_IPV4_TCP   = 25,
    ETH_IPV4_GRE_ETH_IPV4_TCP          = 26,
    ETH_IPV4_GRE_ERSPAN_II_ETH_IPV4_TCP = 27,
    ETH_IPV4_UDP_GTP_U_IPV4_TCP        = 28,
    // VLAN + Tunnel
    ETH_VLAN_IPV4_UDP_VXLAN_ETH_IPV4_TCP = 30,
    // RDMA
    ETH_IPV4_UDP_ROCEV2                = 40,
    ETH_VLAN_IPV4_UDP_ROCEV2           = 41,
    // Storage
    ETH_IPV4_TCP_NVME_TCP              = 50,
    ETH_IPV4_UDP_ROCEV2_NVME_RDMA     = 51,
    ETH_IPV4_TCP_ISCSI                 = 52,
    // iWARP
    ETH_IPV4_TCP_IWARP                 = 53,
    // Mgmt/Control
    ETH_IPV4_UDP_DHCP                  = 60,
    ETH_IPV6_UDP_DHCPV6                = 61,
    ETH_IPV4_UDP_DNS                   = 62,
    ETH_IPV4_UDP_BFD                   = 63,
    ETH_IPV4_UDP_PTP                   = 64,
    ETH_PTP_L2                         = 65,
    ETH_IGMP                           = 66,
    ETH_LLDP                           = 67,
    ETH_LACP                           = 68,
    ETH_STP                            = 69,
    ETH_MAC_CONTROL                    = 70,
    // MPLS
    ETH_MPLS_IPV4_TCP                  = 80,
    ETH_MPLS_IPV4_UDP                  = 81
} packet_template_e;

typedef enum int {
    PAYLOAD_RANDOM    = 0,
    PAYLOAD_FIXED     = 1,
    PAYLOAD_INCREMENT = 2,
    PAYLOAD_PATTERN   = 3
} payload_mode_e;

typedef enum int {
    MOD_INCREMENT = 0,
    MOD_DECREMENT = 1,
    MOD_RANDOM    = 2,
    MOD_LIST      = 3
} modifier_mode_e;

typedef struct {
    bit              valid;
    protocol_type_e  proto_chain[$];
    string           errors[$];
    string           warnings[$];
} parse_result_t;

typedef struct {
    protocol_type_e  layer;
    string           field_name;
    string           val_a;
    string           val_b;
} diff_entry_t;

typedef enum bit [15:0] {
    ETHERTYPE_IPV4        = 16'h0800,
    ETHERTYPE_IPV6        = 16'h86DD,
    ETHERTYPE_ARP         = 16'h0806,
    ETHERTYPE_VLAN        = 16'h8100,
    ETHERTYPE_QINQ        = 16'h88A8,
    ETHERTYPE_MPLS_UNI    = 16'h8847,
    ETHERTYPE_MPLS_MULTI  = 16'h8848,
    ETHERTYPE_LLDP        = 16'h88CC,
    ETHERTYPE_PTP         = 16'h88F7,
    ETHERTYPE_MACSEC      = 16'h88E5,
    ETHERTYPE_EAP         = 16'h888E,
    ETHERTYPE_SLOW        = 16'h8809
} ethertype_e;

typedef enum bit [7:0] {
    IP_PROTO_ICMP     = 8'd1,
    IP_PROTO_IGMP     = 8'd2,
    IP_PROTO_IP_IN_IP = 8'd4,
    IP_PROTO_TCP      = 8'd6,
    IP_PROTO_UDP      = 8'd17,
    IP_PROTO_IPV6     = 8'd41,
    IP_PROTO_GRE      = 8'd47,
    IP_PROTO_ICMPV6   = 8'd58,
    IP_PROTO_OSPF     = 8'd89,
    IP_PROTO_SCTP     = 8'd132,
    IP_PROTO_L2TP     = 8'd115
} ip_protocol_e;

typedef enum bit [7:0] {
    IPV6_NH_HBH       = 8'd0,
    IPV6_NH_TCP        = 8'd6,
    IPV6_NH_UDP        = 8'd17,
    IPV6_NH_IPV6       = 8'd41,
    IPV6_NH_ROUTING    = 8'd43,
    IPV6_NH_FRAGMENT   = 8'd44,
    IPV6_NH_GRE        = 8'd47,
    IPV6_NH_ICMPV6     = 8'd58,
    IPV6_NH_DEST       = 8'd60,
    IPV6_NH_OSPF       = 8'd89,
    IPV6_NH_SCTP       = 8'd132
} ipv6_next_header_e;

`endif // PACKET_DEFINES_SV
