// filelist.f
+incdir+src/common
+incdir+src/protocols
+incdir+src/protocols/l2
+incdir+src/protocols/l3
+incdir+src/protocols/l4
+incdir+src/protocols/tunnel
+incdir+src/core

src/common/packet_defines.sv
src/common/packet_utils.sv
src/protocols/protocol_base.sv
src/protocols/l2/eth_header.sv
src/protocols/l2/vlan_header.sv
src/protocols/l3/ipv4_header.sv
src/protocols/l3/ipv6_header.sv
src/protocols/l3/arp_header.sv
src/protocols/l4/tcp_header.sv
src/protocols/l4/udp_header.sv
src/protocols/l4/icmp_header.sv
src/protocols/l4/icmpv6_header.sv
src/protocols/tunnel/vxlan_header.sv
src/core/protocol_graph.sv
src/core/template_registry.sv
src/core/packet.sv
