// src/parser/protocol_parser.sv
`ifndef PROTOCOL_PARSER_SV
`define PROTOCOL_PARSER_SV

`include "core/packet.sv"

class protocol_parser;

    // Parse raw bytes into a packet object
    function packet parse(byte unsigned data[$]);
        packet pkt = new();
        pkt.unpack(data);
        return pkt;
    endfunction

    // Validate a packet's protocol chain against the protocol graph
    function parse_result_t validate(packet pkt);
        parse_result_t result;
        protocol_type_e chain[$];

        result.valid = 1;

        if (pkt.layer_stack.size() == 0) begin
            result.valid = 0;
            result.errors.push_back("Empty packet: no layers");
            return result;
        end

        // Build chain
        foreach (pkt.layer_stack[i])
            chain.push_back(pkt.layer_stack[i].proto_type);
        result.proto_chain = chain;

        // First layer should be Ethernet
        if (chain[0] != PROTO_ETHERNET) begin
            result.warnings.push_back($sformatf("First layer is %s, expected PROTO_ETHERNET", chain[0].name()));
        end

        // Validate transitions
        for (int i = 0; i < int'(chain.size()) - 1; i++) begin
            if (!pkt.s_graph.is_valid_next(chain[i], chain[i+1])) begin
                result.valid = 0;
                result.errors.push_back($sformatf("Invalid transition: %s -> %s at layer %0d",
                    chain[i].name(), chain[i+1].name(), i));
            end
        end

        // Check for minimum header sizes
        foreach (pkt.layer_stack[i]) begin
            if (pkt.layer_stack[i].get_header_length() < 0) begin
                result.valid = 0;
                result.errors.push_back($sformatf("Invalid header length at layer %0d (%s)",
                    i, chain[i].name()));
            end
        end

        return result;
    endfunction

endclass

`endif // PROTOCOL_PARSER_SV
