// src/protocols/rdma/rocev2_header.sv
`ifndef ROCEV2_HEADER_SV
`define ROCEV2_HEADER_SV

`include "protocol_base.sv"

class rocev2_bth extends protocol_base;

    // === BTH fields (12 bytes) ===
    rand bit [7:0]  opcode;
    rand bit        se;
    rand bit        mig_req;
    rand bit [1:0]  pad_count;
    rand bit [3:0]  tver;
    rand bit [15:0] pkey;
    rand bit [23:0] dest_qp;
    rand bit        ack_req;
    rand bit [6:0]  reserved1;
    rand bit [23:0] psn;
    rand bit [7:0]  reserved2;

    // === RETH fields (16 bytes, conditional) ===
    rand bit [63:0] reth_va;
    rand bit [31:0] reth_r_key;
    rand bit [31:0] reth_dma_len;

    // === AETH fields (4 bytes, conditional) ===
    rand bit [7:0]  aeth_syndrome;
    rand bit [23:0] aeth_msn;

    // === ImmDt fields (4 bytes, conditional) ===
    rand bit [31:0] imm_data;

    // === ICRC (4 bytes, trailer) ===
    bit             icrc_enable;
    bit [31:0]      icrc;

    constraint c_default {
        soft tver      == 4'd0;
        soft reserved1 == 0;
        soft reserved2 == 0;
        soft pad_count == 0;
        soft se        == 0;
        soft mig_req   == 0;
    }

    function new();
        proto_type    = PROTO_ROCEV2;
        opcode        = 8'h04;     // Send Only
        se            = 0;
        mig_req       = 0;
        pad_count     = 0;
        tver          = 0;
        pkey          = 16'hFFFF;
        dest_qp       = 0;
        ack_req       = 0;
        reserved1     = 0;
        psn           = 0;
        reserved2     = 0;
        reth_va       = 0;
        reth_r_key    = 0;
        reth_dma_len  = 0;
        aeth_syndrome = 0;
        aeth_msn      = 0;
        imm_data      = 0;
        icrc_enable   = 1;
        icrc          = 0;
    endfunction

    static function rocev2_bth create(bit [7:0] op = 8'h04, bit [23:0] qp = 0);
        rocev2_bth h = new();
        h.opcode  = op;
        h.dest_qp = qp;
        return h;
    endfunction

    // --- Opcode classification helpers ---
    function bit has_reth();
        return (opcode == 8'h06) || (opcode == 8'h0A) || (opcode == 8'h0B) || (opcode == 8'h0C);
    endfunction

    function bit has_aeth();
        return (opcode == 8'h0D) || (opcode == 8'h0F) || (opcode == 8'h10) || (opcode == 8'h11);
    endfunction

    function bit has_immdt();
        return (opcode == 8'h03) || (opcode == 8'h05) || (opcode == 8'h09) || (opcode == 8'h0B);
    endfunction

    virtual function void pack_header(ref byte unsigned data[$]);
        // BTH (12 bytes)
        bit [31:0] word0 = {opcode, se, mig_req, pad_count, tver, pkey};
        bit [31:0] word1 = {dest_qp, ack_req, reserved1};
        bit [31:0] word2 = {psn, reserved2};
        packet_utils::pack_bytes_32(data, word0);
        packet_utils::pack_bytes_32(data, word1);
        packet_utils::pack_bytes_32(data, word2);

        // RETH (16 bytes)
        if (has_reth()) begin
            packet_utils::pack_bytes_32(data, reth_va[63:32]);
            packet_utils::pack_bytes_32(data, reth_va[31:0]);
            packet_utils::pack_bytes_32(data, reth_r_key);
            packet_utils::pack_bytes_32(data, reth_dma_len);
        end

        // AETH (4 bytes)
        if (has_aeth()) begin
            packet_utils::pack_bytes_32(data, {aeth_syndrome, aeth_msn});
        end

        // ImmDt (4 bytes)
        if (has_immdt()) begin
            packet_utils::pack_bytes_32(data, imm_data);
        end

        // ICRC (4 bytes)
        if (icrc_enable) begin
            packet_utils::pack_bytes_32(data, icrc);
        end
    endfunction

    virtual function void unpack_header(ref byte unsigned data[$], ref int offset);
        bit [31:0] word0, word1, word2;
        // BTH
        word0 = packet_utils::unpack_bytes_32(data, offset);
        word1 = packet_utils::unpack_bytes_32(data, offset);
        word2 = packet_utils::unpack_bytes_32(data, offset);
        opcode    = word0[31:24];
        se        = word0[23];
        mig_req   = word0[22];
        pad_count = word0[21:20];
        tver      = word0[19:16];
        pkey      = word0[15:0];
        dest_qp   = word1[31:8];
        ack_req   = word1[7];
        reserved1 = word1[6:0];
        psn       = word2[31:8];
        reserved2 = word2[7:0];

        // RETH (opcode already parsed, has_reth works)
        if (has_reth()) begin
            reth_va[63:32] = packet_utils::unpack_bytes_32(data, offset);
            reth_va[31:0]  = packet_utils::unpack_bytes_32(data, offset);
            reth_r_key     = packet_utils::unpack_bytes_32(data, offset);
            reth_dma_len   = packet_utils::unpack_bytes_32(data, offset);
        end

        // AETH
        if (has_aeth()) begin
            bit [31:0] aeth_word = packet_utils::unpack_bytes_32(data, offset);
            aeth_syndrome = aeth_word[31:24];
            aeth_msn      = aeth_word[23:0];
        end

        // ImmDt
        if (has_immdt()) begin
            imm_data = packet_utils::unpack_bytes_32(data, offset);
        end

        // ICRC
        if (icrc_enable) begin
            icrc = packet_utils::unpack_bytes_32(data, offset);
        end
    endfunction

    virtual function int get_header_length();
        int len = 12;  // BTH
        if (has_reth())  len += 16;
        if (has_aeth())  len += 4;
        if (has_immdt()) len += 4;
        if (icrc_enable) len += 4;
        return len;
    endfunction

    virtual function void calc_fields(byte unsigned payload_data[$], protocol_type_e next_proto);
        if (!auto_calc) return;
        tver = 0;
        // Simple ICRC placeholder
        if (icrc_enable) begin
            byte unsigned icrc_data[$];
            bit saved = icrc_enable;
            icrc_enable = 0;
            pack_header(icrc_data);
            icrc_enable = saved;
            foreach (payload_data[i]) icrc_data.push_back(payload_data[i]);
            icrc = 32'h0;
            foreach (icrc_data[i])
                icrc = icrc ^ ({24'h0, icrc_data[i]} << ((i % 4) * 8));
        end
    endfunction

    virtual function protocol_base clone();
        rocev2_bth h = new();
        h.opcode        = opcode;
        h.se            = se;
        h.mig_req       = mig_req;
        h.pad_count     = pad_count;
        h.tver          = tver;
        h.pkey          = pkey;
        h.dest_qp       = dest_qp;
        h.ack_req       = ack_req;
        h.reserved1     = reserved1;
        h.psn           = psn;
        h.reserved2     = reserved2;
        h.reth_va       = reth_va;
        h.reth_r_key    = reth_r_key;
        h.reth_dma_len  = reth_dma_len;
        h.aeth_syndrome = aeth_syndrome;
        h.aeth_msn      = aeth_msn;
        h.imm_data      = imm_data;
        h.icrc_enable   = icrc_enable;
        h.icrc          = icrc;
        h.auto_calc     = auto_calc;
        return h;
    endfunction

    virtual function bit compare(protocol_base other);
        rocev2_bth o;
        if (!$cast(o, other)) return 0;
        if (opcode != o.opcode || pkey != o.pkey) return 0;
        if (dest_qp != o.dest_qp || psn != o.psn) return 0;
        if (has_reth())
            if (reth_va != o.reth_va || reth_r_key != o.reth_r_key || reth_dma_len != o.reth_dma_len) return 0;
        if (has_aeth())
            if (aeth_syndrome != o.aeth_syndrome || aeth_msn != o.aeth_msn) return 0;
        if (has_immdt())
            if (imm_data != o.imm_data) return 0;
        return 1;
    endfunction

    virtual function string to_string();
        string s;
        s = $sformatf("=== %s (BTH) ===\n", proto_type.name());
        s = {s, $sformatf("  opcode   : 0x%02x\n", opcode)};
        s = {s, $sformatf("  se       : %0b\n", se)};
        s = {s, $sformatf("  mig_req  : %0b\n", mig_req)};
        s = {s, $sformatf("  pad_count: %0d\n", pad_count)};
        s = {s, $sformatf("  tver     : %0d\n", tver)};
        s = {s, $sformatf("  pkey     : 0x%04x\n", pkey)};
        s = {s, $sformatf("  dest_qp  : 0x%06x\n", dest_qp)};
        s = {s, $sformatf("  ack_req  : %0b\n", ack_req)};
        s = {s, $sformatf("  psn      : 0x%06x\n", psn)};
        if (has_reth()) begin
            s = {s, "  --- RETH ---\n"};
            s = {s, $sformatf("  va       : 0x%016x\n", reth_va)};
            s = {s, $sformatf("  r_key    : 0x%08x\n", reth_r_key)};
            s = {s, $sformatf("  dma_len  : %0d\n", reth_dma_len)};
        end
        if (has_aeth()) begin
            s = {s, "  --- AETH ---\n"};
            s = {s, $sformatf("  syndrome : 0x%02x\n", aeth_syndrome)};
            s = {s, $sformatf("  msn      : 0x%06x\n", aeth_msn)};
        end
        if (has_immdt())
            s = {s, $sformatf("  --- ImmDt: 0x%08x ---\n", imm_data)};
        if (icrc_enable)
            s = {s, $sformatf("  icrc     : 0x%08x\n", icrc)};
        return s;
    endfunction

    virtual function string to_brief();
        string s = $sformatf("RoCEv2 op:0x%02x qp:0x%06x psn:0x%06x", opcode, dest_qp, psn);
        if (has_reth()) s = {s, $sformatf(" rkey:0x%08x", reth_r_key)};
        if (has_aeth()) s = {s, $sformatf(" syn:0x%02x", aeth_syndrome)};
        if (has_immdt()) s = {s, $sformatf(" imm:0x%08x", imm_data)};
        return s;
    endfunction

endclass

`endif // ROCEV2_HEADER_SV
