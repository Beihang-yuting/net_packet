// src/common/packet_utils.sv
`ifndef PACKET_UTILS_SV
`define PACKET_UTILS_SV

class packet_utils;

    static function bit [15:0] ones_complement_checksum(byte unsigned data[$]);
        bit [31:0] sum = 0;
        int len = data.size();
        int i = 0;
        while (i < len - 1) begin
            sum += {data[i], data[i+1]};
            i += 2;
        end
        if (i < len) begin
            sum += {data[i], 8'h00};
        end
        while (sum[31:16] != 0) begin
            sum = sum[15:0] + sum[31:16];
        end
        return ~sum[15:0];
    endfunction

    static function bit [15:0] byte_swap_16(bit [15:0] val);
        return {val[7:0], val[15:8]};
    endfunction

    static function bit [31:0] byte_swap_32(bit [31:0] val);
        return {val[7:0], val[15:8], val[23:16], val[31:24]};
    endfunction

    static function void pack_bytes_16(ref byte unsigned data[$], bit [15:0] val);
        data.push_back(val[15:8]);
        data.push_back(val[7:0]);
    endfunction

    static function void pack_bytes_32(ref byte unsigned data[$], bit [31:0] val);
        data.push_back(val[31:24]);
        data.push_back(val[23:16]);
        data.push_back(val[15:8]);
        data.push_back(val[7:0]);
    endfunction

    static function void pack_bytes_48(ref byte unsigned data[$], bit [47:0] val);
        data.push_back(val[47:40]);
        data.push_back(val[39:32]);
        data.push_back(val[31:24]);
        data.push_back(val[23:16]);
        data.push_back(val[15:8]);
        data.push_back(val[7:0]);
    endfunction

    static function bit [15:0] unpack_bytes_16(byte unsigned data[$], ref int offset);
        bit [15:0] val = {data[offset], data[offset+1]};
        offset += 2;
        return val;
    endfunction

    static function bit [31:0] unpack_bytes_32(byte unsigned data[$], ref int offset);
        bit [31:0] val = {data[offset], data[offset+1], data[offset+2], data[offset+3]};
        offset += 4;
        return val;
    endfunction

    static function bit [47:0] unpack_bytes_48(byte unsigned data[$], ref int offset);
        bit [47:0] val = {data[offset], data[offset+1], data[offset+2],
                          data[offset+3], data[offset+4], data[offset+5]};
        offset += 6;
        return val;
    endfunction

    static function void pack_bytes_64(ref byte unsigned data[$], bit [63:0] val);
        data.push_back(val[63:56]);
        data.push_back(val[55:48]);
        data.push_back(val[47:40]);
        data.push_back(val[39:32]);
        data.push_back(val[31:24]);
        data.push_back(val[23:16]);
        data.push_back(val[15:8]);
        data.push_back(val[7:0]);
    endfunction

    static function bit [63:0] unpack_bytes_64(byte unsigned data[$], ref int offset);
        bit [63:0] val = {data[offset],   data[offset+1], data[offset+2], data[offset+3],
                          data[offset+4], data[offset+5], data[offset+6], data[offset+7]};
        offset += 8;
        return val;
    endfunction

    static function string format_mac(bit [47:0] mac);
        return $sformatf("%02x:%02x:%02x:%02x:%02x:%02x",
                         mac[47:40], mac[39:32], mac[31:24],
                         mac[23:16], mac[15:8], mac[7:0]);
    endfunction

    static function string format_ipv4(bit [31:0] ip);
        return $sformatf("%0d.%0d.%0d.%0d",
                         ip[31:24], ip[23:16], ip[15:8], ip[7:0]);
    endfunction

    static function string format_ipv6(bit [127:0] ip);
        return $sformatf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                         ip[127:112], ip[111:96], ip[95:80], ip[79:64],
                         ip[63:48], ip[47:32], ip[31:16], ip[15:0]);
    endfunction

    static function string hex_dump(byte unsigned data[$], int bytes_per_line = 16);
        string result = "";
        for (int i = 0; i < data.size(); i++) begin
            if (i % bytes_per_line == 0) begin
                if (i > 0) result = {result, "\n"};
                result = {result, $sformatf("  %04x: ", i)};
            end
            result = {result, $sformatf("%02x ", data[i])};
        end
        return result;
    endfunction

endclass

`endif // PACKET_UTILS_SV
