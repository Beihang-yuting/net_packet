// src/protocols/app/ptp_header.sv
`ifndef PTP_HEADER_SV
`define PTP_HEADER_SV

`include "protocol_base.sv"

// PTP Common Header (34 bytes)
// IEEE 1588v2
// Wire format:
//   Byte 0    : {transport_specific[3:0], message_type[3:0]}
//   Byte 1    : {version_ptp[3:0], reserved1[3:0]}
//   Bytes 2-3 : message_length (16-bit)
//   Byte 4    : domain_number (8-bit)
//   Byte 5    : reserved2 (8-bit)
//   Bytes 6-7 : flag_field (16-bit)
//   Bytes 8-15: correction_field (64-bit, signed ns * 2^16)
//   Bytes 16-19: reserved3 (32-bit)
//   Bytes 20-27: clock_identity (64-bit)
//   Bytes 28-29: port_number (16-bit)
//   Bytes 30-31: sequence_id (16-bit)
//   Byte 32   : control_field (8-bit)
//   Byte 33   : log_message_interval (8-bit, signed)

class ptp_header extends protocol_base;

    rand bit [3:0]  transport_specific;
    rand bit [3:0]  message_type;
    rand bit [3:0]  version_ptp;
    rand bit [3:0]  reserved1;
    rand bit [15:0] message_length;
    rand bit [7:0]  domain_number;
    rand bit [7:0]  reserved2;
    rand bit [15:0] flag_field;
    rand bit [63:0] correction_field;
    rand bit [31:0] reserved3;
    rand bit [63:0] clock_identity;
    rand bit [15:0] port_number;
    rand bit [15:0] sequence_id;
    rand bit [7:0]  control_field;
    rand bit [7:0]  log_message_interval;

    function new();
        proto_type           = PROTO_PTP;
        transport_specific   = 4'd0;
        message_type         = 4'd0;   // Sync
        version_ptp          = 4'd2;
        reserved1            = 4'd0;
        message_length       = 16'd34;
        domain_number        = 8'd0;
        reserved2            = 8'd0;
        flag_field           = 16'd0;
        correction_field     = 64'd0;
        reserved3            = 32'd0;
        clock_identity       = 64'd0;
        port_number          = 16'd1;
        sequence_id          = 16'd0;
        control_field        = 8'd0;
        log_message_interval = 8'd0;
    endfunction

    static function ptp_header create(bit [3:0] msg_type = 0);
        ptp_header h = new();
        h.message_type = msg_type;
        return h;
    endfunction

    virtual function void pack_header(ref byte unsigned data[$]);
        data.push_back({transport_specific, message_type});
        data.push_back({version_ptp, reserved1});
        packet_utils::pack_bytes_16(data, message_length);
        data.push_back(domain_number);
        data.push_back(reserved2);
        packet_utils::pack_bytes_16(data, flag_field);
        packet_utils::pack_bytes_64(data, correction_field);
        packet_utils::pack_bytes_32(data, reserved3);
        packet_utils::pack_bytes_64(data, clock_identity);
        packet_utils::pack_bytes_16(data, port_number);
        packet_utils::pack_bytes_16(data, sequence_id);
        data.push_back(control_field);
        data.push_back(log_message_interval);
    endfunction

    virtual function void unpack_header(ref byte unsigned data[$], ref int offset);
        bit [7:0] b;
        b                    = data[offset]; offset++;
        transport_specific   = b[7:4];
        message_type         = b[3:0];
        b                    = data[offset]; offset++;
        version_ptp          = b[7:4];
        reserved1            = b[3:0];
        message_length       = packet_utils::unpack_bytes_16(data, offset);
        domain_number        = data[offset]; offset++;
        reserved2            = data[offset]; offset++;
        flag_field           = packet_utils::unpack_bytes_16(data, offset);
        correction_field     = packet_utils::unpack_bytes_64(data, offset);
        reserved3            = packet_utils::unpack_bytes_32(data, offset);
        clock_identity       = packet_utils::unpack_bytes_64(data, offset);
        port_number          = packet_utils::unpack_bytes_16(data, offset);
        sequence_id          = packet_utils::unpack_bytes_16(data, offset);
        control_field        = data[offset]; offset++;
        log_message_interval = data[offset]; offset++;
    endfunction

    virtual function int get_header_length();
        return 34;
    endfunction

    virtual function void calc_fields(byte unsigned payload_data[$], protocol_type_e next_proto);
        if (!auto_calc) return;
        message_length = 16'(34 + payload_data.size());
    endfunction

    virtual function protocol_base clone();
        ptp_header h = new();
        h.transport_specific   = transport_specific;
        h.message_type         = message_type;
        h.version_ptp          = version_ptp;
        h.reserved1            = reserved1;
        h.message_length       = message_length;
        h.domain_number        = domain_number;
        h.reserved2            = reserved2;
        h.flag_field           = flag_field;
        h.correction_field     = correction_field;
        h.reserved3            = reserved3;
        h.clock_identity       = clock_identity;
        h.port_number          = port_number;
        h.sequence_id          = sequence_id;
        h.control_field        = control_field;
        h.log_message_interval = log_message_interval;
        h.auto_calc            = auto_calc;
        return h;
    endfunction

    virtual function bit compare(protocol_base other);
        ptp_header o;
        if (!$cast(o, other)) return 0;
        return (message_type   == o.message_type)   &&
               (domain_number  == o.domain_number)  &&
               (clock_identity == o.clock_identity) &&
               (port_number    == o.port_number)    &&
               (sequence_id    == o.sequence_id);
    endfunction

    virtual function string to_string();
        string s;
        s = $sformatf("=== %s ===\n", proto_type.name());
        s = {s, $sformatf("  message_type        : %0d\n",   message_type)};
        s = {s, $sformatf("  version_ptp         : %0d\n",   version_ptp)};
        s = {s, $sformatf("  message_length      : %0d\n",   message_length)};
        s = {s, $sformatf("  domain_number       : %0d\n",   domain_number)};
        s = {s, $sformatf("  flag_field          : 0x%04x\n", flag_field)};
        s = {s, $sformatf("  correction_field    : 0x%016x\n", correction_field)};
        s = {s, $sformatf("  clock_identity      : 0x%016x\n", clock_identity)};
        s = {s, $sformatf("  port_number         : %0d\n",   port_number)};
        s = {s, $sformatf("  sequence_id         : %0d\n",   sequence_id)};
        s = {s, $sformatf("  control_field       : %0d\n",   control_field)};
        s = {s, $sformatf("  log_message_interval: %0d\n",   log_message_interval)};
        return s;
    endfunction

    virtual function string to_brief();
        return $sformatf("PTP msg_type:%0d ver:%0d domain:%0d seq:%0d",
                         message_type, version_ptp, domain_number, sequence_id);
    endfunction

endclass

`endif // PTP_HEADER_SV
