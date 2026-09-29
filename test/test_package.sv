// test/test_package.sv：验证外部 package 和模块均能使用唯一的网络报文类型。
// 依赖：先通过 filelist_pkg.f 编译 net_packet_pkg；本文件禁止 include 生产源码。
// 测试对象由 initial 创建，仅在本次仿真内存活，不打开文件或持有外部资源。
package net_packet_consumer_pkg;
    import net_packet_pkg::*;

    // 模拟 VIP package 内持有报文，检查导入类型可以穿过 package 边界。
    class packet_consumer;
        packet pkt;

        // 创建固定模板报文并打包；由调用者断言结果，失败时不隐藏错误。
        function new();
            pkt = new();
            pkt.build_from_template(ETH_IPV4_TCP);
            pkt.do_pack();
        endfunction
    endclass
endpackage

module test_package;
    import net_packet_pkg::*;
    import net_packet_consumer_pkg::*;

    initial begin
        packet_consumer consumer;
        net_packet_pkg::packet same_packet;
        protocol_base first_layer;
        consumer = new();
        same_packet = consumer.pkt;
        if (same_packet.raw_data.size() < 54)
            $fatal(1, "Package packet serialization failed");
        first_layer = same_packet.layer_stack[0];
        if (first_layer.proto_type != PROTO_ETHERNET)
            $fatal(1, "Package protocol enum/type visibility failed");
        $display("[PASS] net_packet_pkg cross-package types and serialization");
        $finish;
    end
endmodule
