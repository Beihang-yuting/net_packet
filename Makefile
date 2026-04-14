# Makefile
SIM ?= vcs
TOP_DIR := $(shell pwd)
SRC_DIR := $(TOP_DIR)/src
TEST_DIR := $(TOP_DIR)/test
FILELIST := $(TOP_DIR)/filelist.f

VCS_FLAGS := -full64 -sverilog -timescale=1ns/1ps -f $(FILELIST) +incdir+$(SRC_DIR)
QUESTA_FLAGS := -sv -f $(FILELIST) +incdir+$(SRC_DIR)

.PHONY: compile run clean

run_%: test/test_%.sv
	@echo "=== Running test: $* ==="
ifeq ($(SIM),vcs)
	vcs $(VCS_FLAGS) $< -o simv_$* && ./simv_$*
else ifeq ($(SIM),questa)
	vlog $(QUESTA_FLAGS) $< && vsim -batch -do "run -all; quit" top
endif

test_utils: test/test_utils.sv
	$(MAKE) run_utils

test_protocol_headers: test/test_protocol_headers.sv
	$(MAKE) run_protocol_headers

test_protocol_graph: test/test_protocol_graph.sv
	$(MAKE) run_protocol_graph

test_packet_builder: test/test_packet_builder.sv
	$(MAKE) run_packet_builder

test_tunnel_headers: test/test_tunnel_headers.sv
	$(MAKE) run_tunnel_headers

test_tunnel_packet: test/test_tunnel_packet.sv
	$(MAKE) run_tunnel_packet

test_rdma_storage_headers: test/test_rdma_storage_headers.sv
	$(MAKE) run_rdma_storage_headers

test_rdma_storage_packet: test/test_rdma_storage_packet.sv
	$(MAKE) run_rdma_storage_packet

test_phase2c_headers: test/test_phase2c_headers.sv
	$(MAKE) run_phase2c_headers

test_all: test_protocol_headers test_protocol_graph test_packet_builder test_tunnel_headers test_tunnel_packet test_rdma_storage_headers test_rdma_storage_packet test_phase2c_headers

clean:
	rm -rf simv_* csrc *.log *.vpd *.fsdb work transcript *.wlf DVEfiles
