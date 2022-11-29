CC = clang
LLC = llc

BUILD_DIR := build
SRC_DIR := src
LIBBPF_DIR := libbpf

LIBBPF_SRC = $(LIBBPF_DIR)/src

LIBBPF_OBJS = $(LIBBPF_SRC)/staticobjs/bpf_prog_linfo.o $(LIBBPF_SRC)/staticobjs/bpf.o $(LIBBPF_SRC)/staticobjs/btf_dump.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/btf.o $(LIBBPF_SRC)/staticobjs/hashmap.o $(LIBBPF_SRC)/staticobjs/libbpf_errno.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/libbpf_probes.o $(LIBBPF_SRC)/staticobjs/libbpf.o $(LIBBPF_SRC)/staticobjs/netlink.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/nlattr.o $(LIBBPF_SRC)/staticobjs/str_error.o
LIBBPF_OBJS += $(LIBBPF_SRC)/staticobjs/xsk.o

LOADER_SRC := xdpfwd.c
LOADER_OUT := xdpfwd
LOADER_FLAGS := -lelf -lz -lconfig

ADD_SRC := xdpfwd-add.c
ADD_OUT := xdpfwd-add

DEL_SRC := xdpfwd-del.c
DEL_OUT := xdpfwd-del

CMD_LINE_SRC := cmdline.c
CMD_LINE_OUT := cmdline.o

CONFIG_SRC := config.c
CONFIG_OUT := config.o

UTILS_SRC := utils.c
UTILS_OUT := utils.o

XDP_PROG_SRC := xdp_prog.c
XDP_PROG_LL := xdp_prog.ll
XDP_PROG_OUT := xdp_prog.o

GLOBAL_OBJS := $(BUILD_DIR)/$(CONFIG_OUT) $(BUILD_DIR)/$(CMD_LINE_OUT) $(BUILD_DIR)/$(UTILS_OUT)
GLOBAL_FLAGS := -O2

all: utils common loader xdp_add xdp_del xdp_prog
mk_build:
	mkdir -p build/
loader: libbpf mk_build common utils
	$(CC) -I$(LIBBPF_SRC) $(LOADER_FLAGS) $(GLOBAL_FLAGS) -o $(BUILD_DIR)/$(LOADER_OUT) $(LIBBPF_OBJS) $(GLOBAL_OBJS) $(SRC_DIR)/$(LOADER_SRC)
xdp_add: libbpf mk_build common utils
	$(CC) -I$(LIBBPF_SRC) $(LOADER_FLAGS) $(GLOBAL_FLAGS) -o $(BUILD_DIR)/$(ADD_OUT) $(LIBBPF_OBJS) $(GLOBAL_OBJS) $(SRC_DIR)/$(ADD_SRC)
xdp_del: libbpf mk_build common utils
	$(CC) -I$(LIBBPF_SRC) $(LOADER_FLAGS) $(GLOBAL_FLAGS) -o $(BUILD_DIR)/$(DEL_OUT) $(LIBBPF_OBJS) $(GLOBAL_OBJS) $(SRC_DIR)/$(DEL_SRC)
xdp_prog: mk_build
	$(CC) -I$(LIBBPF_SRC) -D__BPF__ -Wall -Wextra $(GLOBAL_FLAGS) -emit-llvm -c -o $(BUILD_DIR)/$(XDP_PROG_LL) $(SRC_DIR)/$(XDP_PROG_SRC) 
	$(LLC) -march=bpf -filetype=obj -o $(BUILD_DIR)/$(XDP_PROG_OUT) $(BUILD_DIR)/$(XDP_PROG_LL)
libbpf:
	$(MAKE) -j $(nproc) -C $(LIBBPF_SRC)
common: mk_build
	$(CC) $(GLOBAL_FLAGS) -c -o $(BUILD_DIR)/$(CMD_LINE_OUT) $(SRC_DIR)/$(CMD_LINE_SRC)
	$(CC) $(GLOBAL_FLAGS) -c -o $(BUILD_DIR)/$(CONFIG_OUT) $(SRC_DIR)/$(CONFIG_SRC)
utils: libbpf mk_build
	$(CC) -I$(LIBBPF_SRC) $(GLOBAL_FLAGS) -c -o $(BUILD_DIR)/$(UTILS_OUT) $(SRC_DIR)/$(UTILS_SRC)
clean:
	$(MAKE) -j $(nproc) -C $(LIBBPF_SRC) clean
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.ll
	rm -f $(BUILD_DIR)/$(LOADER_OUT)
	rm -f $(BUILD_DIR)/$(ADD_OUT)
	rm -f $(BUILD_DIR)/$(DEL_OUT)
install:
	mkdir -p /etc/xdpfwd
	cp -n xdpfwd.conf.example /etc/xdpfwd/xdpfwd.conf
	cp $(BUILD_DIR)/$(XDP_PROG_OUT) /etc/xdpfwd/$(XDP_PROG_OUT)
	cp $(BUILD_DIR)/$(LOADER_OUT) /usr/bin/$(LOADER_OUT)
	cp $(BUILD_DIR)/$(ADD_OUT) /usr/bin/$(ADD_OUT)
	cp $(BUILD_DIR)/$(DEL_OUT) /usr/bin/$(DEL_OUT)
	cp -n xdpfwd.service /etc/systemd/system/
.PHONY: libbpf
.DEFAULT: all