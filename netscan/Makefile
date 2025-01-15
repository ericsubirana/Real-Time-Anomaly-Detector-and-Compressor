# TARGET = xdp_lb
# TARGET = packetdrop
TARGET = netscan

CLANG_PATH = /usr/bin
LLC_PATH = /usr/bin
CLANG_VERSION = clang-16
LLC_VERSION = llc-16
CLANG = $(CLANG_PATH)/$(CLANG_VERSION)
LLC = $(LLC_PATH)/$(LLC_VERSION)

# For xdp_liz, make and also make user. The others don't have userspace programs

USER_TARGET = ${TARGET:=_user}
BPF_TARGET = ${TARGET:=_kern}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

.PHONY: user

user: $(BPF_OBJ) $(skel) $(USER_TARGET)

	
xdp: $(BPF_OBJ)
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/$(TARGET)
	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/$(TARGET) dev eth0 


$(USER_TARGET): %: %.c  
	bpftool gen skeleton netscan_kern.o > netscan_user.skel.h
	gcc -Wall $(CFLAGS) -Ilibbpf/src -Ilibbpf/src/include/uapi -Llibbpf/src -o $@  \
	 $< -l:libbpf.a -lelf -lz

$(BPF_OBJ): %.o: %.c
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -Ilibbpf/src\
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -g \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

skel:
	bpftool gen skeleton netscan_kern.o > netscan_user.skel.h

clean:
	#bpftool net detach xdpgeneric dev eth0
	#rm -f /sys/fs/bpf/$(TARGET)
	rm $(BPF_OBJ)
	rm ${BPF_OBJ:.o=.ll}
	rm $(USER_TARGET)




