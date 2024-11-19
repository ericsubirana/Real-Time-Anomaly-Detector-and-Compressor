BPFTOOL = /usr/sbin/bpftool
KERNEL_VERSION = $(shell uname -r)

.PHONY: all clean

all: packet_capture.o

packet_capture.o: packet_capture.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/ -I/usr/include/x86_64-linux-gnu/ \
		-I/lib/modules/$(KERNEL_VERSION)/build/include \
		-I/lib/modules/$(KERNEL_VERSION)/build/include/uapi \
		-I/lib/modules/$(KERNEL_VERSION)/build/include/generated/uapi \
		-c packet_capture.c -o packet_capture.o

clean:
	rm -f packet_capture.o
