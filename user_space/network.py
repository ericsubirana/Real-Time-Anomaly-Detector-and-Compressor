#!/usr/bin/python3

import sys
import time
import ctypes
import socket
from bcc import BPF

# Load the BPF program
bpf = BPF(src_file="../kernel_space/packet_capture.c")

# Load XDP function by its section name
fn = bpf.load_func("xdp_prog", BPF.XDP)
bpf.attach_xdp(dev="enp0s3", fn=fn)

# Define the ctypes structure to match the kernel's struct packet_event
class PacketEvent(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
    ]

# Callback function for processing events from the ring buffer
def callback(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(PacketEvent)).contents
    print("SRC: %s, DST: %s, SRC_PORT: %d, DST_PORT: %d, PROTOCOL: %d" % (
        socket.inet_ntoa(event.src_ip.to_bytes(4, 'big')),
        socket.inet_ntoa(event.dst_ip.to_bytes(4, 'big')),
        socket.ntohs(event.src_port),
        socket.ntohs(event.dst_port),
        event.protocol
    ))

# Open the ring buffer
bpf["buffer"].open_ring_buffer(callback)

print("Monitoring packets on enp0s3. Press Ctrl-C to exit.")
print("%-16s %-16s %-8s %-8s %-10s" % ("SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT", "PROTOCOL"))

try:
    while True:
        bpf.ring_buffer_poll()
except KeyboardInterrupt:
    bpf.remove_xdp(dev="enp0s3")
    sys.exit()
