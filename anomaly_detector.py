#!/usr/bin/python3

import sys
import time
import ctypes
import threading
from socket import inet_ntoa
from bcc import BPF

# Define ctypes structure for flow_key and flow_data
class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8)
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("last_seen", ctypes.c_uint64),
        ("packet_count", ctypes.c_uint32)
    ]

src = r"""
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bcc/proto.h>

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct flow_data {
    __u64 first_seen;
    __u64 last_seen;
    __u32 packet_count;
};

BPF_PERCPU_HASH(flows, struct flow_key, struct flow_data, 1024);
BPF_PERCPU_HASH(exported_flows, struct flow_key, struct flow_data, 1024);

int capture_packet(struct xdp_md *ctx) {
    struct flow_key key = {};
    struct flow_data *data;

    void *data_start = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data_start;
    if ((void *)eth + sizeof(*eth) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data_start + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(*ip) > data_end) return XDP_PASS;

    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    if (key.protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (key.protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)udp + sizeof(*udp) > data_end) return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }

    // Lookup flow data
    data = flows.lookup(&key);
    if (data) {
        // Flow exists, update packet count and last seen timestamp
        __sync_fetch_and_add(&data->packet_count, 1);
        data->last_seen = bpf_ktime_get_ns();
    } else {
        // Create new flow
        struct flow_data new_data = {};
        new_data.packet_count = 1;
        new_data.first_seen = bpf_ktime_get_ns();
        new_data.last_seen = bpf_ktime_get_ns();
        flows.update(&key, &new_data);
    }

    return XDP_PASS;
}
"""

try:
    b = BPF(text=src)
    fn_capture_packet = b.load_func("capture_packet", BPF.XDP)
    b.attach_xdp(dev="enp0s3", fn=fn_capture_packet, flags=0)

    def getting_unupdated_flows(threshold_seconds=20, active_timeout=60):
        flows_map = b.get_table("flows")
        exported_flows_map = b.get_table("exported_flows")
        current_time_ns = time.monotonic_ns()  # Usar monotonic_ns para evitar desincronización
        print(f"Processing flows with idle_timeout={threshold_seconds}s and active_timeout={active_timeout}s:")

        for key, per_cpu_data in flows_map.items():
            src_ip = inet_ntoa(ctypes.c_uint32(key.src_ip).value.to_bytes(4, 'big'))
            dst_ip = inet_ntoa(ctypes.c_uint32(key.dst_ip).value.to_bytes(4, 'big'))

            # Agregar datos de las CPUs
            total_packets = sum(cpu_data.packet_count for cpu_data in per_cpu_data)
            last_seen = max(cpu_data.last_seen for cpu_data in per_cpu_data)
            first_seen = min(cpu_data.first_seen for cpu_data in per_cpu_data if cpu_data.first_seen > 0)

            # Validar que `first_seen` tenga sentido
            if first_seen == 0 or first_seen > current_time_ns:
                print(f"Warning: Invalid first_seen value for flow: src_ip={src_ip}, dst_ip={dst_ip}")
                continue

            # Calcular duraciones
            idle_duration = (current_time_ns - last_seen) / 1e9
            active_duration = (current_time_ns - first_seen) / 1e9

            if idle_duration > threshold_seconds or active_duration > active_timeout:
                print(f"Exporting flow: src_ip={src_ip}, dst_ip={dst_ip}, src_port={key.src_port}, "
                    f"dst_port={key.dst_port}, protocol={key.protocol}, "
                    f"packet_count={total_packets}, idle_duration={idle_duration:.2f}s, "
                    f"active_duration={active_duration:.2f}s")
                exported_flows_map[key] = per_cpu_data
                del flows_map[key]  # Eliminar el flujo del mapa


    def periodic_print_flows(interval):
        def print_and_reschedule():
            getting_unupdated_flows()
            threading.Timer(interval, print_and_reschedule).start()

        print_and_reschedule()

    # Start the periodic function
    periodic_print_flows(3) 
except KeyboardInterrupt:
    b.remove_xdp(dev="enp0s3", flags=0)
    sys.exit()