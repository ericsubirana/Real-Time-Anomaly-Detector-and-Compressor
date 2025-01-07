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
    __u64 byte_count;          // Total bytes in the flow
    __u32 fwd_packet_count;    // Packets from src to dst
    __u32 bwd_packet_count;    // Packets from dst to src
    __u64 fwd_byte_count;      // Bytes from src to dst
    __u64 bwd_byte_count;      // Bytes from dst to src
    __u16 min_packet_length;
    __u16 max_packet_length;
    __u16 syn_count;
    __u16 ack_count;
    __u16 psh_count;
    __u16 urg_count;
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

    __u16 packet_length = data_end - data_start;

    if (key.protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;

        // Extract TCP flags
        __u16 flags = tcp->syn | (tcp->ack << 1) | (tcp->psh << 2) | (tcp->urg << 3);
    } else if (key.protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)udp + sizeof(*udp) > data_end) return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }

    // Lookup or initialize flow data
    data = flows.lookup(&key);
    if (data) {
        __sync_fetch_and_add(&data->packet_count, 1);
        __sync_fetch_and_add(&data->byte_count, packet_length);
        data->last_seen = bpf_ktime_get_ns();

        // Update direction-specific counters
        if (key.src_ip == ip->saddr) {
            __sync_fetch_and_add(&data->fwd_packet_count, 1);
            __sync_fetch_and_add(&data->fwd_byte_count, packet_length);
        } else {
            __sync_fetch_and_add(&data->bwd_packet_count, 1);
            __sync_fetch_and_add(&data->bwd_byte_count, packet_length);
        }

        // Update packet size metrics
        if (packet_length < data->min_packet_length || data->min_packet_length == 0)
            data->min_packet_length = packet_length;
        if (packet_length > data->max_packet_length)
            data->max_packet_length = packet_length;
    } else {
        struct flow_data new_data = {};
        new_data.packet_count = 1;
        new_data.byte_count = packet_length;
        new_data.first_seen = bpf_ktime_get_ns();
        new_data.last_seen = bpf_ktime_get_ns();
        new_data.min_packet_length = packet_length;
        new_data.max_packet_length = packet_length;
        new_data.fwd_packet_count = (key.src_ip == ip->saddr) ? 1 : 0;
        new_data.bwd_packet_count = (key.src_ip != ip->saddr) ? 1 : 0;
        new_data.fwd_byte_count = (key.src_ip == ip->saddr) ? packet_length : 0;
        new_data.bwd_byte_count = (key.src_ip != ip->saddr) ? packet_length : 0;

        flows.update(&key, &new_data);
    }

    return XDP_PASS;
}
