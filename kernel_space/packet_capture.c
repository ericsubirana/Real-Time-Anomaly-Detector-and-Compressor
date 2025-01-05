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