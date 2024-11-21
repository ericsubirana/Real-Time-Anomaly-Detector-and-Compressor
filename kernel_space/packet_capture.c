#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Ensure there's enough data for the Ethernet header
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Check if it's an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);

    // Ensure there's enough data for the IP header
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Check if it's UDP or TCP (protocols 6 and 17)
    if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct packet_event event = {};
    event.src_ip = ip->saddr;
    event.dst_ip = ip->daddr;
    event.protocol = ip->protocol;

    // Check if it's UDP to parse ports
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);

        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_PASS;

        event.src_port = udp->source;
        event.dst_port = udp->dest;
    }

    // Send the event to the user space via the ring buffer
    buffer.ringbuf_output(&event, sizeof(event), 0);

    return XDP_PASS;
}