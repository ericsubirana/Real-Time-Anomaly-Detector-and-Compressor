#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

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
    __u64 byte_count;
    __u32 fwd_packet_count;
    __u32 bwd_packet_count;
    __u64 fwd_byte_count;
    __u64 bwd_byte_count;
    __u16 min_packet_length;
    __u16 max_packet_length;
    __u64 packet_length_square_sum;
    __u64 flow_duration;
    __u64 flow_iat_total;
    __u64 flow_iat_min;
    __u64 flow_iat_max;
    __u64 fwd_iat_total;
    __u64 fwd_iat_min;
    __u64 fwd_iat_max;
    __u64 bwd_iat_total;
    __u64 bwd_iat_min;
    __u64 bwd_iat_max;
    __u32 syn_count;
    __u32 ack_count;
    __u32 psh_count;
    __u32 urg_count;
    __u32 fin_count;
    __u32 rst_count;
};

BPF_PERCPU_HASH(flows, struct flow_key, struct flow_data, 1024);
BPF_PERCPU_HASH(exported_flows, struct flow_key, struct flow_data, 1024);

static __always_inline int parse_ethhdr(struct xdp_md *ctx, struct ethhdr **eth_hdr) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data_start = (void *)(long)ctx->data;

    *eth_hdr = data_start;
    if ((void *)*eth_hdr + sizeof(struct ethhdr) > data_end)
        return -1;
    return 0;
}

static __always_inline int parse_iphdr(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr **ip_hdr) {
    void *data_end = (void *)(long)ctx->data_end;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return -1;

    *ip_hdr = (void *)eth + sizeof(struct ethhdr);
    if ((void *)*ip_hdr + sizeof(struct iphdr) > data_end)
        return -1;
    return 0;
}

static __always_inline int parse_tcphdr(struct xdp_md *ctx, struct iphdr *ip, struct tcphdr **tcp_hdr) {
    void *data_end = (void *)(long)ctx->data_end;

    *tcp_hdr = (void *)ip + sizeof(struct iphdr);
    if ((void *)*tcp_hdr + sizeof(struct tcphdr) > data_end)
        return -1;
    return 0;
}

static __always_inline int parse_udphdr(struct xdp_md *ctx, struct iphdr *ip, struct udphdr **udp_hdr) {
    void *data_end = (void *)(long)ctx->data_end;

    *udp_hdr = (void *)ip + sizeof(struct iphdr);
    if ((void *)*udp_hdr + sizeof(struct udphdr) > data_end)
        return -1;
    return 0;
}

int capture_packet(struct xdp_md *ctx) {
    struct ethhdr *eth;
    if (parse_ethhdr(ctx, &eth) < 0)
        return XDP_PASS;

    struct iphdr *ip;
    if (parse_iphdr(ctx, eth, &ip) < 0)
        return XDP_PASS;

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    struct flow_data *data;
    __u16 packet_length = (void *)(long)ctx->data_end - (void *)(long)ctx->data;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        if (parse_tcphdr(ctx, ip, &tcp) < 0)
            return XDP_PASS;

        key.src_port = tcp->source;
        key.dst_port = tcp->dest;

        data = flows.lookup(&key);
    
        if (data) {            
            __u64 now = bpf_ktime_get_ns() / 1000;
            __u64 iat = now - data->last_seen;
            
            __sync_fetch_and_add(&data->packet_count, 1);
            __sync_fetch_and_add(&data->byte_count, packet_length);
            __sync_fetch_and_add(&data->packet_length_square_sum, packet_length * packet_length);
            data->last_seen = now;
            data->flow_duration = data->last_seen - data->first_seen;

            if (packet_length < data->min_packet_length || data->min_packet_length == 0)
                data->min_packet_length = packet_length;
            
            if(packet_length > data->max_packet_length)
                data->max_packet_length = packet_length;
            

           if (key.src_ip == ip->saddr) { // Forward Direction
                __sync_fetch_and_add(&data->fwd_packet_count, 1);
                __sync_fetch_and_add(&data->fwd_byte_count, packet_length);

                __sync_fetch_and_add(&data->fwd_iat_total, iat);
                if (iat < data->fwd_iat_min || data->fwd_iat_min == 0)
                    data->fwd_iat_min = iat;
                if (iat > data->fwd_iat_max)
                    data->fwd_iat_max = iat;
            } else { // Backward Direction
                __sync_fetch_and_add(&data->bwd_packet_count, 1);
                __sync_fetch_and_add(&data->bwd_byte_count, packet_length);

                __sync_fetch_and_add(&data->bwd_iat_total, iat);
                if (iat < data->bwd_iat_min || data->bwd_iat_min == 0)
                    data->bwd_iat_min = iat;
                if (iat > data->bwd_iat_max)
                    data->bwd_iat_max = iat;
            }

            __sync_fetch_and_add(&data->flow_iat_total, iat);
            if (iat < data->flow_iat_min || data->flow_iat_min == ~0ULL)
                data->flow_iat_min = iat;
            if (iat > data->flow_iat_max)
                data->flow_iat_max = iat;

            // Update TCP flags
            __sync_fetch_and_add(&data->syn_count, tcp->syn);
            __sync_fetch_and_add(&data->ack_count, tcp->ack);
            __sync_fetch_and_add(&data->psh_count, tcp->psh);
            __sync_fetch_and_add(&data->urg_count, tcp->urg);
            __sync_fetch_and_add(&data->fin_count, tcp->fin);
            __sync_fetch_and_add(&data->rst_count, tcp->rst);

        } else {
            //new flow
            struct flow_data new_data = {};
            __u64 now = bpf_ktime_get_ns() / 1000;

            // Timestamps
            new_data.first_seen = now;
            new_data.last_seen = now;
            new_data.flow_duration = 0;

            // Packet and byte counts
            new_data.packet_count = 1;
            new_data.byte_count = packet_length;

            // Packet length metrics
            new_data.min_packet_length = packet_length;
            new_data.max_packet_length = packet_length;
            new_data.packet_length_square_sum = packet_length * packet_length;

            // Directional metrics
            if (key.src_ip == ip->saddr) { // Forward direction
                new_data.fwd_packet_count = 1;
                new_data.fwd_byte_count = packet_length;
                new_data.bwd_packet_count = 0;
                new_data.bwd_byte_count = 0;
            } else { // Backward direction
                new_data.fwd_packet_count = 0;
                new_data.fwd_byte_count = 0;
                new_data.bwd_packet_count = 1;
                new_data.bwd_byte_count = packet_length;
            }

            // Inter-arrival times (IAT)
            new_data.flow_iat_total = 0;
            new_data.flow_iat_min = ~0ULL; // Set to max possible value for comparison
            new_data.flow_iat_max = 0;
            new_data.fwd_iat_total = 0;
            new_data.fwd_iat_min = ~0ULL; // Set to max possible value for comparison
            new_data.fwd_iat_max = 0;
            new_data.bwd_iat_total = 0;
            new_data.bwd_iat_min = ~0ULL; // Set to max possible value for comparison
            new_data.bwd_iat_max = 0;

            // TCP flag counters (only relevant for TCP flows, but initializing them anyway)
            new_data.syn_count = 0;
            new_data.ack_count = 0;
            new_data.psh_count = 0;
            new_data.urg_count = 0;
            new_data.fin_count = 0;
            new_data.rst_count = 0;

            // Update the flow map
            flows.update(&key, &new_data);
        }
    
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if (parse_udphdr(ctx, ip, &udp) < 0)
            return XDP_PASS;

        key.src_port = udp->source;
        key.dst_port = udp->dest;

        data = flows.lookup(&key);
        if (data) {
            __sync_fetch_and_add(&data->packet_count, 1);
            __sync_fetch_and_add(&data->byte_count, packet_length);
            data->last_seen = bpf_ktime_get_ns() / 1000;
            data->flow_duration = data->last_seen - data->first_seen;

            // Directional metrics
            if (key.src_ip == ip->saddr) {
                __sync_fetch_and_add(&data->fwd_packet_count, 1);
                __sync_fetch_and_add(&data->fwd_byte_count, packet_length);
            } else {
                __sync_fetch_and_add(&data->bwd_packet_count, 1);
                __sync_fetch_and_add(&data->bwd_byte_count, packet_length);
            }

            // Packet length metrics
            if (packet_length < data->min_packet_length || data->min_packet_length == 0)
                data->min_packet_length = packet_length;
            if (packet_length > data->max_packet_length)
                data->max_packet_length = packet_length;

            // Inter-arrival times
            __u64 now = bpf_ktime_get_ns() / 1000;
            __u64 iat = now - data->last_seen;
            data->flow_iat_total += iat;
            if (iat < data->flow_iat_min || data->flow_iat_min == 0)
                data->flow_iat_min = iat;
            if (iat > data->flow_iat_max)
                data->flow_iat_max = iat;

        } else {
            // Initialize new flow
            struct flow_data new_data = {};
            new_data.packet_count = 1;
            new_data.byte_count = packet_length;
            new_data.first_seen = bpf_ktime_get_ns() / 1000;
            new_data.last_seen = bpf_ktime_get_ns() / 1000;
            new_data.min_packet_length = packet_length;
            new_data.max_packet_length = packet_length;
            new_data.fwd_packet_count = (key.src_ip == ip->saddr) ? 1 : 0;
            new_data.bwd_packet_count = (key.src_ip != ip->saddr) ? 1 : 0;
            new_data.fwd_byte_count = (key.src_ip == ip->saddr) ? packet_length : 0;
            new_data.bwd_byte_count = (key.src_ip != ip->saddr) ? packet_length : 0;
            new_data.flow_duration = 0;

            flows.update(&key, &new_data);
        }
    }


    return XDP_PASS;
}
