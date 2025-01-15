#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

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

BPF_PERCPU_HASH(flows, struct flow_key, struct flow_data, 1024); //for flow metrics
BPF_PERCPU_HASH(exported_flows, struct flow_key, struct flow_data, 1024); //for anomaly detection
BPF_PERCPU_ARRAY(input_value, __u32, 1); //for packet sampling

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

static __always_inline int parse_icmphdr(struct xdp_md *ctx, struct iphdr *ip, struct icmphdr **icmp_hdr) {
    void *data_end = (void *)(long)ctx->data_end;

    *icmp_hdr = (void *)ip + sizeof(struct iphdr);
    if ((void *)*icmp_hdr + sizeof(struct icmphdr) > data_end)
        return -1;
    return 0;
}

static __always_inline void update_flow_metrics_icmp(struct flow_data *data, __u16 packet_length, __u64 now, __u64 iat) {
    // Al igual que en TCP y UDP, actualizamos las métricas para ICMP.
    __sync_fetch_and_add(&data->packet_count, 1);
    __sync_fetch_and_add(&data->byte_count, packet_length);
    __sync_fetch_and_add(&data->packet_length_square_sum, packet_length * packet_length);
    data->last_seen = now;
    data->flow_duration = now - data->first_seen;

    // Actualizamos los tiempos de interllegada (IAT)
    __sync_fetch_and_add(&data->flow_iat_total, iat);
    if (iat < data->flow_iat_min || data->flow_iat_min == ~0ULL)
        data->flow_iat_min = iat;
    if (iat > data->flow_iat_max)
        data->flow_iat_max = iat;
}

static __always_inline void update_flow_metrics(struct flow_data *data, __u16 packet_length, __u64 now, __u64 iat, bool is_forward) {
    // Update general metrics
    __sync_fetch_and_add(&data->packet_count, 1);
    __sync_fetch_and_add(&data->byte_count, packet_length);
    __sync_fetch_and_add(&data->packet_length_square_sum, packet_length * packet_length);
    data->last_seen = now;
    data->flow_duration = now - data->first_seen;

    // Update min/max packet lengths
    if (packet_length < data->min_packet_length || data->min_packet_length == 0)
        data->min_packet_length = packet_length;
    if (packet_length > data->max_packet_length)
        data->max_packet_length = packet_length;

    // Update directional metrics
    if (is_forward) {
        __sync_fetch_and_add(&data->fwd_packet_count, 1);
        __sync_fetch_and_add(&data->fwd_byte_count, packet_length);
        __sync_fetch_and_add(&data->fwd_iat_total, iat);

        if (iat < data->fwd_iat_min || data->fwd_iat_min == ~0ULL)
            data->fwd_iat_min = iat;
        if (iat > data->fwd_iat_max)
            data->fwd_iat_max = iat;
    } else {
        __sync_fetch_and_add(&data->bwd_packet_count, 1);
        __sync_fetch_and_add(&data->bwd_byte_count, packet_length);
        __sync_fetch_and_add(&data->bwd_iat_total, iat);

        if (iat < data->bwd_iat_min || data->bwd_iat_min == ~0ULL)
            data->bwd_iat_min = iat;
        if (iat > data->bwd_iat_max)
            data->bwd_iat_max = iat;
    }

    // Update overall IAT metrics
    __sync_fetch_and_add(&data->flow_iat_total, iat);
    if (iat < data->flow_iat_min || data->flow_iat_min == ~0ULL)
        data->flow_iat_min = iat;
    if (iat > data->flow_iat_max)
        data->flow_iat_max = iat;
}

static __always_inline void new_flow(struct flow_key *key, __u16 packet_length, __u32 src_ip, __u64 now, bool is_forward, __u8 protocol) {
    struct flow_data new_data = {};

    // Initialize timestamps
    new_data.first_seen = now;
    new_data.last_seen = now;
    new_data.flow_duration = 0;

    // Initialize packet and byte counts
    new_data.packet_count = 1;
    new_data.byte_count = packet_length;

    // Initialize packet length metrics
    new_data.min_packet_length = packet_length;
    new_data.max_packet_length = packet_length;
    new_data.packet_length_square_sum = packet_length * packet_length;

    // Initialize directional metrics
    if (is_forward) {
        new_data.fwd_packet_count = 1;
        new_data.fwd_byte_count = packet_length;
        new_data.bwd_packet_count = 0;
        new_data.bwd_byte_count = 0;
    } else {
        new_data.fwd_packet_count = 0;
        new_data.fwd_byte_count = 0;
        new_data.bwd_packet_count = 1;
        new_data.bwd_byte_count = packet_length;
    }

    // Initialize inter-arrival times (IAT)
    new_data.flow_iat_total = 0;
    new_data.flow_iat_min = ~0ULL; // Max possible value for comparison
    new_data.flow_iat_max = 0;
    new_data.fwd_iat_total = 0;
    new_data.fwd_iat_min = ~0ULL;
    new_data.fwd_iat_max = 0;
    new_data.bwd_iat_total = 0;
    new_data.bwd_iat_min = ~0ULL;
    new_data.bwd_iat_max = 0;

    // TCP case
    new_data.syn_count = 0;
    new_data.ack_count = 0;
    new_data.psh_count = 0;
    new_data.urg_count = 0;
    new_data.fin_count = 0;
    new_data.rst_count = 0;

    flows.update(key, &new_data);
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

    uint32_t key_rate = 0;
    __u32 *value = input_value.lookup(&key_rate);

    if (value) {
        bpf_trace_printk("Sampling rate: %u", *value);
    } else {
        bpf_trace_printk("No value found for key_rate: %u\n", key_rate);
    }

    u64 timestamp = bpf_ktime_get_ns();
    u32 cpu_id = bpf_get_smp_processor_id();
    
    // Combine timestamp and cpu_id to generate a pseudo-random value
    u32 combined_value = (timestamp ^ cpu_id) & 0xFFFFFFF; // Use lower 28 bits for randomness

    // Scale to a range between 0 and 100
    u32 random_value = combined_value % 101; // This will give a value between 0 and 100

    // Do something with the random_value
    bpf_trace_printk("Random Value: %u\n", random_value);
    
    if (value) {
        if (random_value > *value) {
            bpf_trace_printk("Dropping packet\n");
            return XDP_DROP;  // Drop the packet if condition is met
        }
    }

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
            bool is_forward = key.src_ip == ip->saddr;
            update_flow_metrics(data, packet_length, now, iat, is_forward);

            // Update TCP flags
            __sync_fetch_and_add(&data->syn_count, tcp->syn);
            __sync_fetch_and_add(&data->ack_count, tcp->ack);
            __sync_fetch_and_add(&data->psh_count, tcp->psh);
            __sync_fetch_and_add(&data->urg_count, tcp->urg);
            __sync_fetch_and_add(&data->fin_count, tcp->fin);
            __sync_fetch_and_add(&data->rst_count, tcp->rst);

        } else {
            //new flow
            __u64 now = bpf_ktime_get_ns() / 1000;
            bool is_forward = key.src_ip == ip->saddr;
            new_flow(&key, packet_length, ip->saddr, now, is_forward, ip->protocol);
        }
    
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if (parse_udphdr(ctx, ip, &udp) < 0)
            return XDP_PASS;

        key.src_port = udp->source;
        key.dst_port = udp->dest;

        data = flows.lookup(&key);
        if (data) {
            __u64 now = bpf_ktime_get_ns() / 1000;
            __u64 iat = now - data->last_seen;
            bool is_forward = key.src_ip == ip->saddr;
            update_flow_metrics(data, packet_length, now, iat, is_forward);

        } else {
            // Initialize new flow
            __u64 now = bpf_ktime_get_ns() / 1000;
            bool is_forward = key.src_ip == ip->saddr;
            new_flow(&key, packet_length, ip->saddr, now, is_forward, ip->protocol);
        }
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp;
        if (parse_icmphdr(ctx, ip, &icmp) < 0)
            return XDP_PASS;

        // ICMP does not have ports
        key.src_port = 0; 
        key.dst_port = 0; 

        data = flows.lookup(&key);
        if (data) {
            __u64 now = bpf_ktime_get_ns() / 1000;
            __u64 iat = now - data->last_seen;
            bool is_forward = key.src_ip == ip->saddr;
            update_flow_metrics_icmp(data, packet_length, now, iat); 
        } else {
            // Nuevo flujo para ICMP
            __u64 now = bpf_ktime_get_ns() / 1000;
            bool is_forward = key.src_ip == ip->saddr;
            new_flow(&key, packet_length, ip->saddr, now, is_forward, ip->protocol);
        }
    }

    return XDP_PASS;
}
