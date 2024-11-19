#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MAX_PKT_SIZE 4096

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} ringbuff SEC(".maps");

// Define the structure for storing packet data
struct packet_info {
    __u64 timestamp;
    __u32 pkt_len;
    char data[MAX_PKT_SIZE];
};

// XDP program to capture packets
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Calculate packet length
    __u32 pkt_len = data_end - data;

    // Check if packet length exceeds the maximum allowed size
    if (pkt_len > MAX_PKT_SIZE) {
        return XDP_DROP;
    }

    // Reserve space in the ring buffer
    struct packet_info *pkt = bpf_ringbuf_reserve(&ringbuff, sizeof(struct packet_info), 0);
    if (!pkt) {
        bpf_printk("Failed to reserve ringbuf space\n");
        return XDP_DROP;
    }

    // Store timestamp and packet length
    pkt->timestamp = bpf_ktime_get_ns();
    pkt->pkt_len = pkt_len;

    // Copy packet data safely
    __u8 *cursor = data;
    for (__u32 i = 0; i < pkt_len && i < MAX_PKT_SIZE; i++) {
        if ((__u8 *)cursor + 1 > (__u8 *)data_end) { // Explicit check for out-of-bounds access
            bpf_ringbuf_discard(pkt, 0);
            bpf_printk("Packet discarded: out of bounds\n");
            return XDP_DROP;
        }
        pkt->data[i] = *cursor;
        cursor++;
    }

    // Submit the packet to the ring buffer
    bpf_printk("Ring buffer entry: timestamp=%llu, len=%u\n", pkt->timestamp, pkt->pkt_len);
    bpf_ringbuf_submit(pkt, 2);
    bpf_printk("Packet successfully added to ring buffer\n");

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
