#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <sys/resource.h>
#include <string.h>
#include <errno.h>

#define MAX_PKT_SIZE 4096

struct packet_info {
    uint64_t timestamp;
    uint32_t pkt_len;
    char data[MAX_PKT_SIZE];
};

// Callback to process the data read from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
    printf("checkpoint");
    if (data_sz < sizeof(struct packet_info)) {
        fprintf(stderr, "Data size mismatch\n");
        return -1;
    }

    struct packet_info *pkt = (struct packet_info *)data;
    
    printf("Packet received:\n");
    printf("  Timestamp: %llu\n", pkt->timestamp);
    printf("  Length: %u\n", pkt->pkt_len);
    printf("  Data: ");
    for (int i = 0; i < pkt->pkt_len && i < MAX_PKT_SIZE; i++) {
        printf("%02x ", (unsigned char)pkt->data[i]);
    }
    printf("\n");

    return 0;
}

int main() {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    int ringbuf_map_fd;
    int zero = 0; // Defining zero as the key for map lookup
    __u64 free_space_counter = 0; // Declare free_space_counter to store the value

    // Load the XDP program and map
    obj = bpf_object__open_file("packet_capture.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object\n");
        return 1;
    }

    // Obtain the descriptor of the ring buffer map
    ringbuf_map_fd = bpf_object__find_map_fd_by_name(obj, "ringbuff");
    if (ringbuf_map_fd < 0) {
        fprintf(stderr, "Error finding ringbuf map\n");
        return 1;
    }
    printf("Ring buffer map FD: %d\n", ringbuf_map_fd);

    // Create and configure the ring buffer
    rb = ring_buffer__new(ringbuf_map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Error creating ring buffer\n");
        return 1;
    }
    printf("Ring buffer position: %d\n", rb);

    printf("Listening for packets...\n");

    // Loop to process the events
    while (1) {
        int err = ring_buffer__poll(rb, 5000 /* timeout in ms */);
        if (err == -EINTR) {
            fprintf(stderr, "EINTR\n");
            break;
        } else if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        } else if (err == 0) {
            fprintf(stderr, "No packets received within timeout period\n");
        }
    }

    // Free resources and close BPF object
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
