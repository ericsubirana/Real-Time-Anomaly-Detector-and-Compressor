//#include "vmlinux.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
//#include <bpf/bpf.h>
//#include <bpf/libbpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "netscan.h"
#include "ebpf_ml_model.h"


//bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

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

//BPF_MAP_TYPE_PERCPU_ARRAY
struct {
	__uint(type,BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_data);
	__uint(max_entries,256*1024);
} flows SEC(".maps");

struct {
	__uint(type,BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_data);
	__uint(max_entries,256*1024);
} flows_data SEC(".maps");

struct {
	__uint(type,BPF_MAP_TYPE_RINGBUF);
	//__type(key, __u32);
	//__type(value,struct flow_data);
	__uint(max_entries,256*1024);
} flow_exports SEC(".maps");

int predict(){

	return 0;
}

int read = 0;


/*SEC("init")
void load_ml_modle(){
}*/

SEC("xdp")
int netScan(struct xdp_md *ctx){
	struct flow_key key = {};
	struct flow_data *data;
	void *data_start = (void*)(long)ctx->data;
	void *data_end   = (void*)(long)ctx->data_end;

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
		if ((void *)tcp + sizeof(&tcp) > data_end) return XDP_PASS;
		key.src_port = tcp->source;
		key.dst_port = tcp->dest;
	} else if (key.protocol == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)(ip + 1);
		if ((void *)udp + sizeof(*udp) > data_end) return XDP_PASS;
		key.src_port = udp->source;
		key.dst_port = udp->dest;
	}
	data = bpf_map_lookup_elem(&flows,&key);
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
		//flows.update(&key, &new_data);
		bpf_map_update_elem(&flows,&key,&new_data,BPF_NOEXIST);
	}
	int result = predict(data);
	if(result){
	}
	else{
	}

	return XDP_PASS;

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
