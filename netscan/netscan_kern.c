//#include "vmlinux.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/icmp.h>
//#include <bpf/bpf.h>
//#include <bpf/libbpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "netscan.h"
#include "ebpf_ml_model.h"


//bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

/*enum lg_values{//linear regression values
	FIRST_SEEN;
	LAST_SEEN;
	PACKET_COUNT;
	BYTE_COUNT;
	FWD_PACKET_COUNT;
	BWD_PACKET_COUNT;
	FWD_BYTE_COUNT;
	BWD_BYTE_COUNT;
	MIN_PACKET_LENGTH;
	MAX_PACKET_LENGTH;
	PACKET_LENGTH_SQUARE_SUM;
	FLOW_DURATION;
	FLOW_IAT_TOTAL;
	FLOW_IAT_MIN;
	FLOW_IAT_MAX;
	FWD_IAT_TOTAL;
	FWD_IAT_MIN;
	FWD_IAT_MAX;
	BWD_IAT_TOTAL;
	BWD_IAT_MIN;
	BWD_IAT_MAX;
	SYN_COUNT;
	ACK_COUNT;
	PSH_COUNT;
	URG_COUNT;
	FIN_COUNT;
	RST_COUNT;
};*/

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


static __always_inline void update_flow(struct flow_data *data){
	data->first_seen = bpf_ktime_get_ns();
	data->last_seen = data->first_seen;
	data->packet_count;
	data->byte_count;
	data->fwd_packet_count;
	data->bwd_packet_count;
	data->fwd_byte_count;
	data->bwd_byte_count;
	data->min_packet_length;
	data->max_packet_length;
	data->packet_length_square_sum;
	data->flow_duration;
	data->flow_iat_total;
	data->flow_iat_min;
	data->flow_iat_max;
	data->fwd_iat_total;
	data->fwd_iat_min;
	data->fwd_iat_max;
	data->bwd_iat_total;
	data->bwd_iat_min;
	data->bwd_iat_max;
	data->syn_count;
	data->ack_count;
	data->psh_count;
	data->urg_count;
	data->fin_count;
	data->rst_count;
};

static __always_inline void new_flow(struct flow_data *data){
};

int predict(struct flow_key *key,struct flow_data *data){
	int i,j;
	for(i=0;i<ML_HEIGHT;i++){
		for(j=0;j<ML_WIDTH;j++){
		}
	}

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
	else if (key.protocol == IPPROTO_UDP) {
		struct icmphdr *icmp = (struct icmphdr*)(ip + 1);
		if ((void *)icmp + sizeof(*icmp) > data_end) return XDP_PASS;
		key.src_port = 0;
		key.dst_port = 0;
	}
	data = bpf_map_lookup_elem(&flows,&key);
	if (data) {
		update_flow(data);
		// Flow exists, update packet count and last seen timestamp
		__sync_fetch_and_add(&data->packet_count, 1);
		data->last_seen = bpf_ktime_get_ns();
	} else {
		struct flow_key tmp_key = key;
		__u32 tmp = key.src_ip;
		key.src_ip = key.dst_ip;
		key.dst_ip = tmp;
		tmp = key.src_port;
		key.src_port = key.dst_port;
		key.dst_port = tmp;

		data = bpf_map_lookup_elem(&flows,&key);
		if(data){
			//update
		}
		else{
			key = tmp_key;
			// Create new flow
			struct flow_data new_data = {};
			new_flow(&new_data);
			new_data.packet_count = 1;
			new_data.first_seen = bpf_ktime_get_ns();
			new_data.last_seen = bpf_ktime_get_ns();
			/*new_data.total_fwd_length;
			new_data.total_bwd_length;
			new_data.total_fwd;
			new_data.total_bwd;
			new_data.;
			*/
			//flows.update(&key, &new_data);
			bpf_map_update_elem(&flows,&key,&new_data,BPF_NOEXIST);
		}
	}
	int result = predict(&key,data);
	if(result){
	}
	else{
	}

	return XDP_PASS;

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
