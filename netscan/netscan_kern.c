//#include "vmlinux.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
//#include <bpf/bpf.h>
//#include <bpf/libbpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "netscan.h"


//bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

/*struct data_t {
	unsigned int pid;
	char comm[250];
	int data;
};*/


struct {
	__uint(type,BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries,256*1024);
} user_ringbuf SEC(".maps");

struct {
	__uint(type,BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256*1024);
} kernel_ringbuf SEC(".maps");

//BPF_RINGBUF_OUTPUT(buffer, 1 << 4);


int read = 0;

/*unsigned char lookup_protocol(struct xdp_md *ctx){
	unsigned char protocol = 0;
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if(data+sizeof(struct ethhdr)>data_end)
		return 0;
	if(bpf_ntohs(eth->h_proto)==ETH_P_IP){
		struct iphdr *iph = data+sizeof(struct ethhdr);
		if(data+sizeof(struct ethhdr)+sizeof(struct iphdr)<=data_end)
			protocol = iph->protocol;
	}
	return protocol;
}*/

unsigned int parse_xdp(struct xdp_md *ctx){
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	//struct icmphdf *icmp;
	//struct tcphdr *tcp;
	//struct updhdr *upd;
	if(data+sizeof(struct ethhdr)>data_end){
		return 0;
	}
	if(bpf_ntohs(eth->h_proto)!=ETH_P_IP){
		return 0;
	}
	iph = data+sizeof(struct ethhdr);
	switch(iph->protocol){
	case IPPROTO_ICMP:
	case IPPROTO_IPIP:
	case IPPROTO_IPV6:
	case IPPROTO_GRE:
		return 0;
	case IPPROTO_TCP:
		return IPPROTO_TCP;
		break;
	case IPPROTO_UDP:
		return IPPROTO_UDP;
		break;
	case IPPROTO_UDPLITE:
	default:
		return 0;
	}

}

/*static long do_nothing_cb(struct bpf_dynptr *dynptr){
	struct data_t *e;
	pid_t pid;
	e = bpf_ringbuf_reserve(&kernel_ringbuf,sizeof(*e),0);
	if(!e){
		return 0;
	}
	e->pid bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm,sizeof(e->comm));
	bpf_ringbuf_submit(e,0);
	__sync_fetch_and_add(&read,1);
	return 0;
}*/

inline void init_kernel_buff(){}

inline void init_user_buff(){}

/*SEC("init")
void load_ml_modle(){
}*/

SEC("xdp")
int netScan(struct xdp_md *ctx){
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;
	//struct ethhdr *eth = data;
	struct data_t *ddata;
	ddata = bpf_ringbuf_reserve(&kernel_ringbuf,sizeof(*ddata),0);
	if(!ddata) return XDP_PASS;
	ddata->pid = bpf_get_current_pid_tgid() >> 32;
	//struct kernel_ringbuf ringbuff = {};
	if(data+sizeof(struct ethhdr)>data_end){
		return XDP_PASS; //Not an ethernet header;
	}
	ddata->data = parse_xdp(ctx);
	//bpf_probe_read_str((void*)&(ddata->data),sizeof(ddata->data),(void*)&tmp);
	return XDP_PASS;

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
