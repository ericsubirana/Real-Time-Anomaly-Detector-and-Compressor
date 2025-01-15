#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <sys/resource.h>
#include <string.h>
#include <errno.h>

#include "netscan.h"
#include "netscan_user.skel.h"

static void drain_current_samples(){
	printf("Draining current Samples\n");
}

static volatile bool exiting = false;
static void sig_handler(int sig){
	exiting = true;
}

static int handle_event(void *ctx,void *data, long unsigned int size){
	printf("Read from kernel ring buffer\n");
	return 0;
}

int main(){
	int err =0;
	struct ring_buffer *rb = NULL;
	struct netscan_kern *skel;

	signal(SIGINT,sig_handler);
	signal(SIGTERM,sig_handler);

	//Load and Verify BPF application
	skel = netscan_kern__open();
	if(!skel){
		fprintf(stderr, "Failted ot open and load BPF skeleton\n");
		drain_current_samples();
		return 1;
	}
	err = netscan_kern__load(skel);
	if(err){
		fprintf(stderr, "Failted to create ring buffer\n");
		return 1;
	}
	rb = ring_buffer__new(bpf_map__fd(skel->maps.flow_exports),handle_event,NULL,NULL);
	
	//write_samples(user_ring_buffer);

	//bpf_ringbuf_poll(NULL,NULL,handle_event,NULL);
	
	ring_buffer__free(rb);
	netscan_kern__destroy(skel);
	return 0;
}
