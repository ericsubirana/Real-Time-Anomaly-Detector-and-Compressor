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

/*static int write_samples(struct user_ring_buffer *ringbuf){
	int i=0;
	struct data_t *entry;
	entry = user_ring_buffer__reserve(ringbuf,sizeof(*entry));
	if(!entry){
		drain_current_samples();
		return -errno;
	}
	entry->pid = getpid();
	//strncpy(entry->comm,"1\n",1*sizeof(char));
	(entry->comm)[0]='1';
	int read = snprintf(entry->comm,sizeof(entry->comm),"%u",i);
	if(read<=0){
		user_ring_buffer__discard(ringbuf, entry);
		drain_current_samples();
		return -errno;
	}
	user_ring_buffer__submit(ringbuf,entry);

	return 0;
}*/

static int handle_event(void *ctx,void *data, long unsigned int size){
	printf("Read from kernel ring buffer\n");
	return 0;
}

int main(){
	int err =0;
	struct ring_buffer *rb = NULL;
	struct user_ring_buffer *user_ring_buffer;
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
	skel->bss->read = 0; //Parameterize BPF code with minimim duration parameter
	err = netscan_kern__load(skel);
	if(err){
		fprintf(stderr, "Failted to create ring buffer\n");
		return 1;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.kernel_ringbuf),handle_event,NULL,NULL);
	if(!rb){
		fprintf(stderr,"Failed to create ring buffer!\n");
		return -1;
	}
	user_ring_buffer = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ringbuf),NULL);

	
	//write_samples(user_ring_buffer);

	//bpf_ringbuf_poll(NULL,NULL,handle_event,NULL);
	
	ring_buffer__free(rb);
	netscan_kern__destroy(skel);
	user_ring_buffer__free(user_ring_buffer);
	return 0;
}
