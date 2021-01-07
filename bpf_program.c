#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int bpf_prog(void *ctx) {
	char msg[] = "A new process spawned";
	bpf_trace_printk(msg, sizeof(msg));
	return 0;
}
