#ifndef MIN_COREHDR_EXAMPLE_BPF_HELPERS_H
#define MIN_COREHDR_EXAMPLE_BPF_HELPERS_H

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]

#define BPF_MAP_TYPE_RINGBUF 27

static void *(*bpf_ringbuf_reserve)(void *ringbuf, unsigned long size,
                                    unsigned long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long flags) = (void *)132;
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static void *(*bpf_get_current_task_btf)(void) = (void *)158;
static long (*bpf_probe_read_kernel_str)(void *dst, unsigned int size,
                                         const void *unsafe_ptr) = (void *)115;

#endif
