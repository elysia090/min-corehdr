#include "local_types.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]

#define BPF_MAP_TYPE_RINGBUF 27

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

static void *(*bpf_ringbuf_reserve)(void *ringbuf, unsigned long size,
                                    unsigned long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long flags) = (void *)132;
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static void *(*bpf_get_current_task_btf)(void) = (void *)158;
static long (*bpf_probe_read_kernel_str)(void *dst, unsigned int size,
                                         const void *unsafe_ptr) = (void *)115;

typedef struct task_struct task_alias;
typedef task_alias task_alias2;

struct exec_event {
  unsigned int pid;
  unsigned int tgid;
  int kernel_pid;
  int kernel_tgid;
  uid_t uid;
  gid_t gid;
  unsigned int flags;
  unsigned long arg_bytes;
  unsigned long task_size;
  char comm[16];
  enum pid_type kind;
  struct {
    struct list_head sibling_link;
    union {
      unsigned long raw;
      enum pid_type kind;
    } payload;
  } surface;
  unsigned int optional_ids[];
};

static __attribute__((noinline)) enum pid_type classify_pid(task_alias2 *task) {
  return task->pid == task->tgid ? PIDTYPE_TGID : PIDTYPE_PID;
}

SEC("tracepoint/sched/sched_process_exec")
int audit_exec(void *ctx) {
  (void)ctx;

  struct task_struct *task = bpf_get_current_task_btf();
  struct exec_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (event == 0) {
    return 0;
  }

  unsigned long long pid_tgid = bpf_get_current_pid_tgid();
  typeof(task->pid) kernel_pid = task->pid;
  const struct cred *cred = task->real_cred;
  struct mm_struct *mm = task->mm;

  event->pid = (unsigned int)pid_tgid;
  event->tgid = (unsigned int)(pid_tgid >> 32);
  event->kernel_pid = kernel_pid;
  event->kernel_tgid = task->tgid;
  event->flags = task->flags;
  event->uid = cred != 0 ? cred->uid.val : 0;
  event->gid = cred != 0 ? cred->gid.val : 0;
  event->arg_bytes = mm != 0 ? mm->arg_end - mm->arg_start : 0;
  event->task_size = sizeof(struct task_struct);
  event->kind = classify_pid(task);
  event->surface.sibling_link = task->tasks;
  event->surface.payload.raw = task->tasks.next != 0;

  bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), task->comm);
  bpf_ringbuf_submit(event, 0);
  return 0;
}

char _license[] SEC("license") = "GPL";
