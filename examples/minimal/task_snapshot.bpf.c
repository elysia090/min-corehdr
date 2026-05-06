#include "bpf_helpers.h"
#include "local_types.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22);
} task_events SEC(".maps");

struct task_snapshot {
  unsigned int pid;
  unsigned int tgid;
  int parent_pid;
  int leader_tgid;
  enum pid_type relation;
  char comm[16];
};

static __attribute__((noinline)) enum pid_type classify_relation(struct task_struct *task) {
  return task->group_leader == task ? PIDTYPE_TGID : PIDTYPE_PID;
}

SEC("tracepoint/sched/sched_switch")
int snapshot_current_task(void *ctx) {
  (void)ctx;

  struct task_struct *task = bpf_get_current_task_btf();
  struct task_snapshot *event = bpf_ringbuf_reserve(&task_events, sizeof(*event), 0);
  if (event == 0) {
    return 0;
  }

  unsigned long long pid_tgid = bpf_get_current_pid_tgid();
  struct task_struct *parent = task->real_parent;
  struct task_struct *leader = task->group_leader;

  event->pid = (unsigned int)pid_tgid;
  event->tgid = (unsigned int)(pid_tgid >> 32);
  event->parent_pid = parent != 0 ? parent->pid : 0;
  event->leader_tgid = leader != 0 ? leader->tgid : 0;
  event->relation = classify_relation(task);

  bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), task->comm);
  bpf_ringbuf_submit(event, 0);
  return 0;
}

char _license[] SEC("license") = "GPL";
