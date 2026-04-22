#include "local_types.h"

#define SEC(name) __attribute__((section(name), used))

enum pid_type _pid_type_anchor SEC(".data") = PIDTYPE_PID;

typedef struct task_struct task_alias1;
typedef task_alias1 task_alias2;
typedef task_alias2 task_alias3;

struct local_event {
  int pid;
  enum pid_type kind;
  struct list_head by_value;
  union {
    struct list_head as_list;
    int raw;
  } payload;
  struct {
    int nested_value;
    struct list_head nested_list;
  };
  unsigned int flags : 3;
  int values[];
};

static __attribute__((noinline)) enum pid_type choose_kind(enum pid_type kind) { return kind; }

static __attribute__((noinline)) int read_task(task_alias3 *task) {
  typeof(task->pid) pid = task->pid;
  struct local_event *event = (void *)task;
  int value = pid;

  value += sizeof(struct task_struct);
  value += sizeof(struct list_head);
  value += sizeof(struct local_event);
  value += choose_kind(PIDTYPE_PID);
  value += event->payload.raw;
  value += event->nested_list.next != 0;
  value += task->flags != 0;
  value += task->tasks.next != 0;
  value += task->rcu.func != 0;
  value += task->mm->mm_count.counter;
  return value;
}

SEC("xdp")
int min_corehdr_minimal_task_pid(void *ctx) { return read_task((struct task_struct *)ctx); }

char _license[] SEC("license") = "GPL";
