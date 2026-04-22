#ifndef MIN_COREHDR_EXAMPLE_LOCAL_TYPES_H
#define MIN_COREHDR_EXAMPLE_LOCAL_TYPES_H

#define __pai __attribute__((preserve_access_index))

struct list_head {
  struct list_head *next;
  struct list_head *prev;
} __pai;

struct callback_head {
  struct callback_head *next;
  void (*func)(struct callback_head *head);
} __pai;

struct mm_struct {
  struct {
    struct {
      struct {
        int counter;
      } mm_count;
    };
  };
} __pai;

enum pid_type {
  PIDTYPE_PID = 0,
  PIDTYPE_TGID = 1,
  PIDTYPE_PGID = 2,
  PIDTYPE_SID = 3,
  PIDTYPE_MAX = 4,
};

struct task_struct {
  int pid;
  unsigned int flags;
  struct list_head tasks;
  struct mm_struct *mm;
  struct callback_head rcu;
} __pai;

#endif
