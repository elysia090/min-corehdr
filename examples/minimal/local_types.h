#ifndef MIN_COREHDR_EXAMPLE_LOCAL_TYPES_H
#define MIN_COREHDR_EXAMPLE_LOCAL_TYPES_H

#define __pai __attribute__((preserve_access_index))

struct list_head {
  struct list_head *next;
  struct list_head *prev;
} __pai;

typedef unsigned int uid_t;
typedef unsigned int gid_t;

typedef struct {
  uid_t val;
} kuid_t;

typedef struct {
  gid_t val;
} kgid_t;

struct mm_struct {
  unsigned long start_code;
  unsigned long end_code;
  unsigned long start_stack;
  unsigned long arg_start;
  unsigned long arg_end;
} __pai;

struct cred {
  kuid_t uid;
  kgid_t gid;
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
  int tgid;
  unsigned int flags;
  char comm[16];
  struct list_head tasks;
  struct mm_struct *mm;
  const struct cred *real_cred;
} __pai;

#endif
