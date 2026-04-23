#!/usr/bin/env sh
set -eu

tool=${1:?usage: spec_integration.sh /path/to/min-corehdr}
kernel_btf=${MIN_COREHDR_KERNEL_BTF:-/sys/kernel/btf/vmlinux}

if [ ! -r "$kernel_btf" ]; then
  echo "skip: kernel BTF not readable at $kernel_btf" >&2
  exit 77
fi
if ! command -v clang >/dev/null 2>&1; then
  echo "skip: clang is not available" >&2
  exit 77
fi
if ! command -v llvm-readelf >/dev/null 2>&1; then
  echo "skip: llvm-readelf is not available" >&2
  exit 77
fi

tmpdir=${TMPDIR:-/tmp}/min-corehdr-spec-integration.$$
cleanup() {
  rm -rf "$tmpdir"
}
finish() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    for file in "$tmpdir/stdout.txt" "$tmpdir/stats.txt"; do
      [ -f "$file" ] && { echo "== $file ==" >&2; cat "$file" >&2; }
    done
  fi
  cleanup
  exit "$rc"
}
trap finish EXIT INT TERM
mkdir -p "$tmpdir/local" "$tmpdir/generated" "$tmpdir/generated-reversed" "$tmpdir/recompiled"

cat > "$tmpdir/local/local_types.h" <<'EOF'
#define __pai __attribute__((preserve_access_index))

struct list_head {
    struct list_head *next;
    struct list_head *prev;
} __pai;

struct hlist_node {
    struct hlist_node *next;
    struct hlist_node **pprev;
} __pai;

struct hlist_head {
    struct hlist_node *first;
} __pai;

struct callback_head {
    struct callback_head *next;
    void (*func)(struct callback_head *head);
} __pai;

struct cacheline_padding {
    unsigned char x[];
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
    struct hlist_node pid_links[4];
    struct mm_struct *mm;
    unsigned int sched_reset_on_fork : 1;
    struct callback_head rcu;
    struct cacheline_padding padding;
} __pai;
EOF

cat > "$tmpdir/object_a.bpf.c" <<'EOF'
#include <local_types.h>

#define SEC(name) __attribute__((section(name), used))

enum pid_type _pid_type_anchor SEC(".data") = PIDTYPE_PID;

struct file;

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
    struct file *incomplete_ptr;
    unsigned int flags : 3;
    int values[];
};

static __attribute__((noinline)) enum pid_type choose_kind(enum pid_type kind)
{
    return kind;
}

static __attribute__((noinline)) int read_task(task_alias3 *task)
{
    enum pid_type kind = choose_kind(PIDTYPE_PID);
    int value = task->pid;

    value += sizeof(struct list_head);
    value += sizeof(struct cacheline_padding);
    value += sizeof(struct local_event);
    value += kind;
    value += task->tasks.next != 0;
    value += task->pid_links[0].next != 0;
    value += task->rcu.func != 0;
    value += task->sched_reset_on_fork;
    value += task->mm->mm_count.counter;
    return value;
}

SEC("xdp")
int min_corehdr_spec_a(void *ctx)
{
    return read_task((struct task_struct *)ctx);
}

char _license[] SEC("license") = "GPL";
EOF

cat > "$tmpdir/object_b.bpf.c" <<'EOF'
#include <local_types.h>

#define SEC(name) __attribute__((section(name), used))

struct local_holder {
    struct hlist_head head;
    struct hlist_node node;
    union {
        struct callback_head callback;
        struct list_head list;
    } storage;
};

SEC("xdp")
int min_corehdr_spec_b(void *ctx)
{
    struct task_struct *task = ctx;
    struct local_holder *holder = ctx;

    return task->pid + (holder->head.first != 0) + (holder->storage.callback.func != 0);
}

char _license[] SEC("license") = "GPL";
EOF

real_clang=$(clang -print-prog-name=clang)
"$real_clang" -target bpf -g -O2 -I"$tmpdir/local" -c "$tmpdir/object_a.bpf.c" \
  -o "$tmpdir/object_a.bpf.o"
"$real_clang" -target bpf -g -O2 -I"$tmpdir/local" -c "$tmpdir/object_b.bpf.c" \
  -o "$tmpdir/object_b.bpf.o"

"$tool" --btf "$kernel_btf" --stats -o "$tmpdir/generated/local_types.h" \
  "$tmpdir/object_a.bpf.o" "$tmpdir/object_b.bpf.o" >"$tmpdir/stdout.txt" \
  2>"$tmpdir/stats.txt"
test ! -s "$tmpdir/stdout.txt"

"$tool" --btf "$kernel_btf" -o "$tmpdir/generated-reversed/local_types.h" \
  "$tmpdir/object_b.bpf.o" "$tmpdir/object_a.bpf.o"
cmp -s "$tmpdir/generated/local_types.h" "$tmpdir/generated-reversed/local_types.h"

grep -q 'struct task_struct' "$tmpdir/generated/local_types.h"
grep -q 'struct list_head' "$tmpdir/generated/local_types.h"
grep -q 'struct callback_head' "$tmpdir/generated/local_types.h"
grep -q 'enum pid_type' "$tmpdir/generated/local_types.h"
grep -q 'CO-RE relocations:' "$tmpdir/stats.txt"

"$real_clang" -target bpf -g -O2 -I"$tmpdir/generated" -c "$tmpdir/object_a.bpf.c" \
  -o "$tmpdir/recompiled/object_a.bpf.o"
"$real_clang" -target bpf -g -O2 -I"$tmpdir/generated" -c "$tmpdir/object_b.bpf.c" \
  -o "$tmpdir/recompiled/object_b.bpf.o"

llvm-readelf -S "$tmpdir/recompiled/object_a.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'
llvm-readelf -S "$tmpdir/recompiled/object_b.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'
