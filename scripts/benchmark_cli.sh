#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tool=${1:-$root/build/dev/min-corehdr}
kernel_btf=${MIN_COREHDR_KERNEL_BTF:-/sys/kernel/btf/vmlinux}

if [ ! -x "$tool" ]; then
  echo "error: tool is not executable: $tool" >&2
  exit 1
fi
if [ ! -r "$kernel_btf" ]; then
  echo "skip: kernel BTF not readable at $kernel_btf" >&2
  exit 77
fi
if ! command -v clang >/dev/null 2>&1; then
  echo "error: clang is not available" >&2
  exit 1
fi

tmpdir=${TMPDIR:-/tmp}/min-corehdr-bench.$$
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM
mkdir -p "$tmpdir"

cat > "$tmpdir/fixture.bpf.c" <<'EOF'
#define SEC(name) __attribute__((section(name), used))

struct list_head {
    struct list_head *next;
    struct list_head *prev;
} __attribute__((preserve_access_index));

struct task_struct {
    int pid;
    struct list_head tasks;
} __attribute__((preserve_access_index));

SEC("xdp")
int min_corehdr_bench(void *ctx)
{
    struct task_struct *task = ctx;
    return task->pid + (task->tasks.next != 0);
}

char _license[] SEC("license") = "GPL";
EOF

real_clang=$(clang -print-prog-name=clang)
"$real_clang" -target bpf -g -O2 -c "$tmpdir/fixture.bpf.c" -o "$tmpdir/fixture.bpf.o"

cmd="$tool --btf $kernel_btf -o $tmpdir/vmlinux.h $tmpdir/fixture.bpf.o"
if command -v hyperfine >/dev/null 2>&1; then
  hyperfine --warmup 3 --runs 10 "$cmd"
else
  i=0
  while [ "$i" -lt 10 ]; do
    /usr/bin/time -f 'elapsed=%e user=%U sys=%S maxrss_kb=%M' sh -c "$cmd"
    i=$((i + 1))
  done
fi
