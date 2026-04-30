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

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/min-corehdr-bench.XXXXXX")
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

quote_for_sh() {
  printf "'"
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}

example_dir="$root/examples/minimal"
fixture_source="$tmpdir/fixture.bpf.c"
fixture_object="$tmpdir/fixture.bpf.o"

if [ -r "$example_dir/exec_audit.bpf.c" ] && [ -r "$example_dir/local_types.h" ]; then
  cp "$example_dir/exec_audit.bpf.c" "$fixture_source"
  cp "$example_dir/local_types.h" "$tmpdir/local_types.h"
else
  cat > "$fixture_source" <<'EOF'
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
fi

real_clang=$(clang -print-prog-name=clang)
"$real_clang" -target bpf -g -O2 -I"$tmpdir" -c "$fixture_source" -o "$fixture_object"

cmd="$(quote_for_sh "$tool") --btf $(quote_for_sh "$kernel_btf") -o $(quote_for_sh "$tmpdir/vmlinux.h") $(quote_for_sh "$fixture_object")"

if command -v hyperfine >/dev/null 2>&1; then
  hyperfine --warmup 3 --runs 10 --shell=none "$cmd"
else
  i=0
  while [ "$i" -lt 10 ]; do
    /usr/bin/time -f 'elapsed=%e user=%U sys=%S maxrss_kb=%M' \
      "$tool" --btf "$kernel_btf" -o "$tmpdir/vmlinux.h" "$fixture_object"
    i=$((i + 1))
  done
fi
