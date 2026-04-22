#!/usr/bin/env sh
set -eu

tool=${1:?usage: cli_smoke.sh /path/to/min-corehdr}
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

tmpdir=${TMPDIR:-/tmp}/min-corehdr-cli-smoke.$$
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM
mkdir -p "$tmpdir"

cat > "$tmpdir/fixture.bpf.c" <<'EOF'
#define SEC(name) __attribute__((section(name), used))

struct task_struct {
    int pid;
} __attribute__((preserve_access_index));

SEC("xdp")
int min_corehdr_fixture(void *ctx)
{
    struct task_struct *task = ctx;
    return task->pid;
}

char _license[] SEC("license") = "GPL";
EOF

real_clang=$(clang -print-prog-name=clang)
"$real_clang" -target bpf -g -O2 -c "$tmpdir/fixture.bpf.c" -o "$tmpdir/fixture.bpf.o"

printf 'stale temp must survive\n' >"$tmpdir/vmlinux.h.tmp"
"$tool" --btf "$kernel_btf" --stats -o "$tmpdir/vmlinux.h" "$tmpdir/fixture.bpf.o" \
  >"$tmpdir/min-corehdr.out" 2>"$tmpdir/min-corehdr.err"

grep -q 'struct task_struct' "$tmpdir/vmlinux.h"
grep -qx 'stale temp must survive' "$tmpdir/vmlinux.h.tmp"
grep -q 'CO-RE relocations: 1' "$tmpdir/min-corehdr.err"

cat > "$tmpdir/recompile.bpf.c" <<'EOF'
#include "vmlinux.h"
#define SEC(name) __attribute__((section(name), used))

SEC("xdp")
int min_corehdr_fixture(void *ctx)
{
    struct task_struct *task = ctx;
    return task->pid;
}

char _license[] SEC("license") = "GPL";
EOF

"$real_clang" -target bpf -g -O2 -I"$tmpdir" -c "$tmpdir/recompile.bpf.c" \
  -o "$tmpdir/recompile.bpf.o"

llvm-readelf -S "$tmpdir/recompile.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'

"$tool" --btf "$kernel_btf" "$tmpdir/fixture.bpf.o" >"$tmpdir/stdout-header.h" \
  2>"$tmpdir/stdout-stderr.txt"
test ! -s "$tmpdir/stdout-stderr.txt"
grep -q 'struct task_struct' "$tmpdir/stdout-header.h"

"$tool" -vv --btf "$kernel_btf" --stats -o "$tmpdir/verbose.h" "$tmpdir/fixture.bpf.o" \
  >"$tmpdir/verbose.out" 2>"$tmpdir/verbose.err"
test ! -s "$tmpdir/verbose.out"
grep -q 'loading base BTF:' "$tmpdir/verbose.err"
grep -q 'loading object BTF:' "$tmpdir/verbose.err"
grep -q 'computing dependency closure' "$tmpdir/verbose.err"
grep -q 'seed candidates' "$tmpdir/verbose.err"

set +e
"$tool" --unknown >"$tmpdir/usage.out" 2>"$tmpdir/usage.err"
rc=$?
set -e
test "$rc" -eq 2
grep -q 'error: unknown option --unknown' "$tmpdir/usage.err"

set +e
"$tool" --btf "$tmpdir/missing-base.btf" "$tmpdir/fixture.bpf.o" \
  >"$tmpdir/missing-base.out" 2>"$tmpdir/missing-base.err"
rc=$?
set -e
test "$rc" -eq 1
grep -q 'failed to parse base BTF' "$tmpdir/missing-base.err"

set +e
"$tool" --btf "$kernel_btf" "$tmpdir/missing-object.bpf.o" \
  >"$tmpdir/missing-object.out" 2>"$tmpdir/missing-object.err"
rc=$?
set -e
test "$rc" -eq 1
grep -q 'failed to parse object BTF' "$tmpdir/missing-object.err"

set +e
"$tool" --btf "$kernel_btf" -o "$tmpdir/no-such-dir/out.h" "$tmpdir/fixture.bpf.o" \
  >"$tmpdir/output-open.out" 2>"$tmpdir/output-open.err"
rc=$?
set -e
test "$rc" -eq 1
grep -q 'failed to open output' "$tmpdir/output-open.err"
