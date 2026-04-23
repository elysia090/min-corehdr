#!/usr/bin/env sh
set -eu

tool=${1:?usage: cli_unresolved.sh /path/to/min-corehdr}
kernel_btf=${MIN_COREHDR_KERNEL_BTF:-/sys/kernel/btf/vmlinux}

if [ ! -r "$kernel_btf" ]; then
  echo "skip: kernel BTF not readable at $kernel_btf" >&2
  exit 77
fi
if ! command -v clang >/dev/null 2>&1; then
  echo "skip: clang is not available" >&2
  exit 77
fi

tmpdir=${TMPDIR:-/tmp}/min-corehdr-cli-unresolved.$$
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM
mkdir -p "$tmpdir"

cat > "$tmpdir/bad.bpf.c" <<'EOF'
#define SEC(name) __attribute__((section(name), used))

struct definitely_not_a_kernel_type_for_min_corehdr {
    int value;
} __attribute__((preserve_access_index));

SEC("xdp")
int min_corehdr_bad(void *ctx)
{
    struct definitely_not_a_kernel_type_for_min_corehdr *bad = ctx;
    return bad->value;
}

char _license[] SEC("license") = "GPL";
EOF

real_clang=$(clang -print-prog-name=clang)
"$real_clang" -target bpf -g -O2 -c "$tmpdir/bad.bpf.c" -o "$tmpdir/bad.bpf.o"

set +e
"$tool" --btf "$kernel_btf" -o "$tmpdir/out.h" "$tmpdir/bad.bpf.o" \
  >"$tmpdir/stdout.txt" 2>"$tmpdir/stderr.txt"
rc=$?
set -e

test "$rc" -eq 1
test ! -s "$tmpdir/stdout.txt"
test ! -f "$tmpdir/out.h"
grep -q "error: failed to resolve kernel type 'definitely_not_a_kernel_type_for_min_corehdr'" \
  "$tmpdir/stderr.txt"
grep -q "in: .*bad.bpf.c:" "$tmpdir/stderr.txt"
grep -q "function: min_corehdr_bad" "$tmpdir/stderr.txt"
grep -q "section: xdp" "$tmpdir/stderr.txt"
grep -q "CO-RE FIELD_BYTE_OFFSET" "$tmpdir/stderr.txt"
grep -q "access:" "$tmpdir/stderr.txt"
grep -q "file: .*bad.bpf.o" "$tmpdir/stderr.txt"
grep -q "hint:" "$tmpdir/stderr.txt"
