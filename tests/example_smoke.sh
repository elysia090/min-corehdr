#!/usr/bin/env sh
set -eu

tool=${1:?usage: example_smoke.sh /path/to/min-corehdr}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
kernel_btf=${MIN_COREHDR_KERNEL_BTF:-/sys/kernel/btf/vmlinux}
example_dir="$root/examples/minimal"

if [ ! -x "$tool" ]; then
  echo "skip: tool is not executable: $tool" >&2
  exit 77
fi
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
if [ ! -r "$example_dir/exec_audit.bpf.c" ] || [ ! -r "$example_dir/local_types.h" ]; then
  echo "skip: minimal example sources are missing" >&2
  exit 77
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/min-corehdr-example-smoke.XXXXXX")
cleanup() {
  rm -rf "$tmpdir"
}
finish() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    for file in "$tmpdir/stdout.txt" "$tmpdir/stats.txt"; do
      [ -f "$file" ] && {
        echo "== $file ==" >&2
        cat "$file" >&2
      }
    done
  fi
  cleanup
  exit "$rc"
}
trap finish EXIT INT TERM
mkdir -p "$tmpdir/original" "$tmpdir/generated" "$tmpdir/generated-expand" "$tmpdir/recompiled" \
  "$tmpdir/recompiled-expand"

cp "$example_dir/exec_audit.bpf.c" "$example_dir/local_types.h" "$tmpdir/original/"

real_clang=$(clang -print-prog-name=clang)
bpf_cflags="-target bpf -g -O2 -Wall -Wextra -Werror"
"$real_clang" $bpf_cflags -I"$tmpdir/original" -c "$tmpdir/original/exec_audit.bpf.c" \
  -o "$tmpdir/original/exec_audit.bpf.o"
llvm-readelf -S "$tmpdir/original/exec_audit.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'

"$tool" --btf "$kernel_btf" --stats -o "$tmpdir/generated/local_types.h" \
  "$tmpdir/original/exec_audit.bpf.o" >"$tmpdir/stdout.txt" 2>"$tmpdir/stats.txt"

test ! -s "$tmpdir/stdout.txt"
grep -q 'preserve_access_index' "$tmpdir/generated/local_types.h"
grep -q 'struct task_struct' "$tmpdir/generated/local_types.h"
grep -q 'struct list_head' "$tmpdir/generated/local_types.h"
grep -q 'struct mm_struct' "$tmpdir/generated/local_types.h"
grep -q 'struct cred' "$tmpdir/generated/local_types.h"
grep -q 'enum pid_type' "$tmpdir/generated/local_types.h"
! grep -q 'struct exec_event' "$tmpdir/generated/local_types.h"
grep -q 'CO-RE relocations:' "$tmpdir/stats.txt"
grep -q 'emitted required types:' "$tmpdir/stats.txt"

cp "$example_dir/exec_audit.bpf.c" "$tmpdir/recompiled/"
cp "$tmpdir/generated/local_types.h" "$tmpdir/recompiled/local_types.h"
"$real_clang" $bpf_cflags -I"$tmpdir/recompiled" -c \
  "$tmpdir/recompiled/exec_audit.bpf.c" -o "$tmpdir/recompiled/exec_audit.bpf.o"
llvm-readelf -S "$tmpdir/recompiled/exec_audit.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'

"$tool" --expand-pointers --btf "$kernel_btf" -o "$tmpdir/generated-expand/local_types.h" \
  "$tmpdir/original/exec_audit.bpf.o"
cp "$example_dir/exec_audit.bpf.c" "$tmpdir/recompiled-expand/"
cp "$tmpdir/generated-expand/local_types.h" "$tmpdir/recompiled-expand/local_types.h"
"$real_clang" $bpf_cflags -I"$tmpdir/recompiled-expand" -c \
  "$tmpdir/recompiled-expand/exec_audit.bpf.c" -o "$tmpdir/recompiled-expand/exec_audit.bpf.o"
llvm-readelf -S "$tmpdir/recompiled-expand/exec_audit.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'
