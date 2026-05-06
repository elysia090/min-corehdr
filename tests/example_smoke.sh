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
if [ ! -r "$example_dir/build.sh" ] || [ ! -r "$example_dir/exec_audit.bpf.c" ] ||
  [ ! -r "$example_dir/task_snapshot.bpf.c" ] || [ ! -r "$example_dir/local_types.h" ]; then
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
    for file in "$tmpdir/stdout.txt" "$tmpdir/build-stderr.txt" \
      "$tmpdir/example/min-corehdr.stdout.txt" "$tmpdir/example/min-corehdr.stderr.txt"; do
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
mkdir -p "$tmpdir/example"

MIN_COREHDR_EXAMPLE_OUT="$tmpdir/example" sh "$example_dir/build.sh" "$tool" \
  >"$tmpdir/stdout.txt" 2>"$tmpdir/build-stderr.txt"

header="$tmpdir/example/generated/local_types.h"
stderr_log="$tmpdir/example/min-corehdr.stderr.txt"
stdout_log="$tmpdir/example/min-corehdr.stdout.txt"

test ! -s "$stdout_log"
grep -q 'preserve_access_index' "$header"
grep -q 'struct task_struct' "$header"
grep -q 'struct list_head' "$header"
grep -q 'struct mm_struct' "$header"
grep -q 'struct cred' "$header"
grep -q 'enum pid_type' "$header"
grep -q 'real_parent' "$header"
grep -q 'group_leader' "$header"
! grep -q 'struct exec_event' "$header"
! grep -q 'struct task_snapshot' "$header"

line_count=$(wc -l <"$header")
test "$line_count" -gt 20
test "$line_count" -lt 1000

grep -q 'requirements:' "$stderr_log"
grep -q 'source: object BTF seed' "$stderr_log"
grep -q 'source: CO-RE relocation FIELD_BYTE_OFFSET' "$stderr_log"
grep -q 'access:' "$stderr_log"
grep -q 'location:' "$stderr_log"
grep -q 'exec_audit.bpf.o' "$stderr_log"
grep -q 'task_snapshot.bpf.o' "$stderr_log"
grep -q 'objects: 2' "$stderr_log"
grep -q 'requirement root types:' "$stderr_log"
grep -q 'required record members:' "$stderr_log"
grep -q 'emitted required types:' "$stderr_log"

llvm-readelf -S "$tmpdir/example/original/exec_audit.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'
llvm-readelf -S "$tmpdir/example/original/task_snapshot.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'
llvm-readelf -S "$tmpdir/example/recompiled/exec_audit.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'
llvm-readelf -S "$tmpdir/example/recompiled/task_snapshot.bpf.o" | grep -Eq '\.BTF|\.BTF\.ext'
