#!/usr/bin/env sh
set -eu

tool=${1:-${MIN_COREHDR_TOOL:-}}
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kernel_btf=${MIN_COREHDR_KERNEL_BTF:-/sys/kernel/btf/vmlinux}
out=${MIN_COREHDR_EXAMPLE_OUT:-"$root/build"}
sources="exec_audit.bpf.c task_snapshot.bpf.c"

if [ -z "$tool" ]; then
  tool="$root/../../build/dev/min-corehdr"
fi
if [ ! -x "$tool" ]; then
  echo "error: min-corehdr is not executable: $tool" >&2
  exit 1
fi
if [ ! -r "$kernel_btf" ]; then
  echo "error: kernel BTF is not readable: $kernel_btf" >&2
  exit 1
fi
if ! command -v clang >/dev/null 2>&1; then
  echo "error: clang is not available" >&2
  exit 1
fi
if ! command -v llvm-readelf >/dev/null 2>&1; then
  echo "error: llvm-readelf is not available" >&2
  exit 1
fi

original_dir="$out/original"
generated_dir="$out/generated"
recompiled_src_dir="$out/recompiled-src"
recompiled_dir="$out/recompiled"
stdout_log="$out/min-corehdr.stdout.txt"
stderr_log="$out/min-corehdr.stderr.txt"
header="$generated_dir/local_types.h"

mkdir -p "$original_dir" "$generated_dir" "$recompiled_src_dir" "$recompiled_dir"

real_clang=$(clang -print-prog-name=clang)
bpf_cflags="-target bpf -g -O2 -Wall -Wextra -Werror"

objects=
for src in $sources; do
  base=${src%.c}
  obj="$original_dir/$base.o"

  "$real_clang" $bpf_cflags -I"$root" -c "$root/$src" -o "$obj"
  llvm-readelf -S "$obj" | grep -Eq '\.BTF|\.BTF\.ext'
  objects="$objects $obj"
done

"$tool" --btf "$kernel_btf" --explain --stats -o "$header" $objects >"$stdout_log" \
  2>"$stderr_log"

for src in $sources; do
  cp "$root/$src" "$recompiled_src_dir/"
done
cp "$root/bpf_helpers.h" "$recompiled_src_dir/"

for src in $sources; do
  base=${src%.c}
  obj="$recompiled_dir/$base.o"

  "$real_clang" $bpf_cflags -I"$generated_dir" -I"$recompiled_src_dir" \
    -c "$recompiled_src_dir/$src" -o "$obj"
  llvm-readelf -S "$obj" | grep -Eq '\.BTF|\.BTF\.ext'
done

wc -l "$header"
printf 'generated header: %s\n' "$header"
printf 'witness/stats:    %s\n' "$stderr_log"
