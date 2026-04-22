# Minimal CO-RE Header Example

This example shows the intended `min-corehdr` workflow with a small hand-written local type header
and a practical BPF program shape: an `exec` tracepoint that writes task metadata to a ring buffer.
It is a build-time demonstration, not a runnable loader.

From the repository root:

```sh
nix develop
cmake --preset dev
cmake --build --preset dev
tmpdir=$(mktemp -d)
cp examples/minimal/exec_audit.bpf.c examples/minimal/local_types.h "$tmpdir/"
real_clang=$(clang -print-prog-name=clang)
bpf_cflags="-target bpf -g -O2 -Wall -Wextra -Werror"
"$real_clang" $bpf_cflags -I"$tmpdir" -c "$tmpdir/exec_audit.bpf.c" \
  -o "$tmpdir/exec_audit.bpf.o"
build/dev/min-corehdr --btf /sys/kernel/btf/vmlinux --stats \
  -o "$tmpdir/generated_local_types.h" "$tmpdir/exec_audit.bpf.o"
cp "$tmpdir/generated_local_types.h" "$tmpdir/local_types.h"
"$real_clang" $bpf_cflags -I"$tmpdir" -c "$tmpdir/exec_audit.bpf.c" \
  -o "$tmpdir/exec_audit.recompiled.bpf.o"
```

The source intentionally exercises the SPEC's compile-completeness surface:

- `task_struct->pid`, `task_struct->tgid`, `task_struct->comm`, and nested cred access
- pointer target access through `mm_struct` for argument bounds
- `sizeof(struct task_struct)` and by-value `struct list_head` assignment
- enum usage and an enum data anchor
- typedef chains resolving back to `struct task_struct`
- by-value embedded kernel structs, a union member, an anonymous nested record, and a flexible array

The generated header is expected to replace `local_types.h` for recompilation.
