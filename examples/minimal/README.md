# Minimal CO-RE Header Example

This example shows the intended `min-corehdr` workflow with a tiny hand-written local type header.
It is a build-time demonstration, not a runnable loader.

From the repository root:

```sh
nix develop
cmake --preset dev
cmake --build --preset dev
tmpdir=$(mktemp -d)
cp examples/minimal/task_pid.bpf.c examples/minimal/local_types.h "$tmpdir/"
real_clang=$(clang -print-prog-name=clang)
"$real_clang" -target bpf -g -O2 -I"$tmpdir" -c "$tmpdir/task_pid.bpf.c" \
  -o "$tmpdir/task_pid.bpf.o"
build/dev/min-corehdr --btf /sys/kernel/btf/vmlinux --stats \
  -o "$tmpdir/generated_local_types.h" "$tmpdir/task_pid.bpf.o"
cp "$tmpdir/generated_local_types.h" "$tmpdir/local_types.h"
"$real_clang" -target bpf -g -O2 -I"$tmpdir" -c "$tmpdir/task_pid.bpf.c" \
  -o "$tmpdir/task_pid.recompiled.bpf.o"
```

The source intentionally exercises the SPEC's compile-completeness surface:

- `task_struct->pid`, nested field access, and pointer target access through `mm_struct`
- `sizeof(struct task_struct)` and `sizeof(struct list_head)`
- enum usage and an enum data anchor
- typedef chains resolving back to `struct task_struct`
- by-value embedded kernel structs, a union member, an anonymous nested record, and a flexible array

The generated header is expected to replace `local_types.h` for recompilation.
