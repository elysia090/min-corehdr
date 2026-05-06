# Practical Minimal Example

This directory is a small but realistic libbpf-style CO-RE source set. It starts with a
hand-written `local_types.h`, builds two `.bpf.o` objects, asks `min-corehdr` to generate a smaller
compile-complete replacement header, and recompiles both BPF sources with the generated header.

The example intentionally covers common maintenance pressure points:

- multiple BPF objects sharing one local type header
- object-BTF roots such as `task_struct`, `cred`, `mm_struct`, typedefs, and `pid_type`
- CO-RE field relocations over nested pointers and anonymous target records
- by-value local event structs that must not leak into the generated kernel header
- `--explain` witness output that shows why roots and record members were required

Run it from a configured checkout:

```sh
cmake --build --preset dev
sh examples/minimal/build.sh build/dev/min-corehdr
```

Useful outputs are written under `examples/minimal/build/` by default:

- `original/*.bpf.o`: objects built against the hand-written header
- `generated/local_types.h`: generated replacement header
- `min-corehdr.stderr.txt`: requirement witness and stats
- `recompiled/*.bpf.o`: objects rebuilt against the generated header

Use `MIN_COREHDR_EXAMPLE_OUT=/tmp/min-corehdr-example` to write artifacts outside the source tree.
