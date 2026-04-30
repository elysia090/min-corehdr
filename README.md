<!-- SPDX-License-Identifier: MIT -->

# min-corehdr

`min-corehdr` is an object-driven build-time utility for generating a reduced local CO-RE C header from one or more `.bpf.o` files and an explicit base BTF file.

The v0.1 implementation is intentionally narrow: load BTF with libbpf, derive initial kernel-facing seeds from object-local BTF by exact same-name/same-kind matching, mix in CO-RE relocation roots from `.BTF.ext`, close dependencies conservatively, then emit one deterministic C header.

## Problem

CO-RE BPF projects often choose between a full `vmlinux.h`, which is large and noisy for builds, indexing, and review, or a hand-trimmed local header, which is easy to forget and brittle when BPF programs change. Existing tools cover nearby jobs: `bpftool gen min_core_btf` emits runtime BTF, and `bpftool btf dump ... root_id ... format c` can emit C only after the user already knows numeric roots.

`min-corehdr` closes that build-time gap by deriving the roots from `.bpf.o` metadata, then emitting a compile-complete reduced C header from an explicit base BTF.

## Development

Enter the Nix development shell first. It provides the compiler, LLVM inspection tools, and native build tools so the host system does not need them installed globally.

```sh
nix develop
```

Configure, build, and run tests with the CMake presets. The CLI smoke test uses `/sys/kernel/btf/vmlinux` when available and skips itself otherwise:

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
cmake --build --preset dev --target check-format
```

Measure source coverage with LLVM coverage instrumentation:

```sh
scripts/coverage.sh
```

Benchmark the main CLI path against the local kernel BTF with `hyperfine`:

```sh
scripts/benchmark_cli.sh
```

Format sources when needed:

```sh
cmake --build --preset dev --target format
```

CI runs the same Nix-backed build, unit/integration test, check-format, coverage, and package
smoke gates on GitHub Actions.

## Try the Minimal Example

For a first end-to-end run, use `examples/minimal`. It contains a small hand-written CO-RE
`local_types.h` plus an `exec` tracepoint/ringbuf BPF source that exercises field access,
`sizeof`, enum usage, typedef chains, by-value embedded structs/unions, an anonymous nested
record, and generated-header recompilation.

```sh
cmake --build --preset dev
sh tests/example_smoke.sh build/dev/min-corehdr
```

The same example is wired into CTest as `example-smoke`; it skips automatically when the local
kernel BTF or BPF-capable clang is unavailable.

## Usage

```sh
min-corehdr --btf /sys/kernel/btf/vmlinux -o vmlinux.h foo.bpf.o
```

Without `-o`, the generated header is written to stdout and diagnostics stay on stderr.

Use `--expand-pointers` when you prefer conservative compile-time coverage over the smallest
possible header. The default keeps pointer targets as forward declarations unless they are reached
by fields, arrays, function prototypes, variables, datasecs, or CO-RE relocation roots.

## Current Slice

Implemented now:

- CLI shape from `docs/CLI.md`
- explicit base BTF and object BTF loading through libbpf
- O(1)-average base BTF exact name/kind lookup through a compact index
- object-local BTF seed extraction with v0.1 exact name/kind resolution and local typedef-chain unwrapping
- CO-RE relocation root extraction from `.BTF.ext`
- source-aware failure diagnostics from `.BTF.ext` function and line metadata, including the
  object-BTF type, base-BTF lookup, and CO-RE relocation ordinal when available
- worklist-based conservative dependency closure over base BTF
- C header emission with include guard, forward declarations, record definitions, enums, member-position typedef names, and `preserve_access_index`
- unit tests for CLI parsing, type sets, base BTF indexing, seed extraction, and dependency closure
- checked-in practical BPF example plus fixture-based integration tests for the SPEC compile-completeness matrix, multi-object union, deterministic output, generated-header recompilation, and unresolved CO-RE failure paths
- LLVM coverage and `hyperfine` benchmark scripts for standard measurement

## Implementation Notes

`min-corehdr` uses libbpf for BTF loading and parses the libbpf-provided raw `.BTF.ext` UAPI
records to derive CO-RE relocation roots and source-aware diagnostics. This is intentionally kept
small and covered by malformed-record tests because libbpf does not expose a public CO-RE relocation
iterator API.

## Current Limits

The v0.1 matcher is intentionally strict: named kernel types must resolve by exact same-name,
same-kind lookup, ambiguous matches fail, and `struct`/`union` forward-declaration flavoring is not
guessed. Anonymous enums are matched only when their enumerator names, values, signedness, size, and
order exactly match the base BTF. These rules favor reproducible headers and clear failures over
opaque best-effort output.

## License

MIT. See `LICENSE`.
