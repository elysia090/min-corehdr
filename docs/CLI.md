CLI.md

1. Command-Line Philosophy

min-corehdr is a single-purpose build-time tool.

Its CLI should follow four rules:

1. one primary mode of operation
2. explicit inputs
3. predictable stdout/stderr behavior
4. no command hierarchy unless a second independent responsibility appears

In v0.1, this means:

* no subcommands for the main workflow
* one required domain-specific input option: --btf
* one or more positional object inputs
* generated header to stdout by default
* diagnostics to stderr
* standard --help and --version

This keeps the tool aligned with common Unix/GNU practice while staying small.

2. Scope of the CLI

The CLI is for generating a reduced local CO-RE header from one or more .bpf.o files.

The CLI is not designed to replace:

* bpftool gen skeleton
* bpftool gen min_core_btf
* runtime BTF selection
* verifier log tooling

It is intentionally narrow.

3. Canonical Binary Name

The canonical binary name is:

min-corehdr

The repository name and binary name should match.

4. Top-Level Syntax

4.1 Canonical Synopsis

min-corehdr [OPTIONS] --btf FILE OBJECT...
min-corehdr [GLOBAL_OPTIONS] --help
min-corehdr [GLOBAL_OPTIONS] --version

4.2 Rationale

This shape is preferred over a subcommand-based form because:

* the tool has only one real job in v0.1
* a top-level direct invocation is simpler to remember
* it stays consistent with Unix utility conventions
* it avoids inventing a command namespace before it is needed

4.3 Positional Rules

* OBJECT... means one or more .bpf.o files
* positional arguments are inputs only
* output files are always specified by option, never by positional argument
* -- must terminate option parsing

Example:

min-corehdr --btf /sys/kernel/btf/vmlinux -- foo.bpf.o

5. Global Options

Global options apply to the whole invocation and must appear before or after --btf without changing meaning.

5.1 -h, --help

Print concise usage information and exit successfully.

Behavior:

* min-corehdr --help prints top-level help
* help output must fit ordinary terminal use
* help must show the main synopsis first
* help must include at least one example

5.2 -V, --version

Print version information and exit successfully.

Version output should include:

* tool version
* build or git revision if available
* linked libbpf version if cheap and reliable to report

The output should be one compact block, suitable for bug reports.

5.3 -v, --verbose

Increase diagnostic verbosity.

Rules:

* repeatable
* affects stderr only
* must not change the generated header

Examples:

min-corehdr -v --btf FILE foo.bpf.o
min-corehdr -vv --btf FILE foo.bpf.o

Suggested levels:

* default: errors only
* -v: high-level progress and counts
* -vv: per-object seed/closure details

5.4 -q, --quiet

Reduce non-error diagnostics.

Rules:

* affects stderr only
* must not suppress actual failures
* must not change generated header output

If both --quiet and --verbose are provided, the last one wins.

6. Main Options

These options control header generation.

6.1 --btf FILE

Required.

Path to the base BTF file used as the source of truth for kernel types.

Rules:

* exactly one --btf is required in v0.1
* missing --btf is a usage error
* unreadable or invalid --btf is a runtime error
* no implicit fallback to /sys/kernel/btf/vmlinux in v0.1

Example:

min-corehdr --btf /sys/kernel/btf/vmlinux foo.bpf.o

6.2 -o FILE, --output FILE

Optional.

Write the generated header to FILE instead of stdout.

Rules:

* if omitted, header is written to stdout
* if provided, stdout should normally remain empty
* diagnostics still go to stderr
* output file is truncated and rewritten atomically if practical

Example:

min-corehdr --btf /sys/kernel/btf/vmlinux -o vmlinux.h foo.bpf.o

6.3 --stats

Optional.

Print a short human-readable summary to stderr after successful generation.

The summary may include:

* number of input objects
* number of seed types
* number of emitted types
* approximate reduction relative to full header source

Rules:

* not machine-stable in v0.1
* must never be mixed into stdout header output
* intended for humans only

Example:

min-corehdr --btf /sys/kernel/btf/vmlinux --stats foo.bpf.o > vmlinux.h

6.4 --explain

Optional.

Print a human-readable requirement witness to stderr after successful generation.

The witness describes direct object-derived requirements, such as root kernel types and CO-RE
record members, that caused the generated header to include type surface.

Rules:

* not machine-stable in v0.1
* must never be mixed into stdout header output
* must remain deterministic for identical inputs
* must be concise enough for review in normal CI logs

Example:

min-corehdr --btf /sys/kernel/btf/vmlinux --explain foo.bpf.o > vmlinux.h

6.5 --expand-pointers

Optional.

Also include pointee types in the dependency closure.

The default closure keeps pointer targets as forward declarations unless another required path
reaches the pointee type. This keeps the generated header small for large kernel records. Use
--expand-pointers when conservative compile-time completeness is more important than minimal output.

Rules:

* must not affect seed resolution
* may increase output size
* must remain deterministic
* must not change stdout/stderr stream rules

7. Output Stream Rules

7.1 Stdout

Stdout is for the generated header only.

If --output is not used:

* write header text to stdout
* write nothing else to stdout

If --output is used:

* stdout should normally remain empty

7.2 Stderr

Stderr is for:

* errors
* warnings
* verbose progress
* stats
* requirement witness output
* non-header diagnostics

This split is mandatory.

It allows safe shell usage such as:

min-corehdr --btf FILE foo.bpf.o > vmlinux.h

without contaminating the generated header.

8. Exit Codes

Use a small, stable exit-code set.

8.1 0

Success.

8.2 2

Usage error.

Examples:

* missing --btf
* no input objects
* unknown option
* invalid option combination

8.3 1

Operational failure.

Examples:

* unreadable input file
* ELF parse failure
* BTF parse failure
* unresolved required type
* output write failure
* internal consistency failure

Do not over-segment exit codes in v0.1.

9. Help Text Style

Help output should follow these rules:

* start with one-line purpose
* show synopsis early
* keep option descriptions short
* prefer examples over long prose
* avoid implementation detail in --help
* point users to full docs only if those docs exist

Suggested structure:

min-corehdr — generate a compile-complete minimal local CO-RE header from .bpf.o inputs
Usage:
  min-corehdr [OPTIONS] --btf FILE OBJECT...
  min-corehdr --help
  min-corehdr --version
Global options:
  -h, --help
  -V, --version
  -v, --verbose
  -q, --quiet
Main options:
      --btf FILE
  -o, --output FILE
      --expand-pointers
      --explain
      --stats

10. Error Message Style

Errors must be short, direct, and actionable.

Format:

error: failed to resolve kernel type 'task_struct'
in:    source.bpf.c:42:7 (function: handle_exec, section: xdp, insn: 16, CO-RE FIELD_BYTE_OFFSET, access: 0:1, type_id: 12, relo: #1, section relo: #1)
file: foo.bpf.o
detail: CO-RE relocation object type: id 12 STRUCT 'task_struct'; base BTF query: id 12 STRUCT 'task_struct' -> no same-name, same-kind match
hint: verify that --btf points to the intended target kernel BTF

Rules:

* first line states the failure
* `in:` identifies the source location, function, section, CO-RE relocation kind, access string,
  object type id, and relocation ordinal when `.BTF.ext` metadata is available
* `file:` identifies the object file when possible
* `detail:` describes the object-BTF type and base-BTF lookup that failed
* optional hint gives one next action
* no stack traces by default
* no internal jargon unless unavoidable

11. Examples

11.1 Basic Usage

min-corehdr --btf /sys/kernel/btf/vmlinux foo.bpf.o > vmlinux.h

11.2 Write Directly to a File

min-corehdr --btf /sys/kernel/btf/vmlinux -o vmlinux.h foo.bpf.o

11.3 Multiple Objects

min-corehdr --btf /sys/kernel/btf/vmlinux -o vmlinux.h foo.bpf.o bar.bpf.o

11.4 Verbose Diagnostics

min-corehdr -v --btf /sys/kernel/btf/vmlinux foo.bpf.o

11.5 Human Summary on Stderr

min-corehdr --btf /sys/kernel/btf/vmlinux --stats foo.bpf.o > vmlinux.h

11.6 End of Option Parsing

min-corehdr --btf /sys/kernel/btf/vmlinux -- -strange-name.bpf.o

12. Future Extension Rules

v0.1 intentionally avoids subcommands.

If a future version gains a second independent responsibility, then and only then a command hierarchy may be introduced.

If that happens, it should follow this shape:

min-corehdr [GLOBAL_OPTIONS] COMMAND [COMMAND_OPTIONS] [ARGS...]

with rules:

* existing top-level generation form should remain valid if possible
* new commands must be verbs or short action nouns
* command names must be lower-case
* command names must avoid collision with existing options
* command structure must not break simple shell redirection patterns

12.1 Reserved Expansion Areas

The following areas are plausible future commands, but are not part of v0.1:

* inspect
* diff
* roots
* emit-btf

These names are reserved only conceptually, not formally.

13. Compatibility Guidance

The standalone CLI should remain close in spirit to both Unix/GNU utility conventions and bpftool habits, but it should not blindly copy bpftool.

That means:

* keep --help, --version, and -o, --output
* keep one-purpose invocation simple
* do not introduce bpftool-style command depth unless needed
* do not add JSON flags before there is a machine-stable schema
* do not make stdout human-chatty

If the project is later upstreamed, a natural mapping would be a bpftool gen-style subcommand, but the standalone tool should optimize first for clarity and minimalism.

14. Non-Goals for the CLI

The CLI must not, in v0.1:

* expose internal matching policy knobs
* expose experimental type-resolution strategies
* expose unstable debug-only output formats as public API
* provide both positional and option-based output-file forms
* provide multiple equivalent ways to do the same core operation

Each of these would increase ambiguity and technical debt.

15. Final Rule

The CLI should feel boring in the good sense:

* obvious to invoke
* easy to script
* hard to misuse
* easy to extend later without regret

That is the target.
