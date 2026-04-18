SPEC: Object-Driven Minimal Local CO-RE Header Generator

1. Purpose

In libbpf-style BPF CO-RE development, the normal workflow is: compile .bpf.c into .bpf.o, let libbpf load and relocate it, and use a generated skeleton on the userspace side. Skeleton-based userspace handling is the recommended interface, and CO-RE itself relies on the BPF program’s local type definitions plus target-kernel BTF. Those local type definitions can be a full vmlinux.h, but they can also be a much smaller manually written subset annotated for CO-RE.  ￼

Today, many projects still choose between two bad options: keep using a huge full vmlinux.h, which is expensive for builds, indexing, and review, or maintain a hand-trimmed local header, which is fragile and becomes ongoing manual work. Existing tooling already solves adjacent problems: bpftool gen min_core_btf generates runtime-oriented minimal BTF for CO-RE deployment, and bpftool btf dump ... format c [root_id ...] can emit a reduced C header from explicitly chosen roots. What is still missing is an object-driven build-time tool that derives a compile-complete local CO-RE header directly from .bpf.o.  ￼

This tool exists to automate that missing step.

Its job is to generate, from one or more .bpf.o files, a reduced local type header sufficient to rebuild the corresponding BPF sources in a standard libbpf CO-RE workflow.

This tool is a build-time developer utility.

It is not responsible for:

* runtime BTF packaging
* skeleton generation
* libbpf object loading or attachment
* verifier diagnostics
* kfunc declaration authoring
* IDE integration
* source rewriting

2. Primary Requirement

Given:

* one base BTF file
* one or more .bpf.o files

the tool must produce:

* a valid C header
* suitable for normal BPF compilation
* containing all kernel-facing local type definitions required to recompile the corresponding BPF source set
* while excluding unrelated kernel types as much as possible without sacrificing correctness

The output must be compile-complete for the input object set.

3. Definition of Compile-Complete

A generated header is compile-complete if the BPF source corresponding to the input .bpf.o can be recompiled successfully using that generated header in place of a full vmlinux.h or equivalent local CO-RE type header.

This definition assumes an ordinary libbpf-style BPF build:

* normal BPF target compilation
* normal CO-RE-oriented source layout
* no exotic preprocessing assumptions
* a base BTF that matches the intended target kernel type universe

Compile-complete includes, at minimum, support for type usage required by:

* struct or union field access
* sizeof(type)
* typeof(type)
* array element typing
* by-value embedding of structs or unions
* enum definitions and enum values
* typedef chains
* function prototype argument and return types
* pointer target typing when downstream use requires full definitions

Compile-complete does not mean mathematically minimal.

For v0.1, correctness takes priority over maximal shrinking.

4. Scope

In Scope

* parse base BTF
* parse .bpf.o ELF inputs
* read object-local BTF
* read object-local CO-RE relocation metadata
* compute the required local kernel type set
* compute dependency closure
* emit a deterministic reduced local CO-RE header in C

Out of Scope

* emitting raw BTF
* generating compile databases
* auto-detecting target kernels
* combining multiple kernel BTFs
* flavored type generation
* full split-BTF workflow support
* performance tuning beyond ordinary developer usability
* kfunc prototype synthesis
* replacement of skeleton generation or libbpf load flow

5. Existing Assets and Reuse Policy

This project is not a greenfield implementation.

It exists because important building blocks already exist, but they do not yet form a single object-driven compile-complete header workflow. In particular: libbpf already defines the standard CO-RE app lifecycle and recommends skeleton-based userspace handling; bpftool gen min_core_btf already produces runtime-oriented minimal BTF from BPF objects; bpftool btf dump ... format c [root_id ...] already emits reduced C output from selected roots; and CO-RE itself already treats the program’s local type view as a minimal “local expectation” that can be smaller than full kernel type coverage.  ￼

The implementation must reuse existing concepts and machinery whenever possible.

It should reuse, adapt, or mirror:

* base BTF parsing logic
* object-local BTF parsing logic
* CO-RE relocation-driven type discovery logic
* reduced type-graph construction logic
* vmlinux.h-style emission conventions such as preserve_access_index

The project should add only the missing logic needed to bridge these pieces into one workflow:

* derive compile-time-complete type roots from .bpf.o
* close dependencies conservatively
* emit a reduced local header from that reduced type universe

The tool must not depend on parsing unstable human-readable command output. bpftool explicitly warns that its textual output is not guaranteed stable across versions, so reuse must happen at the data or library level, not by scraping CLI text.  ￼

The tool must not reimplement large subsystems from scratch unless reuse is impossible.

In particular, v0.1 must not introduce a new:

* BTF format
* CO-RE relocation model
* header format
* object metadata model
* generic code generation framework

6. Design Constraints

6.1 KISS

The tool must do one thing only:

* generate a compile-complete minimal local CO-RE header

The tool must have one primary output:

* C header text

The tool must require explicit inputs:

* base BTF path
* one or more object files

The tool must not depend on unstable tool-text parsing.

6.2 Technical Debt Minimization

The implementation must avoid:

* wrappers around bpftool text output
* speculative abstraction layers
* plugin systems
* hidden global state
* multiple overlapping internal representations without clear need

The implementation should prefer:

* direct BTF/libbpf-level parsing
* explicit data flow
* small modules with single responsibilities
* deterministic behavior

6.3 Ease of Change

The implementation must separate:

* CLI parsing
* object/BTF loading
* seed extraction
* dependency closure
* reduced representation construction
* C emission

This separation is required so that matching rules or emission logic can change without rewriting unrelated code.

6.4 Correctness Rule

If there is a tradeoff between:

* a smaller header with fragile omission rules
* a slightly larger header with simpler and safer inclusion rules

v0.1 must choose the latter.

False positives are acceptable.
False negatives are not.

7. Inputs

7.1 Required Inputs

* --btf <path>: base BTF file
* OBJECT...: one or more .bpf.o files

7.2 Optional Inputs

* -o, --output <path>: output file path
* --verbose: human-readable extraction details
* --stats: summary counts and size reduction information

7.3 v0.1 Input Rules

* the base BTF file must be readable
* each object file must be valid ELF
* each object file must contain usable BTF
* each object file must contain enough local metadata to derive required type seeds
* if required types cannot be resolved against the base BTF, the tool must fail

v0.1 does not auto-discover /sys/kernel/btf/vmlinux.

8. Outputs

8.1 Main Output

A C header that behaves as a reduced local CO-RE type header.

The header must include:

* include guards
* preserve_access_index pragmas
* required type definitions
* stable, deterministic ordering

8.2 Output Properties

The output must be:

* valid for normal BPF compilation
* deterministic for identical inputs
* stable enough for diff/review
* materially smaller than full vmlinux.h in ordinary cases

8.3 Non-Requirements for Output

v0.1 does not guarantee:

* globally minimal type count
* formatting identical to upstream bpftool
* compatibility with every nonstandard build environment

9. Functional Model

The required type set is defined as:

required_types = closure(object_btf_types ∪ core_relo_types)

where:

* object_btf_types are kernel-facing types referenced by object-local BTF in ways relevant to compilation
* core_relo_types are types referenced by CO-RE relocation metadata
* closure(...) is the transitive dependency closure required to emit a valid compile-complete local header

This is the core semantic model of the tool.

The purpose of the tool is not to discover every type that exists in the target kernel.

The purpose is to discover the smallest practical local type universe needed to rebuild the input BPF objects correctly.

10. Seed Extraction

10.1 Object-BTF-Based Seeds

The tool must extract initial required types from object-local BTF.

This exists to cover type usage that may not appear in CO-RE relocation records.

This includes cases such as:

* sizeof(struct X)
* by-value struct embedding
* local references that require complete type definitions
* function prototypes that mention kernel-facing types
* array element types
* enum references needed at compile time

The exact extraction logic may be conservative.

Over-inclusion is acceptable in v0.1.

10.2 CO-RE-Based Seeds

The tool must extract initial required types from CO-RE relocation metadata.

This includes at least types involved in:

* field relocations
* type existence relocations
* type size relocations
* enum relocations

These seeds ensure that CO-RE-relevant type coverage is preserved in the generated header.

10.3 Seed Union Rule

For each input object:

* compute object-BTF-based seeds
* compute CO-RE-based seeds
* union the results

For multiple input objects:

* union all per-object seed sets

11. Dependency Closure

The tool must recursively include all types required to make the seed set compile-complete.

The closure must traverse at least:

* struct member types
* union member types
* typedef targets
* const-qualified base types
* volatile-qualified base types
* restrict-qualified base types
* pointer targets
* array element types
* function prototype argument types
* function prototype return types
* enum definitions

11.1 v0.1 Closure Rule

If there is uncertainty about whether a dependent type is required, v0.1 should include it.

The rule is:

* false positives are acceptable
* false negatives are not

This keeps the implementation simple and avoids fragile under-inclusion.

12. Matching Against Base BTF

The tool must map object-derived type requirements onto the base BTF.

This mapping must be:

* deterministic
* explicit in code
* easy to inspect
* easy to tighten later

v0.1 uses one matching strategy only.

v0.1 must not introduce:

* pluggable matchers
* dynamic rule selection
* policy configuration layers

The tool must not rely on loose or opaque matching behavior.

If a required type cannot be resolved clearly against the base BTF, the tool must fail.

The tool must not guess past ambiguity and continue.

This rule exists because trust in the generated header depends on predictable resolution behavior.

13. Reduced Representation Construction

After computing the full required type set, the tool must construct a reduced in-memory representation suitable for C emission.

This stage is responsible for:

* deduplication
* preserving dependency validity
* preserving required names
* preserving layout-relevant type structure
* producing a stable emission order

The reduced representation may be a partial BTF-like graph or another internal form, as long as:

* the source of truth remains the base BTF
* the resulting header remains compile-complete
* the implementation remains simple

The implementation should not maintain multiple semantic sources of truth unless clearly necessary.

14. C Header Emission

The emitter must produce a valid reduced local CO-RE header.

At minimum, it must emit:

* a header guard
* preserve_access_index push/pop pragmas
* all required type definitions
* deterministic ordering

The emitter must preserve kernel-facing type names.

The emitter must not invent renamed types in v0.1.

The emitter may include extra dependent types if necessary to keep output valid and logic simple.

The output should be reviewable enough that a developer can inspect diffs and understand what kernel-facing local types the object set depends on.

15. libbpf / CO-RE Convention Alignment

The tool must align with current libbpf and CO-RE conventions.

That means:

* it operates on the BPF-side local type header only
* it does not replace skeleton generation
* it does not replace libbpf load/relocate/attach flow
* it does not replace runtime BTF selection
* it does not attempt to synthesize kfunc declarations

This distinction matters because CO-RE separates the program’s local type expectations from the target kernel’s BTF, and libbpf already provides explicit mechanisms for runtime BTF selection such as btf_custom_path, while also noting that some features still require actual kernel BTF.  ￼

16. Multi-Object Semantics

If multiple .bpf.o files are provided, the generated header must satisfy the union of all their type requirements.

There is only one output header.

The tool must not emit one header per object in v0.1.

If one object introduces an unresolved required type, the whole run fails.

There is no partial success mode.

This keeps behavior simple and avoids producing headers with unclear guarantees.

17. Error Handling

17.1 Error Classes

The tool must distinguish at least:

* usage errors
* file I/O errors
* ELF parse errors
* BTF parse errors
* unresolved type errors
* internal consistency errors

17.2 Error Style

Errors must be short and direct.

Format:

error: failed to resolve kernel type 'task_struct'
file: foo.bpf.o
hint: verify that --btf points to the intended target kernel BTF

17.3 Failure Policy

The tool must fail fast.

The tool must not:

* silently skip unresolved required types
* downgrade resolution failures to warnings
* emit incomplete headers and report success

This is a correctness tool.
A partial answer is misleading and therefore worse than failure.

18. Determinism

Given identical:

* base BTF
* input objects
* tool version

the tool must produce identical output.

The output must not depend on:

* current time
* filesystem enumeration order
* hash randomization
* pointer address ordering
* unrelated process state

Deterministic output is required for:

* reproducible builds
* reviewable diffs
* later caching if needed

19. Performance

v0.1 performance target is practical usability, not maximal speed.

The tool should be fast enough for ordinary local development and CI usage.

v0.1 must not add:

* background daemons
* on-disk caches
* speculative precomputation

Performance work is deferred unless profiling shows a clear need.

The main performance goal is to reduce downstream cost by generating much smaller local headers than a full vmlinux.h, not to micro-optimize the generator itself.

20. Maintainability Rules

The implementation must follow these rules:

* each module should have one primary responsibility
* avoid hidden cross-module mutation
* prefer explicit data structures over side-effect-driven control flow
* do not add an abstraction layer before there is a proven second implementation need
* when a bug is found, add a reproducer before fixing it
* keep diagnostics human-readable but small

If a module begins to own more than one concern, split it.

If two modules mirror the same semantic state in different forms, simplify unless the duplication is clearly justified.

The code should remain understandable to a new contributor reading it without prior framework knowledge.

21. Testing Requirements

21.1 Unit Tests

Unit tests must cover:

* seed extraction behavior
* dependency closure behavior
* deduplication
* deterministic ordering
* unresolved type failure paths

21.2 Integration Tests

Integration tests must cover at least:

1. simple field access
2. sizeof(struct X)
3. by-value embedded struct or union
4. enum definition usage
5. multiple object union behavior
6. recompilation using generated header

21.3 Regression Policy

Every fixed bug must add a reproducer.

This tool is only useful if developers can trust that once a compile-completeness bug is fixed, it stays fixed.

22. Success Criteria

v0.1 is successful if all of the following are true:

1. the tool generates headers for multiple real .bpf.o inputs
2. those headers can be used to recompile the corresponding BPF sources
3. generated headers are materially smaller than full vmlinux.h
4. output is deterministic
5. the code remains small and easy to change
6. the implementation structure would allow later upstreaming without major rewrite

The real measure of success is not “smallest possible header.”

The real measure is that developers no longer need to maintain slim local CO-RE headers by hand.

23. Deferred Work

The following are intentionally deferred:

* automatic kernel BTF discovery
* raw BTF output mode
* full split-BTF workflow support
* multi-kernel merged headers
* flavored type generation
* compile database generation
* IDE integration
* advanced stats formats
* exact bpftool CLI compatibility
* plugin systems
* policy scripting
* kfunc declaration synthesis

These may become useful later, but they are not necessary to prove the core value of the tool.

24. Implementation Order

The implementation should proceed in this order:

1. produce a minimal working pipeline for one .bpf.o
2. make the output compile-complete
3. stabilize ordering and output form
4. add multi-object support
5. add tests and regressions
6. improve human-facing diagnostics

Do not start with:

* extensibility frameworks
* output format families
* editor integration
* optimization work
* upstream CLI alignment

The first version should prove one thing only:

* object-driven extraction can replace manual slim-header maintenance in a libbpf CO-RE workflow

25. Core Value

The value of this tool is not breadth.

The value is:

* explicit inputs
* small useful output
* compile-complete correctness
* simple internal structure
* low technical debt
* straightforward future upstream path

More specifically, its value is that it removes a piece of recurring manual work that CO-RE developers still carry today:

* either living with a huge full vmlinux.h
* or maintaining a fragile reduced local header by hand

This tool exists to automate that burden from .bpf.o inputs directly.
