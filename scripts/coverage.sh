#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build="$root/build/coverage"
profiles="$build/profiles"
profdata="$build/coverage.profdata"

cmake --preset coverage
cmake --build --preset coverage

rm -rf "$profiles"
mkdir -p "$profiles"
LLVM_PROFILE_FILE="$profiles/%p.profraw" ctest --preset coverage --output-on-failure

llvm-profdata merge -sparse "$profiles"/*.profraw -o "$profdata"
llvm-cov report "$build/min-corehdr" \
  -object "$build/test-cli" \
  -object "$build/test-type-set" \
  -object "$build/test-btf-index" \
  -object "$build/test-btf-loader" \
  -object "$build/test-seeds" \
  -object "$build/test-closure" \
  -object "$build/test-emitter" \
  -object "$build/test-error" \
  -instr-profile "$profdata" \
  -ignore-filename-regex='(^|/)(tests|build)/|/nix/store/'

llvm-cov export "$build/min-corehdr" \
  -object "$build/test-cli" \
  -object "$build/test-type-set" \
  -object "$build/test-btf-index" \
  -object "$build/test-btf-loader" \
  -object "$build/test-seeds" \
  -object "$build/test-closure" \
  -object "$build/test-emitter" \
  -object "$build/test-error" \
  -instr-profile "$profdata" > "$build/coverage.json"
