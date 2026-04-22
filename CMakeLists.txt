cmake_minimum_required(VERSION 3.20)

project(min_corehdr VERSION 0.1.0 LANGUAGES C)

include(CTest)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf>=1.5)

set(MIN_COREHDR_HEADERS
  include/min_corehdr/btf_index.h
  include/min_corehdr/btf_loader.h
  include/min_corehdr/cli.h
  include/min_corehdr/closure.h
  include/min_corehdr/emitter.h
  include/min_corehdr/error.h
  include/min_corehdr/seeds.h
  include/min_corehdr/type_set.h
)

set(MIN_COREHDR_LIB_SOURCES
  src/btf_index.c
  src/btf_loader.c
  src/cli.c
  src/closure.c
  src/emitter.c
  src/error.c
  src/seeds.c
  src/type_set.c
)

set(MIN_COREHDR_FORMAT_FILES
  src/main.c
  ${MIN_COREHDR_LIB_SOURCES}
  ${MIN_COREHDR_HEADERS}
  tests/test_cli.c
  tests/test_closure.c
  tests/test_emitter.c
  tests/test_error.c
  tests/test_btf_index.c
  tests/test_btf_loader.c
  tests/test_seeds.c
  tests/test_type_set.c
)

option(MIN_COREHDR_ENABLE_COVERAGE "Build with clang source coverage instrumentation" OFF)

if(MIN_COREHDR_ENABLE_COVERAGE)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "MIN_COREHDR_ENABLE_COVERAGE requires clang")
  endif()
  add_compile_options(-O1 -g -fprofile-instr-generate -fcoverage-mapping)
  add_link_options(-fprofile-instr-generate -fcoverage-mapping)
endif()

add_library(min-corehdr-core STATIC ${MIN_COREHDR_LIB_SOURCES} ${MIN_COREHDR_HEADERS})
target_include_directories(min-corehdr-core PUBLIC include)
target_link_libraries(min-corehdr-core PUBLIC PkgConfig::LIBBPF)
target_compile_features(min-corehdr-core PUBLIC c_std_17)

add_executable(min-corehdr src/main.c)
target_link_libraries(min-corehdr PRIVATE min-corehdr-core)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(min-corehdr-core PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror=implicit-function-declaration
  )
  target_compile_options(min-corehdr PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror=implicit-function-declaration
  )
endif()

find_program(CLANG_FORMAT_EXE NAMES clang-format)
if(CLANG_FORMAT_EXE)
  add_custom_target(format
    COMMAND ${CLANG_FORMAT_EXE} -i ${MIN_COREHDR_FORMAT_FILES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Formatting C sources"
  )
  add_custom_target(check-format
    COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror ${MIN_COREHDR_FORMAT_FILES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Checking C source formatting"
  )
endif()

install(TARGETS min-corehdr RUNTIME DESTINATION bin)

if(BUILD_TESTING)
  add_executable(test-cli tests/test_cli.c)
  target_link_libraries(test-cli PRIVATE min-corehdr-core)

  add_executable(test-type-set tests/test_type_set.c)
  target_link_libraries(test-type-set PRIVATE min-corehdr-core)

  add_executable(test-btf-index tests/test_btf_index.c)
  target_link_libraries(test-btf-index PRIVATE min-corehdr-core)

  add_executable(test-btf-loader tests/test_btf_loader.c)
  target_link_libraries(test-btf-loader PRIVATE min-corehdr-core)

  add_executable(test-seeds tests/test_seeds.c)
  target_link_libraries(test-seeds PRIVATE min-corehdr-core)

  add_executable(test-closure tests/test_closure.c)
  target_link_libraries(test-closure PRIVATE min-corehdr-core)

  add_executable(test-emitter tests/test_emitter.c)
  target_link_libraries(test-emitter PRIVATE min-corehdr-core)

  add_executable(test-error tests/test_error.c)
  target_link_libraries(test-error PRIVATE min-corehdr-core)

  add_test(NAME min-corehdr-help COMMAND min-corehdr --help)
  add_test(NAME min-corehdr-version COMMAND min-corehdr --version)
  add_test(NAME cli-parser COMMAND test-cli)
  add_test(NAME type-set COMMAND test-type-set)
  add_test(NAME btf-index COMMAND test-btf-index)
  add_test(NAME btf-loader COMMAND test-btf-loader)
  add_test(NAME seeds COMMAND test-seeds)
  add_test(NAME closure COMMAND test-closure)
  add_test(NAME emitter COMMAND test-emitter)
  add_test(NAME error COMMAND test-error)
  add_test(NAME cli-smoke
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_smoke.sh $<TARGET_FILE:min-corehdr>)
  add_test(NAME spec-integration
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/spec_integration.sh $<TARGET_FILE:min-corehdr>)
  add_test(NAME cli-unresolved
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_unresolved.sh $<TARGET_FILE:min-corehdr>)
  set_tests_properties(cli-smoke PROPERTIES SKIP_RETURN_CODE 77)
  set_tests_properties(spec-integration cli-unresolved PROPERTIES SKIP_RETURN_CODE 77)
endif()
