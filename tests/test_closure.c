#include "min_corehdr/closure.h"
#include "min_corehdr/error.h"
#include "min_corehdr/type_set.h"

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

#if defined(__linux__)
void *__real_malloc(size_t size);
void *__real_realloc(void *ptr, size_t size);

static long fail_malloc_after = -1;
static long fail_realloc_after = -1;

void *__wrap_malloc(size_t size) {
  if (fail_malloc_after == 0) {
    fail_malloc_after = -1;
    return NULL;
  }
  if (fail_malloc_after > 0) {
    fail_malloc_after--;
  }
  return __real_malloc(size);
}

void *__wrap_realloc(void *ptr, size_t size) {
  if (fail_realloc_after == 0) {
    fail_realloc_after = -1;
    return NULL;
  }
  if (fail_realloc_after > 0) {
    fail_realloc_after--;
  }
  return __real_realloc(ptr, size);
}
#endif

static int test_dependency_closure(void) {
  struct mch_type_set required;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct btf *btf;
  int int_id;
  int leaf_id;
  int enum_id;
  int union_id;
  int alias1_id;
  int alias2_id;
  int alias3_id;
  int leaf_ptr_id;
  int array_id;
  int proto_id;
  int proto_ptr_id;
  int root_id;

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);

  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  leaf_id = btf__add_struct(btf, "leaf", 4);
  REQUIRE(leaf_id > 0);
  REQUIRE(btf__add_field(btf, "value", int_id, 0, 0) == 0);
  enum_id = btf__add_enum(btf, "unused_enum", 4);
  REQUIRE(enum_id > 0);
  REQUIRE(btf__add_enum_value(btf, "UNUSED", 0) == 0);
  union_id = btf__add_union(btf, "payload", 4);
  REQUIRE(union_id > 0);
  REQUIRE(btf__add_field(btf, "leaf", leaf_id, 0, 0) == 0);
  alias1_id = btf__add_typedef(btf, "alias1", leaf_id);
  REQUIRE(alias1_id > 0);
  alias2_id = btf__add_typedef(btf, "alias2", alias1_id);
  REQUIRE(alias2_id > 0);
  alias3_id = btf__add_typedef(btf, "alias3", alias2_id);
  REQUIRE(alias3_id > 0);
  leaf_ptr_id = btf__add_ptr(btf, leaf_id);
  REQUIRE(leaf_ptr_id > 0);
  array_id = btf__add_array(btf, int_id, leaf_id, 3);
  REQUIRE(array_id > 0);
  proto_id = btf__add_func_proto(btf, int_id);
  REQUIRE(proto_id > 0);
  REQUIRE(btf__add_func_param(btf, "leaf", leaf_ptr_id) == 0);
  proto_ptr_id = btf__add_ptr(btf, proto_id);
  REQUIRE(proto_ptr_id > 0);
  root_id = btf__add_struct(btf, "root", 64);
  REQUIRE(root_id > 0);
  REQUIRE(btf__add_field(btf, "leaf", leaf_id, 0, 0) == 0);
  REQUIRE(btf__add_field(btf, "alias", alias3_id, 32, 0) == 0);
  REQUIRE(btf__add_field(btf, "array", array_id, 64, 0) == 0);
  REQUIRE(btf__add_field(btf, "payload", union_id, 160, 0) == 0);
  REQUIRE(btf__add_field(btf, "callback", proto_ptr_id, 192, 0) == 0);

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)root_id));
  REQUIRE(mch_compute_dependency_closure(btf, &required, &stats, &err) == 0);

  REQUIRE(mch_type_set_contains(&required, (size_t)root_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)int_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)leaf_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)union_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)alias1_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)alias2_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)alias3_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)array_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)proto_ptr_id));
  REQUIRE(!mch_type_set_contains(&required, (size_t)leaf_ptr_id));
  REQUIRE(!mch_type_set_contains(&required, (size_t)proto_id));
  REQUIRE(!mch_type_set_contains(&required, (size_t)enum_id));
  REQUIRE(stats.added_types == required.selected - 1);

  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_dependency_closure_grows_worklist(void) {
  struct mch_type_set required;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct btf *btf;
  int int_id;
  int leaf_ids[24];
  int root_id;

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);

  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  for (size_t i = 0; i < sizeof(leaf_ids) / sizeof(leaf_ids[0]); i++) {
    char name[32];

    snprintf(name, sizeof(name), "leaf_%zu", i);
    leaf_ids[i] = btf__add_struct(btf, name, 4);
    REQUIRE(leaf_ids[i] > 0);
    REQUIRE(btf__add_field(btf, "value", int_id, 0, 0) == 0);
  }

  root_id = btf__add_struct(btf, "root", sizeof(leaf_ids));
  REQUIRE(root_id > 0);
  for (size_t i = 0; i < sizeof(leaf_ids) / sizeof(leaf_ids[0]); i++) {
    char name[32];

    snprintf(name, sizeof(name), "leaf_%zu", i);
    REQUIRE(btf__add_field(btf, name, leaf_ids[i], (unsigned int)(i * 32), 0) == 0);
  }

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)root_id));
  REQUIRE(mch_compute_dependency_closure(btf, &required, &stats, &err) == 0);

  for (size_t i = 0; i < sizeof(leaf_ids) / sizeof(leaf_ids[0]); i++) {
    REQUIRE(mch_type_set_contains(&required, (size_t)leaf_ids[i]));
  }
  REQUIRE(mch_type_set_contains(&required, (size_t)int_id));

  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_dependency_closure_can_expand_pointers(void) {
  struct mch_type_set required;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct mch_closure_options options = {.expand_pointers = true};
  struct btf *btf;
  int int_id;
  int leaf_id;
  int leaf_ptr_id;
  int root_id;

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);

  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  leaf_id = btf__add_struct(btf, "leaf", 4);
  REQUIRE(leaf_id > 0);
  REQUIRE(btf__add_field(btf, "value", int_id, 0, 0) == 0);
  leaf_ptr_id = btf__add_ptr(btf, leaf_id);
  REQUIRE(leaf_ptr_id > 0);
  root_id = btf__add_struct(btf, "pointer_root", 8);
  REQUIRE(root_id > 0);
  REQUIRE(btf__add_field(btf, "leaf", leaf_ptr_id, 0, 0) == 0);

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)root_id));
  REQUIRE(mch_compute_dependency_closure_with_options(btf, &required, &stats, &options, &err) == 0);

  REQUIRE(mch_type_set_contains(&required, (size_t)leaf_ptr_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)leaf_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)int_id));

  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_dependency_closure_can_prune_record_members(void) {
  struct mch_type_set required;
  struct mch_member_filter members;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct mch_closure_options options = {0};
  struct btf *btf;
  int int_id;
  int used_id;
  int unused_id;
  int root_id;

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);
  memset(&members, 0, sizeof(members));

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);

  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  used_id = btf__add_struct(btf, "used_leaf", 4);
  REQUIRE(used_id > 0);
  REQUIRE(btf__add_field(btf, "value", int_id, 0, 0) == 0);
  unused_id = btf__add_struct(btf, "unused_leaf", 4);
  REQUIRE(unused_id > 0);
  REQUIRE(btf__add_field(btf, "value", int_id, 0, 0) == 0);
  root_id = btf__add_struct(btf, "member_root", 8);
  REQUIRE(root_id > 0);
  REQUIRE(btf__add_field(btf, "used", used_id, 0, 0) == 0);
  REQUIRE(btf__add_field(btf, "unused", unused_id, 32, 0) == 0);

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_member_filter_init(&members, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_member_filter_add(btf, &members, (size_t)root_id, 0, &err) == 0);
  options.member_filter = &members;
  REQUIRE(mch_type_set_add(&required, (size_t)root_id));
  REQUIRE(mch_compute_dependency_closure_with_options(btf, &required, &stats, &options, &err) == 0);

  REQUIRE(mch_type_set_contains(&required, (size_t)root_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)used_id));
  REQUIRE(!mch_type_set_contains(&required, (size_t)unused_id));

  mch_member_filter_destroy(&members);
  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

#if defined(__linux__)
static int test_dependency_closure_allocation_failures(void) {
  struct mch_type_set required;
  struct mch_type_set oversized = {.selected = SIZE_MAX};
  struct mch_closure_stats stats;
  struct mch_error err;
  struct btf *btf;
  int int_id;
  int leaf_ids[24];
  int root_id;
  int rc;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);
  rc = mch_compute_dependency_closure(btf, &oversized, &stats, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, "worklist is too large") != NULL);

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)int_id));
  mch_error_clear(&err);
  mch_closure_stats_init(&stats);
  fail_malloc_after = 0;
  rc = mch_compute_dependency_closure(btf, &required, &stats, &err);
  fail_malloc_after = -1;
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, "out of memory while preparing dependency closure worklist") != NULL);
  mch_type_set_destroy(&required);
  btf__free(btf);

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  for (size_t i = 0; i < sizeof(leaf_ids) / sizeof(leaf_ids[0]); i++) {
    char name[32];

    snprintf(name, sizeof(name), "alloc_leaf_%zu", i);
    leaf_ids[i] = btf__add_struct(btf, name, 4);
    REQUIRE(leaf_ids[i] > 0);
    REQUIRE(btf__add_field(btf, "value", int_id, 0, 0) == 0);
  }
  root_id = btf__add_struct(btf, "alloc_root", 96);
  REQUIRE(root_id > 0);
  for (size_t i = 0; i < sizeof(leaf_ids) / sizeof(leaf_ids[0]); i++) {
    char name[32];

    snprintf(name, sizeof(name), "leaf_%zu", i);
    REQUIRE(btf__add_field(btf, name, leaf_ids[i], (unsigned int)(i * 32), 0) == 0);
  }
  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)root_id));
  mch_error_clear(&err);
  mch_closure_stats_init(&stats);
  fail_realloc_after = 0;
  rc = mch_compute_dependency_closure(btf, &required, &stats, &err);
  fail_realloc_after = -1;
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, "out of memory while growing dependency closure worklist") != NULL);

  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}
#endif

static int test_dependency_closure_special_roots(void) {
  struct mch_type_set required;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct btf *btf;
  int int_id;
  int leaf_id;
  int leaf_ptr_id;
  int proto_id;
  int void_proto_id;
  int func_id;
  int var_id;
  int datasec_id;

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);

  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  leaf_id = btf__add_struct(btf, "leaf", 4);
  REQUIRE(leaf_id > 0);
  REQUIRE(btf__add_field(btf, "value", int_id, 0, 0) == 0);
  leaf_ptr_id = btf__add_ptr(btf, leaf_id);
  REQUIRE(leaf_ptr_id > 0);
  proto_id = btf__add_func_proto(btf, int_id);
  REQUIRE(proto_id > 0);
  REQUIRE(btf__add_func_param(btf, "leaf", leaf_ptr_id) == 0);
  void_proto_id = btf__add_func_proto(btf, 0);
  REQUIRE(void_proto_id > 0);
  REQUIRE(btf__add_func_param(btf, "unused", 0) == 0);
  func_id = btf__add_func(btf, "handle_leaf", BTF_FUNC_GLOBAL, proto_id);
  REQUIRE(func_id > 0);
  var_id = btf__add_var(btf, "global_leaf", BTF_VAR_GLOBAL_ALLOCATED, leaf_id);
  REQUIRE(var_id > 0);
  datasec_id = btf__add_datasec(btf, ".data", 4);
  REQUIRE(datasec_id > 0);
  REQUIRE(btf__add_datasec_var_info(btf, var_id, 0, 4) == 0);

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)proto_id));
  REQUIRE(mch_type_set_add(&required, (size_t)void_proto_id));
  REQUIRE(mch_type_set_add(&required, (size_t)func_id));
  REQUIRE(mch_type_set_add(&required, (size_t)datasec_id));
  REQUIRE(mch_compute_dependency_closure(btf, &required, &stats, &err) == 0);

  REQUIRE(mch_type_set_contains(&required, (size_t)int_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)leaf_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)leaf_ptr_id));
  REQUIRE(mch_type_set_contains(&required, (size_t)var_id));

  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

int main(void) {
  REQUIRE(test_dependency_closure() == 0);
  REQUIRE(test_dependency_closure_special_roots() == 0);
  REQUIRE(test_dependency_closure_grows_worklist() == 0);
  REQUIRE(test_dependency_closure_can_expand_pointers() == 0);
  REQUIRE(test_dependency_closure_can_prune_record_members() == 0);
#if defined(__linux__)
  REQUIRE(test_dependency_closure_allocation_failures() == 0);
#endif
  return 0;
}
