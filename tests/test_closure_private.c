#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include "min_corehdr/closure.h"
#include "min_corehdr/error.h"
#include "min_corehdr/type_set.h"

#ifndef BTF_INFO_ENC
#define BTF_INFO_ENC(kind, kflag, vlen)                                                            \
  (((!!(kflag)) << 31) | (((kind) & 0x1f) << 24) | ((vlen) & 0xffff))
#endif

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

struct closure_worklist {
  __u32 *ids;
  size_t len;
  size_t cap;
};

int worklist_push(struct closure_worklist *worklist, __u32 id, struct mch_error *err);
int add_dep(const struct btf *btf, struct mch_type_set *required, __u32 id,
            struct closure_worklist *worklist, struct mch_closure_stats *stats,
            struct mch_error *err);
int add_type_deps(const struct btf *btf, const struct btf_type *type, struct mch_type_set *required,
                  struct mch_closure_stats *stats, struct closure_worklist *worklist,
                  const struct mch_closure_options *options, struct mch_error *err);

static int test_worklist_overflow_guard(void) {
  struct closure_worklist worklist = {.len = SIZE_MAX / 2 + 1, .cap = SIZE_MAX / 2 + 1};
  struct mch_error err;

  mch_error_clear(&err);
  REQUIRE(worklist_push(&worklist, 1, &err) != 0);
  REQUIRE(strstr(err.message, "worklist is too large") != NULL);
  return 0;
}

static int test_invalid_dependency_ids(void) {
  struct closure_worklist worklist = {0};
  struct mch_closure_stats stats;
  struct mch_type_set required;
  struct mch_error err;
  struct btf *btf;
  __u32 storage[4];

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  REQUIRE(mch_type_set_init(&required, 128) == 0);
  worklist.ids = storage;
  worklist.cap = 4;
  mch_closure_stats_init(&stats);
  mch_error_clear(&err);

  REQUIRE(add_dep(btf, &required, 127, &worklist, &stats, &err) != 0);
  REQUIRE(strstr(err.message, "invalid type id") != NULL);
  REQUIRE(err.hint[0] != '\0');

  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_synthetic_type_dependency_failures(void) {
  struct closure_worklist worklist = {0};
  struct mch_closure_stats stats;
  struct mch_type_set required;
  struct mch_error err;
  struct btf *btf;
  __u32 storage[8];
  int int_id;
  struct {
    struct btf_type type;
    struct btf_array array;
  } array_type;
  struct {
    struct btf_type type;
  } proto_type;
  struct {
    struct btf_type type;
    struct btf_var_secinfo info;
  } datasec_type;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  REQUIRE(mch_type_set_init(&required, 128) == 0);
  worklist.ids = storage;
  worklist.cap = 8;
  mch_closure_stats_init(&stats);

  memset(&array_type, 0, sizeof(array_type));
  array_type.type.info = BTF_INFO_ENC(BTF_KIND_ARRAY, 0, 0);
  array_type.array.type = (__u32)int_id;
  array_type.array.index_type = 127;
  mch_error_clear(&err);
  REQUIRE(add_type_deps(btf, &array_type.type, &required, &stats, &worklist, NULL, &err) != 0);

  memset(&proto_type, 0, sizeof(proto_type));
  proto_type.type.info = BTF_INFO_ENC(BTF_KIND_FUNC_PROTO, 0, 0);
  proto_type.type.type = 127;
  mch_error_clear(&err);
  REQUIRE(add_type_deps(btf, &proto_type.type, &required, &stats, &worklist, NULL, &err) != 0);

  memset(&datasec_type, 0, sizeof(datasec_type));
  datasec_type.type.info = BTF_INFO_ENC(BTF_KIND_DATASEC, 0, 1);
  datasec_type.info.type = 127;
  mch_error_clear(&err);
  REQUIRE(add_type_deps(btf, &datasec_type.type, &required, &stats, &worklist, NULL, &err) != 0);

  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_public_missing_required_type(void) {
  struct mch_type_set required;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct btf *btf;
  int int_id;
  size_t invalid_id;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  invalid_id = (size_t)btf__type_cnt(btf) + 8;
  REQUIRE(mch_type_set_init(&required, invalid_id + 1) == 0);
  REQUIRE(mch_type_set_add(&required, invalid_id));
  mch_closure_stats_init(&stats);
  mch_error_clear(&err);

  REQUIRE(mch_compute_dependency_closure(btf, &required, &stats, &err) != 0);
  REQUIRE(strstr(err.message, "missing required type id") != NULL);

  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

int main(void) {
  REQUIRE(test_worklist_overflow_guard() == 0);
  REQUIRE(test_invalid_dependency_ids() == 0);
  REQUIRE(test_synthetic_type_dependency_failures() == 0);
  REQUIRE(test_public_missing_required_type() == 0);
  return 0;
}
