#include "min_corehdr/btf_index.h"
#include "min_corehdr/error.h"

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

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
void *__real_calloc(size_t nmemb, size_t size);
void *__real_malloc(size_t size);

static long fail_calloc_after = -1;
static long fail_malloc_after = -1;

void *__wrap_calloc(size_t nmemb, size_t size) {
  if (fail_calloc_after == 0) {
    fail_calloc_after = -1;
    return NULL;
  }
  if (fail_calloc_after > 0) {
    fail_calloc_after--;
  }
  return __real_calloc(nmemb, size);
}

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
#endif

static int test_btf_index_lookup_and_guards(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct btf *btf;
  unsigned int id = 0;
  int task_id;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);

  task_id = btf__add_struct(btf, "task_struct", 4);
  REQUIRE(task_id > 0);
  REQUIRE(btf__add_union(btf, "task_union", 8) > 0);
  REQUIRE(btf__add_struct(btf, "dup_type", 4) > 0);
  REQUIRE(btf__add_struct(btf, "dup_type", 8) > 0);

  REQUIRE(mch_btf_index_init(&index, btf, &err) == 0);
  REQUIRE(mch_btf_index_lookup(&index, "task_struct", BTF_KIND_STRUCT, &id) == 1);
  REQUIRE(id == (unsigned int)task_id);
  REQUIRE(mch_btf_index_lookup(&index, "task_struct", BTF_KIND_UNION, &id) == 0);
  REQUIRE(mch_btf_index_lookup(&index, "missing_type", BTF_KIND_STRUCT, &id) == 0);
  REQUIRE(mch_btf_index_lookup(&index, "dup_type", BTF_KIND_STRUCT, &id) == -1);
  REQUIRE(mch_btf_index_lookup(NULL, "task_struct", BTF_KIND_STRUCT, &id) == 0);
  REQUIRE(mch_btf_index_lookup(&index, NULL, BTF_KIND_STRUCT, &id) == 0);
  REQUIRE(mch_btf_index_lookup(&index, "", BTF_KIND_STRUCT, &id) == 0);

  mch_btf_index_destroy(&index);
  REQUIRE(mch_btf_index_lookup(&index, "task_struct", BTF_KIND_STRUCT, &id) == 0);
  mch_btf_index_destroy(NULL);
  btf__free(btf);
  return 0;
}

#if defined(__linux__)
static int test_btf_index_allocation_failures(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct btf *btf;
  int task_id;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  task_id = btf__add_struct(btf, "task_struct", 4);
  REQUIRE(task_id > 0);

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  fail_malloc_after = 0;
  REQUIRE(mch_btf_index_init(&index, btf, &err) != 0);
  fail_malloc_after = -1;
  REQUIRE(strstr(err.message, "out of memory") != NULL);

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  fail_calloc_after = 0;
  REQUIRE(mch_btf_index_init(&index, btf, &err) != 0);
  fail_calloc_after = -1;
  REQUIRE(strstr(err.message, "out of memory") != NULL);

  btf__free(btf);
  return 0;
}
#endif

int main(void) {
  REQUIRE(test_btf_index_lookup_and_guards() == 0);
#if defined(__linux__)
  REQUIRE(test_btf_index_allocation_failures() == 0);
#endif
  return 0;
}
