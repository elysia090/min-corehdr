#include "min_corehdr/btf_index.h"
#include "min_corehdr/error.h"

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include <stdio.h>

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

int main(void) {
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

  mch_btf_index_destroy(&index);
  btf__free(btf);
  return 0;
}
