#include "min_corehdr/closure.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/btf.h>

#include "min_corehdr/btf_loader.h"

#ifndef MCH_PRIVATE
#define MCH_PRIVATE static
#endif

struct closure_worklist {
  __u32 *ids;
  size_t len;
  size_t cap;
};

static void worklist_destroy(struct closure_worklist *worklist) { free(worklist->ids); }

static int worklist_init(struct closure_worklist *worklist, size_t initial_cap,
                         struct mch_error *err) {
  if (initial_cap < 16) {
    initial_cap = 16;
  }
  if (initial_cap > SIZE_MAX / sizeof(*worklist->ids)) {
    mch_error_set(err, "dependency closure worklist is too large");
    return -1;
  }

  worklist->ids = malloc(initial_cap * sizeof(*worklist->ids));
  if (worklist->ids == NULL) {
    mch_error_set(err, "out of memory while preparing dependency closure worklist");
    return -1;
  }
  worklist->len = 0;
  worklist->cap = initial_cap;
  return 0;
}

MCH_PRIVATE int worklist_push(struct closure_worklist *worklist, __u32 id, struct mch_error *err) {
  if (worklist->len == worklist->cap) {
    size_t next_cap = worklist->cap * 2;
    __u32 *next;

    if (worklist->cap > SIZE_MAX / 2 || next_cap > SIZE_MAX / sizeof(*worklist->ids)) {
      mch_error_set(err, "dependency closure worklist is too large");
      return -1;
    }
    next = realloc(worklist->ids, next_cap * sizeof(*worklist->ids));
    if (next == NULL) {
      mch_error_set(err, "out of memory while growing dependency closure worklist");
      return -1;
    }
    worklist->ids = next;
    worklist->cap = next_cap;
  }

  worklist->ids[worklist->len++] = id;
  return 0;
}

MCH_PRIVATE int add_dep(const struct btf *btf, struct mch_type_set *required, __u32 id,
                        struct closure_worklist *worklist, struct mch_closure_stats *stats,
                        struct mch_error *err) {
  if (id == 0) {
    return 0;
  }
  if (id >= btf__type_cnt(btf)) {
    mch_error_set(err, "BTF dependency references invalid type id %u", id);
    mch_error_set_hint(err, "input BTF appears internally inconsistent");
    return -1;
  }
  if (mch_type_set_add(required, id)) {
    if (worklist_push(worklist, id, err) != 0) {
      return -1;
    }
    stats->added_types++;
  }
  return 0;
}

MCH_PRIVATE int add_type_deps(const struct btf *btf, __u32 type_id, const struct btf_type *type,
                              struct mch_type_set *required, struct mch_closure_stats *stats,
                              struct closure_worklist *worklist,
                              const struct mch_closure_options *options, struct mch_error *err) {
  unsigned int kind = btf_kind(type);

  switch (kind) {
  case BTF_KIND_PTR:
    if (options != NULL && options->expand_pointers) {
      return add_dep(btf, required, type->type, worklist, stats, err);
    }
    return 0;
  case BTF_KIND_TYPEDEF:
  case BTF_KIND_VOLATILE:
  case BTF_KIND_CONST:
  case BTF_KIND_RESTRICT:
  case BTF_KIND_FUNC:
  case BTF_KIND_VAR:
  case BTF_KIND_DECL_TAG:
  case BTF_KIND_TYPE_TAG:
    return add_dep(btf, required, type->type, worklist, stats, err);

  case BTF_KIND_ARRAY: {
    const struct btf_array *array = btf_array(type);
    if (add_dep(btf, required, array->type, worklist, stats, err) != 0) {
      return -1;
    }
    return add_dep(btf, required, array->index_type, worklist, stats, err);
  }

  case BTF_KIND_STRUCT:
  case BTF_KIND_UNION: {
    const struct btf_member *members = btf_members(type);
    __u16 vlen = btf_vlen(type);
    for (__u16 i = 0; i < vlen; i++) {
      if (options != NULL && options->requirements != NULL &&
          mch_requirements_has_record_members(options->requirements, type_id) &&
          !mch_requirements_contains_record_member(options->requirements, type_id, i)) {
        continue;
      }
      if (add_dep(btf, required, members[i].type, worklist, stats, err) != 0) {
        return -1;
      }
    }
    return 0;
  }

  case BTF_KIND_FUNC_PROTO: {
    const struct btf_param *params = btf_params(type);
    __u16 vlen = btf_vlen(type);
    if (add_dep(btf, required, type->type, worklist, stats, err) != 0) {
      return -1;
    }
    for (__u16 i = 0; i < vlen; i++) {
      if (add_dep(btf, required, params[i].type, worklist, stats, err) != 0) {
        return -1;
      }
    }
    return 0;
  }

  case BTF_KIND_DATASEC: {
    const struct btf_var_secinfo *vars = btf_var_secinfos(type);
    __u16 vlen = btf_vlen(type);
    for (__u16 i = 0; i < vlen; i++) {
      if (add_dep(btf, required, vars[i].type, worklist, stats, err) != 0) {
        return -1;
      }
    }
    return 0;
  }

  case BTF_KIND_INT:
  case BTF_KIND_ENUM:
  case BTF_KIND_ENUM64:
  case BTF_KIND_FWD:
  case BTF_KIND_FLOAT:
  case BTF_KIND_UNKN:
  default:
    return 0;
  }
}

void mch_closure_stats_init(struct mch_closure_stats *stats) { stats->added_types = 0; }

int mch_compute_dependency_closure(const struct btf *btf, struct mch_type_set *required,
                                   struct mch_closure_stats *stats, struct mch_error *err) {
  return mch_compute_dependency_closure_with_options(btf, required, stats, NULL, err);
}

int mch_compute_dependency_closure_with_options(const struct btf *btf,
                                                struct mch_type_set *required,
                                                struct mch_closure_stats *stats,
                                                const struct mch_closure_options *options,
                                                struct mch_error *err) {
  struct closure_worklist worklist;
  size_t cursor = 1;
  size_t id = 0;
  size_t next = 0;

  if (worklist_init(&worklist, required->selected, err) != 0) {
    return -1;
  }

  while (mch_type_set_next(required, &cursor, &id)) {
    if (worklist_push(&worklist, (__u32)id, err) != 0) {
      worklist_destroy(&worklist);
      return -1;
    }
  }

  while (next < worklist.len) {
    const struct btf_type *type;
    __u32 current = worklist.ids[next++];

    type = btf__type_by_id(btf, current);
    if (type == NULL) {
      mch_error_set(err, "base BTF is missing required type id %u", current);
      worklist_destroy(&worklist);
      return -1;
    }
    if (add_type_deps(btf, current, type, required, stats, &worklist, options, err) != 0) {
      worklist_destroy(&worklist);
      return -1;
    }
  }

  worklist_destroy(&worklist);
  return 0;
}
