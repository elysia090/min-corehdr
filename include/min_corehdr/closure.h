#ifndef MIN_COREHDR_CLOSURE_H
#define MIN_COREHDR_CLOSURE_H

#include <stdbool.h>
#include <stddef.h>

#include <bpf/btf.h>

#include "min_corehdr/error.h"
#include "min_corehdr/type_set.h"

struct mch_closure_stats {
  size_t added_types;
};

struct mch_closure_options {
  bool expand_pointers;
};

void mch_closure_stats_init(struct mch_closure_stats *stats);
int mch_compute_dependency_closure_with_options(const struct btf *btf,
                                                struct mch_type_set *required,
                                                struct mch_closure_stats *stats,
                                                const struct mch_closure_options *options,
                                                struct mch_error *err);
int mch_compute_dependency_closure(const struct btf *btf, struct mch_type_set *required,
                                   struct mch_closure_stats *stats, struct mch_error *err);

#endif
