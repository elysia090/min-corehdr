#ifndef MIN_COREHDR_SEEDS_H
#define MIN_COREHDR_SEEDS_H

#include <stddef.h>

#include <bpf/btf.h>

#include "min_corehdr/btf_index.h"
#include "min_corehdr/error.h"
#include "min_corehdr/member_filter.h"
#include "min_corehdr/type_set.h"

struct mch_seed_stats {
  size_t candidates;
  size_t kernel_types;
  size_t program_local_types;
  size_t core_relocations;
  size_t core_kernel_types;
};

void mch_seed_stats_init(struct mch_seed_stats *stats);
int mch_extract_object_seeds(const struct mch_btf_index *base_index, const struct btf *object_btf,
                             const char *object_path, struct mch_type_set *seeds,
                             struct mch_seed_stats *stats, struct mch_error *err);
int mch_extract_core_relo_seeds(const struct mch_btf_index *base_index,
                                const struct btf *object_btf, const struct btf_ext *object_ext,
                                const char *object_path, struct mch_type_set *seeds,
                                struct mch_seed_stats *stats, struct mch_error *err);
int mch_extract_core_relo_seeds_with_members(const struct mch_btf_index *base_index,
                                             const struct btf *object_btf,
                                             const struct btf_ext *object_ext,
                                             const char *object_path, struct mch_type_set *seeds,
                                             struct mch_member_filter *members,
                                             struct mch_seed_stats *stats, struct mch_error *err);

#endif
