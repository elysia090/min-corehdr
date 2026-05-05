#ifndef MIN_COREHDR_REQUIREMENTS_H
#define MIN_COREHDR_REQUIREMENTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpf/btf.h>

#include "min_corehdr/error.h"

struct mch_requirements {
  uint64_t **record_member_words;
  size_t type_count;
};

int mch_requirements_init(struct mch_requirements *requirements, size_t type_count);
void mch_requirements_destroy(struct mch_requirements *requirements);
bool mch_requirements_has_record_members(const struct mch_requirements *requirements,
                                         size_t type_id);
bool mch_requirements_contains_record_member(const struct mch_requirements *requirements,
                                             size_t type_id, size_t member_index);
int mch_requirements_add_record_member(const struct btf *btf, struct mch_requirements *requirements,
                                       size_t type_id, size_t member_index, struct mch_error *err);

#endif
