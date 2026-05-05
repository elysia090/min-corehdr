#ifndef MIN_COREHDR_MEMBER_FILTER_H
#define MIN_COREHDR_MEMBER_FILTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpf/btf.h>

#include "min_corehdr/error.h"

struct mch_member_filter {
  uint64_t **words;
  size_t type_count;
};

int mch_member_filter_init(struct mch_member_filter *filter, size_t type_count);
void mch_member_filter_destroy(struct mch_member_filter *filter);
bool mch_member_filter_has_record(const struct mch_member_filter *filter, size_t type_id);
bool mch_member_filter_contains(const struct mch_member_filter *filter, size_t type_id,
                                size_t member_index);
int mch_member_filter_add(const struct btf *btf, struct mch_member_filter *filter, size_t type_id,
                          size_t member_index, struct mch_error *err);

#endif
