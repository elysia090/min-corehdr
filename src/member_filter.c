#include "min_corehdr/member_filter.h"

#include <stdlib.h>

#include <linux/btf.h>

static size_t word_count_for_bits(size_t count) { return count == 0 ? 1 : (count + 63) / 64; }

int mch_member_filter_init(struct mch_member_filter *filter, size_t type_count) {
  if (filter == NULL) {
    return -1;
  }

  filter->words = calloc(type_count == 0 ? 1 : type_count, sizeof(*filter->words));
  if (filter->words == NULL) {
    filter->type_count = 0;
    return -1;
  }

  filter->type_count = type_count;
  return 0;
}

void mch_member_filter_destroy(struct mch_member_filter *filter) {
  if (filter == NULL) {
    return;
  }
  if (filter->words != NULL) {
    for (size_t i = 0; i < filter->type_count; i++) {
      free(filter->words[i]);
    }
  }
  free(filter->words);
  filter->words = NULL;
  filter->type_count = 0;
}

bool mch_member_filter_has_record(const struct mch_member_filter *filter, size_t type_id) {
  return filter != NULL && filter->words != NULL && type_id < filter->type_count &&
         filter->words[type_id] != NULL;
}

bool mch_member_filter_contains(const struct mch_member_filter *filter, size_t type_id,
                                size_t member_index) {
  size_t word;
  uint64_t mask;

  if (!mch_member_filter_has_record(filter, type_id)) {
    return false;
  }

  word = member_index >> 6;
  mask = UINT64_C(1) << (member_index & 63u);
  return (filter->words[type_id][word] & mask) != 0;
}

int mch_member_filter_add(const struct btf *btf, struct mch_member_filter *filter, size_t type_id,
                          size_t member_index, struct mch_error *err) {
  const struct btf_type *type;
  size_t member_count;
  size_t word;
  uint64_t mask;

  if (filter == NULL) {
    return 0;
  }
  if (btf == NULL || filter->words == NULL || type_id >= filter->type_count) {
    mch_error_set(err, "member filter references invalid type id %zu", type_id);
    return -1;
  }

  type = btf__type_by_id(btf, (__u32)type_id);
  if (type == NULL || (btf_kind(type) != BTF_KIND_STRUCT && btf_kind(type) != BTF_KIND_UNION)) {
    mch_error_set(err, "member filter references non-record type id %zu", type_id);
    return -1;
  }

  member_count = btf_vlen(type);
  if (member_index >= member_count) {
    mch_error_set(err, "member filter references invalid member %zu on type id %zu", member_index,
                  type_id);
    return -1;
  }

  if (filter->words[type_id] == NULL) {
    size_t words = word_count_for_bits(member_count);

    filter->words[type_id] = calloc(words, sizeof(*filter->words[type_id]));
    if (filter->words[type_id] == NULL) {
      mch_error_set(err, "out of memory while recording required record members");
      return -1;
    }
  }

  word = member_index >> 6;
  mask = UINT64_C(1) << (member_index & 63u);
  filter->words[type_id][word] |= mask;
  return 0;
}
