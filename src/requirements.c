#include "min_corehdr/requirements.h"

#include <stdlib.h>

#include <linux/btf.h>

static size_t word_count_for_bits(size_t count) { return count == 0 ? 1 : (count + 63) / 64; }

int mch_requirements_init(struct mch_requirements *requirements, size_t type_count) {
  if (requirements == NULL) {
    return -1;
  }

  requirements->record_member_words =
      calloc(type_count == 0 ? 1 : type_count, sizeof(*requirements->record_member_words));
  if (requirements->record_member_words == NULL) {
    requirements->type_count = 0;
    return -1;
  }

  requirements->type_count = type_count;
  return 0;
}

void mch_requirements_destroy(struct mch_requirements *requirements) {
  if (requirements == NULL) {
    return;
  }
  if (requirements->record_member_words != NULL) {
    for (size_t i = 0; i < requirements->type_count; i++) {
      free(requirements->record_member_words[i]);
    }
  }
  free(requirements->record_member_words);
  requirements->record_member_words = NULL;
  requirements->type_count = 0;
}

bool mch_requirements_has_record_members(const struct mch_requirements *requirements,
                                         size_t type_id) {
  return requirements != NULL && requirements->record_member_words != NULL &&
         type_id < requirements->type_count && requirements->record_member_words[type_id] != NULL;
}

bool mch_requirements_contains_record_member(const struct mch_requirements *requirements,
                                             size_t type_id, size_t member_index) {
  size_t word;
  uint64_t mask;

  if (!mch_requirements_has_record_members(requirements, type_id)) {
    return false;
  }

  word = member_index >> 6;
  mask = UINT64_C(1) << (member_index & 63u);
  return (requirements->record_member_words[type_id][word] & mask) != 0;
}

int mch_requirements_add_record_member(const struct btf *btf, struct mch_requirements *requirements,
                                       size_t type_id, size_t member_index, struct mch_error *err) {
  const struct btf_type *type;
  size_t member_count;
  size_t word;
  uint64_t mask;

  if (requirements == NULL) {
    return 0;
  }
  if (btf == NULL || requirements->record_member_words == NULL ||
      type_id >= requirements->type_count) {
    mch_error_set(err, "requirements reference invalid type id %zu", type_id);
    return -1;
  }

  type = btf__type_by_id(btf, (__u32)type_id);
  if (type == NULL || (btf_kind(type) != BTF_KIND_STRUCT && btf_kind(type) != BTF_KIND_UNION)) {
    mch_error_set(err, "requirements reference non-record type id %zu", type_id);
    return -1;
  }

  member_count = btf_vlen(type);
  if (member_index >= member_count) {
    mch_error_set(err, "requirements reference invalid member %zu on type id %zu", member_index,
                  type_id);
    return -1;
  }

  if (requirements->record_member_words[type_id] == NULL) {
    size_t words = word_count_for_bits(member_count);

    requirements->record_member_words[type_id] =
        calloc(words, sizeof(*requirements->record_member_words[type_id]));
    if (requirements->record_member_words[type_id] == NULL) {
      mch_error_set(err, "out of memory while recording required record members");
      return -1;
    }
  }

  word = member_index >> 6;
  mask = UINT64_C(1) << (member_index & 63u);
  requirements->record_member_words[type_id][word] |= mask;
  return 0;
}
