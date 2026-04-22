#ifndef MIN_COREHDR_BTF_INDEX_H
#define MIN_COREHDR_BTF_INDEX_H

#include <stddef.h>
#include <stdint.h>

#include <bpf/btf.h>

#include "min_corehdr/error.h"

struct mch_btf_index_entry {
  const char *name;
  uint32_t type_id;
  uint32_t next;
  unsigned int kind;
  unsigned char ambiguous;
};

struct mch_btf_index {
  uint32_t *buckets;
  struct mch_btf_index_entry *entries;
  size_t bucket_count;
  size_t entry_count;
};

void mch_btf_index_init_empty(struct mch_btf_index *index);
int mch_btf_index_init(struct mch_btf_index *index, const struct btf *btf, struct mch_error *err);
void mch_btf_index_destroy(struct mch_btf_index *index);
int mch_btf_index_lookup(const struct mch_btf_index *index, const char *name, unsigned int kind,
                         unsigned int *type_id);

#endif
