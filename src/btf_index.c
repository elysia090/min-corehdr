#include "min_corehdr/btf_index.h"

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/btf.h>

#include "min_corehdr/btf_loader.h"

#define MCH_BTF_INDEX_NONE UINT32_MAX

static bool is_indexed_kind(unsigned int kind) {
  return kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION || kind == BTF_KIND_ENUM ||
         kind == BTF_KIND_ENUM64 || kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_FWD;
}

static size_t next_power_of_two(size_t value) {
  size_t result = 1;

  while (result < value && result <= SIZE_MAX / 2) {
    result *= 2;
  }
  return result < value ? value : result;
}

static uint32_t hash_name_kind(const char *name, unsigned int kind) {
  uint32_t hash = 2166136261u;

  hash ^= kind & 0xffu;
  hash *= 16777619u;
  for (const unsigned char *p = (const unsigned char *)name; *p != '\0'; p++) {
    hash ^= *p;
    hash *= 16777619u;
  }
  return hash;
}

void mch_btf_index_init_empty(struct mch_btf_index *index) {
  index->buckets = NULL;
  index->entries = NULL;
  index->bucket_count = 0;
  index->entry_count = 0;
}

static void init_buckets(uint32_t *buckets, size_t bucket_count) {
  memset(buckets, 0xff, bucket_count * sizeof(*buckets));
}

static void index_insert(struct mch_btf_index *index, const char *name, unsigned int kind,
                         uint32_t type_id) {
  uint32_t bucket = hash_name_kind(name, kind) & (uint32_t)(index->bucket_count - 1);

  for (uint32_t entry_id = index->buckets[bucket]; entry_id != MCH_BTF_INDEX_NONE;
       entry_id = index->entries[entry_id].next) {
    struct mch_btf_index_entry *entry = &index->entries[entry_id];

    if (entry->kind == kind && strcmp(entry->name, name) == 0) {
      entry->ambiguous = 1;
      entry->type_id = 0;
      return;
    }
  }

  index->entries[index->entry_count] = (struct mch_btf_index_entry){
      .name = name,
      .type_id = type_id,
      .next = index->buckets[bucket],
      .kind = kind,
      .ambiguous = 0,
  };
  index->buckets[bucket] = (uint32_t)index->entry_count;
  index->entry_count++;
}

int mch_btf_index_init(struct mch_btf_index *index, const struct btf *btf, struct mch_error *err) {
  size_t entry_capacity;
  size_t bucket_count;
  __u32 type_count;

  mch_btf_index_init_empty(index);

  type_count = btf__type_cnt(btf);
  entry_capacity = type_count > 1 ? (size_t)type_count - 1 : 1;
  if (entry_capacity > UINT32_MAX || entry_capacity > SIZE_MAX / 2) {
    mch_error_set(err, "base BTF type index is too large");
    return -1;
  }
  bucket_count = next_power_of_two(entry_capacity * 2);
  if (bucket_count > UINT32_MAX) {
    mch_error_set(err, "base BTF type index is too large");
    return -1;
  }

  index->buckets = malloc(bucket_count * sizeof(*index->buckets));
  index->entries = calloc(entry_capacity, sizeof(*index->entries));
  if (index->buckets == NULL || index->entries == NULL) {
    mch_error_set(err, "out of memory while building base BTF type index");
    mch_btf_index_destroy(index);
    return -1;
  }

  index->bucket_count = bucket_count;
  init_buckets(index->buckets, index->bucket_count);
  for (__u32 id = 1; id < type_count; id++) {
    const struct btf_type *type = btf__type_by_id(btf, id);
    const char *name;

    if (type == NULL || !is_indexed_kind(btf_kind(type))) {
      continue;
    }

    name = mch_btf_type_name(btf, type);
    if (name[0] == '\0') {
      continue;
    }

    index_insert(index, name, btf_kind(type), id);
  }

  return 0;
}

void mch_btf_index_destroy(struct mch_btf_index *index) {
  if (index == NULL) {
    return;
  }
  free(index->buckets);
  free(index->entries);
  mch_btf_index_init_empty(index);
}

int mch_btf_index_lookup(const struct mch_btf_index *index, const char *name, unsigned int kind,
                         unsigned int *type_id) {
  uint32_t bucket;

  if (index == NULL || index->bucket_count == 0 || name == NULL || name[0] == '\0') {
    return 0;
  }

  bucket = hash_name_kind(name, kind) & (uint32_t)(index->bucket_count - 1);
  for (uint32_t entry_id = index->buckets[bucket]; entry_id != MCH_BTF_INDEX_NONE;
       entry_id = index->entries[entry_id].next) {
    const struct mch_btf_index_entry *entry = &index->entries[entry_id];

    if (entry->kind != kind || strcmp(entry->name, name) != 0) {
      continue;
    }
    if (entry->ambiguous) {
      return -1;
    }
    *type_id = entry->type_id;
    return 1;
  }

  return 0;
}
