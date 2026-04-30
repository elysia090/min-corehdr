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
  index->btf = NULL;
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
  index->btf = btf;
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

static bool enum_value_matches(const struct btf *left_btf, const struct btf_type *left_type,
                               const struct btf *right_btf, const struct btf_type *right_type,
                               __u16 i) {
  const char *left_name;
  const char *right_name;

  if (btf_kind(left_type) == BTF_KIND_ENUM) {
    const struct btf_enum *left_values = btf_enum(left_type);
    const struct btf_enum *right_values = btf_enum(right_type);

    left_name = btf__name_by_offset(left_btf, left_values[i].name_off);
    right_name = btf__name_by_offset(right_btf, right_values[i].name_off);
    return left_name != NULL && right_name != NULL && strcmp(left_name, right_name) == 0 &&
           left_values[i].val == right_values[i].val;
  }

  const struct btf_enum64 *left_values = btf_enum64(left_type);
  const struct btf_enum64 *right_values = btf_enum64(right_type);

  left_name = btf__name_by_offset(left_btf, left_values[i].name_off);
  right_name = btf__name_by_offset(right_btf, right_values[i].name_off);
  return left_name != NULL && right_name != NULL && strcmp(left_name, right_name) == 0 &&
         left_values[i].val_lo32 == right_values[i].val_lo32 &&
         left_values[i].val_hi32 == right_values[i].val_hi32;
}

static bool anonymous_enum_matches(const struct btf *base_btf, const struct btf_type *base_type,
                                   const struct btf *object_btf,
                                   const struct btf_type *object_type) {
  __u16 vlen = btf_vlen(object_type);

  if (btf_kind(base_type) != btf_kind(object_type) || base_type->size != object_type->size ||
      btf_kflag(base_type) != btf_kflag(object_type) || btf_vlen(base_type) != vlen ||
      mch_btf_type_name(base_btf, base_type)[0] != '\0') {
    return false;
  }

  for (__u16 i = 0; i < vlen; i++) {
    if (!enum_value_matches(base_btf, base_type, object_btf, object_type, i)) {
      return false;
    }
  }

  return true;
}

int mch_btf_index_lookup_anonymous_enum(const struct mch_btf_index *index,
                                        const struct btf *object_btf,
                                        const struct btf_type *object_type, unsigned int *type_id) {
  unsigned int found = 0;
  unsigned int matches = 0;
  unsigned int kind;

  if (index == NULL || index->btf == NULL || object_btf == NULL || object_type == NULL ||
      type_id == NULL) {
    return 0;
  }

  kind = btf_kind(object_type);
  if ((kind != BTF_KIND_ENUM && kind != BTF_KIND_ENUM64) ||
      mch_btf_type_name(object_btf, object_type)[0] != '\0') {
    return 0;
  }

  for (__u32 id = 1; id < btf__type_cnt(index->btf); id++) {
    const struct btf_type *base_type = btf__type_by_id(index->btf, id);

    if (base_type == NULL ||
        !anonymous_enum_matches(index->btf, base_type, object_btf, object_type)) {
      continue;
    }
    found = id;
    matches++;
    if (matches > 1) {
      return -1;
    }
  }

  if (matches == 0) {
    return 0;
  }
  *type_id = found;
  return 1;
}
