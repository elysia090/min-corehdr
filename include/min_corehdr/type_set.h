#ifndef MIN_COREHDR_TYPE_SET_H
#define MIN_COREHDR_TYPE_SET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mch_type_set {
  uint64_t *words;
  size_t count;
  size_t word_count;
  size_t selected;
};

int mch_type_set_init(struct mch_type_set *set, size_t count);
void mch_type_set_destroy(struct mch_type_set *set);
bool mch_type_set_contains(const struct mch_type_set *set, size_t id);
bool mch_type_set_add(struct mch_type_set *set, size_t id);
bool mch_type_set_next(const struct mch_type_set *set, size_t *cursor, size_t *id);

#endif
