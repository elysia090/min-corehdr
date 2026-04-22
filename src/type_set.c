#include "min_corehdr/type_set.h"

#include <stdint.h>
#include <stdlib.h>

static size_t bit_index(uint64_t word);
static size_t word_count_for_bits(size_t count) { return count == 0 ? 1 : (count + 63) / 64; }

int mch_type_set_init(struct mch_type_set *set, size_t count) {
  if (set == NULL) {
    return -1;
  }

  set->word_count = word_count_for_bits(count);
  set->words = calloc(set->word_count, sizeof(*set->words));
  if (set->words == NULL) {
    set->count = 0;
    set->word_count = 0;
    set->selected = 0;
    return -1;
  }

  set->count = count;
  set->selected = 0;
  return 0;
}

void mch_type_set_destroy(struct mch_type_set *set) {
  if (set == NULL) {
    return;
  }
  free(set->words);
  set->words = NULL;
  set->count = 0;
  set->word_count = 0;
  set->selected = 0;
}

bool mch_type_set_contains(const struct mch_type_set *set, size_t id) {
  size_t word;
  uint64_t mask;

  if (set == NULL || id >= set->count) {
    return false;
  }

  word = id >> 6;
  mask = UINT64_C(1) << (id & 63u);
  return (set->words[word] & mask) != 0;
}

bool mch_type_set_add(struct mch_type_set *set, size_t id) {
  size_t word;
  uint64_t mask;

  if (set == NULL || id >= set->count) {
    return false;
  }

  word = id >> 6;
  mask = UINT64_C(1) << (id & 63u);
  if ((set->words[word] & mask) != 0) {
    return false;
  }

  set->words[word] |= mask;
  set->selected++;
  return true;
}

bool mch_type_set_next(const struct mch_type_set *set, size_t *cursor, size_t *id) {
  size_t start;
  size_t word_index;
  unsigned int bit_offset;
  uint64_t word;

  if (set == NULL || cursor == NULL || id == NULL || set->words == NULL || *cursor >= set->count) {
    return false;
  }

  start = *cursor;
  word_index = start >> 6;
  bit_offset = (unsigned int)(start & 63u);
  word = set->words[word_index] & (~UINT64_C(0) << bit_offset);

  while (word_index < set->word_count) {
    if (word != 0) {
      size_t found = word_index * 64 + bit_index(word);
      if (found >= set->count) {
        return false;
      }
      *id = found;
      *cursor = found + 1;
      return true;
    }

    word_index++;
    if (word_index >= set->word_count) {
      break;
    }
    word = set->words[word_index];
  }

  *cursor = set->count;
  return false;
}

static size_t bit_index(uint64_t word) {
#if defined(__GNUC__) || defined(__clang__)
  return (size_t)__builtin_ctzll(word);
#else
  size_t bit = 0;

  while ((word & UINT64_C(1)) == 0) {
    word >>= 1;
    bit++;
  }
  return bit;
#endif
}
