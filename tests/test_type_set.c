#include "min_corehdr/type_set.h"

#include <stdint.h>
#include <stdio.h>

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

int main(void) {
  struct mch_type_set set;
  size_t cursor = 0;
  size_t id = 0;

  REQUIRE(mch_type_set_init(NULL, 1) != 0);
  mch_type_set_destroy(NULL);
  REQUIRE(!mch_type_set_contains(NULL, 0));
  REQUIRE(!mch_type_set_add(NULL, 0));
  REQUIRE(!mch_type_set_next(NULL, &cursor, &id));
  REQUIRE(!mch_type_set_next(&set, NULL, &id));
  REQUIRE(!mch_type_set_next(&set, &cursor, NULL));

  REQUIRE(mch_type_set_init(&set, 0) == 0);
  REQUIRE(set.word_count == 1);
  REQUIRE(!mch_type_set_next(&set, &cursor, &id));
  mch_type_set_destroy(&set);

  REQUIRE(mch_type_set_init(&set, 1) == 0);
  set.words[0] = UINT64_C(1) << 2;
  cursor = 0;
  REQUIRE(!mch_type_set_next(&set, &cursor, &id));
  mch_type_set_destroy(&set);

  REQUIRE(mch_type_set_init(&set, 130) == 0);
  REQUIRE(set.selected == 0);
  REQUIRE(!mch_type_set_contains(&set, 0));
  REQUIRE(!mch_type_set_contains(&set, 64));
  REQUIRE(!mch_type_set_contains(&set, 129));
  REQUIRE(!mch_type_set_contains(&set, 130));

  REQUIRE(mch_type_set_add(&set, 0));
  REQUIRE(mch_type_set_add(&set, 64));
  REQUIRE(mch_type_set_add(&set, 129));
  REQUIRE(!mch_type_set_add(&set, 64));
  REQUIRE(!mch_type_set_add(&set, 130));

  REQUIRE(mch_type_set_contains(&set, 0));
  REQUIRE(mch_type_set_contains(&set, 64));
  REQUIRE(mch_type_set_contains(&set, 129));
  REQUIRE(!mch_type_set_contains(&set, 128));
  REQUIRE(set.selected == 3);

  REQUIRE(mch_type_set_next(&set, &cursor, &id));
  REQUIRE(id == 0);
  REQUIRE(mch_type_set_next(&set, &cursor, &id));
  REQUIRE(id == 64);
  REQUIRE(mch_type_set_next(&set, &cursor, &id));
  REQUIRE(id == 129);
  REQUIRE(!mch_type_set_next(&set, &cursor, &id));
  cursor = 130;
  REQUIRE(!mch_type_set_next(&set, &cursor, &id));

  mch_type_set_destroy(&set);
  REQUIRE(set.words == NULL);
  REQUIRE(set.count == 0);
  REQUIRE(set.word_count == 0);
  REQUIRE(set.selected == 0);
  return 0;
}
