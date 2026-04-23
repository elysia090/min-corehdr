#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include "min_corehdr/btf_index.h"
#include "min_corehdr/error.h"

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

struct mch_btf_ext_info_sec {
  __u32 sec_name_off;
  __u32 num_info;
};

struct mch_ext_info {
  const uint8_t *pos;
  const uint8_t *end;
  __u32 rec_size;
  bool present;
};

int init_ext_info(struct mch_ext_info *info, const uint8_t *raw, __u32 raw_size, __u32 hdr_len,
                  __u32 off, __u32 len, size_t min_rec_size, const char *label,
                  const char *object_path, bool required, struct mch_error *err);
const uint8_t *find_ext_info_section(const struct mch_ext_info *info, __u32 sec_name_off,
                                     __u32 *num_info);
int resolve_object_type_to_base(const struct mch_btf_index *base_index,
                                const struct btf *object_btf, __u32 object_type_id,
                                const char *object_path, const char *reference,
                                bool allow_program_local, unsigned int *base_id,
                                struct mch_error *err);

static void write_u32(uint8_t *dst, __u32 value) { memcpy(dst, &value, sizeof(value)); }

static int test_init_ext_info_boundaries(void) {
  struct mch_ext_info info;
  struct mch_error err;
  uint8_t raw[16] = {0};

  mch_error_clear(&err);
  REQUIRE(init_ext_info(&info, raw, 8, 16, 0, 4, 4, "CO-RE relocation", "bad.o", true, &err) != 0);
  REQUIRE(strstr(err.message, "out of bounds") != NULL);
  mch_error_clear(&err);
  REQUIRE(init_ext_info(&info, raw, 8, 16, 0, 4, 4, "line info", "bad.o", false, &err) == 0);

  mch_error_clear(&err);
  REQUIRE(init_ext_info(&info, raw, sizeof(raw), 0, 0, 2, 4, "CO-RE relocation", "bad.o", true,
                        &err) != 0);
  REQUIRE(strstr(err.message, "truncated") != NULL);
  mch_error_clear(&err);
  REQUIRE(init_ext_info(&info, raw, sizeof(raw), 0, 0, 2, 4, "line info", "bad.o", false, &err) ==
          0);

  write_u32(raw, 1);
  mch_error_clear(&err);
  REQUIRE(init_ext_info(&info, raw, sizeof(raw), 0, 0, sizeof(__u32), 8, "CO-RE relocation",
                        "bad.o", true, &err) != 0);
  REQUIRE(strstr(err.message, "record size is unsupported") != NULL);
  mch_error_clear(&err);
  REQUIRE(init_ext_info(&info, raw, sizeof(raw), 0, 0, sizeof(__u32), 8, "line info", "bad.o",
                        false, &err) == 0);

  return 0;
}

static int test_find_ext_info_section_boundaries(void) {
  struct mch_ext_info info;
  struct mch_btf_ext_info_sec sec;
  uint8_t raw[sizeof(sec) + 4] = {0};
  __u32 num_info = 99;

  REQUIRE(find_ext_info_section(NULL, 1, &num_info) == NULL);

  info = (struct mch_ext_info){.pos = raw, .end = raw + 4, .rec_size = 8, .present = true};
  REQUIRE(find_ext_info_section(&info, 1, &num_info) == NULL);

  sec = (struct mch_btf_ext_info_sec){.sec_name_off = 1, .num_info = 2};
  memcpy(raw, &sec, sizeof(sec));
  info =
      (struct mch_ext_info){.pos = raw, .end = raw + sizeof(sec), .rec_size = 8, .present = true};
  REQUIRE(find_ext_info_section(&info, 1, &num_info) == NULL);

  sec = (struct mch_btf_ext_info_sec){.sec_name_off = 1, .num_info = 0};
  memcpy(raw, &sec, sizeof(sec));
  info =
      (struct mch_ext_info){.pos = raw, .end = raw + sizeof(sec), .rec_size = 8, .present = true};
  REQUIRE(find_ext_info_section(&info, 2, &num_info) == NULL);

  return 0;
}

static int test_resolve_chain_depth_limit(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct btf *base;
  struct btf *object;
  unsigned int base_id = 0;
  int int_id;
  int current_id;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);
  int_id = btf__add_int(object, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  current_id = int_id;
  for (size_t i = 0; i < 33; i++) {
    char name[32];

    snprintf(name, sizeof(name), "deep_%zu", i);
    current_id = btf__add_typedef(object, name, current_id);
    REQUIRE(current_id > 0);
  }
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);

  rc = resolve_object_type_to_base(&index, object, (__u32)current_id, "deep.o", "CO-RE relocation",
                                   false, &base_id, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, "type chain is too deep") != NULL);
  REQUIRE(strstr(err.detail, "CO-RE relocation object type:") != NULL);
  REQUIRE(strstr(err.detail, "type chain too deep") != NULL);
  REQUIRE(err.hint[0] != '\0');

  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

int main(void) {
  REQUIRE(test_init_ext_info_boundaries() == 0);
  REQUIRE(test_find_ext_info_section_boundaries() == 0);
  REQUIRE(test_resolve_chain_depth_limit() == 0);
  return 0;
}
