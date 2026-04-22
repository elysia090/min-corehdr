#include "min_corehdr/btf_index.h"
#include "min_corehdr/error.h"
#include "min_corehdr/seeds.h"
#include "min_corehdr/type_set.h"

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

struct test_btf_ext_header {
  __u16 magic;
  __u8 version;
  __u8 flags;
  __u32 hdr_len;
  __u32 func_info_off;
  __u32 func_info_len;
  __u32 line_info_off;
  __u32 line_info_len;
  __u32 core_relo_off;
  __u32 core_relo_len;
};

struct test_btf_ext_info_sec {
  __u32 sec_name_off;
  __u32 num_info;
};

static int make_core_ext(const uint8_t *core, __u32 core_len, struct btf_ext **out) {
  uint8_t raw[512];
  struct test_btf_ext_header header = {
      .magic = BTF_MAGIC,
      .version = BTF_VERSION,
      .hdr_len = sizeof(header),
      .core_relo_off = 0,
      .core_relo_len = core_len,
  };
  struct btf_ext *ext;

  REQUIRE(sizeof(header) + core_len <= sizeof(raw));
  memcpy(raw, &header, sizeof(header));
  if (core_len != 0) {
    memcpy(raw + sizeof(header), core, core_len);
  }

  ext = btf_ext__new(raw, (uint32_t)(sizeof(header) + core_len));
  REQUIRE(libbpf_get_error(ext) == 0);
  *out = ext;
  return 0;
}

static void write_u32(uint8_t **pos, __u32 value) {
  memcpy(*pos, &value, sizeof(value));
  *pos += sizeof(value);
}

static void write_sec(uint8_t **pos, __u32 num_info) {
  struct test_btf_ext_info_sec sec = {.sec_name_off = 0, .num_info = num_info};

  memcpy(*pos, &sec, sizeof(sec));
  *pos += sizeof(sec);
}

static void write_relo_ex(uint8_t **pos, __u32 type_id, __u32 access_str_off,
                          enum bpf_core_relo_kind kind) {
  struct bpf_core_relo relo = {
      .insn_off = 0,
      .type_id = type_id,
      .access_str_off = access_str_off,
      .kind = kind,
  };

  memcpy(*pos, &relo, sizeof(relo));
  *pos += sizeof(relo);
}

static void write_relo(uint8_t **pos, __u32 type_id, enum bpf_core_relo_kind kind) {
  write_relo_ex(pos, type_id, 0, kind);
}

static int add_named_enum(struct btf *btf, const char *name) {
  int id = btf__add_enum(btf, name, 4);
  if (id < 0) {
    return id;
  }
  return btf__add_enum_value(btf, "VALUE", 0) < 0 ? -1 : id;
}

static int test_local_vs_kernel(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf *base;
  struct btf *object;
  int base_task;
  int base_enum;
  int object_task;
  int object_int;
  int object_ptr;
  int object_array;
  int alias1;
  int alias2;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);

  base_task = btf__add_struct(base, "task_struct", 4);
  REQUIRE(base_task > 0);
  base_enum = add_named_enum(base, "pid_type");
  REQUIRE(base_enum > 0);

  object_int = btf__add_int(object, "int", 4, BTF_INT_SIGNED);
  REQUIRE(object_int > 0);
  object_ptr = btf__add_ptr(object, object_int);
  REQUIRE(object_ptr > 0);
  object_array = btf__add_array(object, object_int, object_int, 4);
  REQUIRE(object_array > 0);
  object_task = btf__add_struct(object, "task_struct", 8);
  REQUIRE(object_task > 0);
  REQUIRE(add_named_enum(object, "pid_type") > 0);
  REQUIRE(btf__add_struct(object, "local_event", 16) > 0);
  alias1 = btf__add_typedef(object, "task_alias1", object_task);
  REQUIRE(alias1 > 0);
  alias2 = btf__add_typedef(object, "task_alias2", alias1);
  REQUIRE(alias2 > 0);
  REQUIRE(btf__add_typedef(object, "task_alias3", alias2) > 0);

  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);
  REQUIRE(mch_extract_object_seeds(&index, object, "fixture.bpf.o", &seeds, &stats, &err) == 0);
  REQUIRE(mch_extract_core_relo_seeds(&index, object, NULL, "fixture.bpf.o", &seeds, &stats,
                                      &err) == 0);

  REQUIRE(stats.candidates == 6);
  REQUIRE(stats.kernel_types == 2);
  REQUIRE(stats.program_local_types == 1);
  REQUIRE(mch_type_set_contains(&seeds, (size_t)base_task));
  REQUIRE(mch_type_set_contains(&seeds, (size_t)base_enum));
  REQUIRE(seeds.selected == 2);

  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int test_ambiguous_kernel_match_fails(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf *base;
  struct btf *object;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);

  REQUIRE(btf__add_struct(base, "dup_type", 4) > 0);
  REQUIRE(btf__add_struct(base, "dup_type", 8) > 0);
  REQUIRE(btf__add_struct(object, "dup_type", 4) > 0);

  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);
  rc = mch_extract_object_seeds(&index, object, "ambiguous.bpf.o", &seeds, &stats, &err);
  REQUIRE(rc != 0);
  REQUIRE(err.message[0] != '\0');
  REQUIRE(err.file[0] != '\0');

  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int test_core_relo_synthetic_ext(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t *pos = core;
  int base_task;
  int object_task;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);
  base_task = btf__add_struct(base, "task_struct", 4);
  REQUIRE(base_task > 0);
  object_task = btf__add_struct(object, "task_struct", 4);
  REQUIRE(object_task > 0);

  write_u32(&pos, sizeof(struct bpf_core_relo));
  write_sec(&pos, 1);
  write_relo(&pos, (__u32)object_task, BPF_CORE_FIELD_BYTE_OFFSET);
  REQUIRE(make_core_ext(core, (uint32_t)(pos - core), &ext) == 0);

  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);
  REQUIRE(mch_extract_core_relo_seeds(&index, object, ext, "core.bpf.o", &seeds, &stats, &err) ==
          0);
  REQUIRE(stats.core_relocations == 1);
  REQUIRE(stats.core_kernel_types == 1);
  REQUIRE(mch_type_set_contains(&seeds, (size_t)base_task));

  btf_ext__free(ext);
  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int expect_core_ext_failure(const uint8_t *core, __u32 core_len, const char *message_part) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);
  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);
  REQUIRE(make_core_ext(core, core_len, &ext) == 0);
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);

  rc = mch_extract_core_relo_seeds(&index, object, ext, "bad-core.bpf.o", &seeds, &stats, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, message_part) != NULL);
  REQUIRE(err.file[0] != '\0');

  btf_ext__free(ext);
  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int expect_core_ext_endianness_failure(const uint8_t *core, __u32 core_len) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  enum btf_endianness opposite;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);
  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);
  REQUIRE(make_core_ext(core, core_len, &ext) == 0);
  opposite = btf_ext__endianness(ext) == BTF_LITTLE_ENDIAN ? BTF_BIG_ENDIAN : BTF_LITTLE_ENDIAN;
  REQUIRE(btf_ext__set_endianness(ext, opposite) == 0);
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);

  rc = mch_extract_core_relo_seeds(&index, object, ext, "bad-core.bpf.o", &seeds, &stats, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, "endianness") != NULL);
  REQUIRE(err.file[0] != '\0');
  REQUIRE(err.hint[0] != '\0');

  btf_ext__free(ext);
  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int expect_invalid_core_relo_kind(enum bpf_core_relo_kind kind, __u32 access_str_off) {
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t *pos = core;

  write_u32(&pos, sizeof(struct bpf_core_relo));
  write_sec(&pos, 1);
  write_relo_ex(&pos, 9999, access_str_off, kind);
  return expect_core_ext_failure(core, (uint32_t)(pos - core), "invalid object type id");
}

static int test_core_relo_kind_diagnostics(void) {
  static const enum bpf_core_relo_kind kinds[] = {
      BPF_CORE_FIELD_BYTE_OFFSET, BPF_CORE_FIELD_BYTE_SIZE,  BPF_CORE_FIELD_EXISTS,
      BPF_CORE_FIELD_SIGNED,      BPF_CORE_FIELD_LSHIFT_U64, BPF_CORE_FIELD_RSHIFT_U64,
      BPF_CORE_TYPE_ID_LOCAL,     BPF_CORE_TYPE_ID_TARGET,   BPF_CORE_TYPE_EXISTS,
      BPF_CORE_TYPE_SIZE,         BPF_CORE_ENUMVAL_EXISTS,   BPF_CORE_ENUMVAL_VALUE,
      BPF_CORE_TYPE_MATCHES,
  };

  for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
    REQUIRE(expect_invalid_core_relo_kind(kinds[i], 0) == 0);
  }
  REQUIRE(expect_invalid_core_relo_kind((enum bpf_core_relo_kind)999, 9999) == 0);
  return 0;
}

static int test_core_relo_malformed_ext(void) {
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t *pos;
  struct btf_ext *ext;

  (void)ext;
  memset(core, 0, sizeof(core));

  pos = core;
  write_u32(&pos, sizeof(struct bpf_core_relo));
  write_sec(&pos, 1);
  write_relo(&pos, 9999, BPF_CORE_TYPE_SIZE);
  REQUIRE(expect_core_ext_failure(core, (uint32_t)(pos - core), "invalid object type id") == 0);
  REQUIRE(expect_core_ext_endianness_failure(core, (uint32_t)(pos - core)) == 0);

  return 0;
}

int main(void) {
  REQUIRE(test_local_vs_kernel() == 0);
  REQUIRE(test_core_relo_synthetic_ext() == 0);
  REQUIRE(test_core_relo_malformed_ext() == 0);
  REQUIRE(test_core_relo_kind_diagnostics() == 0);
  REQUIRE(test_ambiguous_kernel_match_fails() == 0);
  return 0;
}
