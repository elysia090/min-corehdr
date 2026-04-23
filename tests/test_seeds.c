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

static int make_ext(const uint8_t *func, __u32 func_len, const uint8_t *line, __u32 line_len,
                    const uint8_t *core, __u32 core_len, struct btf_ext **out) {
  uint8_t raw[1024];
  struct test_btf_ext_header header = {
      .magic = BTF_MAGIC,
      .version = BTF_VERSION,
      .hdr_len = sizeof(header),
      .func_info_off = 0,
      .func_info_len = func_len,
      .line_info_off = func_len,
      .line_info_len = line_len,
      .core_relo_off = func_len + line_len,
      .core_relo_len = core_len,
  };
  uint8_t *pos = raw + sizeof(header);
  struct btf_ext *ext;

  REQUIRE(sizeof(header) + func_len + line_len + core_len <= sizeof(raw));
  memcpy(raw, &header, sizeof(header));
  if (func_len != 0) {
    memcpy(pos, func, func_len);
    pos += func_len;
  }
  if (line_len != 0) {
    memcpy(pos, line, line_len);
    pos += line_len;
  }
  if (core_len != 0) {
    memcpy(pos, core, core_len);
  }

  ext = btf_ext__new(raw, (uint32_t)(sizeof(header) + func_len + line_len + core_len));
  REQUIRE(libbpf_get_error(ext) == 0);
  *out = ext;
  return 0;
}

static int make_core_ext(const uint8_t *core, __u32 core_len, struct btf_ext **out) {
  return make_ext(NULL, 0, NULL, 0, core, core_len, out);
}

static void write_u32(uint8_t **pos, __u32 value) {
  memcpy(*pos, &value, sizeof(value));
  *pos += sizeof(value);
}

static void write_sec_ex(uint8_t **pos, __u32 sec_name_off, __u32 num_info) {
  struct test_btf_ext_info_sec sec = {.sec_name_off = sec_name_off, .num_info = num_info};

  memcpy(*pos, &sec, sizeof(sec));
  *pos += sizeof(sec);
}

static void write_sec(uint8_t **pos, __u32 num_info) { write_sec_ex(pos, 0, num_info); }

static void write_relo_full(uint8_t **pos, __u32 insn_off, __u32 type_id, __u32 access_str_off,
                            enum bpf_core_relo_kind kind) {
  struct bpf_core_relo relo = {
      .insn_off = insn_off,
      .type_id = type_id,
      .access_str_off = access_str_off,
      .kind = kind,
  };

  memcpy(*pos, &relo, sizeof(relo));
  *pos += sizeof(relo);
}

static void write_relo_ex(uint8_t **pos, __u32 type_id, __u32 access_str_off,
                          enum bpf_core_relo_kind kind) {
  write_relo_full(pos, 0, type_id, access_str_off, kind);
}

static void write_relo(uint8_t **pos, __u32 type_id, enum bpf_core_relo_kind kind) {
  write_relo_ex(pos, type_id, 0, kind);
}

static void write_func_info(uint8_t **pos, __u32 insn_off, __u32 type_id) {
  struct bpf_func_info info = {
      .insn_off = insn_off,
      .type_id = type_id,
  };

  memcpy(*pos, &info, sizeof(info));
  *pos += sizeof(info);
}

static void write_line_info(uint8_t **pos, __u32 insn_off, __u32 file_name_off, __u32 line_off,
                            __u32 line, __u32 column) {
  struct bpf_line_info info = {
      .insn_off = insn_off,
      .file_name_off = file_name_off,
      .line_off = line_off,
      .line_col = (line << 10) | column,
  };

  memcpy(*pos, &info, sizeof(info));
  *pos += sizeof(info);
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
  REQUIRE(strstr(err.detail, "object BTF seed object type:") != NULL);
  REQUIRE(strstr(err.detail, "base BTF query: id ") != NULL);
  REQUIRE(strstr(err.detail, "STRUCT 'dup_type' -> ambiguous base matches") != NULL);

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

static int test_core_relo_source_diagnostics(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t func[sizeof(__u32) + 2 * sizeof(struct test_btf_ext_info_sec) +
               3 * sizeof(struct bpf_func_info)];
  uint8_t line[sizeof(__u32) + 2 * sizeof(struct test_btf_ext_info_sec) +
               3 * sizeof(struct bpf_line_info)];
  uint8_t *core_pos = core;
  uint8_t *func_pos = func;
  uint8_t *line_pos = line;
  int missing_type;
  int int_id;
  int proto_id;
  int func_id;
  int section_off;
  int access_off;
  int file_off;
  int unused_section_off;
  int source_line_off;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);

  int_id = btf__add_int(object, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  proto_id = btf__add_func_proto(object, int_id);
  REQUIRE(proto_id > 0);
  func_id = btf__add_func(object, "handle_exec", BTF_FUNC_GLOBAL, proto_id);
  REQUIRE(func_id > 0);
  missing_type = btf__add_struct(object, "missing_kernel_type", 4);
  REQUIRE(missing_type > 0);

  section_off = btf__add_str(object, "tracepoint/syscalls/sys_enter_execve");
  access_off = btf__add_str(object, "0:1");
  file_off = btf__add_str(object, "exec_audit.bpf.c");
  unused_section_off = btf__add_str(object, "unused");
  source_line_off = btf__add_str(object, "return task->pid;");
  REQUIRE(section_off > 0);
  REQUIRE(access_off > 0);
  REQUIRE(file_off > 0);
  REQUIRE(unused_section_off > 0);
  REQUIRE(source_line_off > 0);

  write_u32(&func_pos, sizeof(struct bpf_func_info));
  write_sec_ex(&func_pos, (__u32)unused_section_off, 1);
  write_func_info(&func_pos, 0, (__u32)func_id);
  write_sec_ex(&func_pos, (__u32)section_off, 2);
  write_func_info(&func_pos, 0, (__u32)func_id);
  write_func_info(&func_pos, 8, (__u32)func_id);

  write_u32(&line_pos, sizeof(struct bpf_line_info));
  write_sec_ex(&line_pos, (__u32)unused_section_off, 1);
  write_line_info(&line_pos, 0, (__u32)file_off, (__u32)source_line_off, 1, 0);
  write_sec_ex(&line_pos, (__u32)section_off, 2);
  write_line_info(&line_pos, 0, (__u32)file_off, (__u32)source_line_off, 41, 0);
  write_line_info(&line_pos, 16, (__u32)file_off, (__u32)source_line_off, 42, 7);

  write_u32(&core_pos, sizeof(struct bpf_core_relo));
  write_sec_ex(&core_pos, (__u32)section_off, 1);
  write_relo_full(&core_pos, 16, (__u32)missing_type, (__u32)access_off,
                  BPF_CORE_FIELD_BYTE_OFFSET);

  REQUIRE(make_ext(func, (uint32_t)(func_pos - func), line, (uint32_t)(line_pos - line), core,
                   (uint32_t)(core_pos - core), &ext) == 0);
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);

  rc = mch_extract_core_relo_seeds(&index, object, ext, "source-diag.bpf.o", &seeds, &stats, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, "missing_kernel_type") != NULL);
  REQUIRE(strstr(err.context, "exec_audit.bpf.c:42:7") != NULL);
  REQUIRE(strstr(err.context, "function: handle_exec") != NULL);
  REQUIRE(strstr(err.context, "tracepoint/syscalls/sys_enter_execve") != NULL);
  REQUIRE(strstr(err.context, "FIELD_BYTE_OFFSET") != NULL);
  REQUIRE(strstr(err.context, "access: 0:1") != NULL);
  REQUIRE(strstr(err.context, "type_id:") != NULL);
  REQUIRE(strstr(err.context, "relo: #1") != NULL);
  REQUIRE(strstr(err.context, "section relo: #1") != NULL);
  REQUIRE(strcmp(err.file, "source-diag.bpf.o") == 0);
  REQUIRE(strstr(err.detail, "CO-RE relocation object type:") != NULL);
  REQUIRE(strstr(err.detail, "id ") != NULL);
  REQUIRE(strstr(err.detail, "STRUCT 'missing_kernel_type'") != NULL);
  REQUIRE(strstr(err.detail, "base BTF query: id ") != NULL);
  REQUIRE(strstr(err.detail, "STRUCT 'missing_kernel_type' -> no same-name, same-kind match") !=
          NULL);

  btf_ext__free(ext);
  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int test_core_relo_function_only_diagnostics(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t func[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_func_info)];
  uint8_t *core_pos = core;
  uint8_t *func_pos = func;
  int missing_type;
  int int_id;
  int proto_id;
  int func_id;
  int section_off;
  int access_off;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);

  int_id = btf__add_int(object, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  proto_id = btf__add_func_proto(object, int_id);
  REQUIRE(proto_id > 0);
  func_id = btf__add_func(object, "function_only", BTF_FUNC_GLOBAL, proto_id);
  REQUIRE(func_id > 0);
  missing_type = btf__add_struct(object, "function_only_missing", 4);
  REQUIRE(missing_type > 0);

  section_off = btf__add_str(object, "kprobe/do_execveat_common");
  access_off = btf__add_str(object, "0:0");
  REQUIRE(section_off > 0);
  REQUIRE(access_off > 0);

  write_u32(&func_pos, sizeof(struct bpf_func_info));
  write_sec_ex(&func_pos, (__u32)section_off, 1);
  write_func_info(&func_pos, 8, (__u32)func_id);

  write_u32(&core_pos, sizeof(struct bpf_core_relo));
  write_sec_ex(&core_pos, (__u32)section_off, 1);
  write_relo_full(&core_pos, 8, (__u32)missing_type, (__u32)access_off, BPF_CORE_TYPE_SIZE);

  REQUIRE(make_ext(func, (uint32_t)(func_pos - func), NULL, 0, core, (uint32_t)(core_pos - core),
                   &ext) == 0);
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);

  rc =
      mch_extract_core_relo_seeds(&index, object, ext, "function-only.bpf.o", &seeds, &stats, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.context, "function: function_only") != NULL);
  REQUIRE(strstr(err.context, "section: kprobe/do_execveat_common") != NULL);
  REQUIRE(strstr(err.context, "TYPE_SIZE") != NULL);

  btf_ext__free(ext);
  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int test_core_relo_line_without_column_diagnostics(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t line[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_line_info)];
  uint8_t *core_pos = core;
  uint8_t *line_pos = line;
  int missing_type;
  int section_off;
  int file_off;
  int source_line_off;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);

  missing_type = btf__add_struct(object, "line_only_missing", 4);
  REQUIRE(missing_type > 0);
  section_off = btf__add_str(object, "xdp");
  file_off = btf__add_str(object, "line_only.bpf.c");
  source_line_off = btf__add_str(object, "return bad->value;");
  REQUIRE(section_off > 0);
  REQUIRE(file_off > 0);
  REQUIRE(source_line_off > 0);

  write_u32(&line_pos, sizeof(struct bpf_line_info));
  write_sec_ex(&line_pos, (__u32)section_off, 1);
  write_line_info(&line_pos, 0, (__u32)file_off, (__u32)source_line_off, 7, 0);

  write_u32(&core_pos, sizeof(struct bpf_core_relo));
  write_sec_ex(&core_pos, (__u32)section_off, 1);
  write_relo_full(&core_pos, 0, (__u32)missing_type, 0, BPF_CORE_TYPE_EXISTS);

  REQUIRE(make_ext(NULL, 0, line, (uint32_t)(line_pos - line), core, (uint32_t)(core_pos - core),
                   &ext) == 0);
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);

  rc = mch_extract_core_relo_seeds(&index, object, ext, "line-only.bpf.o", &seeds, &stats, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.context, "line_only.bpf.c:7 ") != NULL);
  REQUIRE(strstr(err.context, "section: xdp") != NULL);
  REQUIRE(strstr(err.context, "TYPE_EXISTS") != NULL);
  REQUIRE(strstr(err.context, "access: <none>") != NULL);

  btf_ext__free(ext);
  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int test_core_relo_section_fallback_with_late_metadata(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t func[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_func_info)];
  uint8_t line[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_line_info)];
  uint8_t *core_pos = core;
  uint8_t *func_pos = func;
  uint8_t *line_pos = line;
  int missing_type;
  int int_id;
  int proto_id;
  int func_id;
  int section_off;
  int file_off;
  int source_line_off;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);

  int_id = btf__add_int(object, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  proto_id = btf__add_func_proto(object, int_id);
  REQUIRE(proto_id > 0);
  func_id = btf__add_func(object, "too_late", BTF_FUNC_GLOBAL, proto_id);
  REQUIRE(func_id > 0);
  missing_type = btf__add_struct(object, "late_metadata_missing", 4);
  REQUIRE(missing_type > 0);
  section_off = btf__add_str(object, "tracepoint/sched/sched_switch");
  file_off = btf__add_str(object, "late.bpf.c");
  source_line_off = btf__add_str(object, "return task->pid;");
  REQUIRE(section_off > 0);
  REQUIRE(file_off > 0);
  REQUIRE(source_line_off > 0);

  write_u32(&func_pos, sizeof(struct bpf_func_info));
  write_sec_ex(&func_pos, (__u32)section_off, 1);
  write_func_info(&func_pos, 8, (__u32)func_id);

  write_u32(&line_pos, sizeof(struct bpf_line_info));
  write_sec_ex(&line_pos, (__u32)section_off, 1);
  write_line_info(&line_pos, 8, (__u32)file_off, (__u32)source_line_off, 9, 1);

  write_u32(&core_pos, sizeof(struct bpf_core_relo));
  write_sec_ex(&core_pos, (__u32)section_off, 1);
  write_relo_full(&core_pos, 4, (__u32)missing_type, 0, BPF_CORE_FIELD_EXISTS);

  REQUIRE(make_ext(func, (uint32_t)(func_pos - func), line, (uint32_t)(line_pos - line), core,
                   (uint32_t)(core_pos - core), &ext) == 0);
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);

  rc =
      mch_extract_core_relo_seeds(&index, object, ext, "late-metadata.bpf.o", &seeds, &stats, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.context, "section: tracepoint/sched/sched_switch") != NULL);
  REQUIRE(strstr(err.context, "FIELD_EXISTS") != NULL);

  btf_ext__free(ext);
  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int test_core_relo_non_func_metadata_falls_back_to_section(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t func[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_func_info)];
  uint8_t *core_pos = core;
  uint8_t *func_pos = func;
  int missing_type;
  int int_id;
  int section_off;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);

  int_id = btf__add_int(object, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  missing_type = btf__add_struct(object, "non_func_metadata_missing", 4);
  REQUIRE(missing_type > 0);
  section_off = btf__add_str(object, "raw_tracepoint/sys_enter");
  REQUIRE(section_off > 0);

  write_u32(&func_pos, sizeof(struct bpf_func_info));
  write_sec_ex(&func_pos, (__u32)section_off, 1);
  write_func_info(&func_pos, 0, (__u32)int_id);

  write_u32(&core_pos, sizeof(struct bpf_core_relo));
  write_sec_ex(&core_pos, (__u32)section_off, 1);
  write_relo_full(&core_pos, 0, (__u32)missing_type, 0, BPF_CORE_TYPE_SIZE);

  REQUIRE(make_ext(func, (uint32_t)(func_pos - func), NULL, 0, core, (uint32_t)(core_pos - core),
                   &ext) == 0);
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);

  rc = mch_extract_core_relo_seeds(&index, object, ext, "non-func-metadata.bpf.o", &seeds, &stats,
                                   &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.context, "section: raw_tracepoint/sys_enter") != NULL);
  REQUIRE(strstr(err.context, "function:") == NULL);

  btf_ext__free(ext);
  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int test_core_relo_empty_line_file_falls_back_to_function(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t func[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_func_info)];
  uint8_t line[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_line_info)];
  uint8_t *core_pos = core;
  uint8_t *func_pos = func;
  uint8_t *line_pos = line;
  int missing_type;
  int int_id;
  int proto_id;
  int func_id;
  int section_off;
  int source_line_off;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);

  int_id = btf__add_int(object, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  proto_id = btf__add_func_proto(object, int_id);
  REQUIRE(proto_id > 0);
  func_id = btf__add_func(object, "empty_file_name", BTF_FUNC_GLOBAL, proto_id);
  REQUIRE(func_id > 0);
  missing_type = btf__add_struct(object, "empty_file_missing", 4);
  REQUIRE(missing_type > 0);
  section_off = btf__add_str(object, "kprobe/empty_file");
  source_line_off = btf__add_str(object, "return 0;");
  REQUIRE(section_off > 0);
  REQUIRE(source_line_off > 0);

  write_u32(&func_pos, sizeof(struct bpf_func_info));
  write_sec_ex(&func_pos, (__u32)section_off, 1);
  write_func_info(&func_pos, 0, (__u32)func_id);

  write_u32(&line_pos, sizeof(struct bpf_line_info));
  write_sec_ex(&line_pos, (__u32)section_off, 1);
  write_line_info(&line_pos, 0, 0, (__u32)source_line_off, 11, 2);

  write_u32(&core_pos, sizeof(struct bpf_core_relo));
  write_sec_ex(&core_pos, (__u32)section_off, 1);
  write_relo_full(&core_pos, 0, (__u32)missing_type, 0, BPF_CORE_TYPE_SIZE);

  REQUIRE(make_ext(func, (uint32_t)(func_pos - func), line, (uint32_t)(line_pos - line), core,
                   (uint32_t)(core_pos - core), &ext) == 0);
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);

  rc = mch_extract_core_relo_seeds(&index, object, ext, "empty-line-file.bpf.o", &seeds, &stats,
                                   &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.context, "function: empty_file_name") != NULL);
  REQUIRE(strstr(err.context, "empty_file_name, section: kprobe/empty_file") != NULL);

  btf_ext__free(ext);
  mch_type_set_destroy(&seeds);
  mch_btf_index_destroy(&index);
  btf__free(object);
  btf__free(base);
  return 0;
}

static int test_core_relo_invalid_string_offsets_fall_back_to_unknowns(void) {
  struct mch_btf_index index;
  struct mch_error err;
  struct mch_type_set seeds;
  struct mch_seed_stats stats;
  struct btf_ext *ext;
  struct btf *base;
  struct btf *object;
  uint8_t core[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_core_relo)];
  uint8_t line[sizeof(__u32) + sizeof(struct test_btf_ext_info_sec) + sizeof(struct bpf_line_info)];
  uint8_t *core_pos = core;
  uint8_t *line_pos = line;
  int missing_type;
  int source_line_off;
  int rc;

  mch_error_clear(&err);
  mch_btf_index_init_empty(&index);
  mch_seed_stats_init(&stats);

  base = btf__new_empty();
  object = btf__new_empty();
  REQUIRE(libbpf_get_error(base) == 0);
  REQUIRE(libbpf_get_error(object) == 0);

  missing_type = btf__add_struct(object, "invalid_string_missing", 4);
  REQUIRE(missing_type > 0);
  source_line_off = btf__add_str(object, "return 0;");
  REQUIRE(source_line_off > 0);

  write_u32(&line_pos, sizeof(struct bpf_line_info));
  write_sec_ex(&line_pos, 9999, 1);
  write_line_info(&line_pos, 0, 9999, (__u32)source_line_off, 13, 4);

  write_u32(&core_pos, sizeof(struct bpf_core_relo));
  write_sec_ex(&core_pos, 9999, 1);
  write_relo_full(&core_pos, 0, (__u32)missing_type, 9999, BPF_CORE_TYPE_EXISTS);

  REQUIRE(make_ext(NULL, 0, line, (uint32_t)(line_pos - line), core, (uint32_t)(core_pos - core),
                   &ext) == 0);
  REQUIRE(mch_btf_index_init(&index, base, &err) == 0);
  REQUIRE(mch_type_set_init(&seeds, btf__type_cnt(base)) == 0);

  rc = mch_extract_core_relo_seeds(&index, object, ext, "invalid-strings.bpf.o", &seeds, &stats,
                                   &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.context, "section: <unknown>") != NULL);
  REQUIRE(strstr(err.context, "access: <none>") != NULL);
  REQUIRE(strstr(err.context, "TYPE_EXISTS") != NULL);

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
  REQUIRE(test_core_relo_source_diagnostics() == 0);
  REQUIRE(test_core_relo_function_only_diagnostics() == 0);
  REQUIRE(test_core_relo_line_without_column_diagnostics() == 0);
  REQUIRE(test_core_relo_section_fallback_with_late_metadata() == 0);
  REQUIRE(test_core_relo_non_func_metadata_falls_back_to_section() == 0);
  REQUIRE(test_core_relo_empty_line_file_falls_back_to_function() == 0);
  REQUIRE(test_core_relo_invalid_string_offsets_fall_back_to_unknowns() == 0);
  REQUIRE(test_core_relo_malformed_ext() == 0);
  REQUIRE(test_core_relo_kind_diagnostics() == 0);
  REQUIRE(test_ambiguous_kernel_match_fails() == 0);
  return 0;
}
