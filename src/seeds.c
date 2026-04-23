#include "min_corehdr/seeds.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include "min_corehdr/btf_loader.h"

#ifndef BPF_LINE_INFO_LINE_NUM
#define BPF_LINE_INFO_LINE_NUM(line_col) ((line_col) >> 10)
#endif
#ifndef BPF_LINE_INFO_LINE_COL
#define BPF_LINE_INFO_LINE_COL(line_col) ((line_col) & 0x3ff)
#endif

struct mch_btf_ext_header {
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

static bool is_seedable_kind(unsigned int kind) {
  return kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION || kind == BTF_KIND_ENUM ||
         kind == BTF_KIND_ENUM64 || kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_FWD;
}

static bool is_chain_kind(unsigned int kind) {
  return kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_VOLATILE || kind == BTF_KIND_CONST ||
         kind == BTF_KIND_RESTRICT || kind == BTF_KIND_TYPE_TAG;
}

static bool host_is_little_endian(void) {
  const uint16_t value = 1;
  return *(const uint8_t *)&value == 1;
}

static __u32 read_u32(const void *ptr) {
  __u32 value;
  memcpy(&value, ptr, sizeof(value));
  return value;
}

static const char *core_relo_kind_name(enum bpf_core_relo_kind kind);

static void set_resolution_detail(const struct btf *object_btf, __u32 root_type_id,
                                  __u32 query_type_id, const char *query_name,
                                  unsigned int query_kind, const char *reference,
                                  const char *base_result, struct mch_error *err) {
  const struct btf_type *root_type = NULL;
  const char *root_name = "<invalid>";
  const char *query_kind_name;
  const char *query_label =
      query_name != NULL && query_name[0] != '\0' ? query_name : "<anonymous>";

  if (root_type_id < btf__type_cnt(object_btf)) {
    root_type = btf__type_by_id(object_btf, root_type_id);
  }
  if (root_type != NULL) {
    const char *name = mch_btf_type_name(object_btf, root_type);

    root_name = name[0] != '\0' ? name : "<anonymous>";
  }

  query_kind_name = mch_btf_kind_name(query_kind);
  mch_error_set_detail(err, "%s object type: id %u %s '%s'; base BTF query: id %u %s '%s' -> %s",
                       reference, root_type_id,
                       root_type == NULL ? "<invalid>" : mch_btf_kind_name(btf_kind(root_type)),
                       root_name, query_type_id, query_kind_name, query_label, base_result);
}

static int init_ext_info(struct mch_ext_info *info, const uint8_t *raw, __u32 raw_size,
                         __u32 hdr_len, __u32 off, __u32 len, size_t min_rec_size,
                         const char *label, const char *object_path, bool required,
                         struct mch_error *err) {
  const uint8_t *data;
  __u32 rec_size;

  *info = (struct mch_ext_info){0};
  if (len == 0) {
    return 0;
  }
  if (hdr_len > raw_size || off > raw_size - hdr_len || len > raw_size - hdr_len - off) {
    if (required) {
      mch_error_set(err, "object .BTF.ext %s section is out of bounds", label);
      mch_error_set_file(err, object_path);
      return -1;
    }
    return 0;
  }

  data = raw + hdr_len + off;
  if (len < sizeof(__u32)) {
    if (required) {
      mch_error_set(err, "object .BTF.ext %s section is truncated", label);
      mch_error_set_file(err, object_path);
      return -1;
    }
    return 0;
  }

  rec_size = read_u32(data);
  if (rec_size < min_rec_size) {
    if (required) {
      mch_error_set(err, "object .BTF.ext %s record size is unsupported", label);
      mch_error_set_file(err, object_path);
      return -1;
    }
    return 0;
  }

  info->pos = data + sizeof(__u32);
  info->end = data + len;
  info->rec_size = rec_size;
  info->present = true;
  return 0;
}

static const uint8_t *find_ext_info_section(const struct mch_ext_info *info, __u32 sec_name_off,
                                            __u32 *num_info) {
  const uint8_t *pos;

  if (info == NULL || !info->present) {
    return NULL;
  }

  pos = info->pos;
  while (pos < info->end) {
    struct mch_btf_ext_info_sec sec;
    size_t byte_count;

    if ((size_t)(info->end - pos) < sizeof(sec)) {
      return NULL;
    }
    memcpy(&sec, pos, sizeof(sec));
    pos += sizeof(sec);

    if (info->rec_size != 0 && sec.num_info > (size_t)(info->end - pos) / info->rec_size) {
      return NULL;
    }
    byte_count = (size_t)sec.num_info * info->rec_size;
    if (sec.sec_name_off == sec_name_off) {
      *num_info = sec.num_info;
      return pos;
    }
    pos += byte_count;
  }

  return NULL;
}

static bool find_line_location(const struct btf *object_btf, const struct mch_ext_info *line_info,
                               __u32 sec_name_off, __u32 insn_off, const char **file_name,
                               unsigned int *line, unsigned int *column) {
  const uint8_t *records;
  struct bpf_line_info best = {0};
  __u32 num_info = 0;
  bool found = false;

  records = find_ext_info_section(line_info, sec_name_off, &num_info);
  if (records == NULL) {
    return false;
  }

  for (__u32 i = 0; i < num_info; i++) {
    struct bpf_line_info current;

    memcpy(&current, records + (size_t)i * line_info->rec_size, sizeof(current));
    if (current.insn_off > insn_off) {
      continue;
    }
    if (!found || current.insn_off >= best.insn_off) {
      best = current;
      found = true;
    }
  }
  if (!found) {
    return false;
  }

  *file_name = btf__str_by_offset(object_btf, best.file_name_off);
  if (*file_name == NULL || (*file_name)[0] == '\0') {
    return false;
  }
  *line = BPF_LINE_INFO_LINE_NUM(best.line_col);
  *column = BPF_LINE_INFO_LINE_COL(best.line_col);
  return true;
}

static const char *find_function_name(const struct btf *object_btf,
                                      const struct mch_ext_info *func_info, __u32 sec_name_off,
                                      __u32 insn_off) {
  const uint8_t *records;
  struct bpf_func_info best = {0};
  __u32 num_info = 0;
  bool found = false;

  records = find_ext_info_section(func_info, sec_name_off, &num_info);
  if (records == NULL) {
    return NULL;
  }

  for (__u32 i = 0; i < num_info; i++) {
    struct bpf_func_info current;

    memcpy(&current, records + (size_t)i * func_info->rec_size, sizeof(current));
    if (current.insn_off > insn_off) {
      continue;
    }
    if (!found || current.insn_off >= best.insn_off) {
      best = current;
      found = true;
    }
  }
  if (found) {
    const struct btf_type *type = btf__type_by_id(object_btf, best.type_id);

    if (type != NULL && btf_kind(type) == BTF_KIND_FUNC) {
      const char *name = mch_btf_type_name(object_btf, type);
      return name[0] != '\0' ? name : NULL;
    }
  }
  return NULL;
}

static void set_core_relo_context(const struct btf *object_btf,
                                  const struct mch_ext_info *func_info,
                                  const struct mch_ext_info *line_info, __u32 sec_name_off,
                                  const struct bpf_core_relo *relo, size_t relo_index,
                                  __u32 section_relo_index, struct mch_error *err) {
  const char *section = btf__str_by_offset(object_btf, sec_name_off);
  const char *access = btf__str_by_offset(object_btf, relo->access_str_off);
  const char *function;
  const char *file_name = NULL;
  unsigned int line = 0;
  unsigned int column = 0;
  char location[160];

  if (section == NULL || section[0] == '\0') {
    section = "<unknown>";
  }
  if (access == NULL || access[0] == '\0') {
    access = "<none>";
  }

  function = find_function_name(object_btf, func_info, sec_name_off, relo->insn_off);
  if (find_line_location(object_btf, line_info, sec_name_off, relo->insn_off, &file_name, &line,
                         &column)) {
    if (column != 0) {
      snprintf(location, sizeof(location), "%s:%u:%u", file_name, line, column);
    } else {
      snprintf(location, sizeof(location), "%s:%u", file_name, line);
    }
  } else if (function != NULL) {
    snprintf(location, sizeof(location), "function: %s", function);
  } else {
    snprintf(location, sizeof(location), "section: %s", section);
  }

  if (function != NULL && file_name != NULL) {
    mch_error_set_context(err,
                          "%s (function: %s, section: %s, insn: %u, CO-RE %s, access: %s, "
                          "type_id: %u, relo: #%zu, section relo: #%u)",
                          location, function, section, relo->insn_off,
                          core_relo_kind_name(relo->kind), access, relo->type_id, relo_index,
                          section_relo_index + 1);
  } else {
    mch_error_set_context(err,
                          "%s (section: %s, insn: %u, CO-RE %s, access: %s, type_id: %u, "
                          "relo: #%zu, section relo: #%u)",
                          location, section, relo->insn_off, core_relo_kind_name(relo->kind),
                          access, relo->type_id, relo_index, section_relo_index + 1);
  }
  if (err->hint[0] == '\0') {
    mch_error_set_hint(err, "check the CO-RE relocation type id against the object BTF");
  }
}

static const char *core_relo_kind_name(enum bpf_core_relo_kind kind) {
  switch (kind) {
  case BPF_CORE_FIELD_BYTE_OFFSET:
    return "FIELD_BYTE_OFFSET";
  case BPF_CORE_FIELD_BYTE_SIZE:
    return "FIELD_BYTE_SIZE";
  case BPF_CORE_FIELD_EXISTS:
    return "FIELD_EXISTS";
  case BPF_CORE_FIELD_SIGNED:
    return "FIELD_SIGNED";
  case BPF_CORE_FIELD_LSHIFT_U64:
    return "FIELD_LSHIFT_U64";
  case BPF_CORE_FIELD_RSHIFT_U64:
    return "FIELD_RSHIFT_U64";
  case BPF_CORE_TYPE_ID_LOCAL:
    return "TYPE_ID_LOCAL";
  case BPF_CORE_TYPE_ID_TARGET:
    return "TYPE_ID_TARGET";
  case BPF_CORE_TYPE_EXISTS:
    return "TYPE_EXISTS";
  case BPF_CORE_TYPE_SIZE:
    return "TYPE_SIZE";
  case BPF_CORE_ENUMVAL_EXISTS:
    return "ENUMVAL_EXISTS";
  case BPF_CORE_ENUMVAL_VALUE:
    return "ENUMVAL_VALUE";
  case BPF_CORE_TYPE_MATCHES:
    return "TYPE_MATCHES";
  default:
    return "UNKNOWN";
  }
}

static int resolve_object_type_to_base(const struct mch_btf_index *base_index,
                                       const struct btf *object_btf, __u32 object_type_id,
                                       const char *object_path, const char *reference,
                                       bool allow_program_local, unsigned int *base_id,
                                       struct mch_error *err) {
  const char *root_name = NULL;
  const char *query_name = NULL;
  unsigned int query_kind = BTF_KIND_UNKN;
  __u32 query_id = object_type_id;
  __u32 id = object_type_id;

  for (unsigned int depth = 0; depth < 32; depth++) {
    const struct btf_type *type;
    const char *name;
    unsigned int kind;
    int match;

    if (id == 0 || id >= btf__type_cnt(object_btf)) {
      mch_error_set(err, "%s references invalid object type id %u", reference, id);
      mch_error_set_file(err, object_path);
      return -1;
    }

    type = btf__type_by_id(object_btf, id);
    if (type == NULL) {
      mch_error_set(err, "object BTF is missing type id %u", id);
      mch_error_set_file(err, object_path);
      return -1;
    }

    kind = btf_kind(type);
    name = mch_btf_type_name(object_btf, type);
    if (root_name == NULL && name[0] != '\0') {
      root_name = name;
    }

    if (is_seedable_kind(kind) && name[0] != '\0') {
      query_id = id;
      query_name = name;
      query_kind = kind;
      match = mch_btf_index_lookup(base_index, name, kind, base_id);
      if (match < 0) {
        mch_error_set(err, "ambiguous kernel type '%s' (%s)", name, mch_btf_kind_name(kind));
        mch_error_set_file(err, object_path);
        set_resolution_detail(object_btf, object_type_id, query_id, query_name, query_kind,
                              reference, "ambiguous base matches", err);
        mch_error_set_hint(err, "v0.1 requires exactly one same-name, same-kind base BTF match");
        return -1;
      }
      if (match != 0) {
        return match;
      }
    }

    if (is_chain_kind(kind)) {
      id = type->type;
      continue;
    }

    if (allow_program_local) {
      return 0;
    }

    mch_error_set(err, "failed to resolve kernel type '%s'",
                  root_name != NULL ? root_name : "<anonymous>");
    mch_error_set_file(err, object_path);
    if (query_name == NULL) {
      query_id = id;
      query_name = mch_btf_type_name(object_btf, type);
      query_kind = kind;
    }
    set_resolution_detail(object_btf, object_type_id, query_id, query_name, query_kind, reference,
                          "no same-name, same-kind match", err);
    mch_error_set_hint(err, "verify that --btf points to the intended target kernel BTF");
    return -1;
  }

  mch_error_set(err, "object BTF type chain is too deep at type id %u", object_type_id);
  mch_error_set_file(err, object_path);
  set_resolution_detail(object_btf, object_type_id, query_id, query_name, query_kind, reference,
                        "type chain too deep before base lookup", err);
  mch_error_set_hint(err, "check for an unexpected typedef or modifier cycle");
  return -1;
}

void mch_seed_stats_init(struct mch_seed_stats *stats) {
  stats->candidates = 0;
  stats->kernel_types = 0;
  stats->program_local_types = 0;
  stats->core_relocations = 0;
  stats->core_kernel_types = 0;
}

int mch_extract_object_seeds(const struct mch_btf_index *base_index, const struct btf *object_btf,
                             const char *object_path, struct mch_type_set *seeds,
                             struct mch_seed_stats *stats, struct mch_error *err) {
  __u32 type_count = btf__type_cnt(object_btf);

  for (__u32 id = 1; id < type_count; id++) {
    unsigned int base_id = 0;
    const struct btf_type *type;
    unsigned int kind;
    const char *name;
    int match;

    type = btf__type_by_id(object_btf, id);
    if (type == NULL) {
      mch_error_set(err, "object BTF is missing type id %u", id);
      mch_error_set_file(err, object_path);
      return -1;
    }
    kind = btf_kind(type);
    if (!is_seedable_kind(kind)) {
      continue;
    }
    name = mch_btf_type_name(object_btf, type);
    if (name[0] == '\0') {
      continue;
    }

    match = resolve_object_type_to_base(base_index, object_btf, id, object_path, "object BTF seed",
                                        true, &base_id, err);
    if (match < 0) {
      return -1;
    }
    if (match == 0) {
      stats->candidates++;
      stats->program_local_types++;
      continue;
    }

    stats->candidates++;
    if (mch_type_set_add(seeds, base_id)) {
      stats->kernel_types++;
    }
  }

  return 0;
}

int mch_extract_core_relo_seeds(const struct mch_btf_index *base_index,
                                const struct btf *object_btf, const struct btf_ext *object_ext,
                                const char *object_path, struct mch_type_set *seeds,
                                struct mch_seed_stats *stats, struct mch_error *err) {
  struct mch_btf_ext_header header;
  struct mch_ext_info core_info = {0};
  struct mch_ext_info func_info = {0};
  struct mch_ext_info line_info = {0};
  const uint8_t *raw;
  const uint8_t *pos;
  const uint8_t *end;
  enum btf_endianness expected_endianness;
  __u32 raw_size = 0;

  if (object_ext == NULL) {
    return 0;
  }

  expected_endianness = host_is_little_endian() ? BTF_LITTLE_ENDIAN : BTF_BIG_ENDIAN;
  if (btf_ext__endianness(object_ext) != expected_endianness) {
    mch_error_set(err, "object .BTF.ext endianness differs from host endianness");
    mch_error_set_file(err, object_path);
    mch_error_set_hint(err, "v0.1 only parses native-endian .BTF.ext data");
    return -1;
  }

  raw = btf_ext__raw_data(object_ext, &raw_size);
  // LLVM_COV_EXCL_START
  if (raw == NULL || raw_size < sizeof(header)) {
    mch_error_set(err, "object .BTF.ext is missing or truncated");
    mch_error_set_file(err, object_path);
    return -1;
  }
  // LLVM_COV_EXCL_STOP

  memcpy(&header, raw, sizeof(header));
  // LLVM_COV_EXCL_START
  if (header.magic != BTF_MAGIC || header.version != BTF_VERSION) {
    mch_error_set(err, "object .BTF.ext has unsupported header");
    mch_error_set_file(err, object_path);
    return -1;
  }
  // LLVM_COV_EXCL_STOP
  // LLVM_COV_EXCL_START
  if (header.hdr_len <
          offsetof(struct mch_btf_ext_header, core_relo_len) + sizeof(header.core_relo_len) ||
      header.hdr_len > raw_size) {
    return 0;
  }
  // LLVM_COV_EXCL_STOP
  // LLVM_COV_EXCL_START
  if (header.hdr_len < sizeof(header) || header.core_relo_len == 0) {
    return 0;
  }
  // LLVM_COV_EXCL_STOP
  if (init_ext_info(&core_info, raw, raw_size, header.hdr_len, header.core_relo_off,
                    header.core_relo_len, sizeof(struct bpf_core_relo), "CO-RE relocation",
                    object_path, true, err) != 0) {
    return -1;
  }
  (void)init_ext_info(&func_info, raw, raw_size, header.hdr_len, header.func_info_off,
                      header.func_info_len, sizeof(struct bpf_func_info), "function info",
                      object_path, false, err);
  (void)init_ext_info(&line_info, raw, raw_size, header.hdr_len, header.line_info_off,
                      header.line_info_len, sizeof(struct bpf_line_info), "line info", object_path,
                      false, err);

  pos = core_info.pos;
  end = core_info.end;
  while (pos < end) {
    struct mch_btf_ext_info_sec sec;

    if ((size_t)(end - pos) < sizeof(sec)) {
      mch_error_set(err, "object .BTF.ext CO-RE relocation section is truncated");
      mch_error_set_file(err, object_path);
      return -1;
    }

    memcpy(&sec, pos, sizeof(sec));
    pos += sizeof(sec);

    for (__u32 i = 0; i < sec.num_info; i++) {
      struct bpf_core_relo relo;
      unsigned int base_id = 0;
      size_t relo_index = stats->core_relocations + 1;
      int match;

      if ((size_t)(end - pos) < core_info.rec_size) {
        mch_error_set(err, "object .BTF.ext CO-RE relocation records are truncated");
        mch_error_set_file(err, object_path);
        return -1;
      }

      memcpy(&relo, pos, sizeof(relo));
      pos += core_info.rec_size;
      stats->core_relocations++;

      match = resolve_object_type_to_base(base_index, object_btf, relo.type_id, object_path,
                                          "CO-RE relocation", false, &base_id, err);
      if (match < 0) {
        set_core_relo_context(object_btf, &func_info, &line_info, sec.sec_name_off, &relo,
                              relo_index, i, err);
        return -1;
      }
      if (mch_type_set_add(seeds, base_id)) {
        stats->core_kernel_types++;
      }
    }
  }

  if (pos != end) {
    mch_error_set(err, "object .BTF.ext CO-RE relocation section has trailing bytes");
    mch_error_set_file(err, object_path);
    return -1;
  }

  return 0;
}
