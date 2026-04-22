#include "min_corehdr/seeds.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include "min_corehdr/btf_loader.h"

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

static bool is_seedable_kind(unsigned int kind) {
  return kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION || kind == BTF_KIND_ENUM ||
         kind == BTF_KIND_ENUM64 || kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_FWD;
}

static bool is_chain_kind(unsigned int kind) {
  return kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_VOLATILE || kind == BTF_KIND_CONST ||
         kind == BTF_KIND_RESTRICT || kind == BTF_KIND_TYPE_TAG || kind == BTF_KIND_DECL_TAG;
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
                                       const char *object_path, bool allow_program_local,
                                       unsigned int *base_id, struct mch_error *err) {
  const char *root_name = NULL;
  __u32 id = object_type_id;

  for (unsigned int depth = 0; depth < 32; depth++) {
    const struct btf_type *type;
    const char *name;
    unsigned int kind;
    int match;

    if (id == 0 || id >= btf__type_cnt(object_btf)) {
      mch_error_set(err, "CO-RE relocation references invalid object type id %u", id);
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
      match = mch_btf_index_lookup(base_index, name, kind, base_id);
      if (match < 0) {
        mch_error_set(err, "ambiguous kernel type '%s' (%s)", name, mch_btf_kind_name(kind));
        mch_error_set_file(err, object_path);
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
    mch_error_set_hint(err, "verify that --btf points to the intended target kernel BTF");
    return -1;
  }

  mch_error_set(err, "object BTF type chain is too deep at type id %u", object_type_id);
  mch_error_set_file(err, object_path);
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

    match =
        resolve_object_type_to_base(base_index, object_btf, id, object_path, true, &base_id, err);
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
  const uint8_t *raw;
  const uint8_t *core;
  const uint8_t *pos;
  const uint8_t *end;
  enum btf_endianness expected_endianness;
  __u32 raw_size = 0;
  __u32 rec_size;

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
  if (raw == NULL || raw_size < sizeof(header)) {
    mch_error_set(err, "object .BTF.ext is missing or truncated");
    mch_error_set_file(err, object_path);
    return -1;
  }

  memcpy(&header, raw, sizeof(header));
  if (header.magic != BTF_MAGIC || header.version != BTF_VERSION) {
    mch_error_set(err, "object .BTF.ext has unsupported header");
    mch_error_set_file(err, object_path);
    return -1;
  }
  if (header.hdr_len <
          offsetof(struct mch_btf_ext_header, core_relo_len) + sizeof(header.core_relo_len) ||
      header.hdr_len > raw_size) {
    return 0;
  }
  if (header.hdr_len < sizeof(header) || header.core_relo_len == 0) {
    return 0;
  }
  if (header.core_relo_off > raw_size - header.hdr_len ||
      header.core_relo_len > raw_size - header.hdr_len - header.core_relo_off) {
    mch_error_set(err, "object .BTF.ext CO-RE relocation section is out of bounds");
    mch_error_set_file(err, object_path);
    return -1;
  }

  core = raw + header.hdr_len + header.core_relo_off;
  end = core + header.core_relo_len;
  if ((size_t)(end - core) < sizeof(__u32)) {
    mch_error_set(err, "object .BTF.ext CO-RE relocation section is truncated");
    mch_error_set_file(err, object_path);
    return -1;
  }

  rec_size = read_u32(core);
  if (rec_size < sizeof(struct bpf_core_relo)) {
    mch_error_set(err, "object .BTF.ext CO-RE relocation record size is unsupported");
    mch_error_set_file(err, object_path);
    return -1;
  }

  pos = core + sizeof(__u32);
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
      int match;

      if ((size_t)(end - pos) < rec_size) {
        mch_error_set(err, "object .BTF.ext CO-RE relocation records are truncated");
        mch_error_set_file(err, object_path);
        return -1;
      }

      memcpy(&relo, pos, sizeof(relo));
      pos += rec_size;
      stats->core_relocations++;

      match = resolve_object_type_to_base(base_index, object_btf, relo.type_id, object_path, false,
                                          &base_id, err);
      if (match < 0) {
        char hint[256];
        const char *access = btf__str_by_offset(object_btf, relo.access_str_off);
        if (access == NULL) {
          access = "";
        }
        snprintf(hint, sizeof(hint), "CO-RE relocation kind: %s, access: %s",
                 core_relo_kind_name(relo.kind), access);
        mch_error_set_hint(err, hint);
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
