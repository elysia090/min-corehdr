#include "min_corehdr/emitter.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/btf.h>

#include "min_corehdr/btf_loader.h"

#ifndef BTF_MEMBER_BITFIELD_SIZE
#define BTF_MEMBER_BITFIELD_SIZE(value) ((value) >> 24)
#endif

struct emit_ctx {
  FILE *out;
  const struct btf *btf;
  const struct mch_type_set *required;
  unsigned char *record_state;
  unsigned char *fwd_state;
  size_t type_count;
  struct mch_error *err;
};

static int emit_decl_ex(struct emit_ctx *ctx, __u32 id, const char *declarator, bool flexible_ok);
static int emit_decl(struct emit_ctx *ctx, __u32 id, const char *declarator) {
  return emit_decl_ex(ctx, id, declarator, true);
}

static const struct btf_type *type_by_id(struct emit_ctx *ctx, __u32 id) {
  if (id >= ctx->type_count) {
    mch_error_set(ctx->err, "emitter saw invalid type id %u", id);
    return NULL;
  }
  return btf__type_by_id(ctx->btf, id);
}

static bool is_named_record(const struct btf *btf, const struct btf_type *type) {
  unsigned int kind = btf_kind(type);
  return (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) &&
         mch_btf_type_name(btf, type)[0] != '\0';
}

static int make_declarator(char *buf, size_t size, const char *fmt, const char *value,
                           unsigned int number) {
  int n;
  if (number == 0) {
    n = snprintf(buf, size, fmt, value);
  } else {
    n = snprintf(buf, size, fmt, value, number);
  }
  return n < 0 || (size_t)n >= size ? -1 : 0;
}

static const char *int_type_name(const struct btf_type *type) {
  const __u32 *data = (const __u32 *)(type + 1);
  __u32 info = *data;
  bool is_bool = (BTF_INT_ENCODING(info) & BTF_INT_BOOL) != 0;
  bool is_char = (BTF_INT_ENCODING(info) & BTF_INT_CHAR) != 0;
  bool is_signed = (BTF_INT_ENCODING(info) & BTF_INT_SIGNED) != 0;
  unsigned int bits = BTF_INT_BITS(info);

  if (is_bool) {
    return "_Bool";
  }
  if (is_char && bits == 8) {
    return is_signed ? "signed char" : "unsigned char";
  }

  switch (bits) {
  case 8:
    return is_signed ? "signed char" : "unsigned char";
  case 16:
    return is_signed ? "short" : "unsigned short";
  case 32:
    return is_signed ? "int" : "unsigned int";
  case 64:
    return is_signed ? "long long" : "unsigned long long";
  default:
    return is_signed ? "int" : "unsigned int";
  }
}

static const char *float_type_name(const struct btf_type *type) {
  switch (type->size) {
  case 4:
    return "float";
  case 8:
    return "double";
  case 16:
    return "long double";
  default:
    return "double";
  }
}

static const char *type_qualifier_name(unsigned int kind) {
  switch (kind) {
  case BTF_KIND_CONST:
    return "const";
  case BTF_KIND_VOLATILE:
    return "volatile";
  case BTF_KIND_RESTRICT:
    return "restrict";
  default:
    return NULL;
  }
}

static int append_type_qualifier(char *buf, size_t size, const char *qualifier) {
  size_t len = strlen(buf);
  int n = snprintf(buf + len, size - len, "%s%s", len == 0 ? "" : " ", qualifier);

  return n < 0 || (size_t)n >= size - len ? -1 : 0;
}

static int emit_qualified_decl(struct emit_ctx *ctx, __u32 id, const char *declarator,
                               bool flexible_ok) {
  char qualifiers[64] = "";
  const struct btf_type *type;
  const char *qualifier;
  __u32 current = id;

  for (;;) {
    type = type_by_id(ctx, current);
    if (type == NULL) {
      return -1;
    }

    qualifier = type_qualifier_name(btf_kind(type));
    if (qualifier == NULL) {
      break;
    }
    if (append_type_qualifier(qualifiers, sizeof(qualifiers), qualifier) != 0) {
      mch_error_set(ctx->err, "type qualifier chain is too long");
      return -1;
    }
    current = type->type;
  }

  if (btf_kind(type) == BTF_KIND_PTR) {
    char next[512];
    int n = snprintf(next, sizeof(next), "* %s%s%s", qualifiers, declarator[0] != '\0' ? " " : "",
                     declarator);

    if (n < 0 || (size_t)n >= sizeof(next)) {
      mch_error_set(ctx->err, "type declarator is too long");
      return -1;
    }
    return emit_decl_ex(ctx, type->type, next, flexible_ok);
  }

  fputs(qualifiers, ctx->out);
  fputc(' ', ctx->out);
  return emit_decl_ex(ctx, current, declarator, flexible_ok);
}

static int emit_params(struct emit_ctx *ctx, const struct btf_type *proto) {
  const struct btf_param *params = btf_params(proto);
  __u16 vlen = btf_vlen(proto);

  if (vlen == 0) {
    fputs("void", ctx->out);
    return 0;
  }

  for (__u16 i = 0; i < vlen; i++) {
    char fallback[32];
    const char *name = btf__name_by_offset(ctx->btf, params[i].name_off);

    if (i > 0) {
      fputs(", ", ctx->out);
    }

    if (params[i].type == 0) {
      fputs("void", ctx->out);
      continue;
    }

    if (name == NULL || name[0] == '\0') {
      snprintf(fallback, sizeof(fallback), "arg%u", (unsigned int)i);
      name = fallback;
    }

    if (emit_decl(ctx, params[i].type, name) != 0) {
      return -1;
    }
  }

  return 0;
}

static int emit_func_decl(struct emit_ctx *ctx, __u32 proto_id, const char *declarator) {
  const struct btf_type *proto = type_by_id(ctx, proto_id);

  if (proto == NULL) {
    return -1;
  }

  if (emit_decl(ctx, proto->type, "") != 0) {
    return -1;
  }

  if (declarator[0] == '*') {
    fprintf(ctx->out, " (%s)(", declarator);
  } else if (declarator[0] != '\0') {
    fprintf(ctx->out, " %s(", declarator);
  } else {
    fputs("(", ctx->out);
  }

  if (emit_params(ctx, proto) != 0) {
    return -1;
  }
  fputc(')', ctx->out);
  return 0;
}

static int emit_record_body(struct emit_ctx *ctx, const struct btf_type *record) {
  const struct btf_member *members = btf_members(record);
  __u16 vlen = btf_vlen(record);

  fputs(" {\n", ctx->out);
  for (__u16 i = 0; i < vlen; i++) {
    const char *name = btf__name_by_offset(ctx->btf, members[i].name_off);
    unsigned int bitfield_size =
        btf_kflag(record) ? BTF_MEMBER_BITFIELD_SIZE(members[i].offset) : 0;

    if (name == NULL) {
      name = "";
    }

    fputs("  ", ctx->out);
    if (emit_decl_ex(ctx, members[i].type, name, i + 1 == vlen) != 0) {
      return -1;
    }
    if (bitfield_size != 0) {
      fprintf(ctx->out, " : %u", bitfield_size);
    }
    fputs(";\n", ctx->out);
  }
  fputc('}', ctx->out);
  return 0;
}

static int emit_inline_record(struct emit_ctx *ctx, const struct btf_type *type,
                              const char *declarator) {
  fputs(btf_kind(type) == BTF_KIND_STRUCT ? "struct" : "union", ctx->out);
  if (emit_record_body(ctx, type) != 0) {
    return -1;
  }
  if (declarator[0] != '\0') {
    fprintf(ctx->out, " %s", declarator);
  }
  return 0;
}

static int emit_decl_ex(struct emit_ctx *ctx, __u32 id, const char *declarator, bool flexible_ok) {
  const struct btf_type *type;
  const char *name;
  unsigned int kind;

  if (id == 0) {
    fprintf(ctx->out, "void%s%s", declarator[0] != '\0' ? " " : "", declarator);
    return 0;
  }

  type = type_by_id(ctx, id);
  if (type == NULL) {
    return -1;
  }

  kind = btf_kind(type);
  switch (kind) {
  case BTF_KIND_INT:
    fprintf(ctx->out, "%s%s%s", int_type_name(type), declarator[0] != '\0' ? " " : "", declarator);
    return 0;

  case BTF_KIND_FLOAT:
    fprintf(ctx->out, "%s%s%s", float_type_name(type), declarator[0] != '\0' ? " " : "",
            declarator);
    return 0;

  case BTF_KIND_PTR: {
    char next[512];

    if (make_declarator(next, sizeof(next), "*%s", declarator, 0) != 0) {
      mch_error_set(ctx->err, "type declarator is too long");
      return -1;
    }
    return emit_decl_ex(ctx, type->type, next, flexible_ok);
  }

  case BTF_KIND_ARRAY: {
    const struct btf_array *array = btf_array(type);
    char next[512];
    const char *fmt = declarator[0] == '*' ? "(%s)[%u]" : "%s[%u]";

    if (array->nelems == 0) {
      fmt = flexible_ok ? (declarator[0] == '*' ? "(%s)[]" : "%s[]")
                        : (declarator[0] == '*' ? "(%s)[0]" : "%s[0]");
      if (make_declarator(next, sizeof(next), fmt, declarator, 0) != 0) {
        mch_error_set(ctx->err, "array declarator is too long");
        return -1;
      }
    } else if (make_declarator(next, sizeof(next), fmt, declarator, array->nelems) != 0) {
      mch_error_set(ctx->err, "array declarator is too long");
      return -1;
    }
    return emit_decl_ex(ctx, array->type, next, flexible_ok);
  }

  case BTF_KIND_CONST:
  case BTF_KIND_VOLATILE:
  case BTF_KIND_RESTRICT:
    return emit_qualified_decl(ctx, id, declarator, flexible_ok);
  case BTF_KIND_TYPE_TAG:
  case BTF_KIND_DECL_TAG:
  case BTF_KIND_TYPEDEF:
    return emit_decl_ex(ctx, type->type, declarator, flexible_ok);

  case BTF_KIND_STRUCT:
  case BTF_KIND_UNION:
  case BTF_KIND_FWD:
    name = mch_btf_type_name(ctx->btf, type);
    if (name[0] == '\0' && kind != BTF_KIND_FWD) {
      return emit_inline_record(ctx, type, declarator);
    }
    fprintf(ctx->out, "%s %s%s%s",
            (kind == BTF_KIND_UNION || (kind == BTF_KIND_FWD && btf_kflag(type))) ? "union"
                                                                                  : "struct",
            name, declarator[0] != '\0' ? " " : "", declarator);
    return 0;

  case BTF_KIND_ENUM:
    name = mch_btf_type_name(ctx->btf, type);
    if (name[0] == '\0') {
      fprintf(ctx->out, "int%s%s", declarator[0] != '\0' ? " " : "", declarator);
      return 0;
    }
    fprintf(ctx->out, "enum %s%s%s", name, declarator[0] != '\0' ? " " : "", declarator);
    return 0;

  case BTF_KIND_ENUM64:
    name = mch_btf_type_name(ctx->btf, type);
    if (name[0] == '\0') {
      fprintf(ctx->out, "unsigned long long%s%s", declarator[0] != '\0' ? " " : "", declarator);
      return 0;
    }
    fprintf(ctx->out, "enum %s%s%s", name, declarator[0] != '\0' ? " " : "", declarator);
    return 0;

  case BTF_KIND_FUNC_PROTO:
    return emit_func_decl(ctx, id, declarator);

  default:
    mch_error_set(ctx->err, "unsupported BTF kind in emitter: %s", mch_btf_kind_name(kind));
    return -1;
  }
}

static int emit_hard_deps(struct emit_ctx *ctx, __u32 id);

static int emit_forward_decl(struct emit_ctx *ctx, __u32 id) {
  const struct btf_type *type = type_by_id(ctx, id);
  const char *name;
  unsigned int kind;

  if (type == NULL) {
    return -1;
  }

  kind = btf_kind(type);
  if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION && kind != BTF_KIND_FWD) {
    return 0;
  }

  name = mch_btf_type_name(ctx->btf, type);
  if (name[0] == '\0' || ctx->fwd_state[id] != 0) {
    return 0;
  }

  fprintf(ctx->out, "%s %s;\n",
          (kind == BTF_KIND_UNION || (kind == BTF_KIND_FWD && btf_kflag(type))) ? "union"
                                                                                : "struct",
          name);
  ctx->fwd_state[id] = 1;
  return 0;
}

static int emit_soft_deps(struct emit_ctx *ctx, __u32 id) {
  const struct btf_type *type;
  unsigned int kind;

  if (id == 0) {
    return 0;
  }

  type = type_by_id(ctx, id);
  if (type == NULL) {
    return -1;
  }

  kind = btf_kind(type);
  switch (kind) {
  case BTF_KIND_TYPEDEF:
  case BTF_KIND_VOLATILE:
  case BTF_KIND_CONST:
  case BTF_KIND_RESTRICT:
  case BTF_KIND_TYPE_TAG:
  case BTF_KIND_DECL_TAG:
  case BTF_KIND_PTR:
    return emit_soft_deps(ctx, type->type);

  case BTF_KIND_ARRAY: {
    const struct btf_array *array = btf_array(type);
    return emit_soft_deps(ctx, array->type);
  }

  case BTF_KIND_FUNC_PROTO: {
    const struct btf_param *params = btf_params(type);
    __u16 vlen = btf_vlen(type);

    if (emit_soft_deps(ctx, type->type) != 0) {
      return -1;
    }
    for (__u16 i = 0; i < vlen; i++) {
      if (emit_soft_deps(ctx, params[i].type) != 0) {
        return -1;
      }
    }
    return 0;
  }

  case BTF_KIND_STRUCT:
  case BTF_KIND_UNION:
  case BTF_KIND_FWD:
    return emit_forward_decl(ctx, id);

  default:
    return 0;
  }
}

static int emit_record_definition(struct emit_ctx *ctx, __u32 id) {
  const struct btf_type *type = type_by_id(ctx, id);
  const struct btf_member *members;
  const char *name;
  __u16 vlen;

  if (type == NULL) {
    return -1;
  }
  if (!is_named_record(ctx->btf, type)) {
    return 0;
  }
  if (ctx->record_state[id] == 2) {
    return 0;
  }
  if (ctx->record_state[id] == 1) {
    return 0;
  }

  ctx->record_state[id] = 1;
  members = btf_members(type);
  vlen = btf_vlen(type);
  for (__u16 i = 0; i < vlen; i++) {
    if (emit_hard_deps(ctx, members[i].type) != 0) {
      return -1;
    }
  }

  name = mch_btf_type_name(ctx->btf, type);
  fprintf(ctx->out, "%s %s", btf_kind(type) == BTF_KIND_STRUCT ? "struct" : "union", name);
  if (emit_record_body(ctx, type) != 0) {
    return -1;
  }
  fputs(";\n\n", ctx->out);

  ctx->record_state[id] = 2;
  return 0;
}

static int emit_hard_deps(struct emit_ctx *ctx, __u32 id) {
  const struct btf_type *type = type_by_id(ctx, id);
  unsigned int kind;

  if (type == NULL) {
    return -1;
  }

  kind = btf_kind(type);
  switch (kind) {
  case BTF_KIND_PTR:
  case BTF_KIND_FUNC_PROTO:
    return emit_soft_deps(ctx, id);
  case BTF_KIND_FWD:
    return emit_forward_decl(ctx, id);
  case BTF_KIND_ARRAY: {
    const struct btf_array *array = btf_array(type);
    return emit_hard_deps(ctx, array->type);
  }
  case BTF_KIND_TYPEDEF:
  case BTF_KIND_VOLATILE:
  case BTF_KIND_CONST:
  case BTF_KIND_RESTRICT:
  case BTF_KIND_TYPE_TAG:
  case BTF_KIND_DECL_TAG:
    return emit_hard_deps(ctx, type->type);
  case BTF_KIND_STRUCT:
  case BTF_KIND_UNION: {
    const struct btf_member *members;
    __u16 vlen;

    if (is_named_record(ctx->btf, type)) {
      return emit_record_definition(ctx, id);
    }

    members = btf_members(type);
    vlen = btf_vlen(type);
    for (__u16 i = 0; i < vlen; i++) {
      if (emit_hard_deps(ctx, members[i].type) != 0) {
        return -1;
      }
    }
    return 0;
  }
  default:
    return 0;
  }
}

static int emit_enum_definition(struct emit_ctx *ctx, __u32 id) {
  const struct btf_type *type = type_by_id(ctx, id);
  const char *name;

  if (type == NULL) {
    return -1;
  }

  name = mch_btf_type_name(ctx->btf, type);
  if (name[0] == '\0') {
    return 0;
  }

  fprintf(ctx->out, "enum %s {\n", name);
  if (btf_kind(type) == BTF_KIND_ENUM) {
    const struct btf_enum *values = btf_enum(type);
    __u16 vlen = btf_vlen(type);
    for (__u16 i = 0; i < vlen; i++) {
      const char *value_name = btf__name_by_offset(ctx->btf, values[i].name_off);
      fprintf(ctx->out, "  %s = %d%s\n", value_name == NULL ? "__anonymous" : value_name,
              values[i].val, i + 1 == vlen ? "" : ",");
    }
  } else {
    const struct btf_enum64 *values = btf_enum64(type);
    __u16 vlen = btf_vlen(type);
    for (__u16 i = 0; i < vlen; i++) {
      const char *value_name = btf__name_by_offset(ctx->btf, values[i].name_off);
      unsigned long long value =
          ((unsigned long long)values[i].val_hi32 << 32) | values[i].val_lo32;
      if (btf_kflag(type)) {
        fprintf(ctx->out, "  %s = %lld%s\n", value_name == NULL ? "__anonymous" : value_name,
                (long long)value, i + 1 == vlen ? "" : ",");
      } else {
        fprintf(ctx->out, "  %s = %lluULL%s\n", value_name == NULL ? "__anonymous" : value_name,
                value, i + 1 == vlen ? "" : ",");
      }
    }
  }
  fputs("};\n\n", ctx->out);
  return 0;
}

static int emit_typedef_definition(struct emit_ctx *ctx, __u32 id) {
  const struct btf_type *type = type_by_id(ctx, id);
  const char *name;

  if (type == NULL) {
    return -1;
  }

  name = mch_btf_type_name(ctx->btf, type);
  if (name[0] == '\0') {
    return 0;
  }

  fputs("typedef ", ctx->out);
  if (emit_decl(ctx, type->type, name) != 0) {
    return -1;
  }
  fputs(";\n\n", ctx->out);
  return 0;
}

struct emit_groups {
  __u32 *storage;
  __u32 *fwds;
  __u32 *enums;
  __u32 *records;
  __u32 *typedefs;
  size_t capacity;
  size_t fwd_count;
  size_t enum_count;
  size_t record_count;
  size_t typedef_count;
};

static void emit_groups_destroy(struct emit_groups *groups) { free(groups->storage); }

static int emit_groups_init(struct emit_groups *groups, size_t selected, struct mch_error *err) {
  size_t capacity = selected == 0 ? 1 : selected;
  size_t bytes;

  if (capacity > SIZE_MAX / sizeof(*groups->storage) / 4) {
    mch_error_set(err, "header emission type order is too large");
    return -1;
  }
  bytes = capacity * 4 * sizeof(*groups->storage);
  groups->storage = malloc(bytes);
  if (groups->storage == NULL) {
    mch_error_set(err, "out of memory while preparing header emission order");
    return -1;
  }

  groups->capacity = capacity;
  groups->fwds = groups->storage;
  groups->enums = groups->fwds + capacity;
  groups->records = groups->enums + capacity;
  groups->typedefs = groups->records + capacity;
  groups->fwd_count = 0;
  groups->enum_count = 0;
  groups->record_count = 0;
  groups->typedef_count = 0;
  return 0;
}

static int collect_emit_groups(struct emit_ctx *ctx, struct emit_groups *groups) {
  size_t cursor = 1;
  size_t required_id = 0;

  while (mch_type_set_next(ctx->required, &cursor, &required_id)) {
    __u32 id = (__u32)required_id;
    const struct btf_type *type = type_by_id(ctx, id);
    const char *name;
    unsigned int kind;

    if (type == NULL) {
      return -1;
    }

    kind = btf_kind(type);
    if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION || kind == BTF_KIND_FWD) {
      name = mch_btf_type_name(ctx->btf, type);
      if (name[0] != '\0') {
        groups->fwds[groups->fwd_count++] = id;
      }
    }
    if (kind == BTF_KIND_ENUM || kind == BTF_KIND_ENUM64) {
      groups->enums[groups->enum_count++] = id;
    }
    if (is_named_record(ctx->btf, type)) {
      groups->records[groups->record_count++] = id;
    }
    if (kind == BTF_KIND_TYPEDEF) {
      groups->typedefs[groups->typedef_count++] = id;
    }
  }

  return 0;
}

int mch_emit_header(FILE *out, const struct btf *btf, const struct mch_type_set *required,
                    struct mch_error *err) {
  struct emit_groups groups = {0};
  struct emit_ctx ctx = {
      .out = out,
      .btf = btf,
      .required = required,
      .record_state = NULL,
      .fwd_state = NULL,
      .type_count = btf__type_cnt(btf),
      .err = err,
  };
  int rc = -1;

  ctx.record_state = calloc(ctx.type_count == 0 ? 1 : ctx.type_count, sizeof(*ctx.record_state));
  if (ctx.record_state == NULL) {
    mch_error_set(err, "out of memory while preparing header emission");
    return -1;
  }
  ctx.fwd_state = calloc(ctx.type_count == 0 ? 1 : ctx.type_count, sizeof(*ctx.fwd_state));
  if (ctx.fwd_state == NULL) {
    mch_error_set(err, "out of memory while preparing header forward declarations");
    goto out;
  }
  if (emit_groups_init(&groups, required->selected, err) != 0) {
    goto out;
  }
  if (collect_emit_groups(&ctx, &groups) != 0) {
    goto out;
  }

  fputs("#ifndef MIN_COREHDR_GENERATED_VMLINUX_H\n", out);
  fputs("#define MIN_COREHDR_GENERATED_VMLINUX_H\n\n", out);
  fputs("#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = "
        "record)\n\n",
        out);

  for (size_t i = 0; i < groups.fwd_count; i++) {
    if (emit_forward_decl(&ctx, groups.fwds[i]) != 0) {
      goto out;
    }
  }
  fputc('\n', out);

  for (size_t i = 0; i < groups.enum_count; i++) {
    if (emit_enum_definition(&ctx, groups.enums[i]) != 0) {
      goto out;
    }
  }

  for (size_t i = 0; i < groups.record_count; i++) {
    if (emit_record_definition(&ctx, groups.records[i]) != 0) {
      goto out;
    }
  }

  for (size_t i = 0; i < groups.typedef_count; i++) {
    if (emit_typedef_definition(&ctx, groups.typedefs[i]) != 0) {
      goto out;
    }
  }

  fputs("#pragma clang attribute pop\n\n", out);
  fputs("#endif\n", out);
  rc = ferror(out) ? -1 : 0;

out:
  emit_groups_destroy(&groups);
  free(ctx.fwd_state);
  free(ctx.record_state);
  return rc;
}
