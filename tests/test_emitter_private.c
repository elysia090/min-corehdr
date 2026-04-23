#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include "min_corehdr/error.h"
#include "min_corehdr/type_set.h"

#ifndef BTF_INFO_ENC
#define BTF_INFO_ENC(kind, kflag, vlen)                                                            \
  (((!!(kflag)) << 31) | (((kind) & 0x1f) << 24) | ((vlen) & 0xffff))
#endif

struct emit_ctx {
  FILE *out;
  const struct btf *btf;
  const struct mch_type_set *required;
  unsigned char *record_state;
  unsigned char *fwd_state;
  unsigned char *typedef_state;
  size_t type_count;
  struct mch_error *err;
};

int emit_decl_ex(struct emit_ctx *ctx, __u32 id, const char *declarator, bool flexible_ok);
int emit_func_decl(struct emit_ctx *ctx, __u32 proto_id, const char *declarator);
int emit_record_body(struct emit_ctx *ctx, const struct btf_type *record);
int emit_inline_record(struct emit_ctx *ctx, const struct btf_type *type, const char *declarator);
int emit_forward_decl(struct emit_ctx *ctx, __u32 id);
int emit_soft_deps(struct emit_ctx *ctx, __u32 id);
int emit_record_definition(struct emit_ctx *ctx, __u32 id);
int emit_hard_deps(struct emit_ctx *ctx, __u32 id);
int emit_enum_definition(struct emit_ctx *ctx, __u32 id);
int emit_typedef_definition(struct emit_ctx *ctx, __u32 id);

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

struct private_fixture {
  struct btf *btf;
  FILE *out;
  struct mch_error err;
  struct mch_type_set required;
  unsigned char *record_state;
  unsigned char *fwd_state;
  unsigned char *typedef_state;
  struct emit_ctx ctx;
};

static int private_fixture_init(struct private_fixture *fixture, struct btf *btf) {
  size_t type_count = btf__type_cnt(btf);

  memset(fixture, 0, sizeof(*fixture));
  mch_error_clear(&fixture->err);
  fixture->btf = btf;
  fixture->out = tmpfile();
  REQUIRE(fixture->out != NULL);
  REQUIRE(mch_type_set_init(&fixture->required, type_count + 16) == 0);
  fixture->record_state = calloc(type_count + 16, sizeof(*fixture->record_state));
  fixture->fwd_state = calloc(type_count + 16, sizeof(*fixture->fwd_state));
  fixture->typedef_state = calloc(type_count + 16, sizeof(*fixture->typedef_state));
  REQUIRE(fixture->record_state != NULL);
  REQUIRE(fixture->fwd_state != NULL);
  REQUIRE(fixture->typedef_state != NULL);
  fixture->ctx = (struct emit_ctx){
      .out = fixture->out,
      .btf = fixture->btf,
      .required = &fixture->required,
      .record_state = fixture->record_state,
      .fwd_state = fixture->fwd_state,
      .typedef_state = fixture->typedef_state,
      .type_count = type_count,
      .err = &fixture->err,
  };
  return 0;
}

static void private_fixture_destroy(struct private_fixture *fixture) {
  free(fixture->typedef_state);
  free(fixture->fwd_state);
  free(fixture->record_state);
  mch_type_set_destroy(&fixture->required);
  if (fixture->out != NULL) {
    fclose(fixture->out);
  }
  btf__free(fixture->btf);
}

static int test_private_invalid_ids(void) {
  struct private_fixture fixture;
  struct btf *btf;
  int int_id;
  __u32 invalid_id;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  REQUIRE(private_fixture_init(&fixture, btf) == 0);
  invalid_id = (__u32)fixture.ctx.type_count + 4;

  REQUIRE(emit_decl_ex(&fixture.ctx, invalid_id, "bad", true) != 0);
  REQUIRE(emit_func_decl(&fixture.ctx, invalid_id, "bad") != 0);
  REQUIRE(emit_forward_decl(&fixture.ctx, invalid_id) != 0);
  REQUIRE(emit_soft_deps(&fixture.ctx, invalid_id) != 0);
  REQUIRE(emit_record_definition(&fixture.ctx, invalid_id) != 0);
  REQUIRE(emit_hard_deps(&fixture.ctx, invalid_id) != 0);
  REQUIRE(emit_enum_definition(&fixture.ctx, invalid_id) != 0);
  REQUIRE(emit_typedef_definition(&fixture.ctx, invalid_id) != 0);
  REQUIRE(strstr(fixture.err.message, "invalid type id") != NULL);

  private_fixture_destroy(&fixture);
  return 0;
}

static int test_private_non_public_decl_paths(void) {
  struct private_fixture fixture;
  struct btf *btf;
  int int_id;
  int proto_id;
  int anonymous_struct_id;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  proto_id = btf__add_func_proto(btf, int_id);
  REQUIRE(proto_id > 0);
  anonymous_struct_id = btf__add_struct(btf, "", 4);
  REQUIRE(anonymous_struct_id > 0);

  REQUIRE(private_fixture_init(&fixture, btf) == 0);

  REQUIRE(emit_forward_decl(&fixture.ctx, (__u32)int_id) == 0);
  REQUIRE(emit_func_decl(&fixture.ctx, (__u32)proto_id, "") == 0);
  REQUIRE(emit_hard_deps(&fixture.ctx, (__u32)proto_id) == 0);
  REQUIRE(emit_record_definition(&fixture.ctx, (__u32)anonymous_struct_id) == 0);

  private_fixture_destroy(&fixture);
  return 0;
}

static int test_private_record_body_failure_paths(void) {
  struct private_fixture fixture;
  struct {
    struct btf_type type;
    struct btf_member member;
  } record;
  struct btf *btf;
  int int_id;
  __u32 invalid_id;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  REQUIRE(private_fixture_init(&fixture, btf) == 0);
  invalid_id = (__u32)fixture.ctx.type_count + 8;

  memset(&record, 0, sizeof(record));
  record.type.info = BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1);
  record.type.size = 4;
  record.member.type = invalid_id;

  REQUIRE(emit_record_body(&fixture.ctx, &record.type) != 0);
  REQUIRE(emit_inline_record(&fixture.ctx, &record.type, "bad") != 0);

  private_fixture_destroy(&fixture);
  return 0;
}

int main(void) {
  REQUIRE(test_private_invalid_ids() == 0);
  REQUIRE(test_private_non_public_decl_paths() == 0);
  REQUIRE(test_private_record_body_failure_paths() == 0);
  return 0;
}
