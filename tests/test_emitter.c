#include "min_corehdr/closure.h"
#include "min_corehdr/emitter.h"
#include "min_corehdr/error.h"
#include "min_corehdr/type_set.h"

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

static int emit_to_string(const struct btf *btf, const struct mch_type_set *required,
                          char **result) {
  struct mch_error err;
  FILE *out;
  long size;
  char *buffer;

  mch_error_clear(&err);
  out = tmpfile();
  REQUIRE(out != NULL);
  REQUIRE(mch_emit_header(out, btf, required, &err) == 0);
  REQUIRE(fflush(out) == 0);
  REQUIRE(fseek(out, 0, SEEK_END) == 0);
  size = ftell(out);
  REQUIRE(size >= 0);
  REQUIRE(fseek(out, 0, SEEK_SET) == 0);

  buffer = malloc((size_t)size + 1);
  REQUIRE(buffer != NULL);
  REQUIRE(fread(buffer, 1, (size_t)size, out) == (size_t)size);
  buffer[size] = '\0';
  REQUIRE(fclose(out) == 0);

  *result = buffer;
  return 0;
}

static int test_emitter_output_and_determinism(void) {
  struct mch_type_set required;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct btf *btf;
  char *first = NULL;
  char *second = NULL;
  int int_id;
  int bool_id;
  int char_id;
  int uchar_id;
  int ushort_id;
  int float_id;
  int double_id;
  int long_double_id;
  int enum_id;
  int enum64_id;
  int signed_enum64_id;
  int anon_enum_id;
  int leaf_id;
  int union_id;
  int alias_id;
  int const_id;
  int volatile_id;
  int type_tag_id;
  int int_ptr_id;
  int const_ptr_id;
  int volatile_ptr_id;
  int restrict_id;
  int decl_tag_id;
  int proto_id;
  int callback_typedef_id;
  int void_param_proto_id;
  int void_param_typedef_id;
  int array_id;
  int fwd_union_id;
  int file_id;
  int file_ptr_id;
  int file_param_proto_id;
  int file_callback_ptr_id;
  int root_id;

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);

  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  bool_id = btf__add_int(btf, "_Bool", 1, BTF_INT_BOOL);
  REQUIRE(bool_id > 0);
  char_id = btf__add_int(btf, "char", 1, BTF_INT_CHAR | BTF_INT_SIGNED);
  REQUIRE(char_id > 0);
  uchar_id = btf__add_int(btf, "unsigned char", 1, BTF_INT_CHAR);
  REQUIRE(uchar_id > 0);
  ushort_id = btf__add_int(btf, "unsigned short", 2, 0);
  REQUIRE(ushort_id > 0);
  float_id = btf__add_float(btf, "float", 4);
  REQUIRE(float_id > 0);
  double_id = btf__add_float(btf, "double", 8);
  REQUIRE(double_id > 0);
  long_double_id = btf__add_float(btf, "long double", 16);
  REQUIRE(long_double_id > 0);
  enum_id = btf__add_enum(btf, "color", 4);
  REQUIRE(enum_id > 0);
  REQUIRE(btf__add_enum_value(btf, "COLOR_RED", 1) == 0);
  REQUIRE(btf__add_enum_value(btf, "COLOR_GREEN", 7) == 0);
  enum64_id = btf__add_enum64(btf, "wide_color", 8, false);
  REQUIRE(enum64_id > 0);
  REQUIRE(btf__add_enum64_value(btf, "WIDE_BLUE", 0x100000000ULL) == 0);
  signed_enum64_id = btf__add_enum64(btf, "signed_wide", 8, true);
  REQUIRE(signed_enum64_id > 0);
  REQUIRE(btf__add_enum64_value(btf, "SIGNED_NEG", (__u64)-1) == 0);
  anon_enum_id = btf__add_enum(btf, "", 4);
  REQUIRE(anon_enum_id > 0);
  REQUIRE(btf__add_enum_value(btf, "ANON_VALUE", 3) == 0);

  leaf_id = btf__add_struct(btf, "leaf", 4);
  REQUIRE(leaf_id > 0);
  REQUIRE(btf__add_field(btf, "value", int_id, 0, 0) == 0);

  union_id = btf__add_union(btf, "payload", 4);
  REQUIRE(union_id > 0);
  REQUIRE(btf__add_field(btf, "raw", int_id, 0, 0) == 0);

  alias_id = btf__add_typedef(btf, "leaf_alias", leaf_id);
  REQUIRE(alias_id > 0);
  const_id = btf__add_const(btf, int_id);
  REQUIRE(const_id > 0);
  volatile_id = btf__add_volatile(btf, int_id);
  REQUIRE(volatile_id > 0);
  type_tag_id = btf__add_type_tag(btf, "tagged", int_id);
  REQUIRE(type_tag_id > 0);
  int_ptr_id = btf__add_ptr(btf, int_id);
  REQUIRE(int_ptr_id > 0);
  const_ptr_id = btf__add_const(btf, int_ptr_id);
  REQUIRE(const_ptr_id > 0);
  volatile_ptr_id = btf__add_volatile(btf, int_ptr_id);
  REQUIRE(volatile_ptr_id > 0);
  restrict_id = btf__add_restrict(btf, int_ptr_id);
  REQUIRE(restrict_id > 0);
  decl_tag_id = btf__add_decl_tag(btf, "declared", int_id, -1);
  REQUIRE(decl_tag_id > 0);
  proto_id = btf__add_func_proto(btf, int_id);
  REQUIRE(proto_id > 0);
  callback_typedef_id = btf__add_typedef(btf, "callback_t", proto_id);
  REQUIRE(callback_typedef_id > 0);
  void_param_proto_id = btf__add_func_proto(btf, int_id);
  REQUIRE(void_param_proto_id > 0);
  REQUIRE(btf__add_func_param(btf, "unused", 0) == 0);
  void_param_typedef_id = btf__add_typedef(btf, "void_param_t", void_param_proto_id);
  REQUIRE(void_param_typedef_id > 0);
  array_id = btf__add_array(btf, int_id, int_id, 2);
  REQUIRE(array_id > 0);
  fwd_union_id = btf__add_fwd(btf, "future_union", BTF_FWD_UNION);
  REQUIRE(fwd_union_id > 0);
  file_id = btf__add_struct(btf, "file", 4);
  REQUIRE(file_id > 0);
  REQUIRE(btf__add_field(btf, "fd", int_id, 0, 0) == 0);
  file_ptr_id = btf__add_ptr(btf, file_id);
  REQUIRE(file_ptr_id > 0);
  file_param_proto_id = btf__add_func_proto(btf, int_id);
  REQUIRE(file_param_proto_id > 0);
  REQUIRE(btf__add_func_param(btf, "file", file_ptr_id) == 0);
  file_callback_ptr_id = btf__add_ptr(btf, file_param_proto_id);
  REQUIRE(file_callback_ptr_id > 0);

  root_id = btf__add_struct(btf, "root", 160);
  REQUIRE(root_id > 0);
  REQUIRE(btf__add_field(btf, "leaf", leaf_id, 0, 0) == 0);
  REQUIRE(btf__add_field(btf, "payload", union_id, 32, 0) == 0);
  REQUIRE(btf__add_field(btf, "shade", enum_id, 64, 0) == 0);
  REQUIRE(btf__add_field(btf, "alias", alias_id, 96, 0) == 0);
  REQUIRE(btf__add_field(btf, "values", array_id, 128, 0) == 0);
  REQUIRE(btf__add_field(btf, "truthy", bool_id, 192, 0) == 0);
  REQUIRE(btf__add_field(btf, "letter", char_id, 200, 0) == 0);
  REQUIRE(btf__add_field(btf, "ratio", float_id, 224, 0) == 0);
  REQUIRE(btf__add_field(btf, "precise", double_id, 256, 0) == 0);
  REQUIRE(btf__add_field(btf, "wide", enum64_id, 320, 0) == 0);
  REQUIRE(btf__add_field(btf, "constant", const_id, 384, 0) == 0);
  REQUIRE(btf__add_field(btf, "changing", volatile_id, 416, 0) == 0);
  REQUIRE(btf__add_field(btf, "tagged", type_tag_id, 448, 0) == 0);
  REQUIRE(btf__add_field(btf, "unsigned_letter", uchar_id, 480, 0) == 0);
  REQUIRE(btf__add_field(btf, "shorty", ushort_id, 488, 0) == 0);
  REQUIRE(btf__add_field(btf, "extended", long_double_id, 528, 0) == 0);
  REQUIRE(btf__add_field(btf, "signed_wide", signed_enum64_id, 656, 0) == 0);
  REQUIRE(btf__add_field(btf, "anonymous_color", anon_enum_id, 720, 0) == 0);
  REQUIRE(btf__add_field(btf, "constant_ptr", const_ptr_id, 752, 0) == 0);
  REQUIRE(btf__add_field(btf, "volatile_ptr", volatile_ptr_id, 816, 0) == 0);
  REQUIRE(btf__add_field(btf, "restricted", restrict_id, 880, 0) == 0);
  REQUIRE(btf__add_field(btf, "declared", decl_tag_id, 944, 0) == 0);
  REQUIRE(btf__add_field(btf, "future", fwd_union_id, 976, 0) == 0);
  REQUIRE(btf__add_field(btf, "open", file_callback_ptr_id, 1024, 0) == 0);

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)root_id));
  REQUIRE(mch_type_set_add(&required, (size_t)callback_typedef_id));
  REQUIRE(mch_type_set_add(&required, (size_t)void_param_typedef_id));
  REQUIRE(mch_compute_dependency_closure(btf, &required, &stats, &err) == 0);

  REQUIRE(emit_to_string(btf, &required, &first) == 0);
  REQUIRE(emit_to_string(btf, &required, &second) == 0);
  REQUIRE(strcmp(first, second) == 0);
  REQUIRE(strstr(first, "#ifndef MIN_COREHDR_GENERATED_VMLINUX_H") != NULL);
  REQUIRE(strstr(first, "preserve_access_index") != NULL);
  REQUIRE(strstr(first, "enum color") != NULL);
  REQUIRE(strstr(first, "COLOR_GREEN = 7") != NULL);
  REQUIRE(strstr(first, "enum wide_color") != NULL);
  REQUIRE(strstr(first, "WIDE_BLUE = 4294967296ULL") != NULL);
  REQUIRE(strstr(first, "enum signed_wide") != NULL);
  REQUIRE(strstr(first, "SIGNED_NEG = -1") != NULL);
  REQUIRE(strstr(first, "struct root") != NULL);
  REQUIRE(strstr(first, "union payload") != NULL);
  REQUIRE(strstr(first, "union future_union;") != NULL);
  REQUIRE(strstr(first, "union future_union future;") != NULL);
  REQUIRE(strstr(first, "typedef struct leaf leaf_alias;") != NULL);
  REQUIRE(strstr(first, "int values[2];") != NULL);
  REQUIRE(strstr(first, "_Bool truthy;") != NULL);
  REQUIRE(strstr(first, "signed char letter;") != NULL);
  REQUIRE(strstr(first, "unsigned char unsigned_letter;") != NULL);
  REQUIRE(strstr(first, "unsigned short shorty;") != NULL);
  REQUIRE(strstr(first, "float ratio;") != NULL);
  REQUIRE(strstr(first, "double precise;") != NULL);
  REQUIRE(strstr(first, "long double extended;") != NULL);
  REQUIRE(strstr(first, "int anonymous_color;") != NULL);
  REQUIRE(strstr(first, "const int constant;") != NULL);
  REQUIRE(strstr(first, "volatile int changing;") != NULL);
  REQUIRE(strstr(first, "int * const constant_ptr;") != NULL);
  REQUIRE(strstr(first, "int * volatile volatile_ptr;") != NULL);
  REQUIRE(strstr(first, "int * restrict restricted;") != NULL);
  REQUIRE(strstr(first, "int declared;") != NULL);
  REQUIRE(strstr(first, "struct file;") != NULL);
  REQUIRE(strstr(first, "struct file {") == NULL);
  REQUIRE(strstr(first, "int (*open)(struct file *file);") != NULL);
  REQUIRE(strstr(first, "typedef int callback_t(void);") != NULL);
  REQUIRE(strstr(first, "typedef int void_param_t(void);") != NULL);

  free(second);
  free(first);
  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_empty_required_output(void) {
  struct mch_type_set required;
  struct btf *btf;
  char *header = NULL;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(emit_to_string(btf, &required, &header) == 0);
  REQUIRE(strstr(header, "#endif") != NULL);

  free(header);
  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_invalid_required_id_fails(void) {
  struct mch_type_set required;
  struct mch_error err;
  struct btf *btf;
  FILE *out;
  size_t invalid_id;
  int rc;

  mch_error_clear(&err);
  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  invalid_id = (size_t)btf__type_cnt(btf) + 1;
  REQUIRE(mch_type_set_init(&required, invalid_id + 1) == 0);
  REQUIRE(mch_type_set_add(&required, invalid_id));
  out = tmpfile();
  REQUIRE(out != NULL);

  rc = mch_emit_header(out, btf, &required, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, "invalid type id") != NULL);

  REQUIRE(fclose(out) == 0);
  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_unsupported_typedef_target_fails(void) {
  struct mch_type_set required;
  struct mch_error err;
  struct btf *btf;
  FILE *out;
  int int_id;
  int var_id;
  int typedef_id;
  int rc;

  mch_error_clear(&err);
  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  var_id = btf__add_var(btf, "bad_global", BTF_VAR_GLOBAL_ALLOCATED, int_id);
  REQUIRE(var_id > 0);
  typedef_id = btf__add_typedef(btf, "bad_alias", var_id);
  REQUIRE(typedef_id > 0);
  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)typedef_id));
  out = tmpfile();
  REQUIRE(out != NULL);

  rc = mch_emit_header(out, btf, &required, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, "unsupported BTF kind") != NULL);

  REQUIRE(fclose(out) == 0);
  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

int main(void) {
  REQUIRE(test_emitter_output_and_determinism() == 0);
  REQUIRE(test_empty_required_output() == 0);
  REQUIRE(test_invalid_required_id_fails() == 0);
  REQUIRE(test_unsupported_typedef_target_fails() == 0);
  return 0;
}
