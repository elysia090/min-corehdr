#include "min_corehdr/closure.h"
#include "min_corehdr/emitter.h"
#include "min_corehdr/error.h"
#include "min_corehdr/type_set.h"

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include <stdint.h>
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

#if defined(__linux__)
void *__real_calloc(size_t nmemb, size_t size);
void *__real_malloc(size_t size);

static long fail_calloc_after = -1;
static long fail_malloc_after = -1;

void *__wrap_calloc(size_t nmemb, size_t size) {
  if (fail_calloc_after == 0) {
    fail_calloc_after = -1;
    return NULL;
  }
  if (fail_calloc_after > 0) {
    fail_calloc_after--;
  }
  return __real_calloc(nmemb, size);
}

void *__wrap_malloc(size_t size) {
  if (fail_malloc_after == 0) {
    fail_malloc_after = -1;
    return NULL;
  }
  if (fail_malloc_after > 0) {
    fail_malloc_after--;
  }
  return __real_malloc(size);
}
#endif

static int emit_to_string_with_options(const struct btf *btf, const struct mch_type_set *required,
                                       const struct mch_emit_options *options, char **result) {
  struct mch_error err;
  FILE *out;
  long size;
  char *buffer;

  mch_error_clear(&err);
  out = tmpfile();
  REQUIRE(out != NULL);
  REQUIRE(mch_emit_header_with_options(out, btf, required, options, &err) == 0);
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

static int emit_to_string(const struct btf *btf, const struct mch_type_set *required,
                          char **result) {
  return emit_to_string_with_options(btf, required, NULL, result);
}

static int test_emitter_output_and_determinism(void) {
  struct mch_type_set required;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct btf *btf;
  char *first = NULL;
  char *second = NULL;
  const char *alias_typedef;
  const char *root_definition;
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
  REQUIRE(strstr(first, "ANON_VALUE = 3") != NULL);
  REQUIRE(strstr(first, "enum wide_color") != NULL);
  REQUIRE(strstr(first, "WIDE_BLUE = 4294967296ULL") != NULL);
  REQUIRE(strstr(first, "enum signed_wide") != NULL);
  REQUIRE(strstr(first, "SIGNED_NEG = -1") != NULL);
  REQUIRE(strstr(first, "struct root") != NULL);
  REQUIRE(strstr(first, "union payload") != NULL);
  REQUIRE(strstr(first, "union future_union;") != NULL);
  REQUIRE(strstr(first, "union future_union future;") != NULL);
  REQUIRE(strstr(first, "typedef struct leaf leaf_alias;") != NULL);
  REQUIRE(strstr(first, "leaf_alias alias;") != NULL);
  REQUIRE(strstr(first, "struct leaf alias;") == NULL);
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
  alias_typedef = strstr(first, "typedef struct leaf leaf_alias;");
  root_definition = strstr(first, "struct root {");
  REQUIRE(alias_typedef != NULL);
  REQUIRE(root_definition != NULL);
  REQUIRE(alias_typedef < root_definition);

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

static int test_typedef_function_pointer_forward_decl(void) {
  struct mch_type_set required;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct btf *btf;
  char *header = NULL;
  const char *forward;
  const char *typedef_decl;
  int int_id;
  int file_id;
  int file_ptr_id;
  int proto_id;
  int proto_ptr_id;
  int typedef_id;

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  file_id = btf__add_struct(btf, "file", 4);
  REQUIRE(file_id > 0);
  REQUIRE(btf__add_field(btf, "fd", int_id, 0, 0) == 0);
  file_ptr_id = btf__add_ptr(btf, file_id);
  REQUIRE(file_ptr_id > 0);
  proto_id = btf__add_func_proto(btf, int_id);
  REQUIRE(proto_id > 0);
  REQUIRE(btf__add_func_param(btf, "file", file_ptr_id) == 0);
  proto_ptr_id = btf__add_ptr(btf, proto_id);
  REQUIRE(proto_ptr_id > 0);
  typedef_id = btf__add_typedef(btf, "file_handler_t", proto_ptr_id);
  REQUIRE(typedef_id > 0);

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)typedef_id));
  REQUIRE(mch_compute_dependency_closure(btf, &required, &stats, &err) == 0);
  REQUIRE(emit_to_string(btf, &required, &header) == 0);

  forward = strstr(header, "struct file;");
  typedef_decl = strstr(header, "typedef int (*file_handler_t)(struct file *file);");
  REQUIRE(forward != NULL);
  REQUIRE(typedef_decl != NULL);
  REQUIRE(forward < typedef_decl);
  REQUIRE(strstr(header, "struct file {") == NULL);

  free(header);
  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_emitter_prunes_selected_record_members(void) {
  struct mch_type_set required;
  struct mch_requirements requirements;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct mch_closure_options closure_options = {0};
  struct mch_emit_options emit_options = {0};
  struct btf *btf;
  char *header = NULL;
  int int_id;
  int root_id;

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);
  memset(&requirements, 0, sizeof(requirements));

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  root_id = btf__add_struct(btf, "task_struct", 8);
  REQUIRE(root_id > 0);
  REQUIRE(btf__add_field(btf, "pid", int_id, 0, 0) == 0);
  REQUIRE(btf__add_field(btf, "unused", int_id, 32, 0) == 0);

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_requirements_init(&requirements, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_requirements_add_record_member(btf, &requirements, (size_t)root_id, 0, &err) == 0);
  closure_options.requirements = &requirements;
  emit_options.requirements = &requirements;
  REQUIRE(mch_type_set_add(&required, (size_t)root_id));
  REQUIRE(mch_compute_dependency_closure_with_options(btf, &required, &stats, &closure_options,
                                                      &err) == 0);
  REQUIRE(emit_to_string_with_options(btf, &required, &emit_options, &header) == 0);

  REQUIRE(strstr(header, "struct task_struct {") != NULL);
  REQUIRE(strstr(header, "int pid;") != NULL);
  REQUIRE(strstr(header, "unused") == NULL);

  free(header);
  mch_requirements_destroy(&requirements);
  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int test_edge_declarators_and_recursive_records(void) {
  struct mch_type_set required;
  struct mch_closure_stats stats;
  struct mch_error err;
  struct btf *btf;
  char *header = NULL;
  int int_id;
  int signed8_id;
  int small_float_id;
  int const_int_id;
  int const_array_id;
  int const_const_array_id;
  int zero_array_id;
  int zero_array_ptr_id;
  int fixed_array_id;
  int fixed_array_ptr_id;
  int anon_enum64_id;
  int fwd_struct_id;
  int node_id;
  int root_id;

  mch_error_clear(&err);
  mch_closure_stats_init(&stats);

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);

  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  signed8_id = btf__add_int(btf, "signed8", 1, BTF_INT_SIGNED);
  REQUIRE(signed8_id > 0);
  small_float_id = btf__add_float(btf, "small_float", 2);
  REQUIRE(small_float_id > 0);
  const_int_id = btf__add_const(btf, int_id);
  REQUIRE(const_int_id > 0);
  const_array_id = btf__add_array(btf, const_int_id, int_id, 0);
  REQUIRE(const_array_id > 0);
  const_const_array_id = btf__add_const(btf, const_array_id);
  REQUIRE(const_const_array_id > 0);
  zero_array_id = btf__add_array(btf, int_id, int_id, 0);
  REQUIRE(zero_array_id > 0);
  zero_array_ptr_id = btf__add_ptr(btf, zero_array_id);
  REQUIRE(zero_array_ptr_id > 0);
  fixed_array_id = btf__add_array(btf, int_id, int_id, 3);
  REQUIRE(fixed_array_id > 0);
  fixed_array_ptr_id = btf__add_ptr(btf, fixed_array_id);
  REQUIRE(fixed_array_ptr_id > 0);
  anon_enum64_id = btf__add_enum64(btf, "", 8, false);
  REQUIRE(anon_enum64_id > 0);
  REQUIRE(btf__add_enum64_value(btf, "ANON64", 9) == 0);
  fwd_struct_id = btf__add_fwd(btf, "future_struct", BTF_FWD_STRUCT);
  REQUIRE(fwd_struct_id > 0);

  node_id = btf__add_struct(btf, "node", 4);
  REQUIRE(node_id > 0);
  REQUIRE(btf__add_field(btf, "self", node_id, 0, 0) == 0);

  root_id = btf__add_struct(btf, "edge_root", 96);
  REQUIRE(root_id > 0);
  REQUIRE(btf__add_field(btf, "tiny", signed8_id, 0, 0) == 0);
  REQUIRE(btf__add_field(btf, "small", small_float_id, 32, 0) == 0);
  REQUIRE(btf__add_field(btf, "name", const_const_array_id, 48, 0) == 0);
  REQUIRE(btf__add_field(btf, "array_ref", fixed_array_ptr_id, 64, 0) == 0);
  REQUIRE(btf__add_field(btf, "flex_ptr", zero_array_ptr_id, 128, 0) == 0);
  REQUIRE(btf__add_field(btf, "flex", zero_array_id, 192, 0) == 0);
  REQUIRE(btf__add_field(btf, "future", fwd_struct_id, 192, 0) == 0);
  REQUIRE(btf__add_field(btf, "anonymous_wide", anon_enum64_id, 256, 0) == 0);
  REQUIRE(btf__add_field(btf, "cycle", node_id, 320, 0) == 0);
  REQUIRE(btf__add_field(btf, "tail", zero_array_id, 352, 0) == 0);

  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)root_id));
  REQUIRE(mch_compute_dependency_closure(btf, &required, &stats, &err) == 0);
  REQUIRE(emit_to_string(btf, &required, &header) == 0);

  REQUIRE(strstr(header, "signed char tiny;") != NULL);
  REQUIRE(strstr(header, "double small;") != NULL);
  REQUIRE(strstr(header, "const int name[0];") != NULL);
  REQUIRE(strstr(header, "const const") == NULL);
  REQUIRE(strstr(header, "int (*array_ref)[3];") != NULL);
  REQUIRE(strstr(header, "int (*flex_ptr)[0];") != NULL);
  REQUIRE(strstr(header, "int flex[0];") != NULL);
  REQUIRE(strstr(header, "int tail[0];") != NULL);
  REQUIRE(strstr(header, "struct future_struct;") != NULL);
  REQUIRE(strstr(header, "struct future_struct future;") != NULL);
  REQUIRE(strstr(header, "ANON64 = 9ULL") != NULL);
  REQUIRE(strstr(header, "unsigned long long anonymous_wide;") != NULL);
  REQUIRE(strstr(header, "struct node {") != NULL);
  REQUIRE(strstr(header, "struct node self;") != NULL);

  free(header);
  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}

static int expect_emit_typedef_failure(struct btf *btf, int typedef_id, const char *message_part) {
  struct mch_type_set required;
  struct mch_error err;
  FILE *out;
  int rc;

  mch_error_clear(&err);
  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)typedef_id));
  out = tmpfile();
  REQUIRE(out != NULL);

  rc = mch_emit_header(out, btf, &required, &err);
  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, message_part) != NULL);

  REQUIRE(fclose(out) == 0);
  mch_type_set_destroy(&required);
  return 0;
}

static int test_declarator_limit_failures(void) {
  struct btf *btf;
  int int_id;
  int current_id;
  int typedef_id;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  current_id = int_id;
  for (size_t i = 0; i < 600; i++) {
    current_id = btf__add_ptr(btf, current_id);
    REQUIRE(current_id > 0);
  }
  typedef_id = btf__add_typedef(btf, "too_many_ptrs_t", current_id);
  REQUIRE(typedef_id > 0);
  REQUIRE(expect_emit_typedef_failure(btf, typedef_id, "type declarator is too long") == 0);
  btf__free(btf);

  return 0;
}

#if defined(__linux__)
static int call_emit_with_failures(const struct btf *btf, const struct mch_type_set *required,
                                   long calloc_after, long malloc_after, const char *message_part) {
  struct mch_error err;
  FILE *out;
  int rc;

  mch_error_clear(&err);
  out = tmpfile();
  REQUIRE(out != NULL);

  fail_calloc_after = calloc_after;
  fail_malloc_after = malloc_after;
  rc = mch_emit_header(out, btf, required, &err);
  fail_calloc_after = -1;
  fail_malloc_after = -1;

  REQUIRE(rc != 0);
  REQUIRE(strstr(err.message, message_part) != NULL);
  REQUIRE(fclose(out) == 0);
  return 0;
}

static int test_emitter_allocation_failures(void) {
  struct mch_type_set required;
  struct mch_type_set oversized = {0};
  struct btf *btf;
  int int_id;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  REQUIRE(mch_type_set_init(&required, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_type_set_add(&required, (size_t)int_id));

  REQUIRE(call_emit_with_failures(btf, &required, 0, -1,
                                  "out of memory while preparing header emission") == 0);
  REQUIRE(call_emit_with_failures(btf, &required, 1, -1,
                                  "out of memory while preparing header forward declarations") ==
          0);
  REQUIRE(call_emit_with_failures(btf, &required, 2, -1,
                                  "out of memory while preparing header typedef declarations") ==
          0);
  REQUIRE(call_emit_with_failures(btf, &required, -1, 0,
                                  "out of memory while preparing header emission order") == 0);

  oversized.selected = SIZE_MAX / sizeof(__u32);
  REQUIRE(call_emit_with_failures(btf, &oversized, -1, -1,
                                  "header emission type order is too large") == 0);

  mch_type_set_destroy(&required);
  btf__free(btf);
  return 0;
}
#endif

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
  REQUIRE(test_typedef_function_pointer_forward_decl() == 0);
  REQUIRE(test_emitter_prunes_selected_record_members() == 0);
  REQUIRE(test_edge_declarators_and_recursive_records() == 0);
  REQUIRE(test_declarator_limit_failures() == 0);
#if defined(__linux__)
  REQUIRE(test_emitter_allocation_failures() == 0);
#endif
  REQUIRE(test_invalid_required_id_fails() == 0);
  REQUIRE(test_unsupported_typedef_target_fails() == 0);
  return 0;
}
