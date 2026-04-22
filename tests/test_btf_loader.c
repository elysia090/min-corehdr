#include "min_corehdr/btf_loader.h"
#include "min_corehdr/error.h"

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include <stdio.h>
#include <string.h>

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

static int test_kind_names(void) {
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_UNKN), "UNKNOWN") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_INT), "INT") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_PTR), "PTR") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_ARRAY), "ARRAY") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_STRUCT), "STRUCT") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_UNION), "UNION") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_ENUM), "ENUM") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_FWD), "FWD") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_TYPEDEF), "TYPEDEF") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_VOLATILE), "VOLATILE") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_CONST), "CONST") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_RESTRICT), "RESTRICT") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_FUNC), "FUNC") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_FUNC_PROTO), "FUNC_PROTO") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_VAR), "VAR") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_DATASEC), "DATASEC") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_FLOAT), "FLOAT") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_DECL_TAG), "DECL_TAG") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_TYPE_TAG), "TYPE_TAG") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(BTF_KIND_ENUM64), "ENUM64") == 0);
  REQUIRE(strcmp(mch_btf_kind_name(255), "UNKNOWN") == 0);
  return 0;
}

static int test_type_names(void) {
  struct btf *btf;
  const struct btf_type *type;
  int int_id;
  int anon_id;

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);

  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  type = btf__type_by_id(btf, int_id);
  REQUIRE(strcmp(mch_btf_type_name(btf, type), "int") == 0);
  REQUIRE(strcmp(mch_btf_type_name(NULL, type), "") == 0);
  REQUIRE(strcmp(mch_btf_type_name(btf, NULL), "") == 0);

  anon_id = btf__add_struct(btf, NULL, 0);
  REQUIRE(anon_id > 0);
  type = btf__type_by_id(btf, anon_id);
  REQUIRE(strcmp(mch_btf_type_name(btf, type), "") == 0);

  btf__free(btf);
  return 0;
}

static int test_load_errors(void) {
  struct mch_btf_doc doc;
  struct mch_error err;

  mch_error_clear(&err);
  mch_btf_doc_init(&doc);
  REQUIRE(mch_load_base_btf("/nonexistent/min-corehdr/base.btf", &doc, &err) != 0);
  REQUIRE(err.message[0] != '\0');
  REQUIRE(err.file[0] != '\0');
  REQUIRE(err.hint[0] != '\0');
  mch_btf_doc_destroy(&doc);

  mch_error_clear(&err);
  mch_btf_doc_init(&doc);
  REQUIRE(mch_load_object_btf("/nonexistent/min-corehdr/object.bpf.o", &doc, &err) != 0);
  REQUIRE(err.message[0] != '\0');
  REQUIRE(err.file[0] != '\0');
  REQUIRE(err.hint[0] != '\0');
  mch_btf_doc_destroy(&doc);
  return 0;
}

int main(void) {
  REQUIRE(test_kind_names() == 0);
  REQUIRE(test_type_names() == 0);
  REQUIRE(test_load_errors() == 0);
  return 0;
}
