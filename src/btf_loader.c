#include "min_corehdr/btf_loader.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>
#include <linux/btf.h>

void mch_btf_doc_init(struct mch_btf_doc *doc) {
  doc->btf = NULL;
  doc->ext = NULL;
  doc->path = NULL;
}

void mch_btf_doc_destroy(struct mch_btf_doc *doc) {
  if (doc == NULL) {
    return;
  }
  btf_ext__free(doc->ext);
  btf__free(doc->btf);
  mch_btf_doc_init(doc);
}

int mch_load_base_btf(const char *path, struct mch_btf_doc *doc, struct mch_error *err) {
  struct btf *btf;
  long libbpf_err;

  mch_btf_doc_init(doc);
  btf = btf__parse(path, NULL);
  libbpf_err = libbpf_get_error(btf);
  if (btf == NULL || libbpf_err != 0) {
    int error_code = libbpf_err != 0 ? (int)-libbpf_err : errno;
    mch_error_set(err, "failed to parse base BTF: %s", strerror(error_code));
    mch_error_set_file(err, path);
    mch_error_set_hint(err, "verify that --btf points to a readable BTF file");
    return -1;
  }

  doc->btf = btf;
  doc->path = path;
  return 0;
}

int mch_load_object_btf(const char *path, struct mch_btf_doc *doc, struct mch_error *err) {
  struct btf_ext *ext = NULL;
  struct btf *btf;
  long libbpf_err;

  mch_btf_doc_init(doc);
  btf = btf__parse_elf(path, &ext);
  libbpf_err = libbpf_get_error(btf);
  if (btf == NULL || libbpf_err != 0) {
    int error_code = libbpf_err != 0 ? (int)-libbpf_err : errno;
    btf_ext__free(ext);
    mch_error_set(err, "failed to parse object BTF: %s", strerror(error_code));
    mch_error_set_file(err, path);
    mch_error_set_hint(err, "compile BPF objects with clang -target bpf -g -O2");
    return -1;
  }

  doc->btf = btf;
  doc->ext = ext;
  doc->path = path;
  return 0;
}

const char *mch_btf_kind_name(unsigned int kind) {
  switch (kind) {
  case BTF_KIND_UNKN:
    return "UNKNOWN";
  case BTF_KIND_INT:
    return "INT";
  case BTF_KIND_PTR:
    return "PTR";
  case BTF_KIND_ARRAY:
    return "ARRAY";
  case BTF_KIND_STRUCT:
    return "STRUCT";
  case BTF_KIND_UNION:
    return "UNION";
  case BTF_KIND_ENUM:
    return "ENUM";
  case BTF_KIND_FWD:
    return "FWD";
  case BTF_KIND_TYPEDEF:
    return "TYPEDEF";
  case BTF_KIND_VOLATILE:
    return "VOLATILE";
  case BTF_KIND_CONST:
    return "CONST";
  case BTF_KIND_RESTRICT:
    return "RESTRICT";
  case BTF_KIND_FUNC:
    return "FUNC";
  case BTF_KIND_FUNC_PROTO:
    return "FUNC_PROTO";
  case BTF_KIND_VAR:
    return "VAR";
  case BTF_KIND_DATASEC:
    return "DATASEC";
  case BTF_KIND_FLOAT:
    return "FLOAT";
  case BTF_KIND_DECL_TAG:
    return "DECL_TAG";
  case BTF_KIND_TYPE_TAG:
    return "TYPE_TAG";
  case BTF_KIND_ENUM64:
    return "ENUM64";
  default:
    return "UNKNOWN";
  }
}

const char *mch_btf_type_name(const struct btf *btf, const struct btf_type *type) {
  const char *name;

  if (btf == NULL || type == NULL || type->name_off == 0) {
    return "";
  }

  name = btf__name_by_offset(btf, type->name_off);
  return name == NULL ? "" : name;
}
