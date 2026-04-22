#ifndef MIN_COREHDR_BTF_LOADER_H
#define MIN_COREHDR_BTF_LOADER_H

#include <bpf/btf.h>

#include "min_corehdr/error.h"

struct mch_btf_doc {
  struct btf *btf;
  struct btf_ext *ext;
  const char *path;
};

void mch_btf_doc_init(struct mch_btf_doc *doc);
void mch_btf_doc_destroy(struct mch_btf_doc *doc);
int mch_load_base_btf(const char *path, struct mch_btf_doc *doc, struct mch_error *err);
int mch_load_object_btf(const char *path, struct mch_btf_doc *doc, struct mch_error *err);
const char *mch_btf_kind_name(unsigned int kind);
const char *mch_btf_type_name(const struct btf *btf, const struct btf_type *type);

#endif
