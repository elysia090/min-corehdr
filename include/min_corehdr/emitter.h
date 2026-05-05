#ifndef MIN_COREHDR_EMITTER_H
#define MIN_COREHDR_EMITTER_H

#include <stdio.h>

#include <bpf/btf.h>

#include "min_corehdr/error.h"
#include "min_corehdr/member_filter.h"
#include "min_corehdr/type_set.h"

struct mch_emit_options {
  const struct mch_member_filter *member_filter;
};

int mch_emit_header_with_options(FILE *out, const struct btf *btf,
                                 const struct mch_type_set *required,
                                 const struct mch_emit_options *options, struct mch_error *err);
int mch_emit_header(FILE *out, const struct btf *btf, const struct mch_type_set *required,
                    struct mch_error *err);

#endif
