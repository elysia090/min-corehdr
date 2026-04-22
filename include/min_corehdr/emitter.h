#ifndef MIN_COREHDR_EMITTER_H
#define MIN_COREHDR_EMITTER_H

#include <stdio.h>

#include <bpf/btf.h>

#include "min_corehdr/error.h"
#include "min_corehdr/type_set.h"

int mch_emit_header(FILE *out, const struct btf *btf, const struct mch_type_set *required,
                    struct mch_error *err);

#endif
