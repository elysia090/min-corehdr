#ifndef MIN_COREHDR_ERROR_H
#define MIN_COREHDR_ERROR_H

#include <stdio.h>

struct mch_error {
  char message[256];
  char context[512];
  char file[512];
  char hint[256];
};

void mch_error_clear(struct mch_error *err);
void mch_error_set(struct mch_error *err, const char *fmt, ...);
void mch_error_set_context(struct mch_error *err, const char *fmt, ...);
void mch_error_set_file(struct mch_error *err, const char *file);
void mch_error_set_hint(struct mch_error *err, const char *hint);
void mch_error_print(FILE *out, const struct mch_error *err);

#endif
