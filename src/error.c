#include "min_corehdr/error.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void mch_error_clear(struct mch_error *err) {
  if (err == NULL) {
    return;
  }
  err->message[0] = '\0';
  err->context[0] = '\0';
  err->file[0] = '\0';
  err->detail[0] = '\0';
  err->hint[0] = '\0';
}

void mch_error_set(struct mch_error *err, const char *fmt, ...) {
  va_list ap;

  if (err == NULL) {
    return;
  }

  va_start(ap, fmt);
  vsnprintf(err->message, sizeof(err->message), fmt, ap);
  va_end(ap);
}

void mch_error_set_context(struct mch_error *err, const char *fmt, ...) {
  va_list ap;

  if (err == NULL) {
    return;
  }

  va_start(ap, fmt);
  vsnprintf(err->context, sizeof(err->context), fmt, ap);
  va_end(ap);
}

void mch_error_set_file(struct mch_error *err, const char *file) {
  if (err == NULL || file == NULL) {
    return;
  }
  snprintf(err->file, sizeof(err->file), "%s", file);
}

void mch_error_set_detail(struct mch_error *err, const char *fmt, ...) {
  va_list ap;

  if (err == NULL) {
    return;
  }

  va_start(ap, fmt);
  vsnprintf(err->detail, sizeof(err->detail), fmt, ap);
  va_end(ap);
}

void mch_error_set_hint(struct mch_error *err, const char *hint) {
  if (err == NULL || hint == NULL) {
    return;
  }
  snprintf(err->hint, sizeof(err->hint), "%s", hint);
}

void mch_error_print(FILE *out, const struct mch_error *err) {
  if (out == NULL || err == NULL || err->message[0] == '\0') {
    return;
  }

  fprintf(out, "error: %s\n", err->message);
  if (err->context[0] != '\0') {
    fprintf(out, "in:    %s\n", err->context);
  }
  if (err->file[0] != '\0') {
    fprintf(out, "file:  %s\n", err->file);
  }
  if (err->detail[0] != '\0') {
    fprintf(out, "detail: %s\n", err->detail);
  }
  if (err->hint[0] != '\0') {
    fprintf(out, "hint:  %s\n", err->hint);
  }
}
