#include "min_corehdr/error.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

int main(void) {
  struct mch_error err;

  mch_error_clear(NULL);
  mch_error_set(NULL, "ignored");
  mch_error_set_context(NULL, "ignored");
  mch_error_set_file(NULL, "ignored");
  mch_error_set_file(&err, NULL);
  mch_error_set_detail(NULL, "ignored");
  mch_error_set_hint(NULL, "ignored");
  mch_error_set_hint(&err, NULL);
  mch_error_print(NULL, &err);
  mch_error_print(stderr, NULL);

  mch_error_clear(&err);
  mch_error_print(stderr, &err);
  mch_error_set(&err, "hello %s", "world");
  mch_error_set_context(&err, "%s:%d", "source.bpf.c", 42);
  mch_error_print(stderr, &err);
  mch_error_set_file(&err, "file.o");
  mch_error_set_detail(&err, "base query: %s", "struct task_struct");
  mch_error_set_hint(&err, "try again");
  mch_error_print(stderr, &err);
  REQUIRE(strstr(err.message, "hello world") != NULL);
  REQUIRE(strcmp(err.context, "source.bpf.c:42") == 0);
  REQUIRE(strcmp(err.file, "file.o") == 0);
  REQUIRE(strcmp(err.detail, "base query: struct task_struct") == 0);
  REQUIRE(strcmp(err.hint, "try again") == 0);
  return 0;
}
