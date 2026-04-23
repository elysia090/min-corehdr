#ifndef MIN_COREHDR_CLI_H
#define MIN_COREHDR_CLI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "min_corehdr/error.h"

struct mch_cli_options {
  const char *btf_path;
  const char *output_path;
  char **objects;
  size_t object_count;
  int verbose;
  bool quiet;
  bool stats;
  bool expand_pointers;
  bool help;
  bool version;
};

void mch_cli_options_init(struct mch_cli_options *opts);
void mch_cli_options_destroy(struct mch_cli_options *opts);
int mch_cli_parse(int argc, char **argv, struct mch_cli_options *opts, struct mch_error *err);
void mch_cli_print_help(FILE *out, const char *argv0);
void mch_cli_print_version(FILE *out);

#endif
