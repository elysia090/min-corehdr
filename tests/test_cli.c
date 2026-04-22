#include "min_corehdr/cli.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

static int parse_ok(int argc, char **argv, struct mch_cli_options *opts) {
  struct mch_error err;

  mch_error_clear(&err);
  mch_cli_options_init(opts);
  if (mch_cli_parse(argc, argv, opts, &err) != 0) {
    fprintf(stderr, "unexpected parse error: %s\n", err.message);
    mch_cli_options_destroy(opts);
    return -1;
  }
  mch_cli_options_destroy(NULL);
  mch_cli_print_help(stderr, NULL);
  mch_cli_print_help(stderr, "");

  return 0;
}

static int parse_fails(int argc, char **argv, const char *message_part) {
  struct mch_cli_options opts;
  struct mch_error err;

  mch_error_clear(&err);
  mch_cli_options_init(&opts);
  if (mch_cli_parse(argc, argv, &opts, &err) == 0) {
    fprintf(stderr, "parse unexpectedly succeeded\n");
    mch_cli_options_destroy(&opts);
    return -1;
  }
  if (strstr(err.message, message_part) == NULL) {
    fprintf(stderr, "expected error containing '%s', got '%s'\n", message_part, err.message);
    mch_cli_options_destroy(&opts);
    return -1;
  }
  mch_cli_options_destroy(&opts);
  return 0;
}

int main(void) {
  {
    char *argv[] = {"min-corehdr", "--help"};
    struct mch_cli_options opts;
    REQUIRE(parse_ok(2, argv, &opts) == 0);
    REQUIRE(opts.help);
    REQUIRE(!opts.version);
    mch_cli_options_destroy(&opts);
  }

  {
    char *argv[] = {"min-corehdr", "--version"};
    struct mch_cli_options opts;
    REQUIRE(parse_ok(2, argv, &opts) == 0);
    REQUIRE(opts.version);
    REQUIRE(!opts.help);
    mch_cli_options_destroy(&opts);
  }

  {
    char *argv[] = {"min-corehdr", "foo.bpf.o"};
    REQUIRE(parse_fails(2, argv, "missing required --btf") == 0);
  }

  {
    char *argv[] = {"min-corehdr", "--btf", "base.btf"};
    REQUIRE(parse_fails(3, argv, "missing OBJECT") == 0);
  }

  {
    char *argv[] = {"min-corehdr", "--btf", "a", "--btf=b", "foo.bpf.o"};
    REQUIRE(parse_fails(5, argv, "duplicate --btf") == 0);
  }

  {
    char *argv[] = {"min-corehdr", "--unknown"};
    REQUIRE(parse_fails(2, argv, "unknown option --unknown") == 0);
  }

  {
    char *argv[] = {"min-corehdr", "-z"};
    REQUIRE(parse_fails(2, argv, "unknown option -z") == 0);
  }

  {
    char *argv[] = {"min-corehdr", "--btf"};
    REQUIRE(parse_fails(2, argv, "missing value for --btf") == 0);
  }

  {
    char *argv[] = {"min-corehdr", "--output"};
    REQUIRE(parse_fails(2, argv, "missing value for --output") == 0);
  }

  {
    char *argv[] = {"min-corehdr", "-o"};
    REQUIRE(parse_fails(2, argv, "missing value for -o") == 0);
  }

  {
    char *argv[] = {"min-corehdr",    "--quiet", "--verbose",
                    "--btf=base.btf", "--",      "-strange.bpf.o"};
    struct mch_cli_options opts;
    REQUIRE(parse_ok(6, argv, &opts) == 0);
    REQUIRE(!opts.quiet);
    REQUIRE(opts.verbose == 1);
    REQUIRE(strcmp(opts.btf_path, "base.btf") == 0);
    REQUIRE(opts.object_count == 1);
    REQUIRE(strcmp(opts.objects[0], "-strange.bpf.o") == 0);
    mch_cli_options_destroy(&opts);
  }

  {
    char *argv[] = {"min-corehdr", "-hV"};
    struct mch_cli_options opts;
    REQUIRE(parse_ok(2, argv, &opts) == 0);
    REQUIRE(opts.help);
    REQUIRE(opts.version);
    mch_cli_options_destroy(&opts);
  }

  {
    char *argv[] = {"min-corehdr", "--output=out.h", "--btf", "base.btf", "foo.bpf.o"};
    struct mch_cli_options opts;
    REQUIRE(parse_ok(5, argv, &opts) == 0);
    REQUIRE(strcmp(opts.output_path, "out.h") == 0);
    mch_cli_options_destroy(&opts);
  }

  {
    char *argv[] = {"min-corehdr", "--output", "out.h", "--btf", "base.btf", "foo.bpf.o"};
    struct mch_cli_options opts;
    REQUIRE(parse_ok(6, argv, &opts) == 0);
    REQUIRE(strcmp(opts.output_path, "out.h") == 0);
    mch_cli_options_destroy(&opts);
  }

  {
    char *argv[] = {"min-corehdr", "-o", "out.h", "--btf", "base.btf", "foo.bpf.o"};
    struct mch_cli_options opts;
    REQUIRE(parse_ok(6, argv, &opts) == 0);
    REQUIRE(strcmp(opts.output_path, "out.h") == 0);
    mch_cli_options_destroy(&opts);
  }

  {
    char *argv[] = {"min-corehdr", "-vvqoout.h", "--btf", "base.btf", "foo.bpf.o"};
    struct mch_cli_options opts;
    REQUIRE(parse_ok(5, argv, &opts) == 0);
    REQUIRE(opts.quiet);
    REQUIRE(opts.verbose == 0);
    REQUIRE(strcmp(opts.output_path, "out.h") == 0);
    REQUIRE(opts.object_count == 1);
    mch_cli_options_destroy(&opts);
  }

  return 0;
}
