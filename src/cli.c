#include "min_corehdr/cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "min_corehdr/version.h"

static int add_object(struct mch_cli_options *opts, char *path, struct mch_error *err) {
  char **next = realloc(opts->objects, (opts->object_count + 1) * sizeof(*next));
  if (next == NULL) {
    mch_error_set(err, "out of memory while parsing object inputs");
    return -1;
  }
  opts->objects = next;
  opts->objects[opts->object_count++] = path;
  return 0;
}

static int require_value(int *index, int argc, char **argv, const char *option, const char **value,
                         struct mch_error *err) {
  if (*index + 1 >= argc) {
    mch_error_set(err, "missing value for %s", option);
    return -1;
  }
  *index += 1;
  *value = argv[*index];
  return 0;
}

static int set_btf_path(struct mch_cli_options *opts, const char *path, struct mch_error *err) {
  if (opts->btf_path != NULL) {
    mch_error_set(err, "duplicate --btf option");
    return -1;
  }
  opts->btf_path = path;
  return 0;
}

static int set_output_path(struct mch_cli_options *opts, const char *path, struct mch_error *err) {
  if (opts->output_path != NULL) {
    mch_error_set(err, "duplicate --output option");
    return -1;
  }
  if (path[0] == '\0') {
    mch_error_set(err, "empty --output FILE");
    return -1;
  }
  opts->output_path = path;
  return 0;
}

void mch_cli_options_init(struct mch_cli_options *opts) { memset(opts, 0, sizeof(*opts)); }

void mch_cli_options_destroy(struct mch_cli_options *opts) {
  if (opts == NULL) {
    return;
  }
  free(opts->objects);
  opts->objects = NULL;
  opts->object_count = 0;
}

int mch_cli_parse(int argc, char **argv, struct mch_cli_options *opts, struct mch_error *err) {
  bool end_of_options = false;

  for (int i = 1; i < argc; i++) {
    char *arg = argv[i];

    if (end_of_options) {
      if (add_object(opts, arg, err) != 0) {
        return -1;
      }
      continue;
    }

    if (strcmp(arg, "--") == 0) {
      end_of_options = true;
      continue;
    }

    if (strcmp(arg, "--help") == 0) {
      opts->help = true;
      continue;
    }
    if (strcmp(arg, "--version") == 0) {
      opts->version = true;
      continue;
    }
    if (strcmp(arg, "--verbose") == 0) {
      opts->quiet = false;
      opts->verbose++;
      continue;
    }
    if (strcmp(arg, "--quiet") == 0) {
      opts->quiet = true;
      opts->verbose = 0;
      continue;
    }
    if (strcmp(arg, "--stats") == 0) {
      opts->stats = true;
      continue;
    }
    if (strcmp(arg, "--explain") == 0) {
      opts->explain = true;
      continue;
    }
    if (strcmp(arg, "--expand-pointers") == 0) {
      opts->expand_pointers = true;
      continue;
    }
    if (strncmp(arg, "--btf=", 6) == 0) {
      if (set_btf_path(opts, arg + 6, err) != 0) {
        return -1;
      }
      continue;
    }
    if (strcmp(arg, "--btf") == 0) {
      const char *path = NULL;
      if (require_value(&i, argc, argv, "--btf", &path, err) != 0 ||
          set_btf_path(opts, path, err) != 0) {
        return -1;
      }
      continue;
    }
    if (strncmp(arg, "--output=", 9) == 0) {
      if (set_output_path(opts, arg + 9, err) != 0) {
        return -1;
      }
      continue;
    }
    if (strcmp(arg, "--output") == 0) {
      const char *path = NULL;
      if (require_value(&i, argc, argv, "--output", &path, err) != 0 ||
          set_output_path(opts, path, err) != 0) {
        return -1;
      }
      continue;
    }

    if (arg[0] == '-' && arg[1] != '\0') {
      if (arg[1] == '-' && arg[2] != '\0') {
        mch_error_set(err, "unknown option %s", arg);
        return -1;
      }

      for (size_t j = 1; arg[j] != '\0'; j++) {
        switch (arg[j]) {
        case 'h':
          opts->help = true;
          break;
        case 'V':
          opts->version = true;
          break;
        case 'v':
          opts->quiet = false;
          opts->verbose++;
          break;
        case 'q':
          opts->quiet = true;
          opts->verbose = 0;
          break;
        case 'o': {
          const char *path = NULL;
          if (arg[j + 1] != '\0') {
            path = &arg[j + 1];
            if (set_output_path(opts, path, err) != 0) {
              return -1;
            }
          } else if (require_value(&i, argc, argv, "-o", &path, err) != 0 ||
                     set_output_path(opts, path, err) != 0) {
            return -1;
          }
          j = strlen(arg) - 1;
          break;
        }
        default:
          mch_error_set(err, "unknown option -%c", arg[j]);
          return -1;
        }
      }
      continue;
    }

    if (add_object(opts, arg, err) != 0) {
      return -1;
    }
  }

  if (opts->help || opts->version) {
    return 0;
  }
  if (opts->btf_path == NULL || opts->btf_path[0] == '\0') {
    mch_error_set(err, "missing required --btf FILE");
    return -1;
  }
  if (opts->object_count == 0) {
    mch_error_set(err, "missing OBJECT input");
    return -1;
  }
  if (opts->output_path != NULL) {
    if (strcmp(opts->output_path, opts->btf_path) == 0) {
      mch_error_set(err, "output path must not match --btf input");
      return -1;
    }
    for (size_t i = 0; i < opts->object_count; i++) {
      if (strcmp(opts->output_path, opts->objects[i]) == 0) {
        mch_error_set(err, "output path must not match OBJECT input");
        return -1;
      }
    }
  }

  return 0;
}

void mch_cli_print_help(FILE *out, const char *argv0) {
  const char *prog = argv0 != NULL && argv0[0] != '\0' ? argv0 : "min-corehdr";

  fprintf(
      out,
      "min-corehdr - generate a compile-complete minimal local CO-RE header from .bpf.o inputs\n");
  fprintf(out, "Usage:\n");
  fprintf(out, "  %s [OPTIONS] --btf FILE OBJECT...\n", prog);
  fprintf(out, "  %s --help\n", prog);
  fprintf(out, "  %s --version\n", prog);
  fprintf(out, "\nGlobal options:\n");
  fprintf(out, "  -h, --help       Show this help and exit\n");
  fprintf(out, "  -V, --version    Show version information and exit\n");
  fprintf(out, "  -v, --verbose    Increase stderr diagnostics; repeatable\n");
  fprintf(out, "  -q, --quiet      Suppress non-error diagnostics\n");
  fprintf(out, "\nMain options:\n");
  fprintf(out, "      --btf FILE   Base BTF file used as the kernel type source\n");
  fprintf(out, "  -o, --output FILE\n");
  fprintf(out, "                  Write the generated header to FILE\n");
  fprintf(out, "      --expand-pointers\n");
  fprintf(out, "                  Also include pointee types in dependency closure\n");
  fprintf(out, "      --explain   Print a requirement witness to stderr\n");
  fprintf(out, "      --stats      Print a short generation summary to stderr\n");
  fprintf(out, "\nExample:\n");
  fprintf(out, "  %s --btf /sys/kernel/btf/vmlinux -o vmlinux.h foo.bpf.o\n", prog);
}

void mch_cli_print_version(FILE *out) {
  fprintf(out, "min-corehdr %s\n", MIN_COREHDR_VERSION);
  fprintf(out, "git %s\n", MIN_COREHDR_GIT_REVISION);
  fprintf(out, "libbpf %s\n", libbpf_version_string());
}
