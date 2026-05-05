#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/btf.h>

#include "min_corehdr/btf_index.h"
#include "min_corehdr/btf_loader.h"
#include "min_corehdr/cli.h"
#include "min_corehdr/closure.h"
#include "min_corehdr/emitter.h"
#include "min_corehdr/error.h"
#include "min_corehdr/seeds.h"
#include "min_corehdr/type_set.h"

static FILE *open_temp_output(const char *path, char *tmp_path, size_t tmp_path_size,
                              struct mch_error *err) {
  long pid = (long)getpid();

  for (unsigned int attempt = 0; attempt < 128; attempt++) {
    int fd;
    int n = snprintf(tmp_path, tmp_path_size, "%s.tmp.%ld.%u", path, pid, attempt);

    if (n < 0 || (size_t)n >= tmp_path_size) {
      mch_error_set(err, "output path is too long");
      mch_error_set_file(err, path);
      return NULL;
    }

    fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, 0666);
    if (fd >= 0) {
      FILE *out = fdopen(fd, "w");
      if (out == NULL) {
        int saved_errno = errno;
        close(fd);
        remove(tmp_path);
        mch_error_set(err, "failed to open output: %s", strerror(saved_errno));
        mch_error_set_file(err, path);
        return NULL;
      }
      return out;
    }

    if (errno != EEXIST) {
      mch_error_set(err, "failed to open output: %s", strerror(errno));
      mch_error_set_file(err, path);
      return NULL;
    }
  }

  mch_error_set(err, "failed to create a unique temporary output path");
  mch_error_set_file(err, path);
  return NULL;
}

static int write_header_to_path(const char *path, const struct btf *btf,
                                const struct mch_type_set *required,
                                const struct mch_emit_options *emit_options,
                                struct mch_error *err) {
  char tmp_path[1024];
  FILE *out;
  int rc;

  out = open_temp_output(path, tmp_path, sizeof(tmp_path), err);
  if (out == NULL) {
    return -1;
  }

  rc = mch_emit_header_with_options(out, btf, required, emit_options, err);
  if (fclose(out) != 0 && rc == 0) {
    mch_error_set(err, "failed to close output: %s", strerror(errno));
    mch_error_set_file(err, path);
    rc = -1;
  }
  if (rc != 0) {
    remove(tmp_path);
    return -1;
  }
  if (rename(tmp_path, path) != 0) {
    mch_error_set(err, "failed to replace output: %s", strerror(errno));
    mch_error_set_file(err, path);
    remove(tmp_path);
    return -1;
  }

  return 0;
}

int main(int argc, char **argv) {
  struct mch_cli_options opts;
  struct mch_error err;
  struct mch_btf_doc base;
  struct mch_btf_index base_index;
  struct mch_type_set required;
  struct mch_requirements requirements;
  struct mch_seed_stats seed_total;
  struct mch_closure_stats closure_stats;
  struct mch_closure_options closure_options;
  struct mch_emit_options emit_options;
  int rc = 1;

  mch_error_clear(&err);
  mch_cli_options_init(&opts);
  mch_btf_doc_init(&base);
  mch_btf_index_init_empty(&base_index);
  memset(&required, 0, sizeof(required));
  memset(&requirements, 0, sizeof(requirements));
  mch_seed_stats_init(&seed_total);
  mch_closure_stats_init(&closure_stats);
  closure_options = (struct mch_closure_options){0};
  emit_options = (struct mch_emit_options){0};

  if (mch_cli_parse(argc, argv, &opts, &err) != 0) {
    mch_error_print(stderr, &err);
    mch_cli_options_destroy(&opts);
    return 2;
  }
  closure_options.expand_pointers = opts.expand_pointers;

  if (opts.help) {
    mch_cli_print_help(stdout, argv[0]);
    mch_cli_options_destroy(&opts);
    return 0;
  }
  if (opts.version) {
    mch_cli_print_version(stdout);
    mch_cli_options_destroy(&opts);
    return 0;
  }

  if (!opts.quiet && opts.verbose > 0) {
    fprintf(stderr, "loading base BTF: %s\n", opts.btf_path);
  }
  if (mch_load_base_btf(opts.btf_path, &base, &err) != 0) {
    goto out;
  }
  if (mch_btf_index_init(&base_index, base.btf, &err) != 0) {
    goto out;
  }
  if (mch_type_set_init(&required, btf__type_cnt(base.btf)) != 0) {
    mch_error_set(&err, "out of memory while preparing required type set");
    goto out;
  }
  if (mch_requirements_init(&requirements, btf__type_cnt(base.btf)) != 0) {
    mch_error_set(&err, "out of memory while preparing requirements");
    goto out;
  }
  closure_options.requirements = &requirements;
  emit_options.requirements = &requirements;

  for (size_t i = 0; i < opts.object_count; i++) {
    struct mch_btf_doc object;
    struct mch_seed_stats stats;

    mch_btf_doc_init(&object);
    mch_seed_stats_init(&stats);

    if (!opts.quiet && opts.verbose > 0) {
      fprintf(stderr, "loading object BTF: %s\n", opts.objects[i]);
    }
    if (mch_load_object_btf(opts.objects[i], &object, &err) != 0) {
      mch_btf_doc_destroy(&object);
      goto out;
    }
    if (mch_extract_object_seeds(&base_index, object.btf, opts.objects[i], &required, &stats,
                                 &err) != 0) {
      mch_btf_doc_destroy(&object);
      goto out;
    }
    if (mch_extract_core_relo_seeds_with_requirements(&base_index, object.btf, object.ext,
                                                      opts.objects[i], &required, &requirements,
                                                      &stats, &err) != 0) {
      mch_btf_doc_destroy(&object);
      goto out;
    }

    seed_total.candidates += stats.candidates;
    seed_total.kernel_types += stats.kernel_types;
    seed_total.program_local_types += stats.program_local_types;
    seed_total.core_relocations += stats.core_relocations;
    seed_total.core_kernel_types += stats.core_kernel_types;

    if (!opts.quiet && opts.verbose > 1) {
      fprintf(stderr,
              "%s: %zu seed candidates, %zu kernel matches, %zu program-local, "
              "%zu CO-RE relos, %zu CO-RE roots\n",
              opts.objects[i], stats.candidates, stats.kernel_types, stats.program_local_types,
              stats.core_relocations, stats.core_kernel_types);
    }

    mch_btf_doc_destroy(&object);
  }

  if (!opts.quiet && opts.verbose > 0) {
    fprintf(stderr, "computing dependency closure\n");
  }
  if (mch_compute_dependency_closure_with_options(base.btf, &required, &closure_stats,
                                                  &closure_options, &err) != 0) {
    goto out;
  }

  if (opts.output_path != NULL) {
    if (write_header_to_path(opts.output_path, base.btf, &required, &emit_options, &err) != 0) {
      goto out;
    }
  } else if (mch_emit_header_with_options(stdout, base.btf, &required, &emit_options, &err) != 0) {
    goto out;
  }

  if (opts.stats) {
    fprintf(stderr, "objects: %zu\n", opts.object_count);
    fprintf(stderr, "seed candidates: %zu\n", seed_total.candidates);
    fprintf(stderr, "kernel seed types: %zu\n", seed_total.kernel_types);
    fprintf(stderr, "program-local candidates: %zu\n", seed_total.program_local_types);
    fprintf(stderr, "CO-RE relocations: %zu\n", seed_total.core_relocations);
    fprintf(stderr, "CO-RE root types: %zu\n", seed_total.core_kernel_types);
    fprintf(stderr, "emitted required types: %zu\n", required.selected);
    fprintf(stderr, "closure additions: %zu\n", closure_stats.added_types);
  }

  rc = 0;

out:
  if (rc != 0) {
    mch_error_print(stderr, &err);
  }
  mch_requirements_destroy(&requirements);
  mch_type_set_destroy(&required);
  mch_btf_index_destroy(&base_index);
  mch_btf_doc_destroy(&base);
  mch_cli_options_destroy(&opts);
  return rc;
}
