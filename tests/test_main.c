#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include "min_corehdr/btf_index.h"
#include "min_corehdr/btf_loader.h"
#include "min_corehdr/closure.h"
#include "min_corehdr/emitter.h"
#include "min_corehdr/error.h"
#include "min_corehdr/seeds.h"
#include "min_corehdr/type_set.h"

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

enum stub_mode {
  STUB_OK,
  STUB_LOAD_BASE_FAIL,
  STUB_INDEX_FAIL,
  STUB_TYPE_SET_FAIL,
  STUB_LOAD_OBJECT_FAIL,
  STUB_OBJECT_SEEDS_FAIL,
  STUB_CORE_SEEDS_FAIL,
  STUB_CLOSURE_FAIL,
  STUB_EMIT_FAIL,
  STUB_FDOPEN_FAIL,
  STUB_FCLOSE_FAIL,
};

static enum stub_mode mode;

static void set_stub_error(struct mch_error *err, const char *message, const char *path) {
  mch_error_set(err, "%s", message);
  mch_error_set_file(err, path);
}

static int make_doc(const char *path, struct mch_btf_doc *doc, struct mch_error *err) {
  int int_id;

  mch_btf_doc_init(doc);
  doc->btf = btf__new_empty();
  if (libbpf_get_error(doc->btf) != 0) {
    set_stub_error(err, "failed to allocate stub BTF", path);
    return -1;
  }
  int_id = btf__add_int(doc->btf, "int", 4, BTF_INT_SIGNED);
  if (int_id <= 0) {
    set_stub_error(err, "failed to add stub int", path);
    return -1;
  }
  doc->path = path;
  return 0;
}

static int test_load_base_btf(const char *path, struct mch_btf_doc *doc, struct mch_error *err) {
  if (mode == STUB_LOAD_BASE_FAIL) {
    set_stub_error(err, "stub base load failed", path);
    return -1;
  }
  return make_doc(path, doc, err);
}

static int test_load_object_btf(const char *path, struct mch_btf_doc *doc, struct mch_error *err) {
  if (mode == STUB_LOAD_OBJECT_FAIL) {
    set_stub_error(err, "stub object load failed", path);
    return -1;
  }
  return make_doc(path, doc, err);
}

static int test_btf_index_init(struct mch_btf_index *index, const struct btf *btf,
                               struct mch_error *err) {
  (void)btf;
  mch_btf_index_init_empty(index);
  if (mode == STUB_INDEX_FAIL) {
    mch_error_set(err, "stub index failed");
    return -1;
  }
  return 0;
}

static int test_type_set_init(struct mch_type_set *set, size_t count) {
  if (mode == STUB_TYPE_SET_FAIL) {
    return -1;
  }
  return mch_type_set_init(set, count);
}

static int test_extract_object_seeds(const struct mch_btf_index *base_index,
                                     const struct btf *object_btf, const char *object_path,
                                     struct mch_type_set *seeds, struct mch_seed_stats *stats,
                                     struct mch_error *err) {
  (void)base_index;
  (void)object_btf;
  (void)seeds;
  if (mode == STUB_OBJECT_SEEDS_FAIL) {
    set_stub_error(err, "stub object seeds failed", object_path);
    return -1;
  }
  stats->candidates++;
  stats->program_local_types++;
  return 0;
}

static int test_extract_core_relo_seeds_with_members(
    const struct mch_btf_index *base_index, const struct btf *object_btf,
    const struct btf_ext *object_ext, const char *object_path, struct mch_type_set *seeds,
    struct mch_member_filter *members, struct mch_seed_stats *stats, struct mch_error *err) {
  (void)base_index;
  (void)object_btf;
  (void)object_ext;
  (void)seeds;
  (void)members;
  if (mode == STUB_CORE_SEEDS_FAIL) {
    set_stub_error(err, "stub CO-RE seeds failed", object_path);
    return -1;
  }
  stats->core_relocations++;
  return 0;
}

static int test_compute_dependency_closure(const struct btf *btf, struct mch_type_set *required,
                                           struct mch_closure_stats *stats,
                                           const struct mch_closure_options *options,
                                           struct mch_error *err) {
  (void)btf;
  (void)required;
  (void)options;
  if (mode == STUB_CLOSURE_FAIL) {
    mch_error_set(err, "stub closure failed");
    return -1;
  }
  stats->added_types = 0;
  return 0;
}

static int test_emit_header_with_options(FILE *out, const struct btf *btf,
                                         const struct mch_type_set *required,
                                         const struct mch_emit_options *options,
                                         struct mch_error *err) {
  (void)btf;
  (void)required;
  (void)options;
  if (mode == STUB_EMIT_FAIL) {
    mch_error_set(err, "stub emit failed");
    return -1;
  }
  return fputs("/* stub header */\n", out) < 0 ? -1 : 0;
}

static FILE *test_fdopen(int fd, const char *open_mode) {
  if (mode == STUB_FDOPEN_FAIL) {
    errno = EMFILE;
    return NULL;
  }
  return fdopen(fd, open_mode);
}

static int test_fclose(FILE *out) {
  if (mode == STUB_FCLOSE_FAIL) {
    errno = EIO;
    return EOF;
  }
  return fclose(out);
}

#define main min_corehdr_main
#define mch_load_base_btf test_load_base_btf
#define mch_load_object_btf test_load_object_btf
#define mch_btf_index_init test_btf_index_init
#define mch_type_set_init test_type_set_init
#define mch_extract_object_seeds test_extract_object_seeds
#define mch_extract_core_relo_seeds_with_members test_extract_core_relo_seeds_with_members
#define mch_compute_dependency_closure_with_options test_compute_dependency_closure
#define mch_emit_header_with_options test_emit_header_with_options
#define fdopen test_fdopen
#define fclose test_fclose
#include "../src/main.c"
#undef fclose
#undef fdopen
#undef mch_emit_header_with_options
#undef mch_compute_dependency_closure_with_options
#undef mch_extract_core_relo_seeds_with_members
#undef mch_extract_object_seeds
#undef mch_type_set_init
#undef mch_btf_index_init
#undef mch_load_object_btf
#undef mch_load_base_btf
#undef main

static int run_main(enum stub_mode next_mode, int argc, char **argv, int expected_rc) {
  int rc;

  mode = next_mode;
  rc = min_corehdr_main(argc, argv);
  mode = STUB_OK;
  REQUIRE(rc == expected_rc);
  return 0;
}

static int test_main_stubbed_failures(void) {
  char *base_args[] = {"min-corehdr", "--btf", "base.btf", "object.o", NULL};
  char *stdout_args[] = {"min-corehdr", "--btf", "base.btf", "object.o", NULL};

  REQUIRE(run_main(STUB_LOAD_BASE_FAIL, 4, base_args, 1) == 0);
  REQUIRE(run_main(STUB_INDEX_FAIL, 4, base_args, 1) == 0);
  REQUIRE(run_main(STUB_TYPE_SET_FAIL, 4, base_args, 1) == 0);
  REQUIRE(run_main(STUB_LOAD_OBJECT_FAIL, 4, base_args, 1) == 0);
  REQUIRE(run_main(STUB_OBJECT_SEEDS_FAIL, 4, base_args, 1) == 0);
  REQUIRE(run_main(STUB_CORE_SEEDS_FAIL, 4, base_args, 1) == 0);
  REQUIRE(run_main(STUB_CLOSURE_FAIL, 4, base_args, 1) == 0);
  REQUIRE(run_main(STUB_EMIT_FAIL, 4, stdout_args, 1) == 0);
  return 0;
}

static int test_main_stubbed_output_failures(void) {
  char tmp_template[] = "/tmp/min-corehdr-main.XXXXXX";
  char *tmpdir;
  char out_path[256];
  char dir_path[256];
  char long_path[1200];
  char *write_args[] = {"min-corehdr", "--btf", "base.btf", "-o", out_path, "object.o", NULL};
  char *dir_args[] = {"min-corehdr", "--btf", "base.btf", "-o", dir_path, "object.o", NULL};
  char *long_args[] = {"min-corehdr", "--btf", "base.btf", "-o", long_path, "object.o", NULL};
  long pid = (long)getpid();

  tmpdir = mkdtemp(tmp_template);
  REQUIRE(tmpdir != NULL);
  snprintf(out_path, sizeof(out_path), "%s/out.h", tmpdir);
  snprintf(dir_path, sizeof(dir_path), "%s/existing-dir", tmpdir);
  REQUIRE(mkdir(dir_path, 0700) == 0);
  memset(long_path, 'x', sizeof(long_path) - 1);
  long_path[sizeof(long_path) - 1] = '\0';

  REQUIRE(run_main(STUB_EMIT_FAIL, 6, write_args, 1) == 0);
  REQUIRE(run_main(STUB_FDOPEN_FAIL, 6, write_args, 1) == 0);
  REQUIRE(run_main(STUB_FCLOSE_FAIL, 6, write_args, 1) == 0);
  REQUIRE(run_main(STUB_OK, 6, dir_args, 1) == 0);
  REQUIRE(run_main(STUB_OK, 6, long_args, 1) == 0);

  for (unsigned int i = 0; i < 128; i++) {
    char collision[320];
    FILE *file;

    snprintf(collision, sizeof(collision), "%s.tmp.%ld.%u", out_path, pid, i);
    file = fopen(collision, "w");
    REQUIRE(file != NULL);
    REQUIRE(fclose(file) == 0);
  }
  REQUIRE(run_main(STUB_OK, 6, write_args, 1) == 0);

  return 0;
}

static int test_main_quiet_verbose_success(void) {
  char tmp_template[] = "/tmp/min-corehdr-main-quiet.XXXXXX";
  char *tmpdir;
  char out_path[256];
  char *args[] = {"min-corehdr", "--quiet", "-vv",    "--stats",  "--btf",
                  "base.btf",    "-o",      out_path, "object.o", NULL};

  tmpdir = mkdtemp(tmp_template);
  REQUIRE(tmpdir != NULL);
  snprintf(out_path, sizeof(out_path), "%s/out.h", tmpdir);
  REQUIRE(run_main(STUB_OK, 9, args, 0) == 0);
  return 0;
}

static int test_main_expand_pointers_success(void) {
  char *args[] = {"min-corehdr", "--expand-pointers", "--btf", "base.btf", "object.o", NULL};

  REQUIRE(run_main(STUB_OK, 5, args, 0) == 0);
  return 0;
}

int main(void) {
  REQUIRE(test_main_stubbed_failures() == 0);
  REQUIRE(test_main_stubbed_output_failures() == 0);
  REQUIRE(test_main_quiet_verbose_success() == 0);
  REQUIRE(test_main_expand_pointers_success() == 0);
  return 0;
}
