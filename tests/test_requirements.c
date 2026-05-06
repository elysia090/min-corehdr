#include "min_corehdr/requirements.h"

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(expr)                                                                              \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "require failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

static int read_stream(FILE *file, char **out) {
  long size;
  char *buffer;

  REQUIRE(fflush(file) == 0);
  REQUIRE(fseek(file, 0, SEEK_END) == 0);
  size = ftell(file);
  REQUIRE(size >= 0);
  REQUIRE(fseek(file, 0, SEEK_SET) == 0);

  buffer = malloc((size_t)size + 1);
  REQUIRE(buffer != NULL);
  REQUIRE(fread(buffer, 1, (size_t)size, file) == (size_t)size);
  buffer[size] = '\0';
  *out = buffer;
  return 0;
}

static int test_requirement_witness_output(void) {
  struct mch_requirements requirements;
  struct mch_requirement_stats stats;
  struct mch_error err;
  struct btf *btf;
  FILE *out;
  char *explanation = NULL;
  int int_id;
  int root_id;
  const struct mch_requirement_origin object_origin = {
      .source = MCH_REQUIREMENT_SOURCE_OBJECT_BTF,
      .object_path = "fixture.bpf.o",
      .detail = "seed",
  };
  const struct mch_requirement_origin core_origin = {
      .source = MCH_REQUIREMENT_SOURCE_CORE_RELO,
      .object_path = "fixture.bpf.o",
      .detail = "FIELD_BYTE_OFFSET",
      .access = "0:0",
      .location = "exec_audit.bpf.c:42:7",
  };

  mch_error_clear(&err);
  memset(&requirements, 0, sizeof(requirements));

  btf = btf__new_empty();
  REQUIRE(libbpf_get_error(btf) == 0);
  int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
  REQUIRE(int_id > 0);
  root_id = btf__add_struct(btf, "task_struct", 8);
  REQUIRE(root_id > 0);
  REQUIRE(btf__add_field(btf, "pid", int_id, 0, 0) == 0);
  REQUIRE(btf__add_field(btf, "unused", int_id, 32, 0) == 0);

  REQUIRE(mch_requirements_init(&requirements, btf__type_cnt(btf)) == 0);
  REQUIRE(mch_requirements_add_type_root(&requirements, (size_t)root_id, &object_origin, &err) ==
          0);
  REQUIRE(mch_requirements_add_type_root(&requirements, (size_t)root_id, &object_origin, &err) ==
          0);
  REQUIRE(mch_requirements_add_record_member(btf, &requirements, (size_t)root_id, 0, &core_origin,
                                             &err) == 0);
  REQUIRE(mch_requirements_add_record_member(btf, &requirements, (size_t)root_id, 0, &core_origin,
                                             &err) == 0);

  REQUIRE(mch_requirements_contains_type_root(&requirements, (size_t)root_id));
  REQUIRE(mch_requirements_contains_record_member(&requirements, (size_t)root_id, 0));
  REQUIRE(!mch_requirements_contains_record_member(&requirements, (size_t)root_id, 1));
  REQUIRE(!mch_requirements_contains_record_member(&requirements, (size_t)root_id, 999));

  mch_requirements_stats(&requirements, &stats);
  REQUIRE(stats.type_roots == 1);
  REQUIRE(stats.record_members == 1);
  REQUIRE(stats.traces == 2);

  out = tmpfile();
  REQUIRE(out != NULL);
  REQUIRE(mch_requirements_write_explanation(out, btf, &requirements, &err) == 0);
  REQUIRE(read_stream(out, &explanation) == 0);
  REQUIRE(strstr(explanation, "requirements:\n") != NULL);
  REQUIRE(strstr(explanation, "root: STRUCT task_struct") != NULL);
  REQUIRE(strstr(explanation, "source: object BTF seed") != NULL);
  REQUIRE(strstr(explanation, "member: struct task_struct.pid") != NULL);
  REQUIRE(strstr(explanation, "source: CO-RE relocation FIELD_BYTE_OFFSET") != NULL);
  REQUIRE(strstr(explanation, "access: 0:0") != NULL);
  REQUIRE(strstr(explanation, "location: exec_audit.bpf.c:42:7") != NULL);
  REQUIRE(strstr(explanation, "file: fixture.bpf.o") != NULL);

  free(explanation);
  REQUIRE(fclose(out) == 0);
  mch_requirements_destroy(&requirements);
  btf__free(btf);
  return 0;
}

int main(void) {
  REQUIRE(test_requirement_witness_output() == 0);
  return 0;
}
