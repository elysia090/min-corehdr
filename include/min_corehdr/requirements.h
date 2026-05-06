#ifndef MIN_COREHDR_REQUIREMENTS_H
#define MIN_COREHDR_REQUIREMENTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <bpf/btf.h>

#include "min_corehdr/error.h"

enum mch_requirement_source {
  MCH_REQUIREMENT_SOURCE_UNKNOWN = 0,
  MCH_REQUIREMENT_SOURCE_OBJECT_BTF,
  MCH_REQUIREMENT_SOURCE_CORE_RELO,
};

struct mch_requirement_origin {
  enum mch_requirement_source source;
  const char *object_path;
  const char *detail;
  const char *access;
  const char *location;
};

struct mch_requirement_stats {
  size_t type_roots;
  size_t record_members;
  size_t traces;
};

struct mch_requirement_trace {
  unsigned int kind;
  enum mch_requirement_source source;
  uint32_t type_id;
  uint32_t member_index;
  char *object_path;
  char *detail;
  char *access;
  char *location;
};

struct mch_requirements {
  uint64_t *type_root_words;
  uint64_t **record_member_words;
  size_t *record_member_counts;
  struct mch_requirement_trace *traces;
  size_t type_count;
  size_t type_root_words_count;
  size_t trace_count;
  size_t trace_capacity;
  size_t type_roots;
  size_t record_members;
};

int mch_requirements_init(struct mch_requirements *requirements, size_t type_count);
void mch_requirements_destroy(struct mch_requirements *requirements);
bool mch_requirements_contains_type_root(const struct mch_requirements *requirements,
                                         size_t type_id);
int mch_requirements_add_type_root(struct mch_requirements *requirements, size_t type_id,
                                   const struct mch_requirement_origin *origin,
                                   struct mch_error *err);
bool mch_requirements_has_record_members(const struct mch_requirements *requirements,
                                         size_t type_id);
bool mch_requirements_contains_record_member(const struct mch_requirements *requirements,
                                             size_t type_id, size_t member_index);
int mch_requirements_add_record_member(const struct btf *btf, struct mch_requirements *requirements,
                                       size_t type_id, size_t member_index,
                                       const struct mch_requirement_origin *origin,
                                       struct mch_error *err);
void mch_requirements_stats(const struct mch_requirements *requirements,
                            struct mch_requirement_stats *stats);
int mch_requirements_write_explanation(FILE *out, const struct btf *btf,
                                       const struct mch_requirements *requirements,
                                       struct mch_error *err);

#endif
