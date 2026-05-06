#include "min_corehdr/requirements.h"

#include <stdlib.h>
#include <string.h>

#include <linux/btf.h>

#include "min_corehdr/btf_loader.h"

enum mch_requirement_trace_kind {
  MCH_REQUIREMENT_TRACE_TYPE_ROOT = 1,
  MCH_REQUIREMENT_TRACE_RECORD_MEMBER,
};

static size_t word_count_for_bits(size_t count) { return count == 0 ? 1 : (count + 63) / 64; }

static bool bitset_contains(const uint64_t *words, size_t count, size_t id) {
  if (words == NULL || id >= count) {
    return false;
  }
  return (words[id >> 6] & (UINT64_C(1) << (id & 63u))) != 0;
}

static bool bitset_add(uint64_t *words, size_t count, size_t id) {
  uint64_t mask;

  if (words == NULL || id >= count) {
    return false;
  }

  mask = UINT64_C(1) << (id & 63u);
  if ((words[id >> 6] & mask) != 0) {
    return false;
  }
  words[id >> 6] |= mask;
  return true;
}

static char *dup_optional(const char *value, struct mch_error *err) {
  size_t len;
  char *copy;

  if (value == NULL || value[0] == '\0') {
    return NULL;
  }

  len = strlen(value);
  copy = malloc(len + 1);
  if (copy == NULL) {
    mch_error_set(err, "out of memory while recording requirement trace");
    return NULL;
  }
  memcpy(copy, value, len + 1);
  return copy;
}

static void free_trace(struct mch_requirement_trace *trace) {
  free(trace->access);
  free(trace->detail);
  free(trace->location);
  free(trace->object_path);
  memset(trace, 0, sizeof(*trace));
}

static int ensure_trace_capacity(struct mch_requirements *requirements, struct mch_error *err) {
  size_t next_capacity;
  struct mch_requirement_trace *next;

  if (requirements->trace_count < requirements->trace_capacity) {
    return 0;
  }

  next_capacity = requirements->trace_capacity == 0 ? 16 : requirements->trace_capacity * 2;
  if (next_capacity < requirements->trace_capacity ||
      next_capacity > SIZE_MAX / sizeof(*requirements->traces)) {
    mch_error_set(err, "requirement trace list is too large");
    return -1;
  }

  next = realloc(requirements->traces, next_capacity * sizeof(*requirements->traces));
  if (next == NULL) {
    mch_error_set(err, "out of memory while growing requirement trace list");
    return -1;
  }

  requirements->traces = next;
  requirements->trace_capacity = next_capacity;
  return 0;
}

static int append_trace(struct mch_requirements *requirements, unsigned int kind, size_t type_id,
                        size_t member_index, const struct mch_requirement_origin *origin,
                        struct mch_error *err) {
  struct mch_requirement_trace trace;

  if (type_id > UINT32_MAX || member_index > UINT32_MAX) {
    mch_error_set(err, "requirement trace references an unsupported type or member id");
    return -1;
  }

  trace = (struct mch_requirement_trace){
      .kind = kind,
      .source = origin == NULL ? MCH_REQUIREMENT_SOURCE_UNKNOWN : origin->source,
      .type_id = (uint32_t)type_id,
      .member_index = (uint32_t)member_index,
  };

  if (origin != NULL) {
    trace.object_path = dup_optional(origin->object_path, err);
    if (origin->object_path != NULL && origin->object_path[0] != '\0' &&
        trace.object_path == NULL) {
      goto fail;
    }
    trace.detail = dup_optional(origin->detail, err);
    if (origin->detail != NULL && origin->detail[0] != '\0' && trace.detail == NULL) {
      goto fail;
    }
    trace.access = dup_optional(origin->access, err);
    if (origin->access != NULL && origin->access[0] != '\0' && trace.access == NULL) {
      goto fail;
    }
    trace.location = dup_optional(origin->location, err);
    if (origin->location != NULL && origin->location[0] != '\0' && trace.location == NULL) {
      goto fail;
    }
  }

  if (ensure_trace_capacity(requirements, err) != 0) {
    goto fail;
  }

  requirements->traces[requirements->trace_count++] = trace;
  return 0;

fail:
  free_trace(&trace);
  return -1;
}

static const char *source_name(enum mch_requirement_source source) {
  switch (source) {
  case MCH_REQUIREMENT_SOURCE_OBJECT_BTF:
    return "object BTF";
  case MCH_REQUIREMENT_SOURCE_CORE_RELO:
    return "CO-RE relocation";
  case MCH_REQUIREMENT_SOURCE_UNKNOWN:
  default:
    return "unknown";
  }
}

static const char *type_name_or_anonymous(const struct btf *btf, const struct btf_type *type) {
  const char *name = mch_btf_type_name(btf, type);

  return name[0] == '\0' ? "<anonymous>" : name;
}

static const char *member_name_or_anonymous(const struct btf *btf,
                                            const struct btf_member *member) {
  const char *name = btf__name_by_offset(btf, member->name_off);

  return name == NULL || name[0] == '\0' ? "<anonymous>" : name;
}

int mch_requirements_init(struct mch_requirements *requirements, size_t type_count) {
  if (requirements == NULL) {
    return -1;
  }

  memset(requirements, 0, sizeof(*requirements));
  requirements->type_root_words_count = word_count_for_bits(type_count);
  requirements->type_root_words =
      calloc(requirements->type_root_words_count, sizeof(*requirements->type_root_words));
  requirements->record_member_words =
      calloc(type_count == 0 ? 1 : type_count, sizeof(*requirements->record_member_words));
  requirements->record_member_counts =
      calloc(type_count == 0 ? 1 : type_count, sizeof(*requirements->record_member_counts));
  if (requirements->type_root_words == NULL || requirements->record_member_words == NULL ||
      requirements->record_member_counts == NULL) {
    mch_requirements_destroy(requirements);
    return -1;
  }

  requirements->type_count = type_count;
  return 0;
}

void mch_requirements_destroy(struct mch_requirements *requirements) {
  if (requirements == NULL) {
    return;
  }
  if (requirements->record_member_words != NULL) {
    for (size_t i = 0; i < requirements->type_count; i++) {
      free(requirements->record_member_words[i]);
    }
  }
  for (size_t i = 0; i < requirements->trace_count; i++) {
    free_trace(&requirements->traces[i]);
  }
  free(requirements->traces);
  free(requirements->record_member_counts);
  free(requirements->record_member_words);
  free(requirements->type_root_words);
  memset(requirements, 0, sizeof(*requirements));
}

bool mch_requirements_contains_type_root(const struct mch_requirements *requirements,
                                         size_t type_id) {
  if (requirements == NULL) {
    return false;
  }
  return bitset_contains(requirements->type_root_words, requirements->type_count, type_id);
}

int mch_requirements_add_type_root(struct mch_requirements *requirements, size_t type_id,
                                   const struct mch_requirement_origin *origin,
                                   struct mch_error *err) {
  if (requirements == NULL) {
    return 0;
  }
  if (requirements->type_root_words == NULL || type_id >= requirements->type_count) {
    mch_error_set(err, "requirements reference invalid type id %zu", type_id);
    return -1;
  }
  if (bitset_contains(requirements->type_root_words, requirements->type_count, type_id)) {
    return 0;
  }
  if (append_trace(requirements, MCH_REQUIREMENT_TRACE_TYPE_ROOT, type_id, 0, origin, err) != 0) {
    return -1;
  }
  bitset_add(requirements->type_root_words, requirements->type_count, type_id);
  requirements->type_roots++;
  return 0;
}

bool mch_requirements_has_record_members(const struct mch_requirements *requirements,
                                         size_t type_id) {
  return requirements != NULL && requirements->record_member_words != NULL &&
         type_id < requirements->type_count && requirements->record_member_words[type_id] != NULL;
}

bool mch_requirements_contains_record_member(const struct mch_requirements *requirements,
                                             size_t type_id, size_t member_index) {
  if (!mch_requirements_has_record_members(requirements, type_id)) {
    return false;
  }

  return bitset_contains(requirements->record_member_words[type_id],
                         requirements->record_member_counts[type_id], member_index);
}

int mch_requirements_add_record_member(const struct btf *btf, struct mch_requirements *requirements,
                                       size_t type_id, size_t member_index,
                                       const struct mch_requirement_origin *origin,
                                       struct mch_error *err) {
  const struct btf_type *type;
  size_t member_count;

  if (requirements == NULL) {
    return 0;
  }
  if (btf == NULL || requirements->record_member_words == NULL ||
      requirements->record_member_counts == NULL || type_id >= requirements->type_count) {
    mch_error_set(err, "requirements reference invalid type id %zu", type_id);
    return -1;
  }

  type = btf__type_by_id(btf, (__u32)type_id);
  if (type == NULL || (btf_kind(type) != BTF_KIND_STRUCT && btf_kind(type) != BTF_KIND_UNION)) {
    mch_error_set(err, "requirements reference non-record type id %zu", type_id);
    return -1;
  }

  member_count = btf_vlen(type);
  if (member_index >= member_count) {
    mch_error_set(err, "requirements reference invalid member %zu on type id %zu", member_index,
                  type_id);
    return -1;
  }

  if (requirements->record_member_words[type_id] == NULL) {
    size_t words = word_count_for_bits(member_count);

    requirements->record_member_words[type_id] =
        calloc(words, sizeof(*requirements->record_member_words[type_id]));
    if (requirements->record_member_words[type_id] == NULL) {
      mch_error_set(err, "out of memory while recording required record members");
      return -1;
    }
    requirements->record_member_counts[type_id] = member_count;
  }

  if (bitset_contains(requirements->record_member_words[type_id],
                      requirements->record_member_counts[type_id], member_index)) {
    return 0;
  }
  if (append_trace(requirements, MCH_REQUIREMENT_TRACE_RECORD_MEMBER, type_id, member_index, origin,
                   err) != 0) {
    return -1;
  }
  bitset_add(requirements->record_member_words[type_id],
             requirements->record_member_counts[type_id], member_index);
  requirements->record_members++;
  return 0;
}

void mch_requirements_stats(const struct mch_requirements *requirements,
                            struct mch_requirement_stats *stats) {
  if (stats == NULL) {
    return;
  }
  if (requirements == NULL) {
    memset(stats, 0, sizeof(*stats));
    return;
  }
  stats->type_roots = requirements->type_roots;
  stats->record_members = requirements->record_members;
  stats->traces = requirements->trace_count;
}

int mch_requirements_write_explanation(FILE *out, const struct btf *btf,
                                       const struct mch_requirements *requirements,
                                       struct mch_error *err) {
  if (out == NULL || btf == NULL || requirements == NULL) {
    return 0;
  }

  fprintf(out, "requirements:\n");
  if (requirements->trace_count == 0) {
    fprintf(out, "  direct requirements: 0\n");
    if (ferror(out)) {
      mch_error_set(err, "failed to write requirement witness");
      return -1;
    }
    return 0;
  }

  for (size_t i = 0; i < requirements->trace_count; i++) {
    const struct mch_requirement_trace *trace = &requirements->traces[i];
    const struct btf_type *type = btf__type_by_id(btf, trace->type_id);

    if (type == NULL) {
      mch_error_set(err, "requirement trace references missing type id %u", trace->type_id);
      return -1;
    }

    if (trace->kind == MCH_REQUIREMENT_TRACE_RECORD_MEMBER) {
      const struct btf_member *members = btf_members(type);
      if (trace->member_index >= btf_vlen(type)) {
        mch_error_set(err, "requirement trace references missing member %u on type id %u",
                      trace->member_index, trace->type_id);
        return -1;
      }
      fprintf(out, "  - member: %s %s.%s", btf_kind(type) == BTF_KIND_UNION ? "union" : "struct",
              type_name_or_anonymous(btf, type),
              member_name_or_anonymous(btf, &members[trace->member_index]));
    } else {
      fprintf(out, "  - root: %s %s", mch_btf_kind_name(btf_kind(type)),
              type_name_or_anonymous(btf, type));
    }

    fprintf(out, "; source: %s", source_name(trace->source));
    if (trace->detail != NULL) {
      fprintf(out, " %s", trace->detail);
    }
    if (trace->access != NULL) {
      fprintf(out, "; access: %s", trace->access);
    }
    if (trace->location != NULL) {
      fprintf(out, "; location: %s", trace->location);
    }
    if (trace->object_path != NULL) {
      fprintf(out, "; file: %s", trace->object_path);
    }
    fputc('\n', out);
  }

  if (ferror(out)) {
    mch_error_set(err, "failed to write requirement witness");
    return -1;
  }
  return 0;
}
