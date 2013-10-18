#include "segment.h"

struct segment_list* segment_list_ctor(uint32_t count) {
  struct segment_list* self = calloc(1, sizeof(*self));
  self->count = count;
  self->list = calloc(count, sizeof(struct segment));
  return self;
}

void segment_list_dtor(struct segment_list** selfp) {
  struct segment_list* self = *selfp;
  if (self == NULL) return;
  free(self->list);
  free(self);
  *selfp = NULL;
}

void segment_list_print(const struct segment_list* self, FILE* output) {
  for (uint32_t i = 0; i < self->count; ++i) {
    const struct segment* seg = self->list + i;
    fprintf(output, "%6" PRIu32 " [%8" PRIu64 ",%8" PRIu64 ")\n        ", i, seg->start, seg->start+seg->length);
    for (int index = 0; index < sizeof(seg->hash); ++index) {
      fprintf(output, "%02" PRIX8 "", seg->hash[index]);
    }
    fprintf(output, "\n");
  }
}

