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

