#ifndef CAREPO_SEGMENT_SEGMENT_H_
#define CAREPO_SEGMENT_SEGMENT_H_
#include "defs.h"

struct segment {
  uint64_t start;
  uint16_t length;
  uint8_t hash[32];
};

struct segment_list {
  uint32_t count;
  struct segment* list;
};

struct segment_list* segment_list_ctor(uint32_t count);
void segment_list_dtor(struct segment_list** selfp);
void segment_list_print(struct segment_list* self, FILE* output);

#endif//CAREPO_SEGMENT_SEGMENT_H_
