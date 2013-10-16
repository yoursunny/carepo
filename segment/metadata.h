#ifndef CAREPO_SEGMENT_METADATA_H_
#define CAREPO_SEGMENT_METADATA_H_
#include "segment.h"

void segment_list_to_metadata(const struct segment_list* self, struct ndn_charbuf* c);
struct segment_list* segment_list_from_metadata(const uint8_t* buf, size_t sz);

#endif//CAREPO_SEGMENT_METADATA_H_
