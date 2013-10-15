#ifndef CAREPO_SEGMENT_RABIN_H_
#define CAREPO_SEGMENT_RABIN_H_
#include "segment.h"

// segment a file according to Rabin Fingerprint boundary
struct segment_list* segment_rabin(FILE* file);

#endif//CAREPO_SEGMENT_RABIN_H_
