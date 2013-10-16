#include "metadata.h"

void segment_list_to_metadata(const struct segment_list* self, struct ndn_charbuf* c) {
  ndnb_element_begin(c, NDN_DTAG_Collection);
  ndnb_append_tagged_binary_number(c, NDN_DTAG_Count, self->count);
  for (uint32_t i = 0; i < self->count; ++i) {
    const struct segment* seg = self->list + i;
    ndnb_element_begin(c, NDN_DTAG_Entry);
    ndnb_append_tagged_binary_number(c, NDN_DTAG_Length, seg->length);
    ndnb_append_tagged_blob(c, NDN_DTAG_ContentHash, seg->hash, sizeof(seg->hash));
    ndnb_element_end(c);//Entry
  }
  ndnb_element_end(c);//Collection
}

struct segment_list* segment_list_from_metadata(const uint8_t* buf, size_t sz) {
  struct ndn_buf_decoder decoder; struct ndn_buf_decoder* d = ndn_buf_decoder_start(&decoder, buf, sz);
  if (!ndn_buf_match_dtag(d, NDN_DTAG_Collection)) return NULL;
  ndn_buf_advance(d);
  uintmax_t count = ndn_parse_required_tagged_binary_number(d, NDN_DTAG_Count, 0, 8);
  if (d->decoder.state < 0) return NULL;
  struct segment_list* self = segment_list_ctor((uint32_t)count);
#define return_FAIL { segment_list_dtor(&self); return NULL; }
  uint64_t start = 0;
  for (uint32_t i = 0; i < self->count; ++i) {
    struct segment* seg = self->list + i;
    if (!ndn_buf_match_dtag(d, NDN_DTAG_Entry)) return_FAIL;
    ndn_buf_advance(d);
    seg->length = (uint16_t)ndn_parse_required_tagged_binary_number(d, NDN_DTAG_Length, 0, 2);
    size_t offset_B_hash = d->decoder.token_index;
    ndn_parse_required_tagged_BLOB(d, NDN_DTAG_ContentHash, sizeof(seg->hash), sizeof(seg->hash));
    size_t offset_E_hash = d->decoder.token_index;
    if (d->decoder.state < 0) return_FAIL;
    seg->start = start;
    start += seg->length;
    const uint8_t* hash; size_t hash_sz;
    ndn_ref_tagged_BLOB(NDN_DTAG_ContentHash, buf, offset_B_hash, offset_E_hash, &hash, &hash_sz);
    assert(sizeof(seg->hash) == hash_sz);
    memcpy(seg->hash, hash, sizeof(seg->hash));
    ndn_buf_check_close(d);
  }
  ndn_buf_check_close(d);
  if (d->decoder.state < 0) return_FAIL;
#undef return_FAIL
  return self;
}

