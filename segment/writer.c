#include "writer.h"
#include <ndn/uri.h>

struct file_writer* file_writer_ctor(struct segment_list* sl, FILE* file, struct ndn* h, struct ndn_charbuf* name, bool sign_segments) {
  struct file_writer* self = calloc(1, sizeof(*self));
  self->h = h;
  self->file = file;

  self->name = ndn_charbuf_create();
  ndn_charbuf_append_charbuf(self->name, name);
  ndn_create_version(self->h, self->name, NDN_V_NOW, 0, 0);
  self->name_comps = ndn_indexbuf_create();
  ndn_name_split(self->name, self->name_comps);
  self->sl = sl;
  self->sign_segments = sign_segments;
  self->sent_segments = calloc(sl->count, sizeof(bool));
  self->remaining_segments = sl->count;

  self->metadata_name = ndn_charbuf_create();
  ndn_charbuf_append_charbuf(self->metadata_name, self->name);
  ndn_name_from_uri(self->metadata_name, "%C1.META/SHA256");
  ndn_create_version(self->h, self->metadata_name, NDN_V_NOW, 0, 0);
  self->metadata = ndn_charbuf_create();
  segment_list_to_metadata(sl, self->metadata);
  self->total_metadata_blocks = self->remaining_metadata_blocks = self->metadata->length/FILE_WRITER_METADATA_BLOCKSZ + (self->metadata->length%FILE_WRITER_METADATA_BLOCKSZ == 0 ? 0 : 1);
  self->sent_metadata_blocks = calloc(self->total_metadata_blocks, sizeof(bool));
  return self;
}

void file_writer_dtor(struct file_writer** selfp) {
  struct file_writer* self = *selfp;
  if (self == NULL) return;
  ndn_charbuf_destroy(&self->name);
  ndn_indexbuf_destroy(&self->name_comps);
  ndn_charbuf_destroy(&self->metadata_name);
  free(self->sent_segments);
  free(self->sent_metadata_blocks);
  free(self);
  *selfp = NULL;
}

bool file_writer_run(struct file_writer* self) {
  int res;
  self->closure = calloc(1, sizeof(*self->closure));
  self->closure->p = &file_writer_incoming_interest;
  self->closure->data = self;
  res = ndn_set_interest_filter(self->h, self->name, self->closure);
  if (res < 0) return false;
  
  if (!file_writer_startwrite(self)) return false;
  
  do {
    self->recent_interests = 0;
    ndn_run(self->h, FILE_WRITER_RUN_TIMEOUT_INTERVAL);
  } while ((self->remaining_segments > 0 || self->remaining_metadata_blocks > 0) && (self->recent_interests > 0));
  if (self->remaining_segments == 0 && self->remaining_metadata_blocks == 0) {
    ndn_set_interest_filter(self->h, self->name, NULL);
    ndn_run(self->h, 1);
    return true;
  }
  return false;
}

bool file_writer_startwrite(struct file_writer* self) {
  int res;

  struct ndn_charbuf* sw_name = ndn_charbuf_create();
  ndn_charbuf_append_charbuf(sw_name, self->name);
  ndn_name_from_uri(sw_name, "%C1.R.sw");
  ndn_name_append_nonce(sw_name);
  res = ndn_get(self->h, sw_name, NULL, FILE_WRITER_STARTWRITE_TIMEOUT, NULL, NULL, NULL, 0);
  if (res < 0) { ndn_charbuf_destroy(&sw_name); return false; }
  
  ndn_charbuf_reset(sw_name);
  ndn_charbuf_append_charbuf(sw_name, self->metadata_name);
  ndn_name_from_uri(sw_name, "%C1.R.sw");
  ndn_name_append_nonce(sw_name);
  res = ndn_get(self->h, sw_name, NULL, FILE_WRITER_STARTWRITE_TIMEOUT, NULL, NULL, NULL, 0);
  if (res < 0) { ndn_charbuf_destroy(&sw_name); return false; }
  
  ndn_charbuf_destroy(&sw_name); return true;
}

enum ndn_upcall_res file_writer_incoming_interest(struct ndn_closure* closure, enum ndn_upcall_kind kind, struct ndn_upcall_info* info) {
  if (kind == NDN_UPCALL_FINAL) free(closure);
  struct file_writer* self = closure->data;
  assert(self != NULL && closure == self->closure);
  if (kind != NDN_UPCALL_INTEREST) return NDN_UPCALL_RESULT_OK;
  
  ++self->recent_interests;
  bool ok = false;
  if (info->pi->prefix_comps == self->name_comps->n) {
    ok = file_writer_respond_segment(self, info);
  } else if (info->pi->prefix_comps == self->name_comps->n + 3) {
    ok = file_writer_respond_metadata(self, info);
  }
  return ok ? NDN_UPCALL_RESULT_INTEREST_CONSUMED : NDN_UPCALL_RESULT_OK;
}

uintmax_t file_writer_extract_number(struct ndn_upcall_info* info) {
  const uint8_t* comp; size_t compsz;
  int res = ndn_name_comp_get(info->interest_ndnb, info->interest_comps, info->pi->prefix_comps-1, &comp, &compsz);
  if (res == -1 || compsz == 0 || comp[0] != '\0') return (uintmax_t)-1;
  uintmax_t n = 0;
  for (size_t i = 1; i < compsz; ++i) {
    n = (n << 8) + comp[i];
  }
  return n;
}

bool file_writer_respond_segment(struct file_writer* self, struct ndn_upcall_info* info) {
  uint32_t seg_i = (uint32_t)file_writer_extract_number(info);
  if (seg_i >= self->sl->count) return false;
  if (!self->sent_segments[seg_i]) {
    self->sent_segments[seg_i] = true;
    --self->remaining_segments;
  }
  struct segment* seg = self->sl->list + seg_i;
  
  struct ndn_charbuf* reply = ndn_charbuf_create();
  if (self->sign_segments) {
    file_writer_segment_sign(self, reply, info, seg_i, seg);
  } else {
    file_writer_segment_hash(self, reply, info, seg_i, seg);
  }
  
  ndn_put(self->h, reply->buf, reply->length);
  ndn_charbuf_destroy(&reply);
  return true;
}

bool file_writer_segment_sign(struct file_writer* self, struct ndn_charbuf* reply, struct ndn_upcall_info* info, uint32_t seg_i, struct segment* seg) {
  struct ndn_charbuf* c = ndn_charbuf_create();
  if (!file_writer_segment_readfile(self, c, seg)) { ndn_charbuf_destroy(&c); return false; }

  struct ndn_charbuf* name = ndn_charbuf_create();
  ndn_charbuf_append(name, info->interest_ndnb+info->pi->offset[NDN_PI_B_Name], info->pi->offset[NDN_PI_E_Name]-info->pi->offset[NDN_PI_B_Name]);
  
  struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
  if (seg_i+1 == self->sl->count) {
    sp.sp_flags |= NDN_SP_FINAL_BLOCK;
  }
  
  int res = ndn_sign_content(self->h, reply, name, &sp, c->buf, c->length);

  ndn_charbuf_destroy(&name);
  ndn_charbuf_destroy(&c);
  return res==0;
}

bool file_writer_segment_hash(struct file_writer* self, struct ndn_charbuf* reply, struct ndn_upcall_info* info, uint32_t seg_i, struct segment* seg) {
  ndnb_element_begin(reply, NDN_DTAG_ContentObject);

  ndnb_element_begin(reply, NDN_DTAG_Signature);
  ndnb_tagged_putf(reply, NDN_DTAG_DigestAlgorithm, "SHA256");
  ndnb_append_tagged_blob(reply, NDN_DTAG_SignatureBits, seg->hash, sizeof(seg->hash));
  ndnb_element_end(reply);//Signature
  
  ndn_charbuf_append(reply, info->interest_ndnb+info->pi->offset[NDN_PI_B_Name], info->pi->offset[NDN_PI_E_Name]-info->pi->offset[NDN_PI_B_Name]);
  
  ndnb_element_begin(reply, NDN_DTAG_SignedInfo);
  ndnb_append_tagged_blob(reply, NDN_DTAG_PublisherPublicKeyDigest, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32);
  ndnb_element_begin(reply, NDN_DTAG_Timestamp);
  ndnb_append_now_blob(reply, NDN_MARKER_NONE);
  ndnb_element_end(reply);//Timestamp
  if (seg_i+1 == self->sl->count) {
    const uint8_t* comp; size_t compsz;
    ndn_name_comp_get(info->interest_ndnb, info->interest_comps, info->pi->prefix_comps-1, &comp, &compsz);
    ndnb_element_begin(reply, NDN_DTAG_FinalBlockID);
    ndn_charbuf_append_tt(reply, compsz, NDN_BLOB);
    ndn_charbuf_append(reply, comp, compsz);
    ndnb_element_end(reply);//FinalBlockID
  }
  ndnb_element_end(reply);//SignedInfo
  
  ndnb_element_begin(reply, NDN_DTAG_Content);
  ndn_charbuf_append_tt(reply, seg->length, NDN_BLOB);
  if (!file_writer_segment_readfile(self, reply, seg)) return false;
  ndnb_element_end(reply);//Content

  ndnb_element_end(reply);//ContentObject
  return true;
}

bool file_writer_segment_readfile(struct file_writer* self, struct ndn_charbuf* c, struct segment* seg) {
  if (0 != fseek(self->file, seg->start, SEEK_SET)) return false;
  size_t read_size = 0;
  uint8_t* buffer = ndn_charbuf_reserve(c, seg->length);
  while (read_size < seg->length) {
    size_t read_want = seg->length - read_size;
    size_t read_res = fread(buffer + read_size, 1, read_want, self->file);
    if (read_res == 0) return false;
    read_size += read_res;
  }
  c->length += seg->length;
  return true;
}

bool file_writer_respond_metadata(struct file_writer* self, struct ndn_upcall_info* info) {
  uintmax_t seg_i = file_writer_extract_number(info);
  if (seg_i >= self->total_metadata_blocks) return false;
  if (!self->sent_metadata_blocks[seg_i]) {
    self->sent_metadata_blocks[seg_i] = true;
    --self->remaining_metadata_blocks;
  }
  
  struct ndn_charbuf* name = ndn_charbuf_create();
  ndn_charbuf_append(name, info->interest_ndnb+info->pi->offset[NDN_PI_B_Name], info->pi->offset[NDN_PI_E_Name]-info->pi->offset[NDN_PI_B_Name]);
  
  struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
  if (seg_i+1 == self->total_metadata_blocks) {
    sp.sp_flags |= NDN_SP_FINAL_BLOCK;
  }
  
  struct ndn_charbuf* reply = ndn_charbuf_create();
  int res = ndn_sign_content(self->h, reply, name, &sp, self->metadata->buf + FILE_WRITER_METADATA_BLOCKSZ*seg_i, seg_i+1 == self->total_metadata_blocks ? self->metadata->length-FILE_WRITER_METADATA_BLOCKSZ*seg_i : FILE_WRITER_METADATA_BLOCKSZ);
  ndn_charbuf_destroy(&name);

  ndn_put(self->h, reply->buf, reply->length);
  ndn_charbuf_destroy(&reply);
  return res==0;
}

