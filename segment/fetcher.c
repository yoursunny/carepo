#include "fetcher.h"
#include <ndn/digest.h>

struct file_fetcher* file_fetcher_ctor(struct segment_list* sl, FILE* file, struct ndn* h, struct ndn_charbuf* name) {
  struct file_fetcher* self = calloc(1, sizeof(*self));
  self->h = h;
  self->sl = sl;
  self->file = file;

  self->name = ndn_charbuf_create();
  ndn_charbuf_append_charbuf(self->name, name);
  self->name_comps = ndn_indexbuf_create();
  ndn_name_split(self->name, self->name_comps);
  if (self->name_comps->n >= 2) {
    const uint8_t* comp; size_t compsz;
    int res = ndn_name_comp_get(self->name->buf, self->name_comps, self->name_comps->n-2, &comp, &compsz);
    if (res == -1 || compsz == 0 || comp[0] != (uint8_t)'\xFD') {
      LOG("file_fetcher_ctor WARNING name has no version\n");
    }
  } else {
    LOG("file_fetcher_ctor WARNING name too short\n");
  }
  
  return self;
}

void file_fetcher_dtor(struct file_fetcher** selfp) {
}

bool file_fetcher_run(struct file_fetcher* self) {
  file_fetcher_build_reqs(self);
  
  while (self->ok_reqs < self->total_reqs) {
    file_fetcher_next_reqs(self);
    ndn_run(self->h, 10);
    if (self->fail_reqs > 0) return false;
  }
  LOG("file_fetcher_run %" PRIu32 " segments fulfilled by %d hashreqs and %d namereqs\n", self->sl->count, self->complete_hashreqs, self->complete_namereqs);
  return true;
}

void file_fetcher_build_reqs(struct file_fetcher* self) {
  self->reqs = calloc(self->sl->count, sizeof(struct file_fetcher_req));
  for (uint32_t i = 0; i < self->sl->count; ++i) {
    const struct segment* seg = self->sl->list + i;
    bool duplicate = false;
    for (int j = 0; j < self->total_reqs; ++j) {
      struct file_fetcher_req* req = self->reqs + j;
      if (0 == memcmp(seg->hash, req->hash, sizeof(seg->hash))) {
        duplicate = true;
        ndn_indexbuf_append_element(req->i, i);
        break;
      }
    }
    if (!duplicate) {
      struct file_fetcher_req* req = self->reqs + self->total_reqs;
      ++self->total_reqs;
      req->hash = seg->hash;
      req->i = ndn_indexbuf_create();
      ndn_indexbuf_append_element(req->i, i);
    }
  }
  LOG("file_fetcher_build_reqs %" PRIu32 " segments, %d requests\n", self->sl->count, self->total_reqs);
}

void file_fetcher_next_reqs(struct file_fetcher* self) {
  for (int j = 0; j < self->total_reqs; ++j) {
    struct file_fetcher_req* req = self->reqs + j;
    if (req->status == FILE_FETCHER_REQ_HWAIT && self->outstanding_hashreqs < FILE_FETCHER_HASHREQ_CONCURRENT) {
      file_fetcher_send_hashreq(self, j);
    } else if (req->status == FILE_FETCHER_REQ_NWAIT && self->outstanding_namereqs < FILE_FETCHER_NAMEREQ_CONCURRENT) {
      file_fetcher_send_namereq(self, j);
    }
  }
}

void file_fetcher_send_hashreq(struct file_fetcher* self, int j) {
  struct file_fetcher_req* req = self->reqs + j;
  //LOG("file_fetcher_send_hashreq NOT-IMPLEMENTED\n");
  req->status = FILE_FETCHER_REQ_NWAIT;
}

void file_fetcher_send_namereq(struct file_fetcher* self, int j) {
  struct file_fetcher_req* req = self->reqs + j;
  req->reexpress_limit = FILE_FETCHER_NAMEREQ_REEXPRESS;
  ++self->outstanding_namereqs;

  struct ndn_charbuf* name = ndn_charbuf_create();
  ndn_charbuf_append_charbuf(name, self->name);
  ndn_name_append_numeric(name, NDN_MARKER_SEQNUM, req->i->buf[0]);
  
  struct ndn_closure* closure = calloc(1, sizeof(*closure));
  closure->p = &file_fetcher_incoming_co_namereq;
  closure->data = self;
  closure->intdata = j;
  
  ndn_express_interest(self->h, name, closure, NULL);
  LOG("file_fetcher_send_namereq %d ", j); LOG_name(name->buf, name->length); LOG("\n");

  ndn_charbuf_destroy(&name);
}

enum ndn_upcall_res file_fetcher_incoming_co_hashreq(struct ndn_closure* closure, enum ndn_upcall_kind kind, struct ndn_upcall_info* info) {
  return NDN_UPCALL_RESULT_OK;
}

enum ndn_upcall_res file_fetcher_incoming_co_namereq(struct ndn_closure* closure, enum ndn_upcall_kind kind, struct ndn_upcall_info* info) {
  if (kind == NDN_UPCALL_FINAL) { free(closure); return NDN_UPCALL_RESULT_OK; }
  struct file_fetcher* self = closure->data;
  int j = (int)closure->intdata;
  struct file_fetcher_req* req = self->reqs + j;
  
  if (kind == NDN_UPCALL_INTEREST_TIMED_OUT) {
    if (--req->reexpress_limit >= 0) {
      LOG("file_fetcher_incoming_co_namereq %d REEXPRESS\n", j); 
      return NDN_UPCALL_RESULT_REEXPRESS;
    }
    --self->outstanding_namereqs;
    ++self->fail_reqs;
    req->status = FILE_FETCHER_REQ_FAIL;
    LOG("file_fetcher_incoming_co_namereq %d TIMEOUT\n", j); 
  }
  
  if (kind == NDN_UPCALL_CONTENT || kind == NDN_UPCALL_CONTENT_UNVERIFIED || kind == NDN_UPCALL_CONTENT_BAD || kind == NDN_UPCALL_CONTENT_KEYMISSING || kind == NDN_UPCALL_CONTENT_RAW) {
    --self->outstanding_namereqs;
    ++self->complete_namereqs;
    file_fetcher_save_co(self, req, info);
  }
  
  return NDN_UPCALL_RESULT_OK;
}

void file_fetcher_save_co(struct file_fetcher* self, struct file_fetcher_req* req, struct ndn_upcall_info* info) {
#define RETURN_FAIL { ++self->fail_reqs; req->status = FILE_FETCHER_REQ_FAIL; return; }
  const uint8_t* payload; size_t payloadsz;
  int res = ndn_content_get_value(info->content_ndnb, info->pco->offset[NDN_PCO_E], info->pco, &payload, &payloadsz);
  if (res != 0) { LOG("file_fetcher_save_co cannot get payload"); RETURN_FAIL; }
  
  struct segment seghash;
  struct ndn_digest* digest = ndn_digest_create(NDN_DIGEST_SHA256);
  ndn_digest_init(digest);
  ndn_digest_update(digest, payload, payloadsz);
  ndn_digest_final(digest, seghash.hash, sizeof(seghash.hash));
  ndn_digest_destroy(&digest);
  if (0 != memcmp(seghash.hash, req->hash, sizeof(seghash.hash))) { LOG("file_fetcher_save_co hash mismatch"); RETURN_FAIL; }
  
  for (size_t k = 0; k < req->i->n; ++k) {
    uint32_t i = (uint32_t)req->i->buf[k];
    struct segment* seg = self->sl->list + i;
    if (payloadsz != seg->length) { LOG("file_fetcher_save_co length mismatch"); RETURN_FAIL; }
    if (0 != fseek(self->file, seg->start, SEEK_SET)) RETURN_FAIL;
    size_t write_size = 0;
    while (write_size < payloadsz) {
      size_t write_want = payloadsz - write_size;
      size_t write_res = fwrite(payload + write_size, 1, write_want, self->file);
      if (write_res == 0) { LOG("file_fetcher_save_co cannot write"); RETURN_FAIL; }
      write_size += write_res;
    }
  }
  
#undef RETURN_FAIL
  ++self->ok_reqs;
  req->status = FILE_FETCHER_REQ_OK;
}

