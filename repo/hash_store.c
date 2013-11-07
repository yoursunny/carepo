#include "hash_store.h"
#include <ndn/digest.h>
#include <sys/stat.h>
#include <errno.h>
#include "segment/segment.h"
#include "ndnr_store.h"

struct content_entry {
  ndnr_accession accession;
  ndnr_cookie cookie;
  int flags;
  int size;
  struct ndn_charbuf* flatname;
  struct ndn_charbuf* cob;
};


struct hash_store* hash_store_ctor(struct ndnr_handle* h) {
  struct hash_store* self = calloc(1, sizeof(*self));
  self->h = h;
  h->hashstore = self;
  
  // open btree with disk IO
  struct ndn_charbuf* path = ndn_charbuf_create();
  ndn_charbuf_putf(path, "%s/hashstore", h->directory);
  int res = mkdir(ndn_charbuf_as_string(path), 0700);
  if (res != 0 && errno != EEXIST) { free(self); ndn_charbuf_destroy(&path); return NULL; }
  self->btree = ndn_btree_create();
  self->btree->io = ndn_btree_io_from_directory(ndn_charbuf_as_string(path), NULL);
  if (self->btree->io == NULL) { free(self); ndn_charbuf_destroy(&path); ndn_btree_destroy(&self->btree); return NULL; }
  ndn_charbuf_destroy(&path);

  struct ndn_btree_node* node = ndn_btree_getnode(self->btree, 1, 0);
  self->btree->nextnodeid = self->btree->io->maxnodeid + 1;
  if (node->buf->length == 0) {
    res = ndn_btree_init_node(node, 0, 'R', 0);
  }
  
  LOG("hash_store_ctor\n");
  return self;
}

void hash_store_dtor(struct hash_store** selfp) {
  struct hash_store* self = *selfp;
  if (self == NULL) return;
// TODO stable mark
  ndn_btree_destroy(&self->btree);
  free(self);
  *selfp = NULL;
  LOG("hash_store_dtor\n");
}

bool hash_store_insert(struct hash_store* self, ndnr_accession accession, struct ndn_charbuf* co, struct ndn_parsed_ContentObject* pco) {
  int res;
  // retrieve payload
  struct ndn_parsed_ContentObject pco2 = {0};
  if (pco == NULL) {
    res = ndn_parse_ContentObject(co->buf, co->length, pco = &pco2, NULL);
    if (res != 0) return false;
  }
  const uint8_t* payload; size_t payloadsz;
  ndn_content_get_value(co->buf, co->length, pco, &payload, &payloadsz);
  // calculate hash
  uint8_t hash[SEGMENT_HASHSZ];
  struct ndn_digest* digest = ndn_digest_create(NDN_DIGEST_SHA256);
  ndn_digest_init(digest);
  ndn_digest_update(digest, payload, payloadsz);
  ndn_digest_final(digest, hash, sizeof(hash));
  ndn_digest_destroy(&digest);

  LOG("hash_store_insert(%" PRIx64 ") ", (uint64_t)ndnr_accession_encode(self->h, accession));
  LOG_hash(hash, SEGMENT_HASHSZ);
  
  // find where to insert
  struct ndn_btree_node* leaf = NULL;
  res = ndn_btree_lookup(self->btree, hash, sizeof(hash), &leaf);
  int i = NDN_BT_SRCH_INDEX(res);
  if (NDN_BT_SRCH_FOUND(res)) {
    LOG(" duplicate(%u,%d)\n", leaf->nodeid, i);
    return true;// already have it
  }
  LOG(" insert(%u,%d)\n", leaf->nodeid, i);
  
  // prepare payload
  uint64_t accession_encoded = ndnr_accession_encode(self->h, accession);
  // insert index entry
  res = ndn_btree_prepare_for_update(self->btree, leaf);
  if (res < 0) return false;
  res = ndn_btree_insert_entry(leaf, i, hash, sizeof(hash), &accession_encoded, sizeof(accession_encoded));
  if (res < 0) return false;

  // btree maintenance
  if (ndn_btree_oversize(self->btree, leaf)) {
    res = ndn_btree_split(self->btree, leaf);
    for (int limit = 100; res >= 0 && self->btree->nextsplit != 0; --limit) {
      if (limit == 0) abort();
      struct ndn_btree_node* node = ndn_btree_getnode(self->btree, self->btree->nextsplit, 0);
      if (node == NULL) break;
      res = ndn_btree_split(self->btree, node);
    }
  }
  
  hash_store_clean(self);
  return true;
}

// TODO deferred cleaning
void hash_store_clean(struct hash_store* self) {
  struct hashtb_enumerator ee; struct hashtb_enumerator* e = &ee;
  hashtb_start(self->btree->resident, e);
  int overquota = 0;
  if (self->btree->nodepool >= 16) overquota = hashtb_n(self->btree->resident) - self->btree->nodepool;
  for (struct ndn_btree_node* node = e->data; node != NULL; node = e->data) {
    if (overquota > 0 && node->activity == 0 && node->iodata == NULL && node->clean == node->buf->length) {
      --overquota;
      hashtb_delete(e);
      continue;
    }
    //node->activity /= 2;
    node->activity = 0;
    if (node->clean != node->buf->length || (node->iodata != NULL && node->activity == 0)) {
      int res = ndn_btree_chknode(node);
      if (res < 0) continue;
      if (node->clean != node->buf->length) {
        res = self->btree->io->btwrite(self->btree->io, node);
        if (res < 0) continue;
        node->clean = node->buf->length;
      }
      if (node->iodata != NULL && node->activity == 0) {
        res = ndn_btree_close_node(self->btree, node);
      }
    }
    hashtb_next(e);
  }
  hashtb_end(e);
}

ndnr_accession hash_store_find(struct hash_store* self, const uint8_t* hash) {
  // find entry
  struct ndn_btree_node* leaf = NULL;
  int res = ndn_btree_lookup(self->btree, hash, SEGMENT_HASHSZ, &leaf);
  if (!NDN_BT_SRCH_FOUND(res)) return NDNR_NULL_ACCESSION;// not have it
  int i = NDN_BT_SRCH_INDEX(res);
  
  // read entry
  uint64_t accession_encoded;
  uint64_t* accession_p = ndn_btree_node_getentry(sizeof(accession_encoded), leaf, i);
  accession_encoded = *accession_p;
  return ndnr_accession_decode(self->h, accession_encoded);
}

enum ndn_upcall_res hash_store_handle_proto_sha256(struct hash_store* self, struct ndn_upcall_info* info) {
  int res;
  // extract hash
  const uint8_t* hash; size_t hashsz;
  res = ndn_name_comp_get(info->interest_ndnb, info->interest_comps, 1, &hash, &hashsz);
  if (res != 0 || hashsz != SEGMENT_HASHSZ) return NDN_UPCALL_RESULT_ERR;
  LOG("hash_store_handle_proto_sha256("); LOG_hash(hash, hashsz); LOG(") ");
  
  // find content
  ndnr_accession accession = hash_store_find(self, hash);
  if (accession == NDNR_NULL_ACCESSION) {
    LOG("MISS\n");
    return NDN_UPCALL_RESULT_OK;
  }
  struct content_entry* orig_content = r_store_content_from_accession(self->h, accession);
  if (orig_content == NULL) { LOG("LOST\n"); return NDN_UPCALL_RESULT_OK; }
  if (orig_content->cob == NULL && r_store_content_base(self->h, orig_content) == NULL) { LOG("LOST\n"); return NDN_UPCALL_RESULT_OK; }
  LOG("HIT %" PRIx64 ", ", (uint64_t)ndnr_accession_encode(self->h, accession));

  // extract payload
  struct ndn_parsed_ContentObject orig_pco = {0};
  res = ndn_parse_ContentObject(orig_content->cob->buf, orig_content->cob->length, &orig_pco, NULL);
  if (res != 0) { LOG("cannot parse\n"); return NDN_UPCALL_RESULT_OK; }
  const uint8_t* payload; size_t payloadsz;
  res = ndn_content_get_value(orig_content->cob->buf, orig_content->cob->length, &orig_pco, &payload, &payloadsz);
  if (res != 0) { LOG("cannot extract payload\n"); return NDN_UPCALL_RESULT_OK; }
  
  // verify hash
  uint8_t hash2[SEGMENT_HASHSZ];
  struct ndn_digest* digest = ndn_digest_create(NDN_DIGEST_SHA256);
  ndn_digest_init(digest);
  ndn_digest_update(digest, payload, payloadsz);
  ndn_digest_final(digest, hash2, sizeof(hash2));
  ndn_digest_destroy(&digest);
  if (0 != memcmp(hash, hash2, sizeof(hash2))) { LOG("hash mismatch\n"); return NDN_UPCALL_RESULT_OK; }
  
  // build reply co TODO don't sign
  struct ndn_charbuf name;
  name.buf = (uint8_t*)info->interest_ndnb + info->pi->offset[NDN_PI_B_Name];
  name.length = info->pi->offset[NDN_PI_E_Name] - info->pi->offset[NDN_PI_B_Name];
  struct ndn_charbuf* co = ndn_charbuf_create();
  res = ndn_sign_content(info->h, co, &name, NULL, payload, payloadsz);
  if (res != 0) { LOG("cannot sign\n"); ndn_charbuf_destroy(&co); return NDN_UPCALL_RESULT_OK; }
  
  // send reply TODO use queues
  res = ndn_put(info->h, co->buf, co->length);
  if (res != 0) { LOG("cannot send\n"); ndn_charbuf_destroy(&co); return NDN_UPCALL_RESULT_OK; }
  ndn_charbuf_destroy(&co);
  LOG("OK\n");
  return NDN_UPCALL_RESULT_INTEREST_CONSUMED;
}

