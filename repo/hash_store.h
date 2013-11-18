#ifndef CAREPO_REPO_HASH_STORE_H_
#define CAREPO_REPO_HASH_STORE_H_
#include "defs.h"
#include <ndn/btree.h>
#include "ndnr_private.h"

struct hash_store {
  struct ndnr_handle* h;
  struct ndn_btree* btree;
};

struct hash_store* hash_store_ctor(struct ndnr_handle* h);
void hash_store_dtor(struct hash_store** selfp);
bool hash_store_insert(struct hash_store* self, ndnr_accession accession, struct ndn_charbuf* co, struct ndn_parsed_ContentObject* pco);
ndnr_accession hash_store_find(struct hash_store* self, const uint8_t* hash);
enum ndn_upcall_res hash_store_handle_proto_sha256(struct hash_store* self, struct ndn_upcall_info* info);
// private begin
void hash_store_clean(struct hash_store* self);
bool hash_store_verify_hash(struct hash_store* self, const uint8_t* payload, size_t payloadsz, const uint8_t* expect_hash);
bool hash_store_build_reply(struct hash_store* self, struct ndn_charbuf* reply, const uint8_t* hash, const uint8_t* payload, size_t payloadsz);
// private end

// to send something: create content_entry* with cob without accession, ++h->cob_count, r_store_enroll_content

#endif//CAREPO_REPO_HASH_STORE_H_
