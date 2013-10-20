#ifndef CAREPO_SEGMENT_WRITER_H_
#define CAREPO_SEGMENT_WRITER_H_
#include "metadata.h"

typedef uint8_t file_fetcher_req_status;
#define FILE_FETCHER_REQ_HWAIT 0
#define FILE_FETCHER_REQ_HSENT 1
#define FILE_FETCHER_REQ_NWAIT 2
#define FILE_FETCHER_REQ_NSENT 3
#define FILE_FETCHER_REQ_OK    4
#define FILE_FETCHER_REQ_FAIL  5

struct file_fetcher_req {
  file_fetcher_req_status status;
  const uint8_t* hash;
  struct ndn_indexbuf* i;
  int reexpress_limit;
};

struct file_fetcher {
  struct ndn* h;
  FILE* file;
  struct ndn_charbuf* name;// Name with version
  struct ndn_indexbuf* name_comps;
  struct segment_list* sl;
  struct file_fetcher_req* reqs;
  int total_reqs;
  int ok_reqs;
  int fail_reqs;
  int outstanding_hashreqs;
  int outstanding_namereqs;
  int complete_hashreqs;
  int complete_namereqs;
};

#define FILE_FETCHER_HASHREQ_CONCURRENT 30
#define FILE_FETCHER_HASHREQ_TIMEOUT 500
#define FILE_FETCHER_NAMEREQ_CONCURRENT 10
#define FILE_FETCHER_NAMEREQ_REEXPRESS 2

struct file_fetcher* file_fetcher_ctor(struct segment_list* sl, FILE* file, struct ndn* h, struct ndn_charbuf* name);
void file_fetcher_dtor(struct file_fetcher** selfp);
bool file_fetcher_run(struct file_fetcher* self);
// private begin
void file_fetcher_build_reqs(struct file_fetcher* self);
void file_fetcher_next_reqs(struct file_fetcher* self);
struct ndn_charbuf* file_fetcher_hashreq_templ(void);
void file_fetcher_send_hashreq(struct file_fetcher* self, int j);
void file_fetcher_send_namereq(struct file_fetcher* self, int j);
enum ndn_upcall_res file_fetcher_incoming_co_hashreq(struct ndn_closure* closure, enum ndn_upcall_kind kind, struct ndn_upcall_info* info);
enum ndn_upcall_res file_fetcher_incoming_co_namereq(struct ndn_closure* closure, enum ndn_upcall_kind kind, struct ndn_upcall_info* info);
void file_fetcher_save_co(struct file_fetcher* self, struct file_fetcher_req* req, struct ndn_upcall_info* info);
// private end

#endif//CAREPO_SEGMENT_WRITER_H_
