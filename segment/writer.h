#ifndef CAREPO_SEGMENT_WRITER_H_
#define CAREPO_SEGMENT_WRITER_H_
#include "metadata.h"

struct file_writer {
  struct ndn* h;
  struct ndn_closure* closure;
  FILE* file;
  struct ndn_charbuf* name;// Name with version
  struct ndn_indexbuf* name_comps;
  struct segment_list* sl;
  bool* sent_segments;
  int remaining_segments;
  struct ndn_charbuf* metadata_name;// Name of metadata with version
  struct ndn_charbuf* metadata;
  int total_metadata_blocks;
  bool* sent_metadata_blocks;
  int remaining_metadata_blocks;
  int recent_interests;
};

#define FILE_WRITER_METADATA_BLOCKSZ 4096
#define FILE_WRITER_STARTWRITE_TIMEOUT 4000 // file_writer_startwrite fails if startwrite is not responded in this duration
#define FILE_WRITER_RUN_TIMEOUT_INTERVAL 1000 // file_writer_run fails if no incoming Interest in this duration

struct file_writer* file_writer_ctor(struct segment_list* sl, FILE* file, struct ndn* h, struct ndn_charbuf* name);
void file_writer_dtor(struct file_writer** selfp);
bool file_writer_run(struct file_writer* self);
// private begin
bool file_writer_startwrite(struct file_writer* self);
enum ndn_upcall_res file_writer_incoming_interest(struct ndn_closure* closure, enum ndn_upcall_kind kind, struct ndn_upcall_info* info);
uintmax_t file_writer_extract_number(struct ndn_upcall_info* info);
bool file_writer_respond_segment(struct file_writer* self, struct ndn_upcall_info* info);
bool file_writer_respond_metadata(struct file_writer* self, struct ndn_upcall_info* info);
// private end

#endif//CAREPO_SEGMENT_WRITER_H_
