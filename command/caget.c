// fetch a file based on metadata
#include "segment/fetcher.h"

void usage(void) {
  printf("Usage: caget name metafile filename\n");
}

int main(int argc, char** argv) {
  optind = 1;
  if (argc-optind != 3) {
    usage();
    return 1;
  }
  const char* name_str = argv[optind+0];
  const char* metadata_filename = argv[optind+1];
  const char* filename = argv[optind+2];
  
  struct ndn_charbuf* name = ndn_charbuf_create();
  ndn_name_from_uri(name, name_str);
  
  FILE* metadata_file = fopen(metadata_filename, "r");
  if (metadata_file == NULL) return 2;
  struct ndn_charbuf* metadata = ndn_charbuf_create();
  while (0 == feof(metadata_file)) {
    size_t read_res = fread(ndn_charbuf_reserve(metadata, 2048), 1, 2048, metadata_file);
    if (read_res == 0) break;
    metadata->length += read_res;
  }
  struct segment_list* sl = segment_list_from_metadata(metadata->buf, metadata->length);
  if (sl == NULL) return 3;
  ndn_charbuf_destroy(&metadata);
  fclose(metadata_file);

  FILE* file = fopen(filename, "w");
  if (file == NULL) return 4;
  
  struct ndn* h = ndn_create();
  if (-1 == ndn_connect(h, NULL)) return 5;

  struct file_fetcher* ff = file_fetcher_ctor(sl, file, h, name);
  if (!file_fetcher_run(ff)) return 6;
  
  file_fetcher_dtor(&ff);
  fclose(file);
  ndn_destroy(&h);
  segment_list_dtor(&sl);
  ndn_charbuf_destroy(&name);
  return 0;
}

