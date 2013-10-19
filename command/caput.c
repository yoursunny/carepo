// put a file and SHA256 metadata into repository
#include "segment/rabin.h"
#include "segment/writer.h"
#include <ndn/uri.h>

void usage(void) {
  printf("Usage: caput [-s] name filename\n");
}

int main(int argc, char** argv) {
  bool sign_segments = false;
  int opt;
  while (-1 != (opt = getopt(argc, argv, "s"))) {
    switch (opt) {
      case 's':
        sign_segments = true;
        break;
    }
  }
  if (argc-optind != 2) {
    usage();
    return 1;
  }
  const char* name_str = argv[optind+0];
  const char* filename = argv[optind+1];
  
  struct ndn_charbuf* name = ndn_charbuf_create();
  ndn_name_from_uri(name, name_str);

  FILE* file = fopen(filename, "r");
  if (file == NULL) return 2;
  struct segment_list* sl = segment_rabin(file);
  if (sl == NULL) return 3;
  
  struct ndn* h = ndn_create();
  if (-1 == ndn_connect(h, NULL)) return 4;

  struct file_writer* fw = file_writer_ctor(sl, file, h, name, sign_segments);
  if (!file_writer_run(fw)) return 5;
  
  file_writer_dtor(&fw);
  fclose(file);
  ndn_destroy(&h);
  segment_list_dtor(&sl);
  ndn_charbuf_destroy(&name);
  return 0;
}

