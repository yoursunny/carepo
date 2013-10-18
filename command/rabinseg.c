// segment a file using Rabin Fingerprint, and print the segment offsets and hashes
#include "segment/rabin.h"
#include "segment/metadata.h"

void usage(void) {
  printf("Usage: rabinseg [-h] filename\n");
}

int main(int argc, char** argv) {
  bool human_readable = false;
  int opt;
  while (-1 != (opt = getopt(argc, argv, "h"))) {
    switch (opt) {
      case 'h':
        human_readable = true;
        break;
    }
  }
  if (optind >= argc) {
    usage();
    return 1;
  }
  
  const char* filename = argv[optind];
  FILE* file = fopen(filename, "r");
  if (file == NULL) return 2;
  struct segment_list* sl = segment_rabin(file);
  fclose(file);
  if (sl == NULL) return 3;
  
  if (human_readable) {
    segment_list_print(sl, stdout);
  } else {
    struct ndn_charbuf* c = ndn_charbuf_create();
    segment_list_to_metadata(sl, c);
    write(1, c->buf, c->length);
    ndn_charbuf_destroy(&c);
  }
  
  segment_list_dtor(&sl);
  return 0;
}

