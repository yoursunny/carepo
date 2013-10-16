#include "segment/rabin.h"
#include "segment/metadata.h"

// segment a file using Rabin Fingerprint, and print the segment offsets and hashes

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Usage: %s filename\n", argv[0]);
    return 1;
  }
  const char* filename = argv[1];
  FILE* file = fopen(filename, "r");
  if (file == NULL) return 2;
  struct segment_list* sl = segment_rabin(file);
  fclose(file);
  if (sl == NULL) return 3;
  
  //segment_list_print(sl, stdout);
  struct ndn_charbuf* c = ndn_charbuf_create();
  segment_list_to_metadata(sl, c);
  write(1, c->buf, c->length);
  
  return 0;
}

