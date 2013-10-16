#include "segment/rabin.h"

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
  if (sl == NULL) return 3;
  segment_list_print(sl, stdout);
  fclose(file);
  return 0;
}

