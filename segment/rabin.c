#include "rabin.h"
#include "rabin/rabin_polynomial.h"
#include <ndn/digest.h>

struct segment_list* segment_rabin(FILE* file) {
  rabin_sliding_window_size = 31;
  rabin_polynomial_max_block_size = 8192;
  rabin_polynomial_min_block_size = 1024;
  rabin_polynomial_average_block_size = 4096;

  if (0 != fseek(file, 0, SEEK_SET)) return NULL;
  struct rabin_polynomial* head = get_file_rabin_polys(file);
  if (head == NULL) return NULL;
  
  if (0 != fseek(file, 0, SEEK_END)) return NULL;
  long int length = ftell(file);
  if (length == -1L) return NULL;
  
  if (0 != fseek(file, 0, SEEK_SET)) return NULL;
  uint32_t count = 0;
  for (struct rabin_polynomial* poly = head; poly != NULL; poly = poly->next_polynomial) {
    ++count;
    length -= poly->length;
  }
  if (length != 0) return NULL;
  
  struct segment_list* sl = segment_list_ctor(count);
  int i = 0; uint64_t start = 0;
  uint8_t buffer[65536];
  struct ndn_digest* digest = ndn_digest_create(NDN_DIGEST_SHA256);
  for (struct rabin_polynomial* poly = head; poly != NULL; poly = poly->next_polynomial) {
    struct segment* seg = sl->list + i;
    seg->start = start;
    seg->length = poly->length;
    ndn_digest_init(digest);
    size_t read_size = 0;
    while (read_size < poly->length) {
      size_t read_want = poly->length - read_size;
      if (read_want > sizeof(buffer)) read_want = sizeof(buffer);
      size_t read_res = fread(buffer, 1, read_want, file);
      ndn_digest_update(digest, buffer, read_res);
      read_size += read_res;
    }
    ndn_digest_final(digest, seg->hash, sizeof(seg->hash));
    ++i;
    start += poly->length;
  }
  ndn_digest_destroy(&digest);
  
  return sl;
}

