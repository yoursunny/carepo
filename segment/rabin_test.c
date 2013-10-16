#include <CUnit/CUnit.h>
#include "rabin.h"
#include "metadata.h"

void test_segment_rabin(void) {
  FILE* file = fopen("waf", "r");
  struct segment_list* sl = segment_rabin(file);
  CU_ASSERT_PTR_NOT_NULL(sl);
  fclose(file);
  
  struct ndn_charbuf* c = ndn_charbuf_create();
  segment_list_to_metadata(sl, c);
  CU_ASSERT(c->length > 0);
  struct segment_list* sl2 = segment_list_from_metadata(c->buf, c->length);
  CU_ASSERT_PTR_NOT_NULL(sl2);
  CU_ASSERT_EQUAL(sl2->count, sl->count);
  for (uint32_t i = 0; i < sl->count; ++i) {\
    CU_ASSERT_EQUAL(sl2->list[i].start, sl->list[i].start);
    CU_ASSERT_EQUAL(sl2->list[i].length, sl->list[i].length);
    CU_ASSERT(0 == memcmp(sl2->list[i].hash, sl->list[i].hash, sizeof(sl->list[i].hash)));
  }
  
  segment_list_dtor(&sl);
  segment_list_dtor(&sl2);
  ndn_charbuf_destroy(&c);
}

