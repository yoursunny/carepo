#include <CUnit/CUnit.h>
#include "rabin.h"

void test_segment_rabin(void) {
  FILE* file = fopen("waf", "r");
  struct segment_list* sl = segment_rabin(file);
  CU_ASSERT_PTR_NOT_NULL(sl);
  segment_list_print(sl, stderr);
  fclose(file);
}

