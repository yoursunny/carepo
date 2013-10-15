#include <CUnit/CUnit.h>
#include "segment.h"

void test_segment_ctor(void) {
  struct segment_list* sl = segment_list_ctor(2);
  CU_ASSERT_PTR_NOT_NULL(sl);
  CU_ASSERT_PTR_NOT_NULL(sl->list);
  CU_ASSERT_EQUAL(sl->count, 2);
  segment_list_dtor(&sl);
  CU_ASSERT_PTR_NULL(sl);
  segment_list_dtor(&sl);
  CU_ASSERT_PTR_NULL(sl);
}

