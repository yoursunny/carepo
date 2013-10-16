#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

int main(void) {
  CU_initialize_registry();
  
  CU_pSuite suite;

#define SUITE(name) { suite = CU_add_suite(#name, NULL, NULL); }
#define TEST(f) { void test_##f(void); CU_add_test(suite, #f, test_##f); }

#include "segment/testsuite.h"
  
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return 0;
}

