find_package(GTest REQUIRED)
include(GoogleTest)

file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ../../src/utils/DynamicMempool.*)

add_executable(DynamicMempoolTests DynamicMempoolTests.cpp ${TEST_SOURCES})
target_link_libraries(DynamicMempoolTests DNSProbe GTest::Main)
target_include_directories(DynamicMempoolTests PUBLIC "../../src")

gtest_discover_tests(DynamicMempoolTests)
