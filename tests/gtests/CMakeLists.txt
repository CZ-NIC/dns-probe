find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(DynamicMempoolTests DynamicMempoolTests.cpp)
target_link_libraries(DynamicMempoolTests DNSCollector GTest::Main)
target_include_directories(DynamicMempoolTests PUBLIC "../../src")

gtest_discover_tests(DynamicMempoolTests)
