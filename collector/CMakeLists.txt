find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(dp-collector main.cpp collector.cpp collector.h)
target_link_libraries(dp-collector PUBLIC Threads::Threads OpenSSL::SSL)
install(TARGETS dp-collector RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if (OPENSSL_VERSION VERSION_LESS "1.1.0")
    target_compile_definitions(dp-collector PRIVATE PROBE_OPENSSL_LEGACY)
endif()
