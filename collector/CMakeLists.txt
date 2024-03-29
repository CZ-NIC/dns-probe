find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(dp-collector main.cpp Collector.cpp Collector.h)
target_link_libraries(dp-collector PUBLIC Threads::Threads OpenSSL::SSL)
configure_file(${CMAKE_SOURCE_DIR}/systemd/dns-probe-collector.service.in
               ${CMAKE_BINARY_DIR}/systemd/dns-probe-collector.service)
install(TARGETS dp-collector RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES dp-collector.conf DESTINATION /etc/dns-probe-collector)
install(FILES ${CMAKE_BINARY_DIR}/systemd/dns-probe-collector.service
        DESTINATION /lib/systemd/system)

target_compile_definitions(dp-collector PUBLIC PROBE_COLLECTOR_CONFIG="${CMAKE_INSTALL_DIR}/etc/dns-probe-collector/dp-collector.conf")
if (OPENSSL_VERSION VERSION_LESS "1.1.0")
    target_compile_definitions(dp-collector PRIVATE PROBE_OPENSSL_LEGACY)
endif()
