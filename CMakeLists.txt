cmake_minimum_required(VERSION 3.5)
project("DNS Probe" VERSION 0.11.2)

set(AF_PACKET_BACKEND ON CACHE BOOL "Define backend for packet processing")
set(DPDK_BACKEND OFF CACHE BOOL "Define backend for packet processing")
set(DPDK_LEGACY_MEM OFF CACHE BOOL "Enable legacy memory management for DPDK")
set(BUILD_COLLECTOR ON CACHE BOOL "Build collector for data from probe's remote export")
set(BUILD_TESTING OFF CACHE BOOL "Enable build testing binaries")
set(BUILD_DOC ON CACHE BOOL "Generate Sphinx and Doxygen documentation")
set(PROBE_CRYPTOPANT ON CACHE BOOL "Enable IP anonymization with cryptopANT library")
set(PROBE_PARQUET ON CACHE BOOL "Enable export to Parquet format with Apache Arrow library")
set(PROBE_CDNS ON CACHE BOOL "Enable export to C-DNS format with C-DNS library")
set(PROBE_DNSTAP ON CACHE BOOL "Enable support for dnstap as input data format")
set(PROBE_KNOT ON CACHE BOOL "Enable support for Knot probe interface as input data format")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

## Find required libraries
find_package(Threads REQUIRED)
find_package(PCAP REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Yaml-cpp REQUIRED)
find_package(MaxmindDB REQUIRED)
find_package(Doxygen)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-msse4 SSE4_FLAG)
if (NOT SSE4_FLAG)
    message(FATAL_ERROR "SSE4 is required for compilation!")
endif ()

# Common library for all backends
file(GLOB PROBE_HEADERS CONFIGURE_DEPENDS src/core/Probe.h
        src/core/*.h
        src/communication/*.h
        src/config/*.h
        src/export/*.h
        src/platform/*.h
        src/utils/*.h
        )

file(GLOB PROBE_SOURCES CONFIGURE_DEPENDS src/core/Probe.cpp
        src/communication/*.cpp
        src/config/*.cpp
        src/core/*.cpp
        src/export/*.cpp
        src/platform/*.cpp
        src/utils/*.cpp
        )

add_library(DNSProbe INTERFACE)
target_link_libraries(DNSProbe INTERFACE ${Boost_LIBRARIES} ${YAML_CPP_LIBRARIES} PCAP::PCAP Threads::Threads OpenSSL::SSL MaxmindDB::MaxmindDB)
target_compile_definitions(DNSProbe INTERFACE $<$<CONFIG:Debug>:PRINT_DEBUG>)
target_include_directories(DNSProbe INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src ${Boost_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIR})
target_compile_options(DNSProbe INTERFACE -msse4)

if (OPENSSL_VERSION VERSION_LESS "1.1.0")
    target_compile_definitions(DNSProbe INTERFACE PROBE_OPENSSL_LEGACY)
endif()

if ((NOT PROBE_PARQUET) AND (NOT PROBE_CDNS))
    message(FATAL_ERROR "You must set at least one of available export formats (PROBE_PARQUET, PROBE_CDNS)!")
endif()

if (PROBE_PARQUET)
    find_package(Arrow REQUIRED)
    find_package(Parquet REQUIRED)
    target_link_libraries(DNSProbe INTERFACE Arrow::Arrow Parquet::Parquet)
    target_compile_definitions(DNSProbe INTERFACE PROBE_PARQUET)
    file(GLOB PARQUET_HEADERS CONFIGURE_DEPENDS src/export/parquet/*.h)
    file(GLOB PARQUET_SOURCES CONFIGURE_DEPENDS src/export/parquet/*.cpp)
endif()

if (PROBE_CDNS)
    find_package(CDNS REQUIRED)
    target_link_libraries(DNSProbe INTERFACE CDNS::CDNS)
    target_compile_definitions(DNSProbe INTERFACE PROBE_CDNS)
    file(GLOB CDNS_HEADERS CONFIGURE_DEPENDS src/export/cdns/*.h)
    file(GLOB CDNS_SOURCES CONFIGURE_DEPENDS src/export/cdns/*.cpp)
endif()

if (PROBE_CRYPTOPANT)
    find_package(cryptopANT REQUIRED)
    target_link_libraries(DNSProbe INTERFACE cryptopANT::cryptopANT)
    target_compile_definitions(DNSProbe INTERFACE PROBE_CRYPTOPANT)
endif()

if (PROBE_DNSTAP)
    find_package(Protobuf REQUIRED)
    find_package(Fstrm REQUIRED)
    execute_process(COMMAND protoc --cpp_out=${CMAKE_CURRENT_BINARY_DIR} --proto_path=${CMAKE_SOURCE_DIR}/src/dnstap ${CMAKE_SOURCE_DIR}/src/dnstap/dnstap.proto)
    add_library(dnstap_proto ${CMAKE_CURRENT_BINARY_DIR}/dnstap.pb.h ${CMAKE_CURRENT_BINARY_DIR}/dnstap.pb.cc)
    target_link_libraries(dnstap_proto PUBLIC ${PROTOBUF_LIBRARIES})
    target_include_directories(dnstap_proto PUBLIC ${PROTOBUF_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(DNSProbe INTERFACE ${PROTOBUF_LIBRARIES} dnstap_proto Fstrm::Fstrm)
    target_include_directories(DNSProbe INTERFACE ${PROTOBUF_INCLUDE_DIRS})
    target_compile_definitions(DNSProbe INTERFACE PROBE_DNSTAP)
    file(GLOB DNSTAP_HEADERS CONFIGURE_DEPENDS src/dnstap/*.h)
    file(GLOB DNSTAP_SOURCES CONFIGURE_DEPENDS src/dnstap/*.cpp)
endif()

if (PROBE_KNOT)
    find_package(Libknot REQUIRED)
    target_link_libraries(DNSProbe INTERFACE Libknot::Libknot)
    target_compile_definitions(DNSProbe INTERFACE PROBE_KNOT)
    file(GLOB KNOT_HEADERS CONFIGURE_DEPENDS src/knot/*.h)
    file(GLOB KNOT_SOURCES CONFIGURE_DEPENDS src/knot/*.cpp)
endif()

# Add warning flags
function(set_warning param)
    check_cxx_compiler_flag(-W${param} WARNING_${param})
    if (WARNING_${param})
        target_compile_options(DNSProbe INTERFACE -W${param})
    endif ()
endfunction()

set_warning(all)
set_warning(extra)
set_warning(no-address-of-packed-member)

include(GNUInstallDirs)

# Settings for AF Packet version
if (AF_PACKET_BACKEND)
    file(GLOB AF_PACKET_HEADERS CONFIGURE_DEPENDS src/non-dpdk/*.h)
    file(GLOB AF_PACKET_SOURCES CONFIGURE_DEPENDS src/non-dpdk/*.cpp)

    set(AF_FILES ${AF_PACKET_HEADERS} ${AF_PACKET_SOURCES} ${PROBE_HEADERS} ${PROBE_SOURCES}
        ${PARQUET_HEADERS} ${PARQUET_SOURCES} ${CDNS_HEADERS} ${CDNS_SOURCES} ${DNSTAP_HEADERS} ${DNSTAP_SOURCES} ${KNOT_HEADERS} ${KNOT_SOURCES})
    add_executable(dns-probe-af src/application/dp.cpp ${AF_FILES})
    target_link_libraries(dns-probe-af PUBLIC DNSProbe)
    install(TARGETS dns-probe-af RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    set(BACKEND af)
    configure_file(${CMAKE_SOURCE_DIR}/src/application/dp-runner.sh ${CMAKE_BINARY_DIR}/dp-af @ONLY)
    configure_file(${CMAKE_SOURCE_DIR}/systemd/dns-probe@.service.in ${CMAKE_BINARY_DIR}/systemd/dns-probe-af@.service)
    install(PROGRAMS ${CMAKE_BINARY_DIR}/dp-af DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES ${CMAKE_SOURCE_DIR}/data-model/dns-probe.yml DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/dns-probe-af)
    install(FILES ${CMAKE_BINARY_DIR}/systemd/dns-probe-af@.service DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
    target_compile_definitions(dns-probe-af PUBLIC PROBE_CONFIG="${CMAKE_INSTALL_DIR}/${CMAKE_INSTALL_SYSCONFDIR}/dns-probe-af/dns-probe.yml")
endif ()

# Settings for DPDK version
if (DPDK_BACKEND)
    find_package(DPDK REQUIRED)

    file(GLOB DPDK_HEADERS CONFIGURE_DEPENDS src/dpdk/*.h)
    file(GLOB DPDK_SOURCES CONFIGURE_DEPENDS src/dpdk/*.cpp)

    set(DPDK_FILES ${DPDK_HEADERS} ${DPDK_SOURCES} ${PROBE_HEADERS} ${PROBE_SOURCES}
        ${PARQUET_HEADERS} ${PARQUET_SOURCES} ${CDNS_HEADERS} ${CDNS_SOURCES} ${DNSTAP_HEADERS} ${DNSTAP_SOURCES} ${KNOT_HEADERS} ${KNOT_SOURCES})
    add_executable(dns-probe-dpdk src/application/ddp.cpp ${DPDK_FILES})
    target_link_libraries(dns-probe-dpdk PUBLIC DNSProbe DPDK::DPDK)
    target_compile_definitions(dns-probe-dpdk PUBLIC USE_DPDK)

    if (DPDK_LEGACY_MEM)
        target_compile_definitions(dns-probe-dpdk PRIVATE DPDK_LEGACY_MEM)
    endif ()

    if (libdpdk_VERSION VERSION_LESS "18.05")
        target_compile_definitions(dns-probe-dpdk PRIVATE DPDK_LEGACY)
    endif()

    install(TARGETS dns-probe-dpdk RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    set(BACKEND dpdk)
    configure_file(${CMAKE_SOURCE_DIR}/src/application/dp-runner.sh ${CMAKE_BINARY_DIR}/dp-dpdk @ONLY)
    install(PROGRAMS ${CMAKE_BINARY_DIR}/dp-dpdk DESTINATION ${CMAKE_INSTALL_BINDIR})
    configure_file(${CMAKE_SOURCE_DIR}/systemd/dns-probe@.service.in ${CMAKE_BINARY_DIR}/systemd/dns-probe-dpdk@.service)
    install(FILES ${CMAKE_SOURCE_DIR}/data-model/dns-probe.yml DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/dns-probe-dpdk)
    install(FILES ${CMAKE_BINARY_DIR}/systemd/dns-probe-dpdk@.service DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
    target_compile_definitions(dns-probe-dpdk PUBLIC PROBE_CONFIG="${CMAKE_INSTALL_DIR}/${CMAKE_INSTALL_SYSCONFDIR}/dns-probe-dpdk/dns-probe.yml")
endif ()

add_custom_target(uninstall COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/Uninstall.cmake")

#Build collector
if (BUILD_COLLECTOR)
    add_subdirectory("collector")
endif()

#Add tests
enable_testing()
if (BUILD_TESTING)
    add_subdirectory(tests/gtests)
endif ()

#Add Doxygen documentation
if (BUILD_DOC)
    if (DOXYGEN_FOUND)
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)

        add_custom_target(doxygen
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating Doxygen documentation"
            VERBATIM
        )
    else (DOXYGEN_FOUND)
        message("Install Doxygen to generate Doxygen documentation")
    endif(DOXYGEN_FOUND)

    add_subdirectory("doc")
endif(BUILD_DOC)

