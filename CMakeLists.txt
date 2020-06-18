cmake_minimum_required(VERSION 3.5)
project("DNS Probe" VERSION 0.4.4)

set(AF_PACKET_BACKEND ON CACHE BOOL "Define backend for packet processing")
set(DPDK_BACKEND OFF CACHE BOOL "Define backend for packet processing")
set(DPDK_LEGACY_MEM OFF CACHE BOOL "Enable legacy memory management for DPDK")
set(BUILD_TESTING OFF CACHE BOOL "Enable build testing binaries")
set(BUILD_DOC ON CACHE BOOL "Generate Sphinx and Doxygen documentation")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

## Find required libraries
find_package(Threads REQUIRED)
find_package(PCAP REQUIRED)
find_package(Arrow REQUIRED)
find_package(Parquet REQUIRED)
find_package(CDNS REQUIRED)
find_package(LibYangCpp REQUIRED)
find_package(SysrepoCpp REQUIRED)
find_package(Boost REQUIRED COMPONENTS log log_setup)
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
target_link_libraries(DNSProbe INTERFACE ${Boost_LIBRARIES} PCAP::PCAP Arrow::Arrow Parquet::Parquet Threads::Threads LibYangCpp::LibYangCpp SysrepoCpp::SysrepoCpp CDNS::CDNS)
target_compile_definitions(DNSProbe INTERFACE $<$<CONFIG:Debug>:PRINT_DEBUG>)
target_include_directories(DNSProbe INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src ${Boost_INCLUDE_DIRS})
target_compile_options(DNSProbe INTERFACE -msse4 -DBOOST_LOG_DYN_LINK)

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

    set(AF_FILES ${AF_PACKET_HEADERS} ${AF_PACKET_SOURCES} ${PROBE_HEADERS} ${PROBE_SOURCES})
    add_executable(dns-probe-af src/application/dp.cpp ${AF_FILES})
    target_link_libraries(dns-probe-af PUBLIC DNSProbe)
    install(TARGETS dns-probe-af RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    set(BACKEND af)
    configure_file(${CMAKE_SOURCE_DIR}/src/application/dp-runner.sh ${CMAKE_BINARY_DIR}/dp-af @ONLY)
    configure_file(${CMAKE_SOURCE_DIR}/systemd/dns-probe@.service.in ${CMAKE_BINARY_DIR}/systemd/dns-probe-af@.service)
    configure_file(${CMAKE_SOURCE_DIR}/etc/probe.conf.in ${CMAKE_BINARY_DIR}/etc/dns-probe-af/probe.conf)
    install(PROGRAMS ${CMAKE_BINARY_DIR}/dp-af DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES ${CMAKE_SOURCE_DIR}/data-model/cznic-dns-probe.yang DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/dns-probe-af)
    install(FILES ${CMAKE_BINARY_DIR}/systemd/dns-probe-af@.service DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
    install(FILES ${CMAKE_BINARY_DIR}/etc/dns-probe-af/probe.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/dns-probe-af)
endif ()

# Settings for DPDK version
if (DPDK_BACKEND)
    find_package(DPDK REQUIRED)

    file(GLOB DPDK_HEADERS CONFIGURE_DEPENDS src/dpdk/*.h)
    file(GLOB DPDK_SOURCES CONFIGURE_DEPENDS src/dpdk/*.cpp)

    set(DPDK_FILES ${DPDK_HEADERS} ${DPDK_SOURCES} ${PROBE_HEADERS} ${PROBE_SOURCES})
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
    configure_file(${CMAKE_SOURCE_DIR}/etc/probe.conf.in ${CMAKE_BINARY_DIR}/etc/dns-probe-dpdk/probe.conf)
    install(FILES ${CMAKE_SOURCE_DIR}/data-model/cznic-dns-probe.yang DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/dns-probe-dpdk)
    install(FILES ${CMAKE_BINARY_DIR}/systemd/dns-probe-dpdk@.service DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
    install(FILES ${CMAKE_BINARY_DIR}/etc/dns-probe-dpdk/probe.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/dns-probe-dpdk)
endif ()

add_custom_target(install_module COMMAND sysrepoctl -i ${CMAKE_SOURCE_DIR}/data-model/cznic-dns-probe.yang)

add_custom_target(uninstall COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/Uninstall.cmake")

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

