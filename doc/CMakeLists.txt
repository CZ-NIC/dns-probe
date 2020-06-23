find_package(Sphinx)

if (Sphinx_FOUND)
    set(SPHINX_SOURCE ${CMAKE_CURRENT_SOURCE_DIR})
    set(SPHINX_BUILD_HTML ${CMAKE_CURRENT_BINARY_DIR}/html)
    set(SPHINX_BUILD_MAN ${CMAKE_CURRENT_BINARY_DIR}/man)

    add_custom_target(doc
                      COMMAND
                      ${SPHINX_EXECUTABLE} -b html
                                           -D version=${PROJECT_VERSION}
                                           -D release=${PROJECT_VERSION}
                                           -D html_title='DNS Probe ${PROJECT_VERSION} Documentation'
                                           -D html_short_title='DNS Probe ${PROJECT_VERSION} Docs'
                                           ${SPHINX_SOURCE} ${SPHINX_BUILD_HTML}
                      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                      COMMENT "Generating documentation with Sphinx")

    add_custom_target(man
                      COMMAND
                      ${SPHINX_EXECUTABLE} -b man
                                           -D needs_sphinx='1.3'
                                           -D version=${PROJECT_VERSION}
                                           -D release=${PROJECT_VERSION}
                                           ${SPHINX_SOURCE} ${SPHINX_BUILD_MAN}
                      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                      COMMENT "Generating manual pages with Sphinx")

    if (AF_PACKET_BACKEND)
        install(FILES ${SPHINX_BUILD_MAN}/dns-probe-af.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 OPTIONAL)
    endif()

    if (DPDK_BACKEND)
        install(FILES ${SPHINX_BUILD_MAN}/dns-probe-dpdk.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 OPTIONAL)
    endif()
else (Sphinx_FOUND)
    message("Install Sphinx to generate documentation and manual pages")
endif(Sphinx_FOUND)