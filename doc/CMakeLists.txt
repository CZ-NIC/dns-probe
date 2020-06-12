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
                      COMMAND
                      ${SPHINX_EXECUTABLE} -b man
                                           -D version=${PROJECT_VERSION}
                                           -D release=${PROJECT_VERSION}
                                           ${SPHINX_SOURCE} ${SPHINX_BUILD_MAN}
                      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                      COMMENT "Generating documentation with Sphinx")

    if (AF_PACKET_BACKEND)
        file(GLOB AF_MAN_FILES CONFIGURE_DEPENDS ${SPHINX_BUILD_MAN}/*af.1)
        install(FILES ${AF_MAN_FILES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
    endif()

    if (DPDK_BACKEND)
        file(GLOB DPDK_MAN_FILES CONFIGURE DEPENDS ${SPHINX_BUILD_MAN}/*dpdk.1)
        install(FILES ${DPDK_MAN_FILES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
    endif()
else (Sphinx_FOUND)
    message("Install Sphinx to generate documentation and manual pages")
endif(Sphinx_FOUND)