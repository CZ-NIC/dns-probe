set(MANIFEST "${CMAKE_CURRENT_BINARY_DIR}/install_manifest.txt")

if(NOT EXISTS ${MANIFEST})
    message(FATAL_ERROR "Cannot find install manifest: ${MANIFEST}")
endif()

file(STRINGS ${MANIFEST} files)
foreach(file ${files})
    message(STATUS "Uninstalling: ${file}")
    if(EXISTS ${file} OR IS_SYMLINK ${file})
        execute_process(COMMAND rm -f ${file}
            RESULT_VARIABLE resval
            OUTPUT_QUIET
            ERROR_VARIABLE stderr
        )

        if(NOT ${resval} EQUAL 0)
            message(FATAL_ERROR "${stderr}")
        endif()
    else()
        message(STATUS "File doesn't exist: ${file}")
    endif()
endforeach(file)
